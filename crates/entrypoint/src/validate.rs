// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Offline node-state validation.
//!
//! Backs the `interfold node validate` CLI command. It opens a node's persisted
//! stores offline (no network or chain writes) and answers the
//! operator question: *"Is my on-disk state intact, internally consistent, free
//! of loose ends, and will this binary be able to load it after an upgrade?"*
//!
//! It never mutates protocol state, talks to the chain, or starts the node. By
//! default it is fully non-destructive. The explicit `--repair` mode may only
//! truncate a provably uncommitted physical event-log tail and rebuild index
//! entries for complete CRC-valid tail records.
//!
//! ## Checks performed
//!
//! 1. **Event-store integrity** — reads every event for every aggregate from
//!    sequence 0 and verifies the sequence numbers are contiguous and strictly
//!    increasing. A gap or a decode failure means the commit log (the source of
//!    truth) is truncated or corrupt.
//! 2. **Snapshot cursor consistency** — verifies the persisted per-aggregate
//!    sequence cursor does not point past the last event actually present in the
//!    log (which would indicate a snapshot that is ahead of a truncated log).
//! 3. **Sortition projection consistency** — rebuilds the registered-node set from
//!    source-of-truth events and compares it with the persisted selection backend.
//! 4. **Open-loop / loose-ends audit** — loads the persisted sortition state and
//!    flags any committee that still holds an active-job slot **even though the
//!    event log already contains a terminal event** for that E3. These are the
//!    orphaned tickets that a crash mid-E3 can leave behind; they are the
//!    "loose ends" a restart should clean up.

use crate::helpers::datastore::get_repositories;
use anyhow::{bail, Context, Result};
use e3_config::AppConfig;
use e3_data::{CommitLogEventLog, EventLogOpenMode, Repositories};
use e3_events::{
    AggregateId, E3Stage, Event, EventContextAccessors, EventContextSeq, InterfoldEvent,
    InterfoldEventData,
};
use e3_sortition::{
    committee_key, NodeRegistry, NodeStateRepositoryFactory, NodeStateStore, SortitionList,
    SortitionRepositoryFactory,
};
use e3_sync::{
    decide_schema_version, has_schema_governed_kv_state, SchemaVersionDecision,
    SyncRepositoryFactory, SCHEMA_VERSION,
};
use e3_utils::enumerate_path;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

/// Outcome severity for a single validation check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Check passed; nothing to do.
    Pass,
    /// Non-fatal observation the operator should be aware of.
    Warn,
    /// A real problem that must be resolved before the node can be trusted.
    Fail,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }
}

/// Result of a single named validation check.
#[derive(Clone, Debug)]
pub struct CheckResult {
    /// Short, stable name of the check (e.g. `"schema"`).
    pub name: String,
    /// Severity of the outcome.
    pub severity: Severity,
    /// Human-readable detail explaining the outcome.
    pub detail: String,
}

impl CheckResult {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            severity: Severity::Pass,
            detail: detail.into(),
        }
    }
    #[allow(dead_code)]
    fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            severity: Severity::Warn,
            detail: detail.into(),
        }
    }
    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            severity: Severity::Fail,
            detail: detail.into(),
        }
    }
}

/// Aggregated result of running every validation check.
#[derive(Clone, Debug, Default)]
pub struct ValidationReport {
    /// Individual check outcomes, in execution order.
    pub checks: Vec<CheckResult>,
}

impl ValidationReport {
    fn push(&mut self, check: CheckResult) {
        self.checks.push(check);
    }

    /// Whether any check failed (i.e. the node should not be trusted/upgraded as-is).
    pub fn has_failure(&self) -> bool {
        self.checks.iter().any(|c| c.severity == Severity::Fail)
    }

    /// Whether any check produced a warning.
    pub fn has_warning(&self) -> bool {
        self.checks.iter().any(|c| c.severity == Severity::Warn)
    }

    /// Render the report as human-readable text.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("Interfold node validation report\n");
        out.push_str("==============================\n");
        for c in &self.checks {
            out.push_str(&format!(
                "[{}] {}: {}\n",
                c.severity.label(),
                c.name,
                c.detail
            ));
        }
        let verdict = if self.has_failure() {
            "VALIDATION FAILED — resolve the FAIL items before starting or upgrading this node."
        } else if self.has_warning() {
            "VALIDATION PASSED WITH WARNINGS — review the WARN items."
        } else {
            "VALIDATION PASSED — state is intact and consistent."
        };
        out.push_str("------------------------------\n");
        out.push_str(verdict);
        out.push('\n');
        out
    }
}

/// Run every validation check against the node configured by `config`.
///
/// Opens the persisted stores while holding the node's exclusive process fence.
/// Returns the full report; callers decide how to surface it (the CLI prints it
/// and exits non-zero on failure).
pub async fn validate_node(config: &AppConfig, repair: bool) -> Result<ValidationReport> {
    let aggregate_ids = aggregate_ids(config);
    let mut report = ValidationReport::default();

    // 1. Read the commit logs directly before starting any EventStore actor. The
    // checked reader lets the operator receive a structured validation report.
    let mut terminal_keys: HashSet<String> = HashSet::new();
    let mut total_events: u64 = 0;
    let mut events_by_aggregate = Vec::with_capacity(aggregate_ids.len());
    let mut unreadable_logs = 0usize;
    for agg in &aggregate_ids {
        let path = enumerate_path(&config.log_file(), agg.to_usize());
        match read_event_log(&path, *agg, repair) {
            Ok(events) => {
                total_events += events.len() as u64;
                collect_terminal_keys(&events, &mut terminal_keys);

                let seqs: Vec<u64> = events.iter().map(|e| e.seq()).collect();
                report.push(check_sequence_integrity(*agg, &seqs));
                events_by_aggregate.push((*agg, events));
            }
            Err(error) => {
                unreadable_logs += 1;
                report.push(CheckResult::fail(
                    "event-log",
                    format!(
                        "aggregate {} at {} is unreadable or corrupt: {error:#}",
                        agg.to_usize(),
                        path.display()
                    ),
                ));
            }
        }
    }

    if unreadable_logs > 0 {
        report.push(CheckResult::fail(
            "event-store",
            format!(
                "{unreadable_logs} of {} aggregate log(s) could not be decoded; snapshot and \
                 open-loop checks were skipped because their inputs are incomplete",
                aggregate_ids.len()
            ),
        ));
        return Ok(report);
    }

    // 2. Only open the snapshot store after every source-of-truth log passed its
    // framing and decode checks. Cross-check each persisted replay cursor.
    let repositories = get_repositories(config)?;
    let persisted_schema = repositories.schema_version().read().await?;
    let has_existing_state =
        total_events > 0 || has_schema_governed_kv_state(&repositories).await?;
    report.push(check_schema_compatibility(
        persisted_schema,
        has_existing_state,
    ));
    for (agg, events) in &events_by_aggregate {
        let seqs: Vec<u64> = events.iter().map(|e| e.seq()).collect();

        let cursor = repositories.aggregate_seq(*agg).read().await?.unwrap_or(0);
        report.push(check_cursor_consistency(*agg, cursor, &seqs));
    }
    report.push(CheckResult::pass(
        "event-store",
        format!(
            "read {total_events} event(s) across {} aggregate(s)",
            aggregate_ids.len()
        ),
    ));

    // 3. A current cursor is not sufficient if a stale batch replaced one projection. Rebuild the
    // registered-node set from the event log and compare it with the persisted backend.
    report.push(check_sortition_projection(&repositories, &events_by_aggregate).await?);

    // 4. Open-loop / loose-ends audit against the persisted sortition state.
    report.push(check_open_loops(&repositories, &terminal_keys).await?);

    Ok(report)
}

async fn check_sortition_projection(
    repositories: &Repositories,
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
) -> Result<CheckResult> {
    let expected = registered_nodes_from_events(events_by_aggregate);
    let backends = repositories.sortition().read().await?.unwrap_or_default();
    let actual = backends
        .iter()
        .filter(|(chain_id, _)| **chain_id != u64::MAX)
        .map(|(chain_id, backend)| {
            (
                *chain_id,
                backend
                    .nodes()
                    .into_iter()
                    .map(|address| address.to_ascii_lowercase())
                    .collect::<HashSet<_>>(),
            )
        })
        .collect::<HashMap<_, _>>();

    compare_sortition_projection(&expected, &actual)
}

fn registered_nodes_from_events(
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
) -> HashMap<u64, HashSet<String>> {
    let mut registered = HashMap::<u64, HashSet<String>>::new();
    for (_, events) in events_by_aggregate {
        for event in events {
            match event.get_data() {
                InterfoldEventData::CiphernodeAdded(data) => {
                    registered
                        .entry(data.chain_id)
                        .or_default()
                        .insert(data.address.to_ascii_lowercase());
                }
                InterfoldEventData::CiphernodeRemoved(data) => {
                    registered
                        .entry(data.chain_id)
                        .or_default()
                        .remove(&data.address.to_ascii_lowercase());
                }
                _ => {}
            }
        }
    }
    registered
}

fn compare_sortition_projection(
    expected: &HashMap<u64, HashSet<String>>,
    actual: &HashMap<u64, HashSet<String>>,
) -> Result<CheckResult> {
    let mut chain_ids = expected
        .keys()
        .chain(actual.keys())
        .copied()
        .collect::<Vec<_>>();
    chain_ids.sort_unstable();
    chain_ids.dedup();

    let mut differences = Vec::new();
    for chain_id in chain_ids {
        let expected_nodes = expected.get(&chain_id).cloned().unwrap_or_default();
        let actual_nodes = actual.get(&chain_id).cloned().unwrap_or_default();
        if expected_nodes == actual_nodes {
            continue;
        }

        let mut missing = expected_nodes
            .difference(&actual_nodes)
            .cloned()
            .collect::<Vec<_>>();
        let mut unexpected = actual_nodes
            .difference(&expected_nodes)
            .cloned()
            .collect::<Vec<_>>();
        missing.sort();
        unexpected.sort();
        differences.push(format!(
            "chain {chain_id}: {} missing, {} unexpected (missing: {}; unexpected: {})",
            missing.len(),
            unexpected.len(),
            display_addresses(&missing),
            display_addresses(&unexpected)
        ));
    }

    if differences.is_empty() {
        return Ok(CheckResult::pass(
            "sortition-projection",
            "persisted registered-node sets match the event log",
        ));
    }

    Ok(CheckResult::fail(
        "sortition-projection",
        format!(
            "persisted registered-node state disagrees with the event log: {}. Stop the node and \
             perform a controlled rescan before relying on committee selection",
            differences.join("; ")
        ),
    ))
}

fn display_addresses(addresses: &[String]) -> String {
    if addresses.is_empty() {
        "none".to_owned()
    } else {
        addresses.join(", ")
    }
}

/// Verify that this binary can safely interpret the persisted schema. A missing
/// marker is acceptable only for a fresh store (empty or containing the complete bootstrap
/// identity pair); stamping a version on protocol or unknown bytes would assert compatibility
/// without evidence.
fn check_schema_compatibility(persisted: Option<u32>, has_existing_state: bool) -> CheckResult {
    let name = "schema";
    match decide_schema_version(persisted, SCHEMA_VERSION, has_existing_state) {
        SchemaVersionDecision::Proceed => CheckResult::pass(
            name,
            format!("on-disk schema version {SCHEMA_VERSION} matches this binary"),
        ),
        SchemaVersionDecision::WriteCurrent => CheckResult::pass(
            name,
            format!("empty store will be initialized at schema version {SCHEMA_VERSION}"),
        ),
        SchemaVersionDecision::Halt(reason) => CheckResult::fail(name, reason),
    }
}

/// The set of aggregate ids to inspect: the local aggregate (0) plus one per
/// configured chain. Mirrors [`AggregateId::from_chain_id`] so the validator
/// looks at exactly the aggregates the running node persists.
fn aggregate_ids(config: &AppConfig) -> Vec<AggregateId> {
    let mut ids: Vec<AggregateId> = vec![AggregateId::new(0)];
    for chain in config.chains() {
        let id = AggregateId::from_chain_id(chain.chain_id);
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// Verify the event sequence numbers are contiguous and strictly increasing.
fn check_sequence_integrity(agg: AggregateId, seqs: &[u64]) -> CheckResult {
    let name = "event-sequence";
    if seqs.is_empty() {
        return CheckResult::pass(name, format!("aggregate {}: no events", agg.to_usize()));
    }
    // Per-aggregate sequences are 1-indexed (the commit log returns `offset + 1`),
    // so a healthy log's first event is seq 1. A higher first seq means the head of
    // the log was truncated — catch it explicitly, since an internal-gap scan alone
    // treats e.g. [5, 6, 7] as healthy.
    if seqs[0] != 1 {
        return CheckResult::fail(
            name,
            format!(
                "aggregate {}: first event starts at seq {} instead of 1 (log truncated at head)",
                agg.to_usize(),
                seqs[0]
            ),
        );
    }
    match detect_sequence_gaps(seqs) {
        SequenceCheck::Ok { first, last, count } => CheckResult::pass(
            name,
            format!(
                "aggregate {}: {count} contiguous event(s), seq {first}..={last}",
                agg.to_usize()
            ),
        ),
        SequenceCheck::Gaps(gaps) => CheckResult::fail(
            name,
            format!(
                "aggregate {}: commit log has {} gap(s) (truncated/corrupt): {}",
                agg.to_usize(),
                gaps.len(),
                gaps.iter()
                    .map(|(a, b)| format!("{a}->{b}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        SequenceCheck::NonMonotonic => CheckResult::fail(
            name,
            format!(
                "aggregate {}: event sequence numbers are not strictly increasing (corrupt)",
                agg.to_usize()
            ),
        ),
    }
}

/// Verify the persisted snapshot cursor does not point past the last event in
/// the log. A cursor ahead of the log means the snapshot survived but the commit
/// log behind it was truncated — replay would silently lose state.
fn check_cursor_consistency(agg: AggregateId, cursor: u64, seqs: &[u64]) -> CheckResult {
    let name = "snapshot-cursor";
    let max_seq = seqs.iter().copied().max();
    match max_seq {
        None => {
            if cursor == 0 {
                CheckResult::pass(
                    name,
                    format!("aggregate {}: empty + cursor 0", agg.to_usize()),
                )
            } else {
                CheckResult::fail(
                    name,
                    format!(
                        "aggregate {}: snapshot cursor {cursor} but the commit log is empty \
                         (log truncated behind snapshot)",
                        agg.to_usize()
                    ),
                )
            }
        }
        Some(max) if cursor > max => CheckResult::fail(
            name,
            format!(
                "aggregate {}: snapshot cursor {cursor} is ahead of last event seq {max} \
                 (log truncated behind snapshot)",
                agg.to_usize()
            ),
        ),
        Some(max) => CheckResult::pass(
            name,
            format!(
                "aggregate {}: cursor {cursor} <= last event seq {max}",
                agg.to_usize()
            ),
        ),
    }
}

/// Cross-check the persisted open committees against terminal events in the log.
async fn check_open_loops(
    repositories: &Repositories,
    terminal_keys: &HashSet<String>,
) -> Result<CheckResult> {
    let name = "open-loops";
    let node_state: HashMap<u64, NodeStateStore> =
        repositories.node_state().read().await?.unwrap_or_default();

    let open = NodeRegistry::open_committees(&node_state);
    let orphaned = find_orphaned_committees(&open, terminal_keys);

    if open.is_empty() {
        return Ok(CheckResult::pass(
            name,
            "no committees holding active-job slots",
        ));
    }
    if orphaned.is_empty() {
        return Ok(CheckResult::pass(
            name,
            format!(
                "{} committee(s) in flight; none have a terminal event in the log",
                open.len()
            ),
        ));
    }
    Ok(CheckResult::fail(
        name,
        format!(
            "{} orphaned committee(s) still hold active-job slots despite a terminal event in \
             the log (tickets stuck). Affected E3 committee keys: {}. A restart re-applies the \
             terminal events and releases these slots.",
            orphaned.len(),
            orphaned.join(", ")
        ),
    ))
}

/// Outcome of a pure sequence-integrity check.
#[derive(Debug, PartialEq, Eq)]
enum SequenceCheck {
    Ok {
        first: u64,
        last: u64,
        count: usize,
    },
    /// One or more `(before, after)` gaps where `after > before + 1`.
    Gaps(Vec<(u64, u64)>),
    /// Sequence numbers did not strictly increase.
    NonMonotonic,
}

/// Pure check that `seqs` (in event order) are strictly increasing by exactly 1.
fn detect_sequence_gaps(seqs: &[u64]) -> SequenceCheck {
    let first = match seqs.first() {
        Some(f) => *f,
        None => {
            return SequenceCheck::Ok {
                first: 0,
                last: 0,
                count: 0,
            }
        }
    };
    let mut gaps = Vec::new();
    for w in seqs.windows(2) {
        let (a, b) = (w[0], w[1]);
        if b <= a {
            return SequenceCheck::NonMonotonic;
        }
        if b != a + 1 {
            gaps.push((a, b));
        }
    }
    if gaps.is_empty() {
        SequenceCheck::Ok {
            first,
            last: *seqs.last().unwrap(),
            count: seqs.len(),
        }
    } else {
        SequenceCheck::Gaps(gaps)
    }
}

/// Pure: open committee keys that also have a terminal event in the log.
fn find_orphaned_committees(
    open: &[e3_sortition::OpenCommittee],
    terminal_keys: &HashSet<String>,
) -> Vec<String> {
    let mut out: Vec<String> = open
        .iter()
        .filter(|c| terminal_keys.contains(&c.committee_key))
        .map(|c| c.committee_key.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Collect the committee key of every terminal lifecycle event in `events`.
///
/// Mirrors the terminal-release dispatch in the `Sortition` actor: an E3 is
/// terminal on `PlaintextOutputPublished`, `E3Failed`, `E3RequestComplete`, or
/// `E3StageChanged` to `Complete`/`Failed`.
fn collect_terminal_keys(events: &[InterfoldEvent], out: &mut HashSet<String>) {
    for event in events {
        match event.get_data() {
            InterfoldEventData::PlaintextOutputPublished(d) => {
                out.insert(committee_key(&d.e3_id));
            }
            InterfoldEventData::E3Failed(d) => {
                out.insert(committee_key(&d.e3_id));
            }
            InterfoldEventData::E3RequestComplete(d) => {
                out.insert(committee_key(&d.e3_id));
            }
            InterfoldEventData::E3StageChanged(d)
                if matches!(d.new_stage, E3Stage::Complete | E3Stage::Failed) =>
            {
                out.insert(committee_key(&d.e3_id));
            }
            _ => {}
        }
    }
}

/// Read one aggregate's source-of-truth commit log without creating an empty log
/// as a side effect when the node has never persisted that aggregate.
fn read_event_log(
    path: &Path,
    expected_aggregate: AggregateId,
    repair: bool,
) -> Result<Vec<InterfoldEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mode = if repair {
        EventLogOpenMode::RecoverTail
    } else {
        EventLogOpenMode::ValidateOnly
    };
    let log = CommitLogEventLog::open(path, mode)
        .with_context(|| format!("failed to open commit log {}", path.display()))?;
    let events: Vec<InterfoldEvent> = log
        .read_from_checked(1)
        .with_context(|| format!("failed integrity scan for {}", path.display()))
        .map(|events| {
            events
                .into_iter()
                .map(|(seq, event)| event.into_sequenced(seq))
                .collect()
        })?;

    if let Some(event) = events
        .iter()
        .find(|event| event.aggregate_id() != expected_aggregate)
    {
        bail!(
            "event at sequence {} belongs to aggregate {}, but log path is for aggregate {}",
            event.seq(),
            event.aggregate_id().to_usize(),
            expected_aggregate.to_usize()
        );
    }

    Ok(events)
}

/// A non-empty `BTreeMap` alias kept for readability in tests.
#[allow(dead_code)]
type SeqMap = BTreeMap<AggregateId, u64>;

#[cfg(test)]
mod tests {
    use super::*;
    use commitlog::{CommitLog, LogOptions};
    use e3_events::{EventConstructorWithTimestamp, EventLog, EventSource, TestEvent, Unsequenced};
    use e3_sortition::OpenCommittee;
    use std::{fs::OpenOptions, io::Write};
    use tempfile::tempdir;

    #[test]
    fn validator_reader_reports_corrupt_tail_instead_of_skipping_it() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("log.0");
        let mut raw_log = CommitLog::new(LogOptions::new(&log_path)).unwrap();
        raw_log
            .append_msg(b"valid commit-log frame, invalid event payload")
            .unwrap();
        drop(raw_log);

        let error = read_event_log(&log_path, AggregateId::new(0), false).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("sequence 1"), "{message}");
        assert!(message.contains("failed to decode"), "{message}");
    }

    #[test]
    fn validator_reader_does_not_create_a_missing_log() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("log.0");

        assert!(read_event_log(&log_path, AggregateId::new(0), false)
            .unwrap()
            .is_empty());
        assert!(!log_path.exists());
    }

    #[test]
    fn validator_repair_recovers_only_an_uncommitted_physical_tail() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("log.0");
        let segment_path = log_path.join("00000000000000000000.log");
        let mut log = CommitLogEventLog::new(&log_path).unwrap();
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("valid", 1).into(),
            None,
            1,
            None,
            EventSource::Local,
        );
        log.append(&event).unwrap();
        log.flush().unwrap();
        drop(log);
        OpenOptions::new()
            .append(true)
            .open(segment_path)
            .unwrap()
            .write_all(b"torn")
            .unwrap();

        let detection = format!(
            "{:#}",
            read_event_log(&log_path, AggregateId::new(0), false).unwrap_err()
        );
        assert!(detection.contains("recoverable uncommitted event-log tail"));

        let events = read_event_log(&log_path, AggregateId::new(0), true).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq(), 1);
    }

    #[test]
    fn validator_reader_rejects_event_in_wrong_aggregate_log() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("log.1");
        let mut log = CommitLogEventLog::new(&log_path).unwrap();
        let aggregate_zero_event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("misfiled", 1).into(),
            None,
            1,
            None,
            EventSource::Local,
        );
        log.append(&aggregate_zero_event).unwrap();
        drop(log);

        let error = read_event_log(&log_path, AggregateId::new(1), false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("belongs to aggregate 0"), "{message}");
        assert!(message.contains("for aggregate 1"), "{message}");
    }

    #[test]
    fn schema_check_accepts_exact_version() {
        let result = check_schema_compatibility(Some(SCHEMA_VERSION), true);
        assert_eq!(result.severity, Severity::Pass);
    }

    #[test]
    fn schema_check_rejects_missing_marker_on_nonempty_log() {
        let result = check_schema_compatibility(None, true);
        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("no schema marker"));
    }

    #[test]
    fn schema_check_rejects_incompatible_version() {
        let result = check_schema_compatibility(Some(SCHEMA_VERSION + 1), true);
        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("newer"));
    }

    #[test]
    fn sequence_ok_when_contiguous() {
        assert_eq!(
            detect_sequence_gaps(&[0, 1, 2, 3]),
            SequenceCheck::Ok {
                first: 0,
                last: 3,
                count: 4
            }
        );
    }

    #[test]
    fn sequence_ok_when_empty() {
        assert_eq!(
            detect_sequence_gaps(&[]),
            SequenceCheck::Ok {
                first: 0,
                last: 0,
                count: 0
            }
        );
    }

    #[test]
    fn sequence_detects_gap() {
        assert_eq!(
            detect_sequence_gaps(&[0, 1, 4, 5]),
            SequenceCheck::Gaps(vec![(1, 4)])
        );
    }

    #[test]
    fn sequence_detects_multiple_gaps() {
        assert_eq!(
            detect_sequence_gaps(&[2, 5, 6, 9]),
            SequenceCheck::Gaps(vec![(2, 5), (6, 9)])
        );
    }

    #[test]
    fn sequence_detects_non_monotonic() {
        assert_eq!(
            detect_sequence_gaps(&[0, 1, 1, 2]),
            SequenceCheck::NonMonotonic
        );
        assert_eq!(
            detect_sequence_gaps(&[3, 2, 1]),
            SequenceCheck::NonMonotonic
        );
    }

    fn open(key: &str) -> OpenCommittee {
        OpenCommittee {
            chain_id: 1,
            committee_key: key.to_string(),
            members: vec!["0xabc".to_string()],
        }
    }

    #[test]
    fn orphans_are_open_committees_with_terminal_events() {
        let open_set = vec![open("1:5"), open("1:6"), open("1:7")];
        let mut terminal = HashSet::new();
        terminal.insert("1:5".to_string()); // finished but still open -> orphan
        terminal.insert("1:9".to_string()); // finished and not open -> fine

        let orphans = find_orphaned_committees(&open_set, &terminal);
        assert_eq!(orphans, vec!["1:5".to_string()]);
    }

    #[test]
    fn no_orphans_when_no_terminal_overlap() {
        let open_set = vec![open("1:5"), open("1:6")];
        let terminal = HashSet::new();
        assert!(find_orphaned_committees(&open_set, &terminal).is_empty());
    }

    #[test]
    fn sortition_projection_accepts_matching_registered_nodes() {
        let nodes = HashSet::from(["0xaaa".to_owned(), "0xbbb".to_owned()]);
        let expected = HashMap::from([(1, nodes.clone())]);
        let actual = HashMap::from([(1, nodes)]);

        let result = compare_sortition_projection(&expected, &actual).unwrap();
        assert_eq!(result.severity, Severity::Pass);
    }

    #[test]
    fn sortition_projection_reports_nodes_missing_from_snapshot() {
        let expected =
            HashMap::from([(1, HashSet::from(["0xaaa".to_owned(), "0xbbb".to_owned()]))]);
        let actual = HashMap::from([(1, HashSet::from(["0xaaa".to_owned()]))]);

        let result = compare_sortition_projection(&expected, &actual).unwrap();
        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("1 missing"));
        assert!(result.detail.contains("0xbbb"));
    }

    #[test]
    fn cursor_ahead_of_log_fails() {
        let r = check_cursor_consistency(AggregateId::new(1), 10, &[0, 1, 2]);
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn cursor_within_log_passes() {
        let r = check_cursor_consistency(AggregateId::new(1), 2, &[0, 1, 2, 3]);
        assert_eq!(r.severity, Severity::Pass);
    }

    #[test]
    fn cursor_nonzero_on_empty_log_fails() {
        let r = check_cursor_consistency(AggregateId::new(1), 5, &[]);
        assert_eq!(r.severity, Severity::Fail);
    }

    #[test]
    fn report_verdict_reflects_severities() {
        let mut report = ValidationReport::default();
        report.push(CheckResult::pass("a", "ok"));
        assert!(!report.has_failure());
        assert!(!report.has_warning());

        report.push(CheckResult::warn("b", "hmm"));
        assert!(report.has_warning());
        assert!(!report.has_failure());

        report.push(CheckResult::fail("c", "bad"));
        assert!(report.has_failure());
        assert!(report.render().contains("VALIDATION FAILED"));
    }
}
