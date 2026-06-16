// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Offline node-state validation.
//!
//! Backs the `interfold node validate` CLI command. It opens a node's persisted
//! stores **read-only** (no actors, no network, no chain writes) and answers the
//! operator question: *"Is my on-disk state intact, internally consistent, free
//! of loose ends, and will this binary be able to load it after an upgrade?"*
//!
//! It is deliberately non-destructive. It never mutates the store, never talks to
//! the chain, and never starts the node. It is safe to run while the node is
//! stopped (the recommended pre-upgrade step) and surfaces problems as a
//! structured report with a non-zero exit on failure.
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
//! 3. **Open-loop / loose-ends audit** — loads the persisted sortition state and
//!    flags any committee that still holds an active-job slot **even though the
//!    event log already contains a terminal event** for that E3. These are the
//!    orphaned tickets that a crash mid-E3 can leave behind; they are the
//!    "loose ends" a restart should clean up.

use crate::helpers::datastore::{get_eventstore_reader, get_repositories};
use anyhow::{anyhow, Result};
use e3_ciphernode_builder::global_eventstore_cache::EventStoreReader;
use e3_config::AppConfig;
use e3_data::Repositories;
use e3_events::{
    AggregateId, CorrelationId, E3Stage, Event, EventContextAccessors, EventContextSeq,
    EventStoreQueryBy, EventStoreQueryResponse, InterfoldEvent, InterfoldEventData, SeqAgg,
};
use e3_sortition::{committee_key, NodeRegistry, NodeStateRepositoryFactory, NodeStateStore};
use e3_sync::SyncRepositoryFactory;
use e3_utils::actix::channel as actix_toolbox;
use std::collections::{BTreeMap, HashMap, HashSet};

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
/// Opens the persisted stores read-only. Returns the full report; callers decide
/// how to surface it (the CLI prints it and exits non-zero on failure).
pub async fn validate_node(config: &AppConfig) -> Result<ValidationReport> {
    let repositories = get_repositories(config)?;
    let eventstore = get_eventstore_reader(config)?;
    let aggregate_ids = aggregate_ids(config);

    let mut report = ValidationReport::default();

    // 1 + 2. Read every event per aggregate, check integrity + cursor consistency,
    //        and collect the terminal-event keys for the open-loop audit.
    let mut terminal_keys: HashSet<String> = HashSet::new();
    let mut total_events: u64 = 0;
    for agg in &aggregate_ids {
        let events = read_all_events(&eventstore, *agg).await?;
        total_events += events.len() as u64;

        collect_terminal_keys(&events, &mut terminal_keys);

        let seqs: Vec<u64> = events.iter().map(|e| e.seq()).collect();
        report.push(check_sequence_integrity(*agg, &seqs));

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

    // 3. Open-loop / loose-ends audit against the persisted sortition state.
    report.push(check_open_loops(&repositories, &terminal_keys).await?);

    Ok(report)
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
/// terminal on `PlaintextOutputPublished`, `E3Failed`, or `E3StageChanged` to
/// `Complete`/`Failed`.
fn collect_terminal_keys(events: &[InterfoldEvent], out: &mut HashSet<String>) {
    for event in events {
        match event.get_data() {
            InterfoldEventData::PlaintextOutputPublished(d) => {
                out.insert(committee_key(&d.e3_id));
            }
            InterfoldEventData::E3Failed(d) => {
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

/// Read every event for a single aggregate from sequence 0, paginating until the
/// store is exhausted.
async fn read_all_events(
    eventstore: &EventStoreReader,
    aggregate: AggregateId,
) -> Result<Vec<InterfoldEvent>> {
    const PAGE: u64 = 1024;
    let mut all: Vec<InterfoldEvent> = Vec::new();
    let mut since: u64 = 0;
    loop {
        let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
        let msg = EventStoreQueryBy::<SeqAgg>::new(
            CorrelationId::new(),
            HashMap::from([(aggregate, since)]),
            addr,
        )
        .with_limit(PAGE);
        eventstore
            .seq()
            .try_send(msg)
            .map_err(|e| anyhow!("event store query failed: {e}"))?;
        let page = rx.await?.into_events();
        if page.is_empty() {
            break;
        }
        let max_seq = page.iter().map(|e| e.seq()).max().unwrap_or(since);
        all.extend(page);
        // Advance past the highest sequence we just read. If the store could not
        // advance (defensive), stop to avoid an infinite loop.
        let next = max_seq.saturating_add(1);
        if next <= since {
            break;
        }
        since = next;
    }
    // The store may interleave aggregates depending on the query; keep only this
    // aggregate's events and order them by sequence for the integrity check. Do not
    // deduplicate by seq — repeated sequence numbers are exactly the corruption the
    // integrity check must surface (pagination advances strictly past the last seq,
    // so it never produces legitimate duplicates).
    all.retain(|e| e.aggregate_id() == aggregate);
    all.sort_by_key(|e| e.seq());
    Ok(all)
}

/// A non-empty `BTreeMap` alias kept for readability in tests.
#[allow(dead_code)]
type SeqMap = BTreeMap<AggregateId, u64>;

#[cfg(test)]
mod tests {
    use super::*;
    use e3_sortition::OpenCommittee;

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
