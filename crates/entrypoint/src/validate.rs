// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Offline node-state validation.
//!
//! Backs the `interfold node validate` CLI command. It opens a node's persisted
//! stores offline (no network or chain writes) and answers whether the on-disk state is intact,
//! internally consistent, free of loose ends, and loadable by this binary after an upgrade.
//!
//! It never mutates protocol state, talks to the chain, or starts the node. By
//! default it is fully non-destructive. The explicit `--repair` mode may truncate a provably
//! uncommitted physical event-log tail, rebuild index entries for complete CRC-valid tail records,
//! and reconcile the derived sortition membership projection from an intact event log. It never
//! deletes the event log or node identity.
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
//!    source-of-truth events through each persisted snapshot cursor and compares it with the
//!    persisted selection backend.
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
    hlc::HlcTimestamp, AggregateId, E3Stage, Event, EventContextAccessors, EventContextSeq,
    InterfoldEvent, InterfoldEventData,
};
use e3_sortition::{
    committee_key, NodeRegistry, NodeStateRepositoryFactory, NodeStateStore, SortitionBackend,
    SortitionList, SortitionRepositoryFactory,
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
    let mut snapshot_cursors = HashMap::new();
    for (agg, events) in &events_by_aggregate {
        let seqs: Vec<u64> = events.iter().map(|e| e.seq()).collect();

        let cursor = repositories.aggregate_seq(*agg).read().await?.unwrap_or(0);
        snapshot_cursors.insert(*agg, cursor);
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
    let source_state_is_valid = !report.has_failure();
    report.push(
        check_sortition_projection(
            &repositories,
            &events_by_aggregate,
            &snapshot_cursors,
            repair,
            source_state_is_valid,
        )
        .await?,
    );

    // 4. Open-loop / loose-ends audit against the persisted sortition state.
    report.push(check_open_loops(&repositories, &terminal_keys).await?);

    Ok(report)
}

async fn check_sortition_projection(
    repositories: &Repositories,
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
    snapshot_cursors: &HashMap<AggregateId, u64>,
    repair: bool,
    source_state_is_valid: bool,
) -> Result<CheckResult> {
    let expected_addresses =
        registered_node_addresses_from_events(events_by_aggregate, snapshot_cursors);
    let expected = registered_node_sets(&expected_addresses);
    let sortition_repository = repositories.sortition();
    let node_state_repository = repositories.node_state();
    let mut backends = sortition_repository.read().await?.unwrap_or_default();
    let mut node_states = node_state_repository.read().await?.unwrap_or_default();
    let rebuilt_node_states =
        registered_node_states_from_events(events_by_aggregate, snapshot_cursors);
    let expected_node_states = node_state_node_sets(&rebuilt_node_states);
    let comparison = compare_sortition_projection(
        &expected,
        &sortition_node_sets(&backends),
        &expected_node_states,
        &node_state_node_sets(&node_states),
    )?;
    if comparison.severity == Severity::Pass || !repair {
        return Ok(comparison);
    }
    if !source_state_is_valid {
        return Ok(CheckResult::fail(
            "sortition-projection",
            "the projection differs, but --repair was not applied because the event log, schema, \
             or snapshot cursor failed an earlier check",
        ));
    }

    reconcile_sortition_backends(&mut backends, &expected_addresses);
    reconcile_node_state_membership(
        &mut node_states,
        &expected_node_states,
        &rebuilt_node_states,
    )?;
    node_state_repository.write_sync(&node_states).await?;
    sortition_repository.write_sync(&backends).await?;

    let persisted_backends = sortition_repository.read().await?.unwrap_or_default();
    let persisted_node_states = node_state_repository.read().await?.unwrap_or_default();
    let verified = compare_sortition_projection(
        &expected,
        &sortition_node_sets(&persisted_backends),
        &expected_node_states,
        &node_state_node_sets(&persisted_node_states),
    )?;
    if verified.severity != Severity::Pass {
        bail!("sortition projection did not match the event log after repair");
    }

    Ok(CheckResult::pass(
        "sortition-projection",
        "reconciled the derived selection and node-state membership projections from the intact event log; ticket history was reconstructed for missing members, and no event or identity data was deleted",
    ))
}

fn sortition_node_sets(backends: &HashMap<u64, SortitionBackend>) -> HashMap<u64, HashSet<String>> {
    backends
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
        .collect()
}

fn node_state_node_sets(
    node_states: &HashMap<u64, NodeStateStore>,
) -> HashMap<u64, HashSet<String>> {
    node_states
        .iter()
        .map(|(chain_id, state)| {
            (
                *chain_id,
                state
                    .nodes
                    .keys()
                    .map(|address| address.to_ascii_lowercase())
                    .collect::<HashSet<_>>(),
            )
        })
        .collect()
}

fn reconcile_sortition_backends(
    backends: &mut HashMap<u64, SortitionBackend>,
    expected: &HashMap<u64, HashMap<String, String>>,
) {
    let default_backend = backends
        .get(&u64::MAX)
        .cloned()
        .unwrap_or_else(SortitionBackend::score);
    let mut chain_ids = expected
        .keys()
        .chain(backends.keys().filter(|chain_id| **chain_id != u64::MAX))
        .copied()
        .collect::<Vec<_>>();
    chain_ids.sort_unstable();
    chain_ids.dedup();

    for chain_id in chain_ids {
        let wanted = expected.get(&chain_id).cloned().unwrap_or_default();
        let backend = backends
            .entry(chain_id)
            .or_insert_with(|| default_backend.clone());
        let present = backend
            .nodes()
            .into_iter()
            .map(|address| (address.to_ascii_lowercase(), address))
            .collect::<HashMap<_, _>>();

        for address in present
            .keys()
            .filter(|address| !wanted.contains_key(*address))
        {
            backend.remove(
                present
                    .get(address)
                    .expect("address came from the same map")
                    .clone(),
            );
        }
        for (normalized, canonical) in &wanted {
            if !present.contains_key(normalized) {
                backend.add(canonical.clone());
            }
        }
    }
}

fn reconcile_node_state_membership(
    node_states: &mut HashMap<u64, NodeStateStore>,
    expected: &HashMap<u64, HashSet<String>>,
    rebuilt: &HashMap<u64, NodeStateStore>,
) -> Result<()> {
    let mut chain_ids = expected
        .keys()
        .chain(node_states.keys())
        .copied()
        .collect::<Vec<_>>();
    chain_ids.sort_unstable();
    chain_ids.dedup();

    for chain_id in chain_ids {
        let wanted = expected.get(&chain_id).cloned().unwrap_or_default();
        let rebuilt_chain = rebuilt.get(&chain_id);
        let chain_state = node_states.entry(chain_id).or_default();
        if chain_state.ticket_price.is_zero() {
            if let Some(rebuilt_chain) = rebuilt_chain {
                chain_state.ticket_price = rebuilt_chain.ticket_price;
            }
        }

        let present = chain_state
            .nodes
            .keys()
            .map(|address| (address.to_ascii_lowercase(), address.clone()))
            .collect::<HashMap<_, _>>();
        for address in present.keys().filter(|address| !wanted.contains(*address)) {
            if let Some(original) = present.get(address) {
                chain_state.nodes.remove(original);
            }
        }

        let rebuilt_nodes = rebuilt_chain
            .map(|state| {
                state
                    .nodes
                    .iter()
                    .map(|(address, state)| (address.to_ascii_lowercase(), (address, state)))
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        for address in wanted
            .iter()
            .filter(|address| !present.contains_key(*address))
        {
            let (canonical_address, rebuilt_state) =
                rebuilt_nodes.get(address).with_context(|| {
                    format!(
                    "cannot reconstruct derived node state for chain {chain_id} member {address}"
                )
                })?;
            let mut state = (*rebuilt_state).clone();
            state.active_jobs = chain_state
                .e3_committees
                .values()
                .filter(|members| {
                    members
                        .iter()
                        .any(|member| member.eq_ignore_ascii_case(address))
                })
                .count()
                .try_into()
                .unwrap_or(u64::MAX);
            chain_state
                .nodes
                .insert((*canonical_address).clone(), state);
        }
    }
    Ok(())
}

#[cfg(test)]
fn registered_nodes_from_events(
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
    snapshot_cursors: &HashMap<AggregateId, u64>,
) -> HashMap<u64, HashSet<String>> {
    registered_node_sets(&registered_node_addresses_from_events(
        events_by_aggregate,
        snapshot_cursors,
    ))
}

fn registered_node_addresses_from_events(
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
    snapshot_cursors: &HashMap<AggregateId, u64>,
) -> HashMap<u64, HashMap<String, String>> {
    let mut registered = HashMap::<u64, HashMap<String, String>>::new();
    for (aggregate_id, events) in events_by_aggregate {
        let cursor = snapshot_cursors.get(aggregate_id).copied().unwrap_or(0);
        for event in events.iter().filter(|event| event.seq() <= cursor) {
            match event.get_data() {
                InterfoldEventData::CiphernodeAdded(data) => {
                    registered
                        .entry(data.chain_id)
                        .or_default()
                        .insert(data.address.to_ascii_lowercase(), data.address.clone());
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

fn registered_node_sets(
    addresses: &HashMap<u64, HashMap<String, String>>,
) -> HashMap<u64, HashSet<String>> {
    addresses
        .iter()
        .map(|(chain_id, nodes)| (*chain_id, nodes.keys().cloned().collect()))
        .collect()
}

fn registered_node_states_from_events(
    events_by_aggregate: &[(AggregateId, Vec<InterfoldEvent>)],
    snapshot_cursors: &HashMap<AggregateId, u64>,
) -> HashMap<u64, NodeStateStore> {
    let mut node_states = HashMap::<u64, NodeStateStore>::new();
    for (aggregate_id, events) in events_by_aggregate {
        let cursor = snapshot_cursors.get(aggregate_id).copied().unwrap_or(0);
        for event in events.iter().filter(|event| event.seq() <= cursor) {
            let timepoint = HlcTimestamp::wall_time(event.get_ctx().ts()) / 1_000_000_000;
            match event.get_data() {
                InterfoldEventData::CiphernodeAdded(data) => {
                    NodeRegistry::add_node(&mut node_states, data.chain_id, data.address.clone())
                }
                InterfoldEventData::CiphernodeRemoved(data) => {
                    NodeRegistry::remove_node(&mut node_states, data.chain_id, &data.address)
                }
                InterfoldEventData::TicketBalanceUpdated(data) => {
                    NodeRegistry::set_ticket_balance(
                        &mut node_states,
                        data.chain_id,
                        data.operator.clone(),
                        data.new_balance,
                        timepoint,
                    );
                }
                InterfoldEventData::OperatorActivationChanged(data) => {
                    NodeRegistry::set_operator_active(
                        &mut node_states,
                        data.chain_id,
                        data.operator.clone(),
                        data.active,
                        timepoint,
                    );
                }
                InterfoldEventData::ConfigurationUpdated(data)
                    if matches!(
                        data.parameter.as_str(),
                        "ticketPrice"
                            | "requiredCiphernodeBond"
                            | "ciphernodeBondActiveBps"
                            | "minTicketBalance"
                    ) =>
                {
                    if data.parameter == "ticketPrice" {
                        NodeRegistry::set_ticket_price(
                            &mut node_states,
                            data.chain_id,
                            data.new_value,
                        );
                    }
                    NodeRegistry::invalidate_operator_activity(
                        &mut node_states,
                        data.chain_id,
                        timepoint,
                    );
                }
                _ => {}
            }
        }
    }
    node_states
}

fn compare_sortition_projection(
    expected_backend: &HashMap<u64, HashSet<String>>,
    backend: &HashMap<u64, HashSet<String>>,
    expected_node_state: &HashMap<u64, HashSet<String>>,
    node_state: &HashMap<u64, HashSet<String>>,
) -> Result<CheckResult> {
    let backend_differences = projection_differences(expected_backend, backend);
    let node_state_differences = projection_differences(expected_node_state, node_state);
    if backend_differences.is_empty() && node_state_differences.is_empty() {
        return Ok(CheckResult::pass(
            "sortition-projection",
            "persisted selection and node-state memberships match the event log through each snapshot cursor",
        ));
    }

    let mut components = Vec::new();
    if !backend_differences.is_empty() {
        components.push(format!(
            "selection backend: {}",
            backend_differences.join("; ")
        ));
    }
    if !node_state_differences.is_empty() {
        components.push(format!("node state: {}", node_state_differences.join("; ")));
    }

    Ok(CheckResult::fail(
        "sortition-projection",
        format!(
            "persisted registered-node state disagrees with the event log: {}. Stop the node and \
             run `interfold node validate --repair` before relying on committee selection",
            components.join(" | ")
        ),
    ))
}

fn projection_differences(
    expected: &HashMap<u64, HashSet<String>>,
    actual: &HashMap<u64, HashSet<String>>,
) -> Vec<String> {
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

    differences
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
    use e3_events::{
        CiphernodeAdded, EventConstructorWithTimestamp, EventLog, EventSource, TestEvent,
        Unsequenced,
    };
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
        let backend = HashMap::from([(1, nodes.clone())]);
        let node_state = HashMap::from([(1, nodes)]);

        let result =
            compare_sortition_projection(&expected, &backend, &expected, &node_state).unwrap();
        assert_eq!(result.severity, Severity::Pass);
    }

    #[test]
    fn sortition_projection_reports_nodes_missing_from_snapshot() {
        let expected =
            HashMap::from([(1, HashSet::from(["0xaaa".to_owned(), "0xbbb".to_owned()]))]);
        let backend = HashMap::from([(1, HashSet::from(["0xaaa".to_owned()]))]);
        let node_state = expected.clone();

        let result =
            compare_sortition_projection(&expected, &backend, &expected, &node_state).unwrap();
        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("selection backend"));
        assert!(result.detail.contains("1 missing"));
        assert!(result.detail.contains("0xbbb"));
        assert!(result.detail.contains("interfold node validate --repair"));
    }

    #[test]
    fn sortition_projection_reports_a_stale_node_state_separately() {
        let expected =
            HashMap::from([(1, HashSet::from(["0xaaa".to_owned(), "0xbbb".to_owned()]))]);
        let backend = expected.clone();
        let node_state = HashMap::from([(1, HashSet::from(["0xaaa".to_owned()]))]);

        let result =
            compare_sortition_projection(&expected, &backend, &expected, &node_state).unwrap();

        assert_eq!(result.severity, Severity::Fail);
        assert!(result.detail.contains("node state"));
        assert!(result.detail.contains("0xbbb"));
    }

    #[test]
    fn sortition_repair_reconciles_only_derived_membership() {
        let kept = "0x1111111111111111111111111111111111111111".to_owned();
        let added = "0x2222222222222222222222222222222222222222".to_owned();
        let removed = "0x3333333333333333333333333333333333333333".to_owned();
        let mut default_backend = SortitionBackend::score();
        default_backend.add(kept.clone());
        let mut chain_backend = SortitionBackend::score();
        chain_backend.add(kept.clone());
        chain_backend.add(removed);
        let mut backends = HashMap::from([(u64::MAX, default_backend), (1, chain_backend)]);
        let expected = HashMap::from([(
            1,
            HashMap::from([(kept.clone(), kept.clone()), (added.clone(), added.clone())]),
        )]);

        reconcile_sortition_backends(&mut backends, &expected);

        assert_eq!(
            sortition_node_sets(&backends).get(&1),
            Some(&HashSet::from([kept.clone(), added]))
        );
        assert_eq!(
            backends.get(&u64::MAX).expect("default backend").nodes(),
            vec![kept]
        );
    }

    #[test]
    fn node_state_repair_restores_missing_history_and_preserves_existing_state() {
        let kept = "0x1111111111111111111111111111111111111111".to_owned();
        let added = "0x2222222222222222222222222222222222222222".to_owned();
        let unexpected = "0x3333333333333333333333333333333333333333".to_owned();
        let mut persisted = HashMap::<u64, NodeStateStore>::new();
        NodeRegistry::set_ticket_balance(
            &mut persisted,
            1,
            kept.clone(),
            alloy::primitives::U256::from(50),
            1,
        );
        NodeRegistry::add_node(&mut persisted, 1, unexpected.clone());
        let kept_history = persisted[&1].nodes[&kept].ticket_balance_history.clone();
        persisted
            .get_mut(&1)
            .expect("chain state")
            .e3_committees
            .insert("1:9".to_owned(), vec![added.clone()]);

        let mut rebuilt = HashMap::<u64, NodeStateStore>::new();
        NodeRegistry::set_ticket_price(&mut rebuilt, 1, alloy::primitives::U256::from(10));
        NodeRegistry::add_node(&mut rebuilt, 1, kept.clone());
        NodeRegistry::set_ticket_balance(
            &mut rebuilt,
            1,
            added.clone(),
            alloy::primitives::U256::from(20),
            2,
        );
        NodeRegistry::set_operator_active(&mut rebuilt, 1, added.clone(), true, 3);
        let expected = HashMap::from([(1, HashSet::from([kept.clone(), added.clone()]))]);

        reconcile_node_state_membership(&mut persisted, &expected, &rebuilt).unwrap();

        let chain = &persisted[&1];
        assert_eq!(chain.nodes.len(), 2);
        assert!(!chain.nodes.contains_key(&unexpected));
        assert_eq!(chain.nodes[&kept].ticket_balance_history.len(), 1);
        assert_eq!(
            chain.nodes[&kept].ticket_balance_history[0].timepoint,
            kept_history[0].timepoint
        );
        assert_eq!(
            chain.nodes[&kept].ticket_balance_history[0].value, kept_history[0].value,
            "existing member history must not be replaced"
        );
        assert_eq!(
            chain.nodes[&added].ticket_balance,
            alloy::primitives::U256::from(20)
        );
        assert!(chain.nodes[&added].active);
        assert_eq!(chain.nodes[&added].active_jobs, 1);
        assert_eq!(chain.ticket_price, alloy::primitives::U256::from(10));
    }

    #[test]
    fn sortition_projection_ignores_the_unapplied_event_log_tail() {
        let added = |address: &str, seq: u64| {
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                CiphernodeAdded {
                    address: address.to_owned(),
                    index: usize::try_from(seq).unwrap(),
                    num_nodes: usize::try_from(seq).unwrap(),
                    chain_id: 1,
                }
                .into(),
                None,
                u128::from(seq),
                Some(seq),
                EventSource::Evm,
            )
            .into_sequenced(seq)
        };
        let events = vec![(
            AggregateId::new(1),
            vec![added("0xaaa", 1), added("0xbbb", 2)],
        )];
        let cursors = HashMap::from([(AggregateId::new(1), 1)]);

        let projected = registered_nodes_from_events(&events, &cursors);

        assert_eq!(
            projected,
            HashMap::from([(1, HashSet::from(["0xaaa".to_owned()]))])
        );
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
