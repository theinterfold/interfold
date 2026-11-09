// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reading node histories and the published key: waiting for an outcome and scanning for faults.

use crate::ciphernode_system::{CiphernodeHistory, CiphernodeSystem};
use anyhow::{bail, Result};
use e3_events::{prelude::*, E3id, InterfoldEvent, InterfoldEventData, PublicKeyAggregated};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Scan a node history for slashing, accusation, and protocol-fault signals that must not
/// appear on an all-honest run. Catches regressions such as spurious C2→C4
/// commitment mismatches when N > H that completion-only assertions would miss.
pub fn collect_honest_run_faults(
    history: &[InterfoldEvent],
    e3_id: &E3id,
    context: &str,
) -> Vec<String> {
    let mut faults = Vec::new();

    for event in history {
        match event.get_data() {
            InterfoldEventData::CommitmentConsistencyCheckComplete(data)
                if data.e3_id == *e3_id && !data.inconsistent_parties.is_empty() =>
            {
                faults.push(format!(
                    "{context}: CommitmentConsistencyCheckComplete kind={:?} inconsistent_parties={:?}",
                    data.kind, data.inconsistent_parties
                ));
            }
            InterfoldEventData::CommitmentConsistencyViolation(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: CommitmentConsistencyViolation accused_party_id={} proof_type={:?}",
                    data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::ProofFailureAccusation(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: ProofFailureAccusation accuser={} accused_party_id={} proof_type={:?}",
                    data.accuser, data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::ProofVerificationFailed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: ProofVerificationFailed accused_party_id={} proof_type={:?}",
                    data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::SignedProofFailed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: SignedProofFailed faulting_node={} proof_type={:?}",
                    data.faulting_node, data.proof_type
                ));
            }
            InterfoldEventData::ShareVerificationComplete(data)
                if data.e3_id == *e3_id && !data.dishonest_parties.is_empty() =>
            {
                faults.push(format!(
                    "{context}: ShareVerificationComplete kind={:?} dishonest_parties={:?}",
                    data.kind, data.dishonest_parties
                ));
            }
            InterfoldEventData::AccusationVote(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: AccusationVote voter={} accusation_id={:?}",
                    data.voter, data.accusation_id
                ));
            }
            InterfoldEventData::CommitteeMemberExpelled(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: CommitteeMemberExpelled node={} party_id={:?}",
                    data.node, data.party_id
                ));
            }
            InterfoldEventData::E3Failed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: E3Failed stage={:?} reason={:?}",
                    data.failed_at_stage, data.reason
                ));
            }
            InterfoldEventData::InterfoldError(data) => {
                faults.push(format!(
                    "{context}: InterfoldError {:?}: {}",
                    data.err_type, data.message
                ));
            }
            _ => {}
        }
    }

    faults
}

/// What `select` extracts from the latest event it accepts.
pub fn last_event<T>(
    history: &[InterfoldEvent],
    select: impl Fn(&InterfoldEventData) -> Option<T>,
) -> Option<T> {
    history
        .iter()
        .rev()
        .find_map(|event| select(event.get_data()))
}

/// Polls the nodes in turn until one's history holds an event `select` accepts. Returns that
/// node, its history, and what `select` extracted from its latest accepted event.
///
/// A failover moves aggregation to another committee party, so an aggregator publication can land
/// on any member that can hold the role. Callers pass those members.
pub async fn wait_for_event_on_any<T>(
    nodes: &CiphernodeSystem,
    node_indices: &[usize],
    description: &str,
    total_timeout: Duration,
    select: impl Fn(&InterfoldEventData) -> Option<T>,
) -> Result<(usize, CiphernodeHistory, T)> {
    let start = Instant::now();
    loop {
        for &node_index in node_indices {
            let history = nodes.get_history(node_index).await?;
            if let Some(value) = last_event(&history, &select) {
                return Ok((node_index, history, value));
            }
        }
        if start.elapsed() >= total_timeout {
            let mut observed = Vec::new();
            for &node_index in node_indices {
                observed.push((
                    node_index,
                    nodes.get_history(node_index).await?.event_types(),
                ));
            }
            bail!(
                "Timed out after {:?} while waiting for {description} on nodes {node_indices:?}; observed events: {observed:?}",
                start.elapsed()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// [`wait_for_event_on_any`] on one node, returning only the extracted value.
pub async fn wait_for_event<T>(
    nodes: &CiphernodeSystem,
    node_index: usize,
    description: &str,
    total_timeout: Duration,
    select: impl Fn(&InterfoldEventData) -> Option<T>,
) -> Result<T> {
    let (_, _, value) =
        wait_for_event_on_any(nodes, &[node_index], description, total_timeout, select).await?;
    Ok(value)
}

/// [`wait_for_event`] for an event that carries nothing to extract.
pub async fn wait_until(
    nodes: &CiphernodeSystem,
    node_index: usize,
    description: &str,
    total_timeout: Duration,
    matches: impl Fn(&InterfoldEventData) -> bool,
) -> Result<()> {
    wait_for_event(nodes, node_index, description, total_timeout, |data| {
        matches(data).then_some(())
    })
    .await
}

/// Histories of the committee members that held the aggregator role for `e3_id`: each one
/// recorded an `AggregatorChanged` naming itself active.
pub async fn aggregator_role_histories(
    nodes: &CiphernodeSystem,
    node_indices: &[usize],
    e3_id: &E3id,
) -> Result<Vec<(usize, CiphernodeHistory)>> {
    let mut held = Vec::new();
    for &node_index in node_indices {
        let history = nodes.get_history(node_index).await?;
        let held_role = history.iter().any(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::AggregatorChanged(data)
                    if data.e3_id == *e3_id && data.is_aggregator
            )
        });
        if held_role {
            held.push((node_index, history));
        }
    }
    Ok(held)
}

/// The party ids of the honest committee the published key lists, in the key's order.
pub fn key_roster(key: &PublicKeyAggregated) -> Vec<u64> {
    key.honest_committee_addresses
        .iter()
        .map(|address| {
            key.committee_addresses
                .iter()
                .position(|member| member == address)
                .expect("the published key lists an honest node outside the committee")
                as u64
        })
        .collect()
}
