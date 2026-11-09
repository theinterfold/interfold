// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reading node histories: waiting for an outcome and scanning for faults.

use crate::ciphernode_system::{CiphernodeHistory, CiphernodeSystem};
use anyhow::{bail, Result};
use e3_events::{prelude::*, E3id, InterfoldEvent, InterfoldEventData};
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

/// Polls a node's history until an event matches, returning that history.
pub async fn wait_for_history_match<F>(
    nodes: &CiphernodeSystem,
    node_index: usize,
    description: &str,
    total_timeout: Duration,
    matches: F,
) -> Result<CiphernodeHistory>
where
    F: Fn(&InterfoldEventData) -> bool,
{
    let start = Instant::now();
    loop {
        let history = nodes.get_history(node_index).await?;
        if history.iter().any(|event| matches(event.get_data())) {
            return Ok(history);
        }
        if start.elapsed() >= total_timeout {
            bail!(
                "Timed out after {:?} while waiting for {description} on node {node_index}; observed events: {:?}",
                start.elapsed(),
                history.event_types()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// [`wait_for_history_match`] over several nodes: the first node whose history contains a match.
///
/// A failover moves aggregation to another committee party, so an aggregator publication can land
/// on any member that can hold the role. Callers pass those members.
pub async fn wait_for_history_match_any<F>(
    nodes: &CiphernodeSystem,
    node_indices: &[usize],
    description: &str,
    total_timeout: Duration,
    matches: F,
) -> Result<(usize, CiphernodeHistory)>
where
    F: Fn(&InterfoldEventData) -> bool,
{
    let start = Instant::now();
    loop {
        for &node_index in node_indices {
            let history = nodes.get_history(node_index).await?;
            if history.iter().any(|event| matches(event.get_data())) {
                return Ok((node_index, history));
            }
        }
        if start.elapsed() >= total_timeout {
            bail!(
                "Timed out after {:?} while waiting for {description} on any of nodes {node_indices:?}",
                start.elapsed()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// Committee members that held the aggregator role for `e3_id`: each one recorded an
/// `AggregatorChanged` naming itself active.
pub async fn aggregator_role_nodes(
    nodes: &CiphernodeSystem,
    node_indices: &[usize],
    e3_id: &E3id,
) -> Result<Vec<usize>> {
    let mut held = Vec::new();
    for &node_index in node_indices {
        let history = nodes.get_history(node_index).await?;
        if history.iter().any(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::AggregatorChanged(data)
                    if data.e3_id == *e3_id && data.is_aggregator
            )
        }) {
            held.push(node_index);
        }
    }
    Ok(held)
}
