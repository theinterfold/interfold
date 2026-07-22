// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic aggregator lease scheduling.
//!
//! The stage deadline is authoritative chain state. Each currently eligible candidate receives an
//! equal share of the remaining window. Recomputing after every promotion preserves the same
//! boundaries (modulo integer rounding), while the final candidate expires strictly after the
//! Solidity deadline because `markE3Failed` requires `block.timestamp > deadline`.

use e3_events::{AggregatorPhase, Committee};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorLease {
    pub phase: AggregatorPhase,
    pub stage_deadline: u64,
    pub attempt_deadline: u64,
    pub active_party_id: Option<u64>,
    pub failure_requested: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorFailoverState {
    pub leases: HashMap<e3_events::E3id, AggregatorLease>,
}

pub(super) struct EligibleAggregators {
    pub committee: Committee,
    pub skipped: Vec<u64>,
    pub standbys: Vec<(u64, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverDecision {
    Hold,
    Promote {
        demote: u64,
        promote_to: u64,
        new_addr: String,
    },
    Exhausted {
        demote: Option<u64>,
    },
}

/// Allocate one equal slice of the remaining stage window to the active candidate.
pub fn next_attempt_deadline(now: u64, stage_deadline: u64, eligible_attempts: usize) -> u64 {
    let failure_eligible_at = stage_deadline.saturating_add(1);
    if eligible_attempts <= 1 || now >= failure_eligible_at {
        return failure_eligible_at.max(now);
    }
    let remaining = failure_eligible_at - now;
    let attempts = eligible_attempts as u64;
    now.saturating_add(remaining.saturating_add(attempts - 1) / attempts)
}

pub fn arm_lease(
    phase: AggregatorPhase,
    now: u64,
    stage_deadline: u64,
    standbys: &[(u64, String)],
) -> AggregatorLease {
    AggregatorLease {
        phase,
        stage_deadline,
        attempt_deadline: next_attempt_deadline(now, stage_deadline, standbys.len().max(1)),
        active_party_id: standbys.first().map(|(party_id, _)| *party_id),
        failure_requested: false,
    }
}

pub fn decide_failover(
    now: u64,
    lease: &AggregatorLease,
    standbys: &[(u64, String)],
) -> FailoverDecision {
    if now < lease.attempt_deadline || lease.failure_requested {
        return FailoverDecision::Hold;
    }
    let Some(active) = lease.active_party_id else {
        return FailoverDecision::Exhausted { demote: None };
    };

    match standbys.iter().find(|(party_id, _)| *party_id > active) {
        Some((next_party, next_addr)) => FailoverDecision::Promote {
            demote: active,
            promote_to: *next_party,
            new_addr: next_addr.clone(),
        },
        None => FailoverDecision::Exhausted {
            demote: Some(active),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(active: u64, attempt_deadline: u64) -> AggregatorLease {
        AggregatorLease {
            phase: AggregatorPhase::AwaitingPublicKey,
            stage_deadline: 90,
            attempt_deadline,
            active_party_id: Some(active),
            failure_requested: false,
        }
    }

    fn standbys() -> Vec<(u64, String)> {
        vec![(0, "0xa".into()), (1, "0xb".into()), (2, "0xc".into())]
    }

    #[test]
    fn divides_remaining_window_across_every_candidate() {
        assert_eq!(next_attempt_deadline(0, 90, 3), 31);
        assert_eq!(next_attempt_deadline(31, 90, 2), 61);
        assert_eq!(next_attempt_deadline(61, 90, 1), 91);
    }

    #[test]
    fn holds_before_exact_attempt_deadline() {
        assert_eq!(
            decide_failover(30, &lease(0, 31), &standbys()),
            FailoverDecision::Hold
        );
    }

    #[test]
    fn promotes_every_candidate_in_canonical_order() {
        assert_eq!(
            decide_failover(31, &lease(0, 31), &standbys()),
            FailoverDecision::Promote {
                demote: 0,
                promote_to: 1,
                new_addr: "0xb".into(),
            }
        );
        assert_eq!(
            decide_failover(61, &lease(1, 61), &standbys()),
            FailoverDecision::Promote {
                demote: 1,
                promote_to: 2,
                new_addr: "0xc".into(),
            }
        );
        assert_eq!(
            decide_failover(91, &lease(2, 91), &standbys()),
            FailoverDecision::Exhausted { demote: Some(2) }
        );
    }

    #[test]
    fn exhaustion_is_single_shot_after_failure_is_requested() {
        let mut exhausted = lease(2, 91);
        exhausted.failure_requested = true;
        assert_eq!(
            decide_failover(100, &exhausted, &standbys()),
            FailoverDecision::Hold
        );
    }

    #[test]
    fn confirmed_next_phase_resets_a_partitioned_primary() {
        let remaining = vec![(1, "0xb".into()), (2, "0xc".into())];
        let dkg = arm_lease(AggregatorPhase::AwaitingPublicKey, 50, 90, &remaining);
        let decryption = arm_lease(AggregatorPhase::AwaitingPlaintext, 100, 190, &standbys());

        assert_eq!(dkg.active_party_id, Some(1));
        assert_eq!(decryption.active_party_id, Some(0));
        assert!(!decryption.failure_requested);
        assert_eq!(decryption.attempt_deadline, 131);
    }
}
