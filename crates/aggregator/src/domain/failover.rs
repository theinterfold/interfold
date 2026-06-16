// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Aggregator liveness / failover policy.
//!
//! The active aggregator for an E3 is chosen deterministically as the lowest
//! non-skipped party in the (score-ordered) committee
//! ([`e3_events::Committee::active_aggregator_party_id`]). If that node crashes
//! after the committee is finalised but before it publishes the aggregated
//! result on-chain, the round stalls indefinitely: no on-chain expulsion is
//! triggered (the node committed no fault), so nothing demotes it.
//!
//! This module is the pure, testable brain of an automatic failover: it tracks
//! how long the *expected on-chain progress* from the active aggregator has been
//! absent and, once a wall-clock budget elapses, decides to mark the current
//! aggregator as locally unresponsive and promote the next standby. Because the
//! committee order and the skip set are derived from signals every node shares,
//! all honest nodes converge on the same replacement without a leader-election
//! round. A brief overlap (old + new aggregator both publishing) is bounded by
//! the timeout and made harmless by the on-chain publish being single-shot.
//!
//! All decisions here are deterministic given their inputs (no clock access),
//! so the policy is exercised entirely by unit tests; the driving actor owns the
//! wall clock and feeds `elapsed` in.

use std::time::Duration;

/// The progress an aggregator round can be waiting on. Used to scope which
/// absence of progress should arm the failover timer.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregatorPhase {
    /// Waiting for the public key to be published on-chain (DKG output).
    AwaitingPublicKey,
    /// Waiting for the plaintext output to be published on-chain (decryption).
    AwaitingPlaintext,
    /// The round is finished; no aggregator action is pending.
    Settled,
}

/// Policy parameters for failover. A single wall-clock budget governs how long
/// the active aggregator may be silent before the next standby is promoted.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct FailoverPolicy {
    /// How long the expected on-chain progress may be absent before the active
    /// aggregator is presumed down and the next standby promoted.
    timeout: Duration,
}

#[allow(dead_code)]
impl FailoverPolicy {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// The outcome of a liveness evaluation for one E3.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverDecision {
    /// The round is settled or making progress within budget; do nothing.
    Hold,
    /// The active aggregator (`demote`, a party_id) has been silent past the
    /// budget. Add it to the locally-presumed-unresponsive set and promote the
    /// next standby (`promote_to`, with its address).
    Promote {
        demote: u64,
        promote_to: u64,
        new_addr: String,
    },
    /// Every standby has been exhausted; the round cannot make progress and must
    /// be failed by the caller.
    Exhausted { demote: u64 },
}

/// Decide whether to fail over for a single E3.
///
/// Inputs:
/// - `phase`: what on-chain progress is pending (Settled => always `Hold`).
/// - `elapsed`: time since the active aggregator was (re)assigned or last made
///   observable progress.
/// - `active`: the current active aggregator party_id.
/// - `standbys`: ordered `[(party_id, addr), ...]` of non-skipped members in
///   promotion order, as produced by
///   [`e3_events::Committee::aggregator_standbys`]. `active` is expected to be
///   `standbys[0].0` when present.
///
/// Deterministic and clock-free.
#[allow(dead_code)]
pub fn decide_failover(
    policy: &FailoverPolicy,
    phase: AggregatorPhase,
    elapsed: Duration,
    active: u64,
    standbys: &[(u64, String)],
) -> FailoverDecision {
    if phase == AggregatorPhase::Settled {
        return FailoverDecision::Hold;
    }
    if elapsed < policy.timeout {
        return FailoverDecision::Hold;
    }
    // Promote the first standby strictly after the active aggregator in order.
    match standbys.iter().find(|(party_id, _)| *party_id > active) {
        Some((next_party, next_addr)) => FailoverDecision::Promote {
            demote: active,
            promote_to: *next_party,
            new_addr: next_addr.clone(),
        },
        None => FailoverDecision::Exhausted { demote: active },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FailoverPolicy {
        FailoverPolicy::new(Duration::from_secs(60))
    }

    fn standbys() -> Vec<(u64, String)> {
        vec![(0, "0xa".into()), (1, "0xb".into()), (2, "0xc".into())]
    }

    #[test]
    fn settled_always_holds() {
        let d = decide_failover(
            &policy(),
            AggregatorPhase::Settled,
            Duration::from_secs(10_000),
            0,
            &standbys(),
        );
        assert_eq!(d, FailoverDecision::Hold);
    }

    #[test]
    fn within_budget_holds() {
        let d = decide_failover(
            &policy(),
            AggregatorPhase::AwaitingPublicKey,
            Duration::from_secs(59),
            0,
            &standbys(),
        );
        assert_eq!(d, FailoverDecision::Hold);
    }

    #[test]
    fn past_budget_promotes_next_standby() {
        let d = decide_failover(
            &policy(),
            AggregatorPhase::AwaitingPlaintext,
            Duration::from_secs(61),
            0,
            &standbys(),
        );
        assert_eq!(
            d,
            FailoverDecision::Promote {
                demote: 0,
                promote_to: 1,
                new_addr: "0xb".into()
            }
        );
    }

    #[test]
    fn promotes_past_already_skipped_members() {
        // active is party 1 (party 0 already skipped); next is party 2.
        let remaining = vec![(1, "0xb".to_string()), (2, "0xc".to_string())];
        let d = decide_failover(
            &policy(),
            AggregatorPhase::AwaitingPlaintext,
            Duration::from_secs(120),
            1,
            &remaining,
        );
        assert_eq!(
            d,
            FailoverDecision::Promote {
                demote: 1,
                promote_to: 2,
                new_addr: "0xc".into()
            }
        );
    }

    #[test]
    fn exhausted_when_no_standby_remains() {
        let only_last = vec![(2, "0xc".to_string())];
        let d = decide_failover(
            &policy(),
            AggregatorPhase::AwaitingPlaintext,
            Duration::from_secs(120),
            2,
            &only_last,
        );
        assert_eq!(d, FailoverDecision::Exhausted { demote: 2 });
    }
}
