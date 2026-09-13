// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure decision logic for staggered, committee-attested slash submission.
//!
//! Every node checks the proof-type policy after an accusation quorum. When the policy accepts
//! proof attestations, only the top `MAX_SLASH_SUBMITTERS` voters can submit a slash proposal.
//! The lowest-address voter submits immediately. Higher-ranked fallback voters wait
//! `rank * SUBMITTER_DELAY_SECS`, and on-chain `DuplicateEvidence` protection limits execution to
//! one proposal.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use alloy::primitives::{Address, B256, U256};
use anyhow::{Context, Result};
use e3_events::{
    AccusationOutcome, AccusationQuorumReached, CommitteeMemberExcluded, ProofType, SlashExecuted,
};
use serde::{Deserialize, Serialize};

/// Maximum number of voters eligible to attempt on-chain submission.
/// Rank 0 submits immediately, rank 1 after one delay interval, etc.
pub(crate) const MAX_SLASH_SUBMITTERS: usize = 3;

/// Delay between fallback submission attempts (seconds).
/// Rank N waits N * SUBMITTER_DELAY_SECS before submitting.
pub(crate) const SUBMITTER_DELAY_SECS: u64 = 30;

/// The exact semantic replay domain consumed by `SlashingManager._proposeSlash`.
/// Vote ordering and signatures are deliberately excluded: Solidity permits one
/// submission for `(chain, E3, operator, proof type)` regardless of evidence encoding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct SlashIntentKey {
    chain_id: u64,
    e3_id: U256,
    operator: Address,
    proof_type: u8,
}

impl SlashIntentKey {
    pub(crate) fn from_quorum(event: &AccusationQuorumReached) -> Result<Self> {
        Ok(Self {
            chain_id: event.e3_id.chain_id(),
            e3_id: event
                .e3_id
                .clone()
                .try_into()
                .context("slash intent has a non-numeric E3 id")?,
            operator: event.accused,
            proof_type: event.proof_type as u8,
        })
    }

    pub(crate) fn from_exclusion(event: &CommitteeMemberExcluded) -> Result<Self> {
        Ok(Self {
            chain_id: event.e3_id.chain_id(),
            e3_id: event
                .e3_id
                .clone()
                .try_into()
                .context("committee exclusion has a non-numeric E3 id")?,
            operator: event.node,
            proof_type: event.proof_type as u8,
        })
    }

    pub(crate) fn from_execution(event: &SlashExecuted) -> Result<Option<Self>> {
        let proof_type = ProofType::ALL
            .into_iter()
            .find(|proof_type| proof_type.attestation_slash_reason() == B256::from(event.reason));
        let Some(proof_type) = proof_type else {
            return Ok(None);
        };
        Ok(Some(Self {
            chain_id: event.e3_id.chain_id(),
            e3_id: event
                .e3_id
                .clone()
                .try_into()
                .context("slash execution has a non-numeric E3 id")?,
            operator: event.operator,
            proof_type: proof_type as u8,
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlashSubmissionDecision {
    Defer,
    Submit,
    IgnoreDuplicate,
}

/// Process-local outbox gate for slash submissions.
///
/// Replayed intents are retained until `EffectsEnabled`, and semantically equivalent
/// events are coalesced while deferred, in flight, or already completed. This prevents
/// startup reconciliation from producing transactions and prevents same-process gas
/// loss from reordered-but-equivalent quorum payloads.
#[derive(Default)]
pub(crate) struct SlashSubmissionGate {
    effects_enabled: bool,
    deferred: BTreeMap<SlashIntentKey, AccusationQuorumReached>,
    in_flight: BTreeSet<SlashIntentKey>,
    completed: BTreeSet<SlashIntentKey>,
}

impl SlashSubmissionGate {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn admit(
        &mut self,
        event: AccusationQuorumReached,
    ) -> Result<(SlashIntentKey, SlashSubmissionDecision)> {
        let key = SlashIntentKey::from_quorum(&event)?;
        if self.completed.contains(&key)
            || self.in_flight.contains(&key)
            || self.deferred.contains_key(&key)
        {
            return Ok((key, SlashSubmissionDecision::IgnoreDuplicate));
        }

        if !self.effects_enabled {
            self.deferred.insert(key.clone(), event);
            return Ok((key, SlashSubmissionDecision::Defer));
        }

        self.in_flight.insert(key.clone());
        Ok((key, SlashSubmissionDecision::Submit))
    }

    pub(crate) fn enable_effects(&mut self) -> Vec<(SlashIntentKey, AccusationQuorumReached)> {
        self.effects_enabled = true;
        let deferred = std::mem::take(&mut self.deferred);
        deferred
            .into_iter()
            .filter_map(|(key, event)| {
                if self.completed.contains(&key) || self.in_flight.contains(&key) {
                    None
                } else {
                    self.in_flight.insert(key.clone());
                    Some((key, event))
                }
            })
            .collect()
    }

    pub(crate) fn finish(&mut self, key: &SlashIntentKey, terminal: bool) {
        self.in_flight.remove(key);
        if terminal {
            self.completed.insert(key.clone());
        }
    }

    pub(crate) fn mark_completed(&mut self, key: SlashIntentKey) {
        self.deferred.remove(&key);
        self.in_flight.remove(&key);
        self.completed.insert(key);
    }
}

/// Determine this node's submission rank: its position in the voter set after
/// sorting ascending by address. `None` when this node is not among the voters.
pub(crate) fn submission_rank<I>(voters: I, my_addr: Address) -> Option<usize>
where
    I: IntoIterator<Item = Address>,
{
    let mut sorted: Vec<Address> = voters.into_iter().collect();
    sorted.sort();
    sorted.iter().position(|&v| v == my_addr)
}

/// Outcomes that warrant an on-chain slash proposal.
pub(crate) fn is_slashable_outcome(outcome: &AccusationOutcome) -> bool {
    matches!(outcome, AccusationOutcome::AccusedFaulted)
}

/// Derive the policy key exactly as `SlashingManager._proposeSlash` does for Lane A evidence.
pub(crate) fn slash_reason(proof_type: ProofType) -> B256 {
    proof_type.attestation_slash_reason()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlashPolicyState {
    Disabled,
    ProofEnabled,
    InvalidForAttestations,
}

pub(crate) fn classify_slash_policy(enabled: bool, requires_proof: bool) -> SlashPolicyState {
    match (enabled, requires_proof) {
        (false, _) => SlashPolicyState::Disabled,
        (true, true) => SlashPolicyState::ProofEnabled,
        (true, false) => SlashPolicyState::InvalidForAttestations,
    }
}

/// Whether this node should attempt submission for the given quorum result.
pub(crate) fn should_submit_slash(
    chain_matches: bool,
    outcome: &AccusationOutcome,
    rank: Option<usize>,
) -> bool {
    chain_matches && is_slashable_outcome(outcome) && rank.is_some_and(|r| r < MAX_SLASH_SUBMITTERS)
}

/// How long a fallback submitter of the given rank should wait before attempting.
pub(crate) fn submission_delay(rank: usize) -> Duration {
    Duration::from_secs(rank as u64 * SUBMITTER_DELAY_SECS)
}

/// Return true when retrying the same attestation cannot change the contract outcome.
///
/// `AccusationIssuedInFuture` is deliberately absent: a bounded clock skew can become valid after
/// time advances. Transport, RPC, nonce, and unknown errors also remain retryable.
pub(crate) fn slash_submission_error_is_terminal(decoded: &str) -> bool {
    [
        "ZeroAddress",
        "ProofRequired",
        "OperatorNotInCommittee",
        "DuplicateEvidence",
        "ChainIdMismatch",
        "InvalidProof",
        "InsufficientAttestations",
        "DuplicateVoter",
        "VoterNotInCommittee",
        "InvalidVoteSignature",
        "VoterIsAccused",
        "EquivocationDetected",
        "SignatureExpired",
        "InvalidAccusationWindow",
        "SlashSubmissionDeadlinePassed",
    ]
    .iter()
    .any(|name| decoded.contains(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, Bytes, B256};
    use e3_events::{AccusationQuorumReached, AccusationVote, E3id, ProofType};
    use e3_utils::ArcBytes;

    fn vote(voter: Address) -> AccusationVote {
        AccusationVote {
            e3_id: E3id::new("1", 1),
            accusation_id: B256::ZERO.0,
            voter,
            data_hash: B256::repeat_byte(7).0,
            issued_at: 90,
            deadline: 100,
            signature: ArcBytes::from_bytes(b"signature"),
        }
    }

    fn quorum(voters: Vec<Address>) -> AccusationQuorumReached {
        AccusationQuorumReached {
            e3_id: E3id::new("1", 1),
            accuser: Address::repeat_byte(9),
            accused: Address::repeat_byte(8),
            proof_type: ProofType::C0PkBfv,
            proof_instance: 0,
            votes_for: voters.into_iter().map(vote).collect(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::from_static(b"evidence"),
        }
    }

    #[test]
    fn test_submission_rank_sorts_ascending() {
        let a = Address::repeat_byte(0x01);
        let b = Address::repeat_byte(0x02);
        let c = Address::repeat_byte(0x03);
        // Provided out of order; my_addr=b should be rank 1.
        assert_eq!(submission_rank([c, a, b], b), Some(1));
        assert_eq!(submission_rank([c, a, b], a), Some(0));
        assert_eq!(submission_rank([c, a, b], c), Some(2));
    }

    #[test]
    fn test_submission_rank_none_when_not_voter() {
        let a = Address::repeat_byte(0x01);
        let other = Address::repeat_byte(0x09);
        assert_eq!(submission_rank([a], other), None);
    }

    #[test]
    fn test_should_submit_slash_gating() {
        // Happy path: chain matches, slashable outcome, rank within bound.
        assert!(should_submit_slash(
            true,
            &AccusationOutcome::AccusedFaulted,
            Some(0)
        ));
        // Wrong chain.
        assert!(!should_submit_slash(
            false,
            &AccusationOutcome::AccusedFaulted,
            Some(0)
        ));
        // Non-slashable outcome.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::Inconclusive,
            Some(0)
        ));
        // Rank exceeds MAX_SLASH_SUBMITTERS.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::AccusedFaulted,
            Some(MAX_SLASH_SUBMITTERS)
        ));
        // Equivocation requires evidence for each distinct payload, which the
        // current single-preimage Lane A format cannot prove.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::Equivocation,
            Some(0)
        ));
    }

    #[test]
    fn slash_reason_matches_uint256_packed_encoding() {
        assert_eq!(
            slash_reason(ProofType::C1PkGeneration),
            keccak256([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ])
        );
    }

    #[test]
    fn slash_execution_recovers_every_proof_type() {
        for proof_type in ProofType::ALL {
            let event = SlashExecuted {
                e3_id: E3id::new("1", 1),
                proposal_id: 1,
                operator: Address::repeat_byte(8),
                reason: proof_type.attestation_slash_reason().0,
                ticket_amount: 0,
                ciphernode_bond_amount: 0,
            };

            let key = SlashIntentKey::from_execution(&event)
                .unwrap()
                .expect("known proof type must be recovered");
            assert_eq!(key.proof_type, proof_type as u8, "{proof_type:?}");
        }
    }

    #[test]
    fn slash_execution_ignores_an_unknown_reason() {
        let event = SlashExecuted {
            e3_id: E3id::new("1", 1),
            proposal_id: 1,
            operator: Address::repeat_byte(8),
            reason: keccak256(U256::from(255).to_be_bytes::<32>()).0,
            ticket_amount: 0,
            ciphernode_bond_amount: 0,
        };

        assert!(SlashIntentKey::from_execution(&event).unwrap().is_none());
    }

    #[test]
    fn persisted_local_exclusion_suppresses_a_deferred_replay() {
        let event = quorum(vec![Address::repeat_byte(1)]);
        let exclusion = CommitteeMemberExcluded {
            e3_id: event.e3_id.clone(),
            node: event.accused,
            proof_type: event.proof_type,
            party_id: Some(0),
        };
        let key = SlashIntentKey::from_exclusion(&exclusion).unwrap();
        let mut gate = SlashSubmissionGate::new();

        assert_eq!(
            gate.admit(event.clone()).unwrap().1,
            SlashSubmissionDecision::Defer
        );
        gate.mark_completed(key);

        assert!(gate.enable_effects().is_empty());
        assert_eq!(
            gate.admit(event).unwrap().1,
            SlashSubmissionDecision::IgnoreDuplicate
        );
    }

    #[test]
    fn disabled_policy_is_distinct_from_invalid_lane_configuration() {
        assert_eq!(
            classify_slash_policy(false, false),
            SlashPolicyState::Disabled
        );
        assert_eq!(
            classify_slash_policy(true, false),
            SlashPolicyState::InvalidForAttestations
        );
        assert_eq!(
            classify_slash_policy(true, true),
            SlashPolicyState::ProofEnabled
        );
    }

    #[test]
    fn test_submission_delay_scales_with_rank() {
        assert_eq!(submission_delay(0), Duration::from_secs(0));
        assert_eq!(
            submission_delay(2),
            Duration::from_secs(2 * SUBMITTER_DELAY_SECS)
        );
    }

    #[test]
    fn replayed_submission_is_deferred_and_released_once_after_effects() {
        let mut gate = SlashSubmissionGate::new();
        let event = quorum(vec![Address::repeat_byte(1)]);
        let (_, decision) = gate.admit(event.clone()).unwrap();
        assert_eq!(decision, SlashSubmissionDecision::Defer);

        let released = gate.enable_effects();
        assert_eq!(released.len(), 1);
        assert!(gate.enable_effects().is_empty());

        let (_, duplicate) = gate.admit(event).unwrap();
        assert_eq!(duplicate, SlashSubmissionDecision::IgnoreDuplicate);
    }

    #[test]
    fn reordered_votes_share_the_contract_replay_key() {
        let a = Address::repeat_byte(1);
        let b = Address::repeat_byte(2);
        let first = SlashIntentKey::from_quorum(&quorum(vec![a, b])).unwrap();
        let reordered = SlashIntentKey::from_quorum(&quorum(vec![b, a])).unwrap();
        assert_eq!(first, reordered);
    }

    #[test]
    fn retryable_failure_clears_in_flight_but_terminal_result_does_not() {
        let event = quorum(vec![Address::repeat_byte(1)]);
        let mut gate = SlashSubmissionGate::new();
        gate.enable_effects();

        let (key, first) = gate.admit(event.clone()).unwrap();
        assert_eq!(first, SlashSubmissionDecision::Submit);
        gate.finish(&key, false);
        let (key, retry) = gate.admit(event.clone()).unwrap();
        assert_eq!(retry, SlashSubmissionDecision::Submit);

        gate.finish(&key, true);
        let (_, completed) = gate.admit(event).unwrap();
        assert_eq!(completed, SlashSubmissionDecision::IgnoreDuplicate);
    }

    #[test]
    fn permanent_reverts_stop_retries() {
        assert!(slash_submission_error_is_terminal(
            "execution reverted: InvalidVoteSignature()"
        ));
        assert!(slash_submission_error_is_terminal(
            "execution reverted: SlashSubmissionDeadlinePassed()"
        ));
        assert!(!slash_submission_error_is_terminal(
            "execution reverted: AccusationIssuedInFuture()"
        ));
        assert!(!slash_submission_error_is_terminal(
            "execution reverted: SlashReasonDisabled()"
        ));
        assert!(!slash_submission_error_is_terminal("temporary RPC timeout"));
    }
}
