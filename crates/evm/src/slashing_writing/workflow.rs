// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure decision logic for staggered, committee-attested slash submission.
//!
//! A node only submits a slash proposal when it is one of the top
//! `MAX_SLASH_SUBMITTERS` voters (ranked ascending by signer address). The
//! lowest-address voter submits immediately; higher-ranked fallback voters wait
//! `rank * SUBMITTER_DELAY_SECS` so on-chain `DuplicateEvidence` protection lets
//! at most one slash execute.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use alloy::primitives::{keccak256, Address, B256, U256};
use anyhow::{Context, Result};
use e3_events::{AccusationOutcome, AccusationQuorumReached, EvmLogObserved};

/// Maximum number of voters eligible to attempt on-chain submission.
/// Rank 0 submits immediately, rank 1 after one delay interval, etc.
pub(crate) const MAX_SLASH_SUBMITTERS: usize = 3;

/// Delay between fallback submission attempts (seconds).
/// Rank N waits N * SUBMITTER_DELAY_SECS before submitting.
pub(crate) const SUBMITTER_DELAY_SECS: u64 = 30;

/// The exact semantic replay domain consumed by `SlashingManager._proposeSlash`.
/// Vote ordering and signatures are deliberately excluded: Solidity permits one
/// submission for `(chain, E3, operator, proof type)` regardless of evidence encoding.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    pub(crate) fn from_observation(event: &EvmLogObserved) -> Option<Self> {
        if event.contract != "SlashingManager" || event.event_name != "SlashProposed" {
            return None;
        }
        let e3_id: U256 = event.e3_id.clone()?.try_into().ok()?;
        let topic = event.topics.get(3)?;
        let hex = topic.strip_prefix("0x").unwrap_or(topic);
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let operator = format!("0x{}", &hex[24..]).parse().ok()?;
        let data = event.data.extract_bytes();
        let reason = data.get(..32)?;
        let proof_type =
            (0u8..=10).find(|candidate| keccak256([*candidate]).as_slice() == reason)?;

        Some(Self {
            chain_id: event.chain_id,
            e3_id,
            operator,
            proof_type,
        })
    }

    pub(crate) fn evidence_key(&self) -> B256 {
        let mut encoded = Vec::with_capacity(32 + 32 + 20 + 1);
        encoded.extend_from_slice(&U256::from(self.chain_id).to_be_bytes::<32>());
        encoded.extend_from_slice(&self.e3_id.to_be_bytes::<32>());
        encoded.extend_from_slice(self.operator.as_slice());
        encoded.push(self.proof_type);
        keccak256(encoded)
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

    pub(crate) fn complete_observed(&mut self, key: SlashIntentKey) {
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
    matches!(
        outcome,
        AccusationOutcome::AccusedFaulted | AccusationOutcome::Equivocation
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, B256};
    use alloy::sol_types::SolValue;
    use e3_events::{AccusationQuorumReached, AccusationVote, E3id, EvmLogObserved, ProofType};
    use e3_utils::ArcBytes;

    alloy::sol! {
        struct EvidenceKeyDomain {
            uint256 chainId;
            uint256 e3Id;
            address operator;
            uint8 proofType;
        }
    }

    fn vote(voter: Address) -> AccusationVote {
        AccusationVote {
            e3_id: E3id::new("1", 1),
            accusation_id: B256::ZERO.0,
            voter,
            data_hash: B256::repeat_byte(7).0,
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
            votes_for: voters.into_iter().map(vote).collect(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::from_static(b"evidence"),
        }
    }

    fn slash_proposed() -> EvmLogObserved {
        let mut data = keccak256([ProofType::C0PkBfv as u8]).to_vec();
        data.resize(32 * 6, 0);
        EvmLogObserved {
            contract: "SlashingManager".to_owned(),
            chain_id: 1,
            e3_id: Some(E3id::new("1", 1)),
            event_name: "SlashProposed".to_owned(),
            signature: None,
            known: true,
            topics: vec![
                String::new(),
                String::new(),
                String::new(),
                format!("0x{}{}", "00".repeat(12), "08".repeat(20)),
            ],
            data: ArcBytes::from_bytes(&data),
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
    fn observed_proposal_closes_deferred_replay_intent() {
        let mut gate = SlashSubmissionGate::new();
        let (_, decision) = gate.admit(quorum(vec![Address::repeat_byte(1)])).unwrap();
        assert_eq!(decision, SlashSubmissionDecision::Defer);

        let key = SlashIntentKey::from_observation(&slash_proposed()).unwrap();
        gate.complete_observed(key);

        assert!(gate.enable_effects().is_empty());
    }

    #[test]
    fn evidence_key_matches_solidity_encode_packed_domain() {
        let event = quorum(vec![Address::repeat_byte(1)]);
        let key = SlashIntentKey::from_quorum(&event).unwrap();
        let expected = keccak256(
            EvidenceKeyDomain {
                chainId: U256::from(1),
                e3Id: U256::from(1),
                operator: Address::repeat_byte(8),
                proofType: ProofType::C0PkBfv as u8,
            }
            .abi_encode_packed(),
        );

        assert_eq!(key.evidence_key(), expected);
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
        // Not a voter.
        assert!(!should_submit_slash(
            true,
            &AccusationOutcome::Equivocation,
            None
        ));
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
}
