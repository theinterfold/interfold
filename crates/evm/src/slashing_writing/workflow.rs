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

use crate::domain::attestation_evidence::encode_attestation_evidence;
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
        let proof_type = (ProofType::C0PkBfv as u8..=ProofType::C7DecryptedSharesAggregation as u8)
            .find(|proof_type| slash_reason_u8(*proof_type) == B256::from(event.reason));
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
            proof_type,
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

    /// Persist an intent with `record`, then admit it, so that the intent survives a crash before
    /// its submission. A completed intent skips both steps: it is settled, and recording it again
    /// would leave a durable entry that no acknowledgment removes.
    pub(crate) fn record_and_admit(
        &mut self,
        event: AccusationQuorumReached,
        record: impl FnOnce(&AccusationQuorumReached) -> Result<()>,
    ) -> Result<(SlashIntentKey, SlashSubmissionDecision)> {
        let key = SlashIntentKey::from_quorum(&event)?;
        if self.completed.contains(&key) {
            return Ok((key, SlashSubmissionDecision::IgnoreDuplicate));
        }
        record(&event)?;
        self.admit(event)
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

/// How a slash submission ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SubmissionEnd {
    /// No later attempt can change the outcome, so the gate completes the intent.
    pub terminal: bool,
    /// The recovery record no longer needs the intent.
    pub acknowledge_recovery: bool,
    /// The writer tries again after its retry delay.
    pub retry: bool,
}

impl SubmissionEnd {
    fn settled(acknowledge_recovery: bool) -> Self {
        Self {
            terminal: true,
            acknowledge_recovery,
            retry: false,
        }
    }

    fn retry() -> Self {
        Self {
            terminal: false,
            acknowledge_recovery: false,
            retry: true,
        }
    }
}

/// What the writer reports when a submission ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionReport {
    /// An error for the operator.
    Error(String),
    /// A revert that a fallback submitter or a stale accusation expects, logged as a warning.
    Skipped(String),
}

/// The next effect of one slash submission. The writer runs it and passes its result to the
/// matching [`SlashSubmission`] method; every decision is made there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SubmissionStep {
    /// Read the proof type's slash policy, then call [`SlashSubmission::policy_read`].
    ReadPolicy,
    /// The policy is disabled. Every node excludes the faulted member from its local E3 work:
    /// publish the exclusion, then call [`SlashSubmission::exclusion_published`].
    Exclude(CommitteeMemberExcluded),
    /// A fallback submitter waits, giving the lower ranks time to land their transaction, and
    /// then submits.
    Wait { rank: usize, delay: Duration },
    /// Send the slash proposal, then call [`SlashSubmission::submitted`].
    Submit { rank: usize },
    /// End the submission, after the report, if any.
    End {
        end: SubmissionEnd,
        report: Option<SubmissionReport>,
    },
}

/// The decisions of one slash submission: policy, exclusion, submitter rank, evidence, wait and
/// the classification of its result.
pub(crate) struct SlashSubmission {
    event: AccusationQuorumReached,
    rank: Option<usize>,
}

impl SlashSubmission {
    /// A submission of `event` by `submitter`, and its first step.
    pub(crate) fn new(
        event: AccusationQuorumReached,
        submitter: Address,
    ) -> (Self, SubmissionStep) {
        let rank = submission_rank(event.votes_for.iter().map(|vote| vote.voter), submitter);
        (Self { event, rank }, SubmissionStep::ReadPolicy)
    }

    pub(crate) fn event(&self) -> &AccusationQuorumReached {
        &self.event
    }

    /// The policy, or the error of its read. A failed read must not invent an exclusion: eligible
    /// submitters go on, so a temporary RPC failure cannot suppress an enabled slash.
    pub(crate) fn policy_read(&self, policy: Result<SlashPolicyState, String>) -> SubmissionStep {
        match policy {
            Ok(SlashPolicyState::Disabled) => SubmissionStep::Exclude(CommitteeMemberExcluded {
                e3_id: self.event.e3_id.clone(),
                node: self.event.accused,
                proof_type: self.event.proof_type,
                party_id: None,
            }),
            Ok(SlashPolicyState::InvalidForAttestations) => SubmissionStep::End {
                end: SubmissionEnd::settled(true),
                report: Some(SubmissionReport::Error(format!(
                    "Slash policy for proof type {} is enabled but does not accept committee attestations",
                    self.event.proof_type
                ))),
            },
            Ok(SlashPolicyState::ProofEnabled) | Err(_) => self.submission(),
        }
    }

    /// Only the first `MAX_SLASH_SUBMITTERS` voters submit, with evidence, rank 0 at once and the
    /// fallback ranks after their delay.
    fn submission(&self) -> SubmissionStep {
        let rank = match self.rank {
            Some(rank) if should_submit_slash(true, &self.event.outcome, Some(rank)) => rank,
            _ => {
                return SubmissionStep::End {
                    end: SubmissionEnd::settled(true),
                    report: None,
                }
            }
        };
        if encode_attestation_evidence(&self.event).is_none() {
            return SubmissionStep::End {
                end: SubmissionEnd::settled(true),
                report: Some(SubmissionReport::Error(format!(
                    "Refusing malformed slash intent for E3 {}: votes or evidence are empty",
                    self.event.e3_id
                ))),
            };
        }
        if rank > 0 {
            SubmissionStep::Wait {
                rank,
                delay: submission_delay(rank),
            }
        } else {
            SubmissionStep::Submit { rank }
        }
    }

    /// The result of publishing the local exclusion. A published exclusion completes the intent
    /// but keeps its recovery entry until the exclusion is observed; a failed one is retried.
    pub(crate) fn exclusion_published(&self, result: Result<(), String>) -> SubmissionStep {
        match result {
            Ok(()) => SubmissionStep::End {
                end: SubmissionEnd::settled(false),
                report: None,
            },
            Err(error) => SubmissionStep::End {
                end: SubmissionEnd::retry(),
                report: Some(SubmissionReport::Error(error)),
            },
        }
    }

    /// The result of the proposal transaction, with a failure as its decoded contract error.
    pub(crate) fn submitted(&self, rank: usize, result: Result<(), String>) -> SubmissionStep {
        let decoded = match result {
            Ok(()) => {
                return SubmissionStep::End {
                    end: SubmissionEnd::settled(true),
                    report: None,
                }
            }
            Err(decoded) => decoded,
        };
        // Fallback submitters expect DuplicateEvidence once the primary landed its proposal.
        // Operator/VoterNotInCommittee mean a stale accusation, not a local fault.
        let expected = decoded.contains("OperatorNotInCommittee")
            || decoded.contains("VoterNotInCommittee")
            || decoded.contains("DuplicateEvidence");
        let report = if expected {
            SubmissionReport::Skipped(format!("Slash submission skipped (rank {rank}): {decoded}"))
        } else {
            SubmissionReport::Error(format!("Error submitting slash proposal: {decoded}"))
        };
        let end = if slash_submission_error_is_terminal(&decoded) {
            SubmissionEnd::settled(true)
        } else {
            SubmissionEnd::retry()
        };
        SubmissionStep::End {
            end,
            report: Some(report),
        }
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

fn slash_reason_u8(proof_type: u8) -> B256 {
    alloy::primitives::keccak256(U256::from(proof_type).to_be_bytes::<32>())
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
            votes_for: voters.into_iter().map(vote).collect(),
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: Bytes::from_static(b"evidence"),
        }
    }

    fn end(terminal: bool, acknowledge_recovery: bool, retry: bool) -> SubmissionEnd {
        SubmissionEnd {
            terminal,
            acknowledge_recovery,
            retry,
        }
    }

    /// The submission of a quorum of four voters by the voter of `rank`, or by a non-voter.
    fn submission_by(rank: Option<usize>) -> SlashSubmission {
        let voters: Vec<_> = (1..=4).map(Address::repeat_byte).collect();
        let submitter = rank.map_or(Address::repeat_byte(0xee), |rank| voters[rank]);
        let (submission, first) = SlashSubmission::new(quorum(voters), submitter);
        assert_eq!(first, SubmissionStep::ReadPolicy);
        submission
    }

    #[test]
    fn a_disabled_policy_excludes_the_member_on_every_node() {
        for rank in [Some(0), Some(3), None] {
            let submission = submission_by(rank);
            let event = submission.event().clone();
            assert_eq!(
                submission.policy_read(Ok(SlashPolicyState::Disabled)),
                SubmissionStep::Exclude(CommitteeMemberExcluded {
                    e3_id: event.e3_id,
                    node: event.accused,
                    proof_type: event.proof_type,
                    party_id: None,
                }),
                "rank {rank:?}"
            );
            // A published exclusion completes the intent but keeps it for recovery until the
            // exclusion is observed; a failed publication retries.
            assert_eq!(
                submission.exclusion_published(Ok(())),
                SubmissionStep::End {
                    end: end(true, false, false),
                    report: None
                }
            );
            assert_eq!(
                submission.exclusion_published(Err("bus closed".into())),
                SubmissionStep::End {
                    end: end(false, false, true),
                    report: Some(SubmissionReport::Error("bus closed".into()))
                }
            );
        }
    }

    #[test]
    fn a_policy_without_attestations_ends_the_submission_with_an_error() {
        let step = submission_by(Some(0)).policy_read(Ok(SlashPolicyState::InvalidForAttestations));
        assert!(matches!(
            step,
            SubmissionStep::End {
                end,
                report: Some(SubmissionReport::Error(_)),
            } if end == end_settled_acknowledged()
        ));
    }

    fn end_settled_acknowledged() -> SubmissionEnd {
        end(true, true, false)
    }

    #[test]
    fn the_first_three_voters_submit_in_rank_order_also_after_a_failed_policy_read() {
        for policy in [
            Ok(SlashPolicyState::ProofEnabled),
            Err("rpc unavailable".to_string()),
        ] {
            assert_eq!(
                submission_by(Some(0)).policy_read(policy.clone()),
                SubmissionStep::Submit { rank: 0 }
            );
            for rank in [1, 2] {
                assert_eq!(
                    submission_by(Some(rank)).policy_read(policy.clone()),
                    SubmissionStep::Wait {
                        rank,
                        delay: Duration::from_secs(rank as u64 * SUBMITTER_DELAY_SECS)
                    }
                );
            }
            // Rank 3 and non-voters do not submit; the intent is settled for them.
            for rank in [Some(3), None] {
                assert_eq!(
                    submission_by(rank).policy_read(policy.clone()),
                    SubmissionStep::End {
                        end: end_settled_acknowledged(),
                        report: None
                    }
                );
            }
        }
    }

    #[test]
    fn a_quorum_without_evidence_is_refused() {
        let voters = vec![Address::repeat_byte(1)];
        let mut event = quorum(voters.clone());
        event.evidence = Bytes::new();
        let (submission, _) = SlashSubmission::new(event, voters[0]);
        assert!(matches!(
            submission.policy_read(Ok(SlashPolicyState::ProofEnabled)),
            SubmissionStep::End {
                end,
                report: Some(SubmissionReport::Error(_)),
            } if end == end_settled_acknowledged()
        ));
    }

    #[test]
    fn submission_results_settle_or_retry_by_the_contract_error() {
        let submission = submission_by(Some(1));
        assert_eq!(
            submission.submitted(1, Ok(())),
            SubmissionStep::End {
                end: end_settled_acknowledged(),
                report: None
            }
        );
        // A revert that a fallback submitter expects is a warning, and it is final.
        assert_eq!(
            submission.submitted(1, Err("DuplicateEvidence()".into())),
            SubmissionStep::End {
                end: end_settled_acknowledged(),
                report: Some(SubmissionReport::Skipped(
                    "Slash submission skipped (rank 1): DuplicateEvidence()".into()
                ))
            }
        );
        // Another final revert is an error.
        assert_eq!(
            submission.submitted(1, Err("InvalidVoteSignature()".into())),
            SubmissionStep::End {
                end: end_settled_acknowledged(),
                report: Some(SubmissionReport::Error(
                    "Error submitting slash proposal: InvalidVoteSignature()".into()
                ))
            }
        );
        // A transport error or a revert that time can change is retried.
        for decoded in ["connection reset", "AccusationIssuedInFuture()"] {
            assert_eq!(
                submission.submitted(1, Err(decoded.into())),
                SubmissionStep::End {
                    end: end(false, false, true),
                    report: Some(SubmissionReport::Error(format!(
                        "Error submitting slash proposal: {decoded}"
                    )))
                }
            );
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
