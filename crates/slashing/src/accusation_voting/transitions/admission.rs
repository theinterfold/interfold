// SPDX-License-Identifier: LGPL-3.0-only

//! Typed admission checks for the inputs of accusation voting. A check admits its input or names
//! why the input does not reach the accusation state. The checks run in the order in which the
//! transitions ran them; the transitions act only on admitted inputs, and their remaining
//! decisions depend on the accusation state.

use super::*;

/// An input that passed its admission checks.
pub(super) struct Admitted<T>(T);

impl<T> Admitted<T> {
    pub(super) fn into_inner(self) -> T {
        self.0
    }
}

/// Why an input does not reach the accusation state.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    /// The input belongs to another E3.
    OtherE3,
    /// The input accuses its own accuser, or this node would accuse itself.
    SelfAccusation,
    /// The input comes from this node, which holds its own accusations and votes already.
    Own,
    /// A forwarded payload with a proof type that has none: only C3 proofs are per recipient.
    UnforwardableProof,
    /// A local failure without the claimed committee member's signature over its payload.
    UnsignedFailure,
    /// A commitment violation against a node that is not on the committee.
    ViolationAgainstNonMember { accused: Address, e3_id: E3id },
    /// A peer's accusation whose deadline is outside the local validity window.
    DeadlineOutsideWindow {
        accuser: Address,
        deadline: u64,
        now: u64,
        vote_validity_secs: u64,
        skew_secs: u64,
    },
    /// An accusation from a node that is not on the committee.
    AccuserNotInCommittee(Address),
    /// An accusation against a node that is not on the committee.
    AccusedNotInCommittee(Address),
    /// An accusation whose signature does not verify.
    InvalidAccusationSignature(Address),
    /// A vote from a node that is not on the committee.
    VoterNotInCommittee(Address),
    /// A vote whose signature does not verify.
    InvalidVoteSignature(Address),
}

impl Rejection {
    /// Log the rejection as the transitions always did: expected inputs pass silently.
    pub(super) fn log(&self) {
        match self {
            Self::OtherE3 | Self::SelfAccusation | Self::Own | Self::UnforwardableProof => {}
            Self::UnsignedFailure => {
                warn!("Ignoring proof failure without the claimed committee member's signature")
            }
            Self::ViolationAgainstNonMember { accused, e3_id } => warn!(
                "Ignoring commitment violation for {} — not on E3 {} committee",
                accused, e3_id
            ),
            Self::DeadlineOutsideWindow {
                accuser,
                deadline,
                now,
                vote_validity_secs,
                skew_secs,
            } => {
                let max_deadline = now
                    .saturating_add(*vote_validity_secs)
                    .saturating_add(*skew_secs);
                warn!(
                    "Ignoring accusation from {} — deadline {} outside local validity window \
                     (now={}, vote_validity_secs={}, skew_secs={}, max_accepted_deadline={})",
                    accuser, deadline, now, vote_validity_secs, skew_secs, max_deadline
                );
            }
            Self::AccuserNotInCommittee(accuser) => {
                warn!("Ignoring accusation from non-committee member {}", accuser)
            }
            Self::AccusedNotInCommittee(accused) => {
                warn!(
                    "Ignoring accusation against non-committee member {}",
                    accused
                )
            }
            Self::InvalidAccusationSignature(accuser) => {
                warn!(
                    "Invalid signature on accusation from {} — ignoring",
                    accuser
                )
            }
            Self::VoterNotInCommittee(voter) => {
                warn!("Ignoring vote from non-committee member {}", voter)
            }
            Self::InvalidVoteSignature(voter) => {
                warn!("Invalid signature on vote from {} — ignoring", voter)
            }
        }
    }
}

impl AccusationVoting {
    /// A proof failure that this node detected. The accused must hold the finalized party slot
    /// that the failure names and must have signed the failed payload; this node never accuses
    /// itself. The finalized party IDs of local inputs are trusted.
    pub(super) fn admit_local_failure(
        &self,
        event: ProofVerificationFailed,
    ) -> Result<Admitted<ProofVerificationFailed>, Rejection> {
        if event.e3_id != self.e3_id {
            return Err(Rejection::OtherE3);
        }
        let accused = event.accused_address;
        let expected = usize::try_from(event.accused_party_id)
            .ok()
            .and_then(|party| self.finalized_committee.get(party));
        if !self.committee.contains(&accused)
            || expected != Some(&accused)
            || event.signed_payload.payload.e3_id != self.e3_id
            || event.signed_payload.payload.proof_type != event.proof_type
            || event.signed_payload.recover_address().ok() != Some(accused)
            || Self::compute_payload_hash(&event.signed_payload) != event.data_hash
        {
            return Err(Rejection::UnsignedFailure);
        }
        if self.is_self_accusation(self.my_address, accused, event.accused_party_id) {
            return Err(Rejection::SelfAccusation);
        }
        Ok(Admitted(event))
    }

    /// A commitment violation that this node's checker found, against another committee member.
    pub(super) fn admit_violation(
        &self,
        data: CommitmentConsistencyViolation,
    ) -> Result<Admitted<CommitmentConsistencyViolation>, Rejection> {
        if data.e3_id != self.e3_id {
            return Err(Rejection::OtherE3);
        }
        if !self.committee.contains(&data.accused_address) {
            return Err(Rejection::ViolationAgainstNonMember {
                accused: data.accused_address,
                e3_id: self.e3_id.clone(),
            });
        }
        if self.is_self_accusation(self.my_address, data.accused_address, data.accused_party_id) {
            return Err(Rejection::SelfAccusation);
        }
        Ok(Admitted(data))
    }

    /// A peer's accusation. Its signature binds the addresses, not `accused_party_id`, so the
    /// self-accusation check compares addresses. Only C3 proofs can be forwarded with it.
    pub(super) fn admit_accusation(
        &self,
        accusation: ProofFailureAccusation,
    ) -> Result<Admitted<ProofFailureAccusation>, Rejection> {
        if accusation.e3_id != self.e3_id {
            return Err(Rejection::OtherE3);
        }
        if accusation.accuser == accusation.accused {
            return Err(Rejection::SelfAccusation);
        }
        if accusation.signed_payload.is_some() && !Self::can_forward_proof(accusation.proof_type) {
            return Err(Rejection::UnforwardableProof);
        }
        let now = self.clock.unix_now_secs();
        if !Self::is_peer_deadline_acceptable(
            accusation.issued_at,
            accusation.deadline,
            now,
            self.vote_validity_secs,
            self.accusation_deadline_skew_secs,
        ) {
            return Err(Rejection::DeadlineOutsideWindow {
                accuser: accusation.accuser,
                deadline: accusation.deadline,
                now,
                vote_validity_secs: self.vote_validity_secs,
                skew_secs: self.accusation_deadline_skew_secs,
            });
        }
        if !self.committee.contains(&accusation.accuser) {
            return Err(Rejection::AccuserNotInCommittee(accusation.accuser));
        }
        // Defense in depth: the accused must be a committee member too.
        if !self.committee.contains(&accusation.accused) {
            return Err(Rejection::AccusedNotInCommittee(accusation.accused));
        }
        if accusation.accuser == self.my_address {
            return Err(Rejection::Own);
        }
        if !self.verify_accusation_signature(&accusation) {
            return Err(Rejection::InvalidAccusationSignature(accusation.accuser));
        }
        Ok(Admitted(accusation))
    }

    /// A peer's vote from a committee member, with a valid signature.
    pub(super) fn admit_vote(
        &self,
        vote: AccusationVote,
    ) -> Result<Admitted<AccusationVote>, Rejection> {
        if vote.e3_id != self.e3_id {
            return Err(Rejection::OtherE3);
        }
        if !self.committee.contains(&vote.voter) {
            return Err(Rejection::VoterNotInCommittee(vote.voter));
        }
        if vote.voter == self.my_address {
            return Err(Rejection::Own);
        }
        if !self.verify_vote_signature(&vote) {
            return Err(Rejection::InvalidVoteSignature(vote.voter));
        }
        Ok(Admitted(vote))
    }
}
