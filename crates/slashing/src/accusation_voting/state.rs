// SPDX-License-Identifier: LGPL-3.0-only

//! Accusation workflow state, inputs, and effect intents.

use super::*;

/// How long to wait for votes before declaring the accusation inconclusive.
pub(crate) const DEFAULT_VOTE_TIMEOUT: Duration = Duration::from_secs(300);

/// Injected time source used by deterministic deadline transitions.
pub trait Clock: Send + Sync + 'static {
    fn unix_now_secs(&self) -> u64;
}

/// An I/O effect the actor must perform on behalf of [`AccusationVoting`].
pub(crate) enum VoteAction {
    PublishAccusation {
        accusation: ProofFailureAccusation,
        ec: EventContext<Sequenced>,
        dedup_key: (Address, ProofIdentity),
    },
    PublishVote {
        vote: AccusationVote,
        ec: EventContext<Sequenced>,
    },
    PublishQuorum {
        quorum: AccusationQuorumReached,
        ec: EventContext<Sequenced>,
    },
    DispatchZk {
        request: ComputeRequest,
        ec: EventContext<Sequenced>,
        correlation_id: CorrelationId,
    },
    StartTimeout([u8; 32]),
    CancelTimeout([u8; 32]),
}

/// An active accusation awaiting agreement votes from committee members.
pub(crate) struct PendingAccusation {
    pub(crate) accusation: ProofFailureAccusation,
    pub(crate) votes_for: Vec<AccusationVote>,
    pub(crate) ec: EventContext<Sequenced>,
}

/// Cached verification result for an accused party and proof type.
pub(super) struct ReceivedProofData {
    pub(super) data_hash: [u8; 32],
    pub(super) verification_passed: bool,
    pub(super) evidence: Bytes,
}

/// An in-flight ZK re-verification for a forwarded C3a/C3b proof.
pub(super) struct PendingReVerification {
    pub(super) accusation_id: [u8; 32],
    pub(super) data_hash: [u8; 32],
    pub(super) accused: Address,
    pub(super) proof_type: ProofType,
    pub(super) proof_instance: u32,
    pub(super) evidence: Bytes,
}

/// Pure, synchronous core of the accusation quorum protocol.
pub(crate) struct AccusationVoting {
    pub(super) e3_id: E3id,
    pub(super) my_address: Address,
    pub(super) signer: PrivateKeySigner,
    pub(super) slashing_manager: Address,
    pub(super) committee: Vec<Address>,
    pub(super) circuit_threshold_t: usize,
    pub(super) vote_quorum_h: usize,
    pub(super) committee_n: usize,
    pub(super) pending: HashMap<[u8; 32], PendingAccusation>,
    pub(super) accused_proofs: HashSet<(Address, ProofIdentity)>,
    pub(super) received_data: HashMap<(Address, ProofIdentity), ReceivedProofData>,
    pub(super) buffered_votes: HashMap<[u8; 32], Vec<AccusationVote>>,
    pub(super) pending_reverifications: HashMap<CorrelationId, PendingReVerification>,
    pub(super) vote_timeout: Duration,
    pub(super) vote_validity_secs: u64,
    pub(super) accusation_deadline_skew_secs: u64,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) params_preset: e3_fhe_params::BfvPreset,
}
