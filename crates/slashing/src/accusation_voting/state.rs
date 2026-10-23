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
        dedup_key: (Address, ProofType),
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

/// A local failure that arrived while startup replayed the event log. It is accused once effects
/// run, unless this node's own accusation of the same proof arrived first.
pub(crate) struct DeferredAccusation {
    pub(super) accused_address: Address,
    pub(super) accused_party_id: u64,
    pub(super) proof_type: ProofType,
    pub(super) data_hash: [u8; 32],
    pub(super) forwarded_payload: Option<SignedProofPayload>,
    pub(super) ec: EventContext<Sequenced>,
}

/// An active accusation awaiting agreement votes from committee members.
pub(crate) struct PendingAccusation {
    pub(crate) accusation: ProofFailureAccusation,
    pub(crate) votes_for: Vec<AccusationVote>,
    pub(crate) ec: EventContext<Sequenced>,
    /// Unix seconds when the vote collection times out. A restart keeps it.
    pub(crate) timeout_at: u64,
}

pub(crate) const ACCUSATION_VOTES_SNAPSHOT_VERSION: u32 = 1;

/// Saved vote state of one E3: the pending accusations that hold this node's vote, with their
/// admitted votes, vote timeouts and the failed proof's evidence, and the proofs that this node
/// accused. Replay starts after the snapshot cursor, so a restarted manager cannot rebuild a tally
/// from the event log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct AccusationVotesSnapshot {
    pub(super) version: u32,
    pub(super) pending: Vec<SavedAccusation>,
    pub(super) accused_proofs: Vec<(Address, ProofType)>,
}

impl Default for AccusationVotesSnapshot {
    fn default() -> Self {
        Self {
            version: ACCUSATION_VOTES_SNAPSHOT_VERSION,
            pending: Vec::new(),
            accused_proofs: Vec::new(),
        }
    }
}

impl AccusationVotesSnapshot {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCUSATION_VOTES_SNAPSHOT_VERSION,
            "unsupported accusation-votes snapshot version {}",
            self.version
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedAccusation {
    pub(super) accusation: ProofFailureAccusation,
    pub(super) votes_for: Vec<AccusationVote>,
    pub(super) ec: EventContext<Sequenced>,
    pub(super) timeout_at: u64,
    /// This node's failed check of the accused proof: a quorum carries its evidence on chain.
    pub(super) failed_proof: Option<SavedFailedProof>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedFailedProof {
    pub(super) data_hash: [u8; 32],
    pub(super) evidence: Bytes,
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
    pub(super) evidence: Bytes,
}

/// Pure, synchronous core of the accusation quorum protocol.
pub(crate) struct AccusationVoting {
    pub(super) e3_id: E3id,
    pub(super) my_address: Address,
    pub(super) signer: PrivateKeySigner,
    pub(super) slashing_manager: Address,
    pub(super) committee: Vec<Address>,
    /// Finalized party IDs stay fixed when slashing removes active members.
    pub(super) committee_party_ids: HashMap<Address, u64>,
    /// Immutable party slots, also after the live voting roster shrinks.
    pub(super) finalized_committee: Vec<Address>,
    pub(super) circuit_threshold_t: usize,
    pub(super) vote_quorum_h: usize,
    pub(super) committee_n: usize,
    pub(super) pending: HashMap<[u8; 32], PendingAccusation>,
    pub(super) accused_proofs: HashSet<(Address, ProofType)>,
    pub(super) received_data: HashMap<(Address, ProofType), ReceivedProofData>,
    pub(super) buffered_votes: HashMap<[u8; 32], Vec<AccusationVote>>,
    /// Accusers whose later vote window this node adopted; each moves a window at most once.
    pub(super) window_movers: HashSet<([u8; 32], Address)>,
    pub(super) pending_reverifications: HashMap<CorrelationId, PendingReVerification>,
    pub(super) vote_timeout: Duration,
    pub(super) vote_validity_secs: u64,
    pub(super) accusation_deadline_skew_secs: u64,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) params_preset: e3_fhe_params::BfvPreset,
    /// Off while startup replays the event log: a replayed local failure must not sign a new
    /// accusation with a vote window from the current clock.
    pub(super) effects_enabled: bool,
    pub(super) deferred_accusations: Vec<DeferredAccusation>,
    /// Restored accusations whose vote timers start at `EffectsEnabled`.
    pub(super) restored_timeouts: Vec<[u8; 32]>,
    /// The last saved vote state, so an event that changes nothing writes nothing.
    pub(super) saved: Option<AccusationVotesSnapshot>,
}
