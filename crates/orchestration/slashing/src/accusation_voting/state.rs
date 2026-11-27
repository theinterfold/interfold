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
        accusation: LbfvProofFailureAccusation,
        ec: EventContext<Sequenced>,
        dedup_key: (Address, ProofIdentity),
    },
    PublishVote {
        vote: AccusationVote,
        ec: EventContext<Sequenced>,
    },
    PublishQuorum {
        quorum: LbfvAccusationQuorumReached,
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
    pub(super) proof_instance: u32,
    pub(super) data_hash: [u8; 32],
    pub(super) forwarded_payload: Option<SignedProofPayload>,
    pub(super) ec: EventContext<Sequenced>,
}

/// An active accusation awaiting agreement votes from committee members.
pub(crate) struct PendingAccusation {
    pub(crate) accusation: LbfvProofFailureAccusation,
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
///
/// The defaults are the trBFV layout, which is persisted and must not change. An l-BFV E3 saves
/// [`LbfvAccusationVotesSnapshot`], which names each proof by its [`ProofIdentity`]. The workflow
/// runs on the l-BFV form; [`PathRepository`](crate::repo::PathRepository) converts at the store.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct AccusationVotesSnapshot<A = ProofFailureAccusation, K = ProofType> {
    pub(super) version: u32,
    pub(super) pending: Vec<SavedAccusation<A>>,
    pub(super) accused_proofs: Vec<(Address, K)>,
}

/// The vote state of an l-BFV E3, and the form the workflow saves and restores.
pub(crate) type LbfvAccusationVotesSnapshot =
    AccusationVotesSnapshot<LbfvProofFailureAccusation, ProofIdentity>;

impl<A, K> Default for AccusationVotesSnapshot<A, K> {
    fn default() -> Self {
        Self {
            version: ACCUSATION_VOTES_SNAPSHOT_VERSION,
            pending: Vec::new(),
            accused_proofs: Vec::new(),
        }
    }
}

impl<A, K> AccusationVotesSnapshot<A, K> {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCUSATION_VOTES_SNAPSHOT_VERSION,
            "unsupported accusation-votes snapshot version {}",
            self.version
        );
        Ok(())
    }
}

impl From<AccusationVotesSnapshot> for LbfvAccusationVotesSnapshot {
    fn from(snapshot: AccusationVotesSnapshot) -> Self {
        Self {
            version: snapshot.version,
            pending: snapshot.pending.into_iter().map(Into::into).collect(),
            accused_proofs: snapshot
                .accused_proofs
                .into_iter()
                .map(|(address, proof_type)| {
                    (
                        address,
                        ProofIdentity {
                            proof_type,
                            instance: 0,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl TryFrom<LbfvAccusationVotesSnapshot> for AccusationVotesSnapshot {
    type Error = RowInstanceNotRepresentable;

    fn try_from(snapshot: LbfvAccusationVotesSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            version: snapshot.version,
            pending: snapshot
                .pending
                .into_iter()
                .map(SavedAccusation::try_from)
                .collect::<Result<_, _>>()?,
            accused_proofs: snapshot
                .accused_proofs
                .into_iter()
                .map(|(address, identity)| {
                    if identity.instance != 0 {
                        return Err(RowInstanceNotRepresentable(identity.instance));
                    }
                    Ok((address, identity.proof_type))
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedAccusation<A = ProofFailureAccusation> {
    pub(super) accusation: A,
    pub(super) votes_for: Vec<AccusationVote>,
    pub(super) ec: EventContext<Sequenced>,
    pub(super) timeout_at: u64,
    /// This node's failed check of the accused proof: a quorum carries its evidence on chain.
    pub(super) failed_proof: Option<SavedFailedProof>,
}

impl From<SavedAccusation> for SavedAccusation<LbfvProofFailureAccusation> {
    fn from(saved: SavedAccusation) -> Self {
        Self {
            accusation: saved.accusation.into(),
            votes_for: saved.votes_for,
            ec: saved.ec,
            timeout_at: saved.timeout_at,
            failed_proof: saved.failed_proof,
        }
    }
}

impl TryFrom<SavedAccusation<LbfvProofFailureAccusation>> for SavedAccusation {
    type Error = RowInstanceNotRepresentable;

    fn try_from(saved: SavedAccusation<LbfvProofFailureAccusation>) -> Result<Self, Self::Error> {
        Ok(Self {
            accusation: saved.accusation.try_into()?,
            votes_for: saved.votes_for,
            ec: saved.ec,
            timeout_at: saved.timeout_at,
            failed_proof: saved.failed_proof,
        })
    }
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
    /// Finalized party IDs stay fixed when slashing removes active members.
    pub(super) committee_party_ids: HashMap<Address, u64>,
    /// Immutable party slots, also after the live voting roster shrinks.
    pub(super) finalized_committee: Vec<Address>,
    pub(super) circuit_threshold_t: usize,
    pub(super) vote_quorum_h: usize,
    pub(super) committee_n: usize,
    pub(super) pending: HashMap<[u8; 32], PendingAccusation>,
    pub(super) accused_proofs: HashSet<(Address, ProofIdentity)>,
    pub(super) received_data: HashMap<(Address, ProofIdentity), ReceivedProofData>,
    pub(super) buffered_votes: HashMap<[u8; 32], Vec<AccusationVote>>,
    /// Accusers whose later vote window this node adopted; each moves a window at most once.
    pub(super) window_movers: HashSet<([u8; 32], Address)>,
    pub(super) pending_reverifications: HashMap<CorrelationId, PendingReVerification>,
    pub(super) vote_timeout: Duration,
    pub(super) vote_validity_secs: u64,
    pub(super) accusation_deadline_skew_secs: u64,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) params_profile: e3_fhe_params::BfvProfile,
    /// Off while startup replays the event log: a replayed local failure must not sign a new
    /// accusation with a vote window from the current clock.
    pub(super) effects_enabled: bool,
    pub(super) deferred_accusations: Vec<DeferredAccusation>,
    /// Restored accusations whose vote timers start at `EffectsEnabled`.
    pub(super) restored_timeouts: Vec<[u8; 32]>,
    /// The last saved vote state, so an event that changes nothing writes nothing.
    pub(super) saved: Option<LbfvAccusationVotesSnapshot>,
}
