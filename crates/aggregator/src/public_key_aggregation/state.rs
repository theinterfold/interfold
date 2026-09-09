// SPDX-License-Identifier: LGPL-3.0-only

//! Persisted public-key aggregation state schema.

use super::*;
use e3_events::{EventContext, PublicKeyAggregated, Sequenced};

pub const PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION: u32 = 1;

/// Restart-only data that is not part of the public-key protocol state machine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyAggregatorRecoveryState {
    pub schema_version: u32,
    pub pending_publication: Option<PublicKeyAggregated>,
    pub last_ec: Option<EventContext<Sequenced>>,
}

impl Default for PublicKeyAggregatorRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
            pending_publication: None,
            last_ec: None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PublicKeyAggregatorState {
    Collecting {
        /// Live committee size after expulsions; used only to decide when enough keyshares arrived.
        threshold_n: usize,
        threshold_m: usize,
        /// Canonical on-chain / circuit committee size N (unchanged after expulsion).
        circuit_committee_n: usize,
        /// Canonical honest-party count H for circuit public IO.
        circuit_committee_h: usize,
        keyshares: OrderedSet<ArcBytes>,
        /// C1 proofs collected from KeyshareCreated events, indexed by insertion order
        /// (matches `submission_order`).
        c1_proofs: Vec<Option<SignedProofPayload>>,
        seed: Seed,
        nodes: OrderedSet<String>,
        /// Insertion-ordered (real sortition `party_id`, node, keyshare) triples.
        /// Index matches `c1_proofs`. The real `party_id` comes from `KeyshareCreated`
        /// and must be used for all downstream circuit slot indexing — arrival order
        /// is non-deterministic and does not match sortition's committee position.
        submission_order: Vec<(u64, String, ArcBytes)>,
        /// Full finalized committee keyed by stable sortition party ID.
        /// This roster is required to resume aggregation after a restart.
        canonical_party_nodes: HashMap<u64, String>,
    },
    VerifyingC1 {
        /// Insertion-ordered (party_id, node, keyshare) triples from Collecting.
        submission_order: Vec<(u64, String, ArcBytes)>,
        threshold_m: usize,
        /// Canonical on-chain / circuit committee size N (for `committee_h` lookup).
        circuit_committee_n: usize,
        /// Canonical honest-party count H for circuit public IO.
        circuit_committee_h: usize,
        /// C1 proofs in the same insertion order as `submission_order`.
        c1_proofs: Vec<Option<SignedProofPayload>>,
        /// Real party_ids that submitted no C1 proof — treated as dishonest.
        no_proof_parties: Vec<u64>,
        /// Full finalized committee keyed by stable sortition party ID.
        /// This roster is required to resume aggregation after a restart.
        canonical_party_nodes: HashMap<u64, String>,
    },
    GeneratingC5Proof {
        public_key: ArcBytes,
        keyshare_bytes: Vec<ArcBytes>,
        nodes: OrderedSet<String>,
        /// Registered node address per sortition `party_id` for the full finalized committee.
        /// This contains all N parties even when one was excluded before submitting a keyshare.
        /// Honest-only lookups must intersect with `honest_party_ids`.
        party_nodes: HashMap<u64, String>,
        /// DKG recursive proofs per party (restart-critical).
        dkg_node_proofs: HashMap<u64, Option<Proof>>,
        /// Per-party fold attestations collected with honest DKG folds.
        dkg_fold_attestations: HashMap<u64, SignedDkgFoldAttestation>,
        honest_party_ids: BTreeSet<u64>,
        dishonest_parties: BTreeSet<u64>,
        /// Circuit committee size N (NodeFold / DKG public IO layout).
        circuit_committee_n: usize,
        /// Circuit honest-party count H (NodeFold / DKG public IO layout).
        circuit_committee_h: usize,
        /// In-flight [`ZkRequest::DkgAggregation`], if any.
        dkg_aggregation_correlation: Option<e3_events::CorrelationId>,
        /// Result from [`ZkResponse::DkgAggregation`] (replaces pairwise `FoldProofs`).
        dkg_aggregated_proof: Option<Proof>,
        c5_proof_pending: Option<Proof>,
        last_ec: Option<e3_events::EventContext<e3_events::Sequenced>>,
        /// Accumulated nodes_fold proof after `nodes_fold_completed_slots` streaming steps.
        nodes_fold_accumulator: Option<Proof>,
        /// Number of slots folded so far; equals the next slot index to dispatch.
        nodes_fold_completed_slots: u32,
        /// Correlation ID of the in-flight [`ZkRequest::NodesFoldStep`], if any.
        nodes_fold_step_correlation: Option<e3_events::CorrelationId>,
        /// Absolute unix second at which the node-proof collection budget expires.
        ///
        /// The in-process timer is a [`SpawnHandle`], which does not survive a restart, and the
        /// events that arm it are not replayed. Persisting the deadline lets a hydrated
        /// aggregator re-arm for the time that is actually left, so a member that goes quiet
        /// cannot convert a restart into an unbounded stall.
        ///
        /// `serde(default)` covers a value built in memory, NOT an old on-disk record: this
        /// state is bincode-encoded as a fixed sequence, so a checkpoint written before this
        /// field existed fails to decode rather than defaulting. `SCHEMA_VERSION` 3 turns that
        /// into an explicit halt-and-migrate message.
        #[serde(default)]
        node_proof_deadline_at: Option<u64>,
    },
    Complete {
        public_key: ArcBytes,
        keyshares: OrderedSet<ArcBytes>,
        nodes: OrderedSet<String>,
        /// Ascending `party_id` order (matches on-chain `topNodes` after finalize sort).
        committee_addresses: Vec<Address>,
        /// Honest subset (H entries) for decryption-share gating after restart.
        honest_committee_addresses: Vec<Address>,
    },
}

impl PublicKeyAggregatorState {
    /// Ordered `topNodes` when the committee set is known (post–committee formation).
    pub fn committee_nodes(&self) -> Option<&OrderedSet<String>> {
        match self {
            PublicKeyAggregatorState::Collecting { nodes, .. } if !nodes.is_empty() => Some(nodes),
            PublicKeyAggregatorState::GeneratingC5Proof { nodes, .. } => Some(nodes),
            PublicKeyAggregatorState::Complete { nodes, .. } => Some(nodes),
            _ => None,
        }
    }

    pub fn committee_addresses(&self) -> Option<&[Address]> {
        match self {
            PublicKeyAggregatorState::Complete {
                committee_addresses,
                ..
            } if !committee_addresses.is_empty() => Some(committee_addresses.as_slice()),
            _ => None,
        }
    }

    pub fn honest_committee_addresses(&self) -> Option<&[Address]> {
        match self {
            PublicKeyAggregatorState::Complete {
                honest_committee_addresses,
                ..
            } if !honest_committee_addresses.is_empty() => {
                Some(honest_committee_addresses.as_slice())
            }
            _ => None,
        }
    }

    pub fn init(
        threshold_n: usize,
        threshold_m: usize,
        seed: Seed,
        canonical_party_nodes: HashMap<u64, String>,
    ) -> Self {
        let circuit_committee_h = committee_h_for(threshold_m, threshold_n)
            .unwrap_or_else(|e| panic!("invalid committee at init: {e}"));
        PublicKeyAggregatorState::Collecting {
            threshold_n,
            threshold_m,
            circuit_committee_n: threshold_n,
            circuit_committee_h,
            keyshares: OrderedSet::new(),
            c1_proofs: Vec::new(),
            seed,
            nodes: OrderedSet::new(),
            submission_order: Vec::new(),
            canonical_party_nodes,
        }
    }
}
