// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use actix::{Actor, Addr, Context, Handler};
use alloy::primitives::{keccak256, Bytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use e3_data::{DataStore, RepositoriesFactory, Repository};
use e3_events::{
    AggregationProofPending, AggregationProofSigned, BusHandle, ComputeRequest,
    ComputeRequestError, ComputeRequestErrorKind, ComputeResponse, ComputeResponseKind,
    CorrelationId, DKGInnerProofReady, DecryptionKeyShared, DecryptionShareProofSigned,
    DecryptionShareProofsPending, DecryptionshareCreated, DkgProofSigned, E3Failed, E3Stage, E3id,
    EncryptionKeyCreated, EncryptionKeyPending, EventContext, EventPublisher, EventSubscriber,
    EventType, FailureReason, InterfoldEvent, InterfoldEventData, PkAggregationProofPending,
    PkAggregationProofSigned, PkBfvProofRequest, PkGenerationProofSigned, Proof, ProofPayload,
    ProofType, ProofVerificationPassed, Sequenced, ShareDecryptionProofPending, SignedProofPayload,
    StoreKeys, ThresholdShareCreated, ThresholdSharePending, TypedEvent, ZkRequest, ZkResponse,
};
use e3_utils::NotifySync;
use e3_zk_helpers::computation::DkgInputType;
use serde::{Deserialize, Serialize};
use tracing::{error, info, trace, warn};

use crate::workflow::proof_request::{
    plan_decryption_dispatch, plan_threshold_dispatch, DecryptionProofKind, NodeAggregationMeta,
    PendingAggregationProof, PendingDecryptionProofs, PendingPkAggregationProof,
    PendingProofRequest, PendingShareDecryptionProof, PendingThresholdProofs, ThresholdProofKind,
};

/// The node's own signed C0 proof, persisted the moment it is produced.
///
/// C0 is generated exactly once per E3, before the threshold share exists. Every other DKG
/// inner proof (C1–C4) is regenerated after a restart because its `*Pending` trigger is
/// replayed and re-proved; C0's trigger (`EncryptionKeyPending`) sits before the aggregate
/// snapshot cursor and is never replayed. Without this record the restarted node's
/// `NodeProofAggregator` reaches 13/14 and its DKG fold never completes (Round 14, cn3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnC0Record {
    pub party_id: u64,
    pub proof: Proof,
}

/// Per-E3 durable record of the own C0 proof.
pub trait OwnC0RepositoryFactory {
    fn own_c0(&self, e3_id: &E3id) -> Repository<OwnC0Record>;
}

impl OwnC0RepositoryFactory for e3_data::Repositories {
    fn own_c0(&self, e3_id: &E3id) -> Repository<OwnC0Record> {
        Repository::new(self.store.scope(StoreKeys::own_c0_proof(e3_id)))
    }
}

/// Core actor that handles encryption key proof requests.
///
/// Proofs are always wrapped in a [`SignedProofPayload`] before being published,
/// enabling fault attribution via the signed proof model.
/// A signer is required — if signing fails, the proof is not published.
pub struct ProofRequestActor {
    bus: BusHandle,
    signer: PrivateKeySigner,
    proof_aggregation_enabled: bool,
    pending: HashMap<CorrelationId, PendingProofRequest>,
    threshold_correlation: HashMap<CorrelationId, (E3id, ThresholdProofKind, usize)>,
    pending_threshold: HashMap<E3id, PendingThresholdProofs>,
    /// C4 proof staging: correlation -> (e3_id, kind, seq)
    decryption_correlation: HashMap<CorrelationId, (E3id, DecryptionProofKind, usize)>,
    /// Per-E3 metadata for DKGInnerProofReady emission.
    node_agg_meta: HashMap<E3id, NodeAggregationMeta>,
    /// C4 dispatch that arrived before `ThresholdSharePending` set the seq layout.
    ///
    /// `c4_base_seq` is derived from `node_agg_meta.total_expected`. On a restart inside the
    /// DKG window the keyshare recovery re-publishes `ThresholdSharePending` and
    /// `DecryptionShareProofsPending` back to back, and the C4 event can be handled first.
    /// Dispatching then would tag C4a/C4b as seq 0/1 — colliding with C0/C1 in the node
    /// fold buffer, leaving the real C4 slots empty forever (Round 11, cn3 stuck at 12/14).
    /// Hold it here and replay once the layout is known.
    held_decryption_pending: HashMap<E3id, TypedEvent<DecryptionShareProofsPending>>,
    /// C4 pending proofs per E3
    pending_decryption: HashMap<E3id, PendingDecryptionProofs>,
    /// C6 proof staging: correlation -> e3_id
    share_decryption_correlation: HashMap<CorrelationId, E3id>,
    /// C6 pending proofs per E3
    pending_share_decryption: HashMap<E3id, PendingShareDecryptionProof>,
    /// C5 proof staging: correlation -> e3_id
    pk_aggregation_correlation: HashMap<CorrelationId, E3id>,
    /// C5 pending proofs per E3
    pending_pk_aggregation: HashMap<E3id, PendingPkAggregationProof>,
    /// C7 proof staging: correlation -> e3_id
    aggregation_correlation: HashMap<CorrelationId, E3id>,
    /// C7 pending proofs per E3
    pending_aggregation: HashMap<E3id, PendingAggregationProof>,
    /// Backing store for [`OwnC0Record`]. `None` only in tests that never restart.
    store: Option<DataStore>,
}

impl ProofRequestActor {
    pub fn new(bus: &BusHandle, signer: PrivateKeySigner, proof_aggregation_enabled: bool) -> Self {
        Self {
            bus: bus.clone(),
            signer,
            proof_aggregation_enabled,
            pending: HashMap::new(),
            pending_threshold: HashMap::new(),
            threshold_correlation: HashMap::new(),
            decryption_correlation: HashMap::new(),
            pending_decryption: HashMap::new(),
            node_agg_meta: HashMap::new(),
            held_decryption_pending: HashMap::new(),
            share_decryption_correlation: HashMap::new(),
            pending_share_decryption: HashMap::new(),
            pk_aggregation_correlation: HashMap::new(),
            pending_pk_aggregation: HashMap::new(),
            aggregation_correlation: HashMap::new(),
            pending_aggregation: HashMap::new(),
            store: None,
        }
    }

    /// Attach the store that keeps each E3's own C0 proof across restarts.
    pub fn with_store(mut self, store: DataStore) -> Self {
        self.store = Some(store);
        self
    }

    pub(in crate::actors::proof_request) fn own_c0_repo(
        &self,
        e3_id: &E3id,
    ) -> Option<Repository<OwnC0Record>> {
        self.store
            .as_ref()
            .map(|store| store.repositories().own_c0(e3_id))
    }

    pub fn setup(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        proof_aggregation_enabled: bool,
        store: Option<DataStore>,
    ) -> Addr<Self> {
        let mut actor = Self::new(bus, signer, proof_aggregation_enabled);
        if let Some(store) = store {
            actor = actor.with_store(store);
        }
        let addr = actor.start();
        bus.subscribe(EventType::EncryptionKeyPending, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        bus.subscribe(EventType::ThresholdSharePending, addr.clone().into());
        bus.subscribe(EventType::DecryptionShareProofsPending, addr.clone().into());
        bus.subscribe(EventType::ShareDecryptionProofPending, addr.clone().into());
        bus.subscribe(EventType::PkAggregationProofPending, addr.clone().into());
        bus.subscribe(EventType::AggregationProofPending, addr.clone().into());
        addr
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "actor_tests.rs"]
mod tests;
