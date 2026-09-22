// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use actix::{Actor, Addr, Context, Handler};
use alloy::primitives::{keccak256, Bytes};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use e3_events::{
    AggregationProofPending, AggregationProofSigned, BusHandle, ComputeRequest,
    ComputeRequestError, ComputeResponse, ComputeResponseKind, CorrelationId, DKGInnerProofReady,
    DecryptionKeyShared, DecryptionShareProofSigned, DecryptionShareProofsPending,
    DecryptionshareCreated, DkgProofSigned, E3id, EncryptionKeyCreated, EncryptionKeyPending,
    EventContext, EventPublisher, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
    PkAggregationProofPending, PkAggregationProofSigned, PkBfvProofRequest,
    PkGenerationProofSigned, Proof, ProofPayload, ProofType, ProofVerificationPassed, Sequenced,
    ShareDecryptionProofPending, SignedProofPayload, ThresholdShareCreated, ThresholdSharePending,
    TypedEvent, ZkRequest, ZkResponse,
};
use e3_utils::NotifySync;
use tracing::{debug, error, info, trace, warn};

use crate::workflow::proof_request::{
    plan_decryption_dispatch, plan_threshold_dispatch, DecryptionProofKind, NodeAggregationMeta,
    PendingAggregationProof, PendingDecryptionProofs, PendingPkAggregationProof,
    PendingProofRequest, PendingShareDecryptionProof, PendingThresholdProofs, ThresholdProofKind,
};

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
    /// Durable C0-C4 proofs recovered by the node-fold collector. A restarted
    /// proof-request actor reuses the C1-C3 subset instead of proving it again.
    recovered_inner_proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
    /// Prevent a duplicate `ThresholdSharePending` delivery from republishing
    /// the same signed share bundle in one process lifetime.
    completed_threshold: HashSet<E3id>,
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
            share_decryption_correlation: HashMap::new(),
            pending_share_decryption: HashMap::new(),
            pk_aggregation_correlation: HashMap::new(),
            pending_pk_aggregation: HashMap::new(),
            aggregation_correlation: HashMap::new(),
            pending_aggregation: HashMap::new(),
            recovered_inner_proofs: HashMap::new(),
            completed_threshold: HashSet::new(),
        }
    }

    pub(crate) fn with_recovered_inner_proofs(
        mut self,
        recovered_inner_proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
    ) -> Self {
        self.recovered_inner_proofs = recovered_inner_proofs;
        self
    }

    pub fn setup(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        proof_aggregation_enabled: bool,
    ) -> Addr<Self> {
        Self::setup_with_recovery(bus, signer, proof_aggregation_enabled, HashMap::new())
    }

    pub(crate) fn setup_with_recovery(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        proof_aggregation_enabled: bool,
        recovered_inner_proofs: HashMap<E3id, BTreeMap<usize, Proof>>,
    ) -> Addr<Self> {
        let addr = Self::new(bus, signer, proof_aggregation_enabled)
            .with_recovered_inner_proofs(recovered_inner_proofs)
            .start();
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
