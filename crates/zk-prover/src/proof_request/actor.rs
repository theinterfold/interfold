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
use e3_events::{
    AggregationProofPending, AggregationProofSigned, BusHandle, ComputeRequest,
    ComputeRequestError, ComputeRequestErrorKind, ComputeResponse, ComputeResponseKind,
    CorrelationId, DKGInnerProofReady, DecryptionKeyShared, DecryptionShareProofSigned,
    DecryptionShareProofsPending, DecryptionshareCreated, DkgProofSigned, E3Failed, E3Stage, E3id,
    EncryptionKeyCreated, EncryptionKeyPending, EventContext, EventPublisher, EventSubscriber,
    EventType, FailureReason, InterfoldEvent, InterfoldEventData, KeyshareCreated,
    PkAggregationProofPending, PkAggregationProofSigned, PkBfvProofRequest,
    PkGenerationCkksProofPending, PkGenerationProofSigned, Proof, ProofPayload, ProofType,
    ProofVerificationPassed, RelinCeremonyProofSigned, RelinRound1ProofPending, Sequenced,
    ShareDecryptionProofPending, SignedProofPayload, ThresholdShareCreated, ThresholdSharePending,
    TypedEvent, ZkRequest, ZkResponse,
};
use e3_utils::NotifySync;
use tracing::{error, info, trace, warn};

use crate::workflow::proof_request::{
    plan_decryption_dispatch, plan_threshold_dispatch, DecryptionProofKind, NodeAggregationMeta,
    PendingAggregationProof, PendingDecryptionProofs, PendingPkAggregationProof,
    PendingPkGenerationCkksProof, PendingProofRequest, PendingRelinRound1Proof,
    PendingShareDecryptionProof, PendingThresholdProofs, ThresholdProofKind,
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
    /// C1-CKKS proof staging: correlation -> e3_id
    pk_generation_ckks_correlation: HashMap<CorrelationId, E3id>,
    /// C1-CKKS pending proofs per E3
    pending_pk_generation_ckks: HashMap<E3id, PendingPkGenerationCkksProof>,
    /// C8-CKKS proof staging: correlation -> e3_id
    relin_round1_correlation: HashMap<CorrelationId, E3id>,
    /// C8-CKKS pending proofs per E3
    pending_relin_round1: HashMap<E3id, PendingRelinRound1Proof>,
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
            pk_generation_ckks_correlation: HashMap::new(),
            pending_pk_generation_ckks: HashMap::new(),
            relin_round1_correlation: HashMap::new(),
            pending_relin_round1: HashMap::new(),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        signer: PrivateKeySigner,
        proof_aggregation_enabled: bool,
    ) -> Addr<Self> {
        let addr = Self::new(bus, signer, proof_aggregation_enabled).start();
        bus.subscribe(EventType::EncryptionKeyPending, addr.clone().into());
        bus.subscribe(EventType::ComputeResponse, addr.clone().into());
        bus.subscribe(EventType::ComputeRequestError, addr.clone().into());
        bus.subscribe(EventType::ThresholdSharePending, addr.clone().into());
        bus.subscribe(EventType::DecryptionShareProofsPending, addr.clone().into());
        bus.subscribe(EventType::ShareDecryptionProofPending, addr.clone().into());
        bus.subscribe(EventType::PkAggregationProofPending, addr.clone().into());
        bus.subscribe(EventType::AggregationProofPending, addr.clone().into());
        bus.subscribe(EventType::PkGenerationCkksProofPending, addr.clone().into());
        bus.subscribe(EventType::RelinRound1ProofPending, addr.clone().into());
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
