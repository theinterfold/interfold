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
    EventType, FailureReason, InterfoldEvent, InterfoldEventData, PkAggregationProofPending,
    PkAggregationProofSigned, PkBfvProofRequest, PkGenerationProofSigned, Proof, ProofPayload,
    ProofType, ProofVerificationPassed, Sequenced, ShareDecryptionProofPending, SignedProofPayload,
    ThresholdShareCreated, ThresholdSharePending, TypedEvent, ZkRequest, ZkResponse,
};
use e3_utils::NotifySync;
use tracing::{error, info, trace, warn};

use crate::domain::proof_request::{
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
}

impl ProofRequestActor {
    pub fn new(bus: &BusHandle, signer: PrivateKeySigner) -> Self {
        Self {
            bus: bus.clone(),
            signer,
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
        }
    }

    pub fn setup(bus: &BusHandle, signer: PrivateKeySigner) -> Addr<Self> {
        let addr = Self::new(bus, signer).start();
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

    fn handle_encryption_key_pending(&mut self, msg: TypedEvent<EncryptionKeyPending>) {
        let (msg, ec) = msg.into_components();
        let correlation_id = CorrelationId::new();
        self.pending.insert(
            correlation_id,
            PendingProofRequest {
                e3_id: msg.e3_id.clone(),
                key: msg.key.clone(),
            },
        );

        let request = ComputeRequest::zk(
            ZkRequest::PkBfv(PkBfvProofRequest::new(
                msg.key.pk_bfv.clone(),
                msg.params_preset,
                msg.committee_size,
            )),
            correlation_id,
            msg.e3_id,
        );

        info!("Requesting C0 proof generation");
        if let Err(err) = self.bus.publish(request, ec) {
            error!("Failed to publish ZK proof request: {err}");
            self.pending.remove(&correlation_id);
        }
    }

    fn handle_threshold_share_pending(&mut self, msg: TypedEvent<ThresholdSharePending>) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        let sk_enc_count = msg.sk_share_encryption_requests.len();
        let e_sm_enc_count = msg.e_sm_share_encryption_requests.len();

        let total_expected = NodeAggregationMeta::total_expected_for(sk_enc_count, e_sm_enc_count);
        let pending_c0 = self
            .node_agg_meta
            .get(&e3_id)
            .and_then(|m| m.pending_c0.clone());
        self.node_agg_meta.insert(
            e3_id.clone(),
            NodeAggregationMeta {
                party_id: msg.full_share.party_id,
                total_expected,
                pending_c0: None,
                proof_aggregation_enabled: msg.proof_aggregation_enabled,
            },
        );
        // If C0 proof arrived before meta, emit DKGInnerProofReady now
        if let Some(c0_proof) = pending_c0 {
            if msg.proof_aggregation_enabled {
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id: msg.full_share.party_id,
                        proof: c0_proof,
                        seq: 0,
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish DKGInnerProofReady for C0: {err}");
                }
            }
        }

        self.pending_threshold.insert(
            e3_id.clone(),
            PendingThresholdProofs::new(
                e3_id.clone(),
                msg.full_share.clone(),
                ec.clone(),
                sk_enc_count,
                e_sm_enc_count,
                msg.recipient_party_ids,
            ),
        );

        // C1/C2/C3: dispatch threshold proof requests in canonical seq order.
        // Sequencing/kind assignment lives in the pure domain planner; the actor
        // only allocates correlation ids, publishes, and rolls back on failure.
        for item in plan_threshold_dispatch(
            msg.proof_request,
            msg.sk_share_computation_request,
            msg.e_sm_share_computation_request,
            msg.sk_share_encryption_requests,
            msg.e_sm_share_encryption_requests,
        ) {
            let corr = CorrelationId::new();
            self.threshold_correlation
                .insert(corr, (e3_id.clone(), item.kind, item.seq));
            if let Err(err) = self.bus.publish(
                ComputeRequest::zk(item.request, corr, e3_id.clone()),
                ec.clone(),
            ) {
                error!("Failed to publish threshold proof request: {err}");
                self.threshold_correlation
                    .retain(|_, (eid, _, _)| *eid != e3_id);
                self.pending_threshold.remove(&e3_id);
                return;
            }
        }
    }

    fn handle_compute_response(&mut self, msg: TypedEvent<ComputeResponse>) {
        let (msg, ec) = msg.into_components();
        match &msg.response {
            ComputeResponseKind::Zk(ZkResponse::PkBfv(resp)) => {
                self.handle_pk_bfv_response(&msg.correlation_id, resp.proof.clone(), &ec);
            }
            ComputeResponseKind::Zk(ZkResponse::PkGeneration(resp)) => {
                self.handle_threshold_proof_response(&msg.correlation_id, resp.proof.clone(), &ec);
            }
            ComputeResponseKind::Zk(ZkResponse::ShareComputation(resp)) => {
                self.handle_threshold_proof_response(&msg.correlation_id, resp.proof.clone(), &ec);
            }
            ComputeResponseKind::Zk(ZkResponse::ShareEncryption(resp)) => {
                self.handle_threshold_proof_response(&msg.correlation_id, resp.proof.clone(), &ec);
            }
            ComputeResponseKind::Zk(ZkResponse::DkgShareDecryption(resp)) => {
                // Try C4 decryption proof first, then fall back to C1/C2/C3 threshold
                if self
                    .decryption_correlation
                    .contains_key(&msg.correlation_id)
                {
                    self.handle_decryption_proof_response(
                        &msg.correlation_id,
                        resp.proof.clone(),
                        &ec,
                    );
                } else {
                    self.handle_threshold_proof_response(
                        &msg.correlation_id,
                        resp.proof.clone(),
                        &ec,
                    );
                }
            }
            ComputeResponseKind::Zk(ZkResponse::ThresholdShareDecryption(resp)) => {
                self.handle_share_decryption_proof_response(
                    &msg.correlation_id,
                    resp.proofs.clone(),
                );
            }
            ComputeResponseKind::Zk(ZkResponse::PkAggregation(resp)) => {
                self.handle_pk_aggregation_proof_response(&msg.correlation_id, resp.proof.clone());
            }
            ComputeResponseKind::Zk(ZkResponse::DecryptedSharesAggregation(resp)) => {
                self.handle_aggregation_proof_response(&msg.correlation_id, resp.proofs.clone());
            }
            _ => {}
        }
    }

    /// Handle DecryptionShareProofsPending: dispatch C4 proof generation.
    fn handle_decryption_share_proofs_pending(
        &mut self,
        msg: TypedEvent<DecryptionShareProofsPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        let esm_count = msg.esm_requests.len();

        if self.pending_decryption.contains_key(&e3_id) {
            warn!(
                "Duplicate DecryptionShareProofsPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_decryption.insert(
            e3_id.clone(),
            PendingDecryptionProofs {
                party_id: msg.party_id,
                node: msg.node,
                ec: ec.clone(),
                sk_proof: None,
                esm_proofs: HashMap::new(),
                expected_esm_count: esm_count,
            },
        );

        // C4a/C4b: dispatch share-decryption proof requests in canonical seq
        // order. The pure domain planner owns seq assignment; the actor only
        // allocates correlation ids, publishes, and rolls back on failure.
        let c4_base_seq = self
            .node_agg_meta
            .get(&e3_id)
            .map(NodeAggregationMeta::c4_base_seq)
            .unwrap_or(0);
        for item in plan_decryption_dispatch(msg.sk_request, msg.esm_requests, c4_base_seq) {
            let corr = CorrelationId::new();
            self.decryption_correlation
                .insert(corr, (e3_id.clone(), item.kind, item.seq));
            if let Err(err) = self.bus.publish(
                ComputeRequest::zk(item.request, corr, e3_id.clone()),
                ec.clone(),
            ) {
                error!("Failed to publish C4 proof request: {err}");
                self.decryption_correlation
                    .retain(|_, (eid, _, _)| *eid != e3_id);
                self.pending_decryption.remove(&e3_id);
                return;
            }
        }
    }

    /// Handle a C4 proof response — store and check completeness.
    fn handle_decryption_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some((e3_id, kind, seq)) = self.decryption_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_decryption.get_mut(&e3_id) else {
            error!(
                "No pending decryption proofs for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let proof_for_agg = proof.clone();
        match kind {
            DecryptionProofKind::SecretKey => {
                info!("Received C4a SK decryption proof for E3 {}", e3_id);
                pending.sk_proof = Some(proof);
            }
            DecryptionProofKind::SmudgingNoise { esi_idx } => {
                info!(
                    "Received C4b ESM decryption proof [{}] for E3 {}",
                    esi_idx, e3_id
                );
                pending.esm_proofs.insert(esi_idx, proof);
            }
        }

        if let Some(meta) = self.node_agg_meta.get(&e3_id) {
            if meta.proof_aggregation_enabled {
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id: meta.party_id,
                        proof: proof_for_agg,
                        seq,
                    },
                    ec.clone(),
                ) {
                    error!(
                        "Failed to publish DKGInnerProofReady for C4 seq={}: {err}",
                        seq
                    );
                }
            }
        }

        if pending.is_complete() {
            info!(
                "All C4 proofs complete for E3 {} — signing and publishing DecryptionKeyShared",
                e3_id
            );
            let pending = self.pending_decryption.remove(&e3_id).unwrap();
            self.sign_and_publish_decryption_key_shared(&e3_id, pending);
        }
    }

    /// Sign all C4 proofs and publish DecryptionKeyShared (Exchange #3).
    fn sign_and_publish_decryption_key_shared(
        &mut self,
        e3_id: &E3id,
        pending: PendingDecryptionProofs,
    ) {
        // Sign C4a (SK decryption proof)
        let Some(signed_sk) = self.sign_proof(
            e3_id,
            ProofType::C4aSkShareDecryption,
            pending.sk_proof.expect("checked in is_complete"),
        ) else {
            error!("Failed to sign C4a SK proof — DecryptionKeyShared will not be published");
            self.fail_dkg_round(e3_id.clone(), &pending.ec, "C4a signing error");
            return;
        };

        // Sign C4b (ESM decryption proofs) in esi_idx order
        let mut signed_esms = Vec::with_capacity(pending.expected_esm_count);
        for idx in 0..pending.expected_esm_count {
            let proof = pending
                .esm_proofs
                .get(&idx)
                .expect("checked in is_complete")
                .clone();
            let Some(signed) = self.sign_proof(e3_id, ProofType::C4bESmShareDecryption, proof)
            else {
                error!(
                    "Failed to sign C4b ESM proof [{}] — DecryptionKeyShared will not be published",
                    idx
                );
                self.fail_dkg_round(e3_id.clone(), &pending.ec, "C4b signing error");
                return;
            };
            signed_esms.push(signed);
        }

        info!(
            "All C4 proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            pending.party_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            DecryptionKeyShared {
                e3_id: e3_id.clone(),
                party_id: pending.party_id,
                node: pending.node,
                signed_sk_decryption_proof: signed_sk,
                signed_e_sm_decryption_proofs: signed_esms,
                external: false,
            },
            pending.ec,
        ) {
            error!("Failed to publish DecryptionKeyShared: {err}");
        }
    }

    /// Handle ShareDecryptionProofPending: dispatch C6 proof generation.
    fn handle_share_decryption_proof_pending(
        &mut self,
        msg: TypedEvent<ShareDecryptionProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_share_decryption.contains_key(&e3_id) {
            warn!(
                "Duplicate ShareDecryptionProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_share_decryption.insert(
            e3_id.clone(),
            PendingShareDecryptionProof {
                party_id: msg.party_id,
                node: msg.node,
                decryption_share: msg.decryption_share,
                ec: ec.clone(),
            },
        );

        let correlation_id = CorrelationId::new();
        self.share_decryption_correlation
            .insert(correlation_id, e3_id.clone());

        info!(
            "Requesting C6 ThresholdShareDecryption proof for E3 {}",
            e3_id
        );
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::ThresholdShareDecryption(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C6 proof request: {err}");
            self.share_decryption_correlation.remove(&correlation_id);
            self.pending_share_decryption.remove(&e3_id);
        }
    }

    /// Handle C6 proof response — sign proofs, publish DecryptionshareCreated.
    fn handle_share_decryption_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proofs: Vec<Proof>,
    ) {
        let Some(e3_id) = self.share_decryption_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_share_decryption.remove(&e3_id) else {
            error!(
                "No pending share decryption proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        // Sign raw C6 proofs (for ShareVerification)
        let mut signed_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Some(signed) =
                self.sign_proof(&e3_id, ProofType::C6ThresholdShareDecryption, proof)
            else {
                error!("Failed to sign C6 proof — DecryptionshareCreated will not be published");
                self.fail_decryption_round(e3_id.clone(), &pending.ec, "C6 signing error");
                return;
            };
            signed_proofs.push(signed);
        }

        info!(
            "All C6 proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            pending.party_id,
            self.signer.address()
        );

        let ec = pending.ec;

        match self.bus.publish(
            DecryptionshareCreated {
                party_id: pending.party_id,
                node: pending.node,
                e3_id: e3_id.clone(),
                decryption_share: pending.decryption_share,
                signed_decryption_proofs: signed_proofs,
            },
            ec.clone(),
        ) {
            Ok(_) => {
                if let Err(err) = self.bus.publish(
                    DecryptionShareProofSigned {
                        e3_id: e3_id.clone(),
                    },
                    ec,
                ) {
                    error!("Failed to publish DecryptionShareProofSigned: {err}");
                }
            }
            Err(err) => {
                error!("Failed to publish DecryptionshareCreated: {err}");
            }
        }
    }

    /// Handle PkAggregationProofPending: dispatch C5 proof generation.
    fn handle_pk_aggregation_proof_pending(&mut self, msg: TypedEvent<PkAggregationProofPending>) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_pk_aggregation.contains_key(&e3_id) {
            warn!(
                "Duplicate PkAggregationProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_pk_aggregation.insert(
            e3_id.clone(),
            PendingPkAggregationProof {
                ec: ec.clone(),
                request: msg.proof_request.clone(),
            },
        );

        let correlation_id = CorrelationId::new();
        self.pk_aggregation_correlation
            .insert(correlation_id, e3_id.clone());

        info!("Requesting C5 PkAggregation proof for E3 {}", e3_id);
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::PkAggregation(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C5 proof request: {err}");
            self.pk_aggregation_correlation.remove(&correlation_id);
            self.pending_pk_aggregation.remove(&e3_id);
        }
    }

    /// Handle C5 proof response — sign proof and publish PkAggregationProofSigned.
    fn handle_pk_aggregation_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
    ) {
        let Some(e3_id) = self.pk_aggregation_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_pk_aggregation.remove(&e3_id) else {
            error!(
                "No pending pk aggregation proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let Some(signed) = self.sign_proof(&e3_id, ProofType::C5PkAggregation, proof) else {
            error!("Failed to sign C5 proof — PkAggregationProofSigned will not be published");
            self.fail_dkg_round(e3_id, &pending.ec, "C5 signing error");
            return;
        };

        info!(
            "C5 proof signed for E3 {} (signer: {})",
            e3_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            PkAggregationProofSigned {
                e3_id: e3_id.clone(),
                signed_proof: signed,
            },
            pending.ec,
        ) {
            error!("Failed to publish PkAggregationProofSigned: {err}");
        }
    }

    /// Handle AggregationProofPending: dispatch C7 proof generation.
    fn handle_aggregation_proof_pending(&mut self, msg: TypedEvent<AggregationProofPending>) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if self.pending_aggregation.contains_key(&e3_id) {
            warn!(
                "Duplicate AggregationProofPending for E3 {} — ignoring",
                e3_id
            );
            return;
        }

        self.pending_aggregation
            .insert(e3_id.clone(), PendingAggregationProof { ec: ec.clone() });

        let correlation_id = CorrelationId::new();
        self.aggregation_correlation
            .insert(correlation_id, e3_id.clone());

        info!(
            "Requesting C7 DecryptedSharesAggregation proof for E3 {}",
            e3_id
        );
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::DecryptedSharesAggregation(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C7 proof request: {err}");
            self.aggregation_correlation.remove(&correlation_id);
            self.pending_aggregation.remove(&e3_id);
        }
    }

    /// Handle C7 proof response — sign proofs and publish AggregationProofSigned.
    fn handle_aggregation_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proofs: Vec<Proof>,
    ) {
        let Some(e3_id) = self.aggregation_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_aggregation.remove(&e3_id) else {
            error!(
                "No pending aggregation proof for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        // Sign each C7 proof
        let mut signed_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Some(signed) =
                self.sign_proof(&e3_id, ProofType::C7DecryptedSharesAggregation, proof)
            else {
                error!("Failed to sign C7 proof — AggregationProofSigned will not be published");
                self.fail_decryption_round(e3_id.clone(), &pending.ec, "C7 signing error");
                return;
            };
            signed_proofs.push(signed);
        }

        info!(
            "All C7 proofs signed for E3 {} (signer: {})",
            e3_id,
            self.signer.address()
        );

        if let Err(err) = self.bus.publish(
            AggregationProofSigned {
                e3_id: e3_id.clone(),
                signed_proofs,
            },
            pending.ec,
        ) {
            error!("Failed to publish AggregationProofSigned: {err}");
        }
    }

    fn handle_threshold_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some((e3_id, kind, seq)) = self.threshold_correlation.remove(correlation_id) else {
            return;
        };

        let Some(pending) = self.pending_threshold.get_mut(&e3_id) else {
            error!(
                "No pending threshold proofs for E3 {} — orphan correlation",
                e3_id
            );
            return;
        };

        let proof_for_agg = proof.clone();
        pending.store_proof(&kind, proof);
        info!(
            "Received {:?} proof for E3 {} ({}/{})",
            kind,
            e3_id,
            pending.total_received(),
            pending.total_expected()
        );

        if let Some(meta) = self.node_agg_meta.get(&e3_id) {
            if meta.proof_aggregation_enabled {
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id: meta.party_id,
                        proof: proof_for_agg,
                        seq,
                    },
                    ec.clone(),
                ) {
                    error!(
                        "Failed to publish DKGInnerProofReady for {:?} seq={}: {err}",
                        kind, seq
                    );
                }
            }
        }

        if pending.is_complete() {
            info!(
                "All {} threshold proofs complete for E3 {}",
                pending.total_expected(),
                e3_id
            );
            let pending = self.pending_threshold.remove(&e3_id).unwrap();
            self.publish_threshold_share_with_proofs(pending);
        }
    }

    fn sign_proof(
        &self,
        e3_id: &E3id,
        proof_type: ProofType,
        proof: Proof,
    ) -> Option<SignedProofPayload> {
        let payload = ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof,
        };
        match SignedProofPayload::sign(payload, &self.signer) {
            Ok(signed) => Some(signed),
            Err(err) => {
                error!("Failed to sign {:?} proof: {err}", proof_type);
                None
            }
        }
    }

    fn fail_dkg_round(&self, e3_id: E3id, ec: &EventContext<Sequenced>, context: &str) {
        if let Err(err) = self.bus.publish(
            E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            },
            ec.clone(),
        ) {
            error!(
                "Failed to publish E3Failed for {context} on E3 {}: {err}",
                e3_id
            );
        }
    }

    fn fail_decryption_round(&self, e3_id: E3id, ec: &EventContext<Sequenced>, context: &str) {
        if let Err(err) = self.bus.publish(
            E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::CiphertextReady,
                reason: FailureReason::DecryptionInvalidShares,
            },
            ec.clone(),
        ) {
            error!(
                "Failed to publish E3Failed for {context} on E3 {}: {err}",
                e3_id
            );
        }
    }

    fn sign_and_group_proofs(
        &self,
        e3_id: &E3id,
        proof_type: ProofType,
        proofs: impl Iterator<Item = (usize, Proof)>,
    ) -> Option<BTreeMap<usize, Vec<SignedProofPayload>>> {
        let mut map: BTreeMap<usize, Vec<SignedProofPayload>> = BTreeMap::new();
        for (recipient, proof) in proofs {
            let signed = self.sign_proof(e3_id, proof_type, proof)?;
            map.entry(recipient).or_default().push(signed);
        }
        Some(map)
    }

    fn publish_threshold_share_with_proofs(&mut self, pending: PendingThresholdProofs) {
        let e3_id = &pending.e3_id;
        let party_id = pending.full_share.party_id;
        let ec = &pending.ec;

        // Sign C1 (PkGeneration)
        let Some(signed_pk_gen) = self.sign_proof(
            e3_id,
            ProofType::C1PkGeneration,
            pending.pk_generation_proof.expect("checked"),
        ) else {
            error!("Failed to sign C1 proof — shares will not be published");
            self.fail_dkg_round(e3_id.clone(), ec, "C1 signing error");
            return;
        };

        // Sign C2a (SkShareComputation)
        let Some(signed_c2a) = self.sign_proof(
            e3_id,
            ProofType::C2aSkShareComputation,
            pending.sk_share_computation_proof.expect("checked"),
        ) else {
            error!("Failed to sign C2a proof — shares will not be published");
            self.fail_dkg_round(e3_id.clone(), ec, "C2a signing error");
            return;
        };

        // Sign C2b (ESmShareComputation)
        let Some(signed_c2b) = self.sign_proof(
            e3_id,
            ProofType::C2bESmShareComputation,
            pending.e_sm_share_computation_proof.expect("checked"),
        ) else {
            error!("Failed to sign C2b proof — shares will not be published");
            self.fail_dkg_round(e3_id.clone(), ec, "C2b signing error");
            return;
        };

        let Some(signed_c3a_map) = self.sign_and_group_proofs(
            e3_id,
            ProofType::C3aSkShareEncryption,
            pending
                .sk_share_encryption_proofs
                .iter()
                .map(|((recipient, _row), proof)| (*recipient, proof.clone())),
        ) else {
            error!("Failed to sign C3a proofs — shares will not be published");
            self.fail_dkg_round(e3_id.clone(), ec, "C3a signing error");
            return;
        };

        let Some(signed_c3b_map) = self.sign_and_group_proofs(
            e3_id,
            ProofType::C3bESmShareEncryption,
            pending
                .e_sm_share_encryption_proofs
                .iter()
                .map(|((_esi, recipient, _row), proof)| (*recipient, proof.clone())),
        ) else {
            error!("Failed to sign C3b proofs — shares will not be published");
            self.fail_dkg_round(e3_id.clone(), ec, "C3b signing error");
            return;
        };

        info!(
            "All proofs signed for E3 {} party {} (signer: {})",
            e3_id,
            party_id,
            self.signer.address()
        );

        // Publish local proof events for the node's own state tracking
        if let Err(err) = self.bus.publish(
            PkGenerationProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_pk_gen,
            },
            ec.clone(),
        ) {
            error!("Failed to publish PkGenerationProofSigned: {err}");
        }

        if let Err(err) = self.bus.publish(
            DkgProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_c2a.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish SkDkgProofSigned: {err}");
        }

        if let Err(err) = self.bus.publish(
            DkgProofSigned {
                e3_id: e3_id.clone(),
                party_id,
                signed_proof: signed_c2b.clone(),
            },
            ec.clone(),
        ) {
            error!("Failed to publish ESmDkgProofSigned: {err}");
        }

        // Publish C3a signed proofs (reuse already-signed proofs from signed_c3a_map)
        for signed_proofs in signed_c3a_map.values() {
            for signed in signed_proofs {
                if let Err(err) = self.bus.publish(
                    DkgProofSigned {
                        e3_id: e3_id.clone(),
                        party_id,
                        signed_proof: signed.clone(),
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish SkShareEncryptionProofSigned: {err}");
                }
            }
        }

        // Publish C3b signed proofs (reuse already-signed proofs from signed_c3b_map)
        for signed_proofs in signed_c3b_map.values() {
            for signed in signed_proofs {
                if let Err(err) = self.bus.publish(
                    DkgProofSigned {
                        e3_id: e3_id.clone(),
                        party_id,
                        signed_proof: signed.clone(),
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish ESmShareEncryptionProofSigned: {err}");
                }
            }
        }

        // Publish ThresholdShareCreated with proofs attached for each recipient
        let share = &pending.full_share;
        let num_parties = share.num_parties();

        info!(
            "Publishing ThresholdShareCreated for E3 {} to {} parties",
            e3_id, num_parties
        );

        for (positional_idx, &real_party_id) in pending.recipient_party_ids.iter().enumerate() {
            match share.extract_for_party(positional_idx) {
                Some(party_share) => {
                    let proof_key = real_party_id as usize;
                    let c3a_proofs = signed_c3a_map.get(&proof_key).cloned().unwrap_or_default();
                    let c3b_proofs = signed_c3b_map.get(&proof_key).cloned().unwrap_or_default();

                    if let Err(err) = self.bus.publish(
                        ThresholdShareCreated {
                            e3_id: e3_id.clone(),
                            share: Arc::new(party_share),
                            target_party_id: real_party_id,
                            external: false,
                            signed_c2a_proof: Some(signed_c2a.clone()),
                            signed_c2b_proof: Some(signed_c2b.clone()),
                            signed_c3a_proofs: c3a_proofs,
                            signed_c3b_proofs: c3b_proofs,
                        },
                        ec.clone(),
                    ) {
                        error!(
                            "Failed to publish ThresholdShareCreated for party {} (idx {}): {err}",
                            real_party_id, positional_idx
                        );
                    }
                }
                None if real_party_id == party_id => {
                    // Own slot is sparse (no self-encryption); nothing to publish.
                    trace!(
                        "Skipping ThresholdShareCreated for own slot (party {} idx {})",
                        real_party_id,
                        positional_idx
                    );
                }
                None => {
                    error!(
                        "Missing encrypted share for recipient party {} (idx {}) from sender party {}; ThresholdShareCreated will not be published for that recipient",
                        real_party_id, positional_idx, party_id
                    );
                }
            }
        }
    }

    fn handle_pk_bfv_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
        ec: &EventContext<Sequenced>,
    ) {
        let Some(pending) = self.pending.remove(correlation_id) else {
            error!(
                "Received PkBfv ComputeResponse with correlation_id {:?} but no matching pending request found.",
                correlation_id
            );
            return;
        };

        let e3_id = pending.e3_id.clone();

        let mut key = (*pending.key).clone();
        key.proof = Some(proof.clone());

        // Always sign the proof payload — unsigned proofs are not published
        let payload = ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C0PkBfv,
            proof: proof.clone(),
        };

        match SignedProofPayload::sign(payload, &self.signer) {
            Ok(signed) => {
                info!(
                    "Signed C0 proof for party {} (signer: {})",
                    key.party_id,
                    self.signer.address()
                );
                key.signed_payload = Some(signed);
            }
            Err(err) => {
                error!("Failed to sign C0 proof payload: {err} — proof will not be published");
                self.fail_dkg_round(e3_id, ec, "C0 signing error");
                return;
            }
        }

        let local_party_id = key.party_id;
        if let Err(err) = self.bus.publish(
            EncryptionKeyCreated {
                e3_id: e3_id.clone(),
                key: Arc::new(key),
                external: false,
            },
            ec.clone(),
        ) {
            error!("Failed to publish EncryptionKeyCreated: {err}");
        }

        // Publish the local node's own C0 as ProofVerificationPassed so the
        // CommitmentConsistencyChecker caches it. Without this, C3 proofs from
        // other parties that encrypt under this node's pk would fail the C3→C0
        // consistency check (the local C0 target wouldn't exist in the cache).
        {
            let msg = (
                Bytes::copy_from_slice(&proof.data),
                Bytes::copy_from_slice(&proof.public_signals),
            )
                .abi_encode();
            let data_hash: [u8; 32] = keccak256(&msg).into();

            if let Err(err) = self.bus.publish(
                ProofVerificationPassed {
                    e3_id: e3_id.clone(),
                    party_id: local_party_id,
                    address: self.signer.address(),
                    proof_type: ProofType::C0PkBfv,
                    data_hash,
                    public_signals: proof.public_signals.clone(),
                    proof_data: proof.data.clone(),
                },
                ec.clone(),
            ) {
                error!("Failed to publish local C0 ProofVerificationPassed: {err}");
            }
        }

        // Emit DKGInnerProofReady for C0, or buffer if meta not yet available
        if let Some(meta) = self.node_agg_meta.get(&e3_id) {
            if meta.proof_aggregation_enabled {
                if let Err(err) = self.bus.publish(
                    DKGInnerProofReady {
                        e3_id: e3_id.clone(),
                        party_id: meta.party_id,
                        proof: proof.clone(),
                        seq: 0,
                    },
                    ec.clone(),
                ) {
                    error!("Failed to publish DKGInnerProofReady for C0: {err}");
                }
            }
        } else {
            // ThresholdSharePending hasn't arrived yet — buffer C0 proof
            self.node_agg_meta.insert(
                e3_id.clone(),
                NodeAggregationMeta {
                    party_id: 0,
                    total_expected: 0,
                    pending_c0: Some(proof),
                    proof_aggregation_enabled: true, // will be overwritten by ThresholdSharePending
                },
            );
        }
    }

    fn handle_compute_request_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, ec) = msg.into_components();
        let ComputeRequestErrorKind::Zk(err) = msg.get_err() else {
            return;
        };

        if let Some(pending) = self.pending.remove(msg.correlation_id()) {
            error!(
                "C0 proof request failed for E3 {}: {err} — key will not be published without proof",
                pending.e3_id
            );
            self.fail_dkg_round(pending.e3_id, &ec, "C0 proof request error");
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.threshold_correlation.remove(msg.correlation_id()) {
            error!(
                "DKG {:?} proof request failed for E3 {}: {err} — threshold share will not be published without proof",
                kind, e3_id
            );
            self.threshold_correlation
                .retain(|_, (eid, _, _)| *eid != e3_id);
            self.pending_threshold.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "DKG threshold proof request error");
            return;
        }

        if let Some((e3_id, kind, _seq)) = self.decryption_correlation.remove(msg.correlation_id())
        {
            error!(
                "C4 {:?} proof request failed for E3 {}: {err} — DecryptionKeyShared will not be published",
                kind, e3_id
            );
            self.decryption_correlation
                .retain(|_, (eid, _, _)| *eid != e3_id);
            self.pending_decryption.remove(&e3_id);
            self.fail_dkg_round(e3_id, &ec, "C4 proof request error");
            return;
        }

        if let Some(e3_id) = self
            .share_decryption_correlation
            .remove(msg.correlation_id())
        {
            error!(
                "C6 proof request failed for E3 {}: {err} — DecryptionshareCreated will not be published",
                e3_id
            );
            self.pending_share_decryption.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C6 proof request error");
            return;
        }

        if let Some(e3_id) = self.pk_aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C5 proof request failed for E3 {}: {err} — PkAggregationProofSigned will not be published",
                e3_id
            );
            self.pending_pk_aggregation.remove(&e3_id);

            self.fail_dkg_round(e3_id, &ec, "C5 proof request error");
            return;
        }

        if let Some(e3_id) = self.aggregation_correlation.remove(msg.correlation_id()) {
            error!(
                "C7 proof request failed for E3 {}: {err} — AggregationProofSigned will not be published",
                e3_id
            );
            self.pending_aggregation.remove(&e3_id);
            self.fail_decryption_round(e3_id, &ec, "C7 proof request error");
        }
    }
}

impl Actor for ProofRequestActor {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for ProofRequestActor {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();

        match msg {
            InterfoldEventData::EncryptionKeyPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ThresholdSharePending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DecryptionShareProofsPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareDecryptionProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PkAggregationProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AggregationProofPending(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<EncryptionKeyPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<EncryptionKeyPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_encryption_key_pending(msg)
    }
}

impl Handler<TypedEvent<ThresholdSharePending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_threshold_share_pending(msg);
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_response(msg)
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_compute_request_error(msg)
    }
}

impl Handler<TypedEvent<DecryptionShareProofsPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionShareProofsPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_decryption_share_proofs_pending(msg)
    }
}

impl Handler<TypedEvent<ShareDecryptionProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareDecryptionProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_share_decryption_proof_pending(msg)
    }
}

impl Handler<TypedEvent<PkAggregationProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PkAggregationProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_pk_aggregation_proof_pending(msg)
    }
}

impl Handler<TypedEvent<AggregationProofPending>> for ProofRequestActor {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<AggregationProofPending>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.handle_aggregation_proof_pending(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use anyhow::Result;
    use e3_events::{
        ComputeRequestErrorKind, EncryptionKey, Event, HistoryCollector, TakeEvents, Unsequenced,
        ZkError,
    };
    use e3_test_helpers::get_common_setup;
    use e3_utils::utility_types::ArcBytes;

    fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
        EventContext::<Unsequenced>::from(data.into()).sequence(0)
    }

    async fn next_event(
        history: &Addr<HistoryCollector<InterfoldEvent>>,
    ) -> Result<InterfoldEvent> {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(!result.timed_out, "timed out waiting for an event");
        Ok(result.events.pop().expect("expected one event"))
    }

    #[actix::test]
    async fn c0_compute_error_emits_e3_failed() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
        let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random());
        let e3_id = E3id::new("44", 1);
        let correlation_id = CorrelationId::new();

        actor.pending.insert(
            correlation_id,
            PendingProofRequest {
                e3_id: e3_id.clone(),
                key: Arc::new(EncryptionKey::new(7, ArcBytes::from_bytes(&[1]))),
            },
        );

        actor.handle_compute_request_error(TypedEvent::new(
            ComputeRequestError::new(
                ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("boom".to_string())),
                ComputeRequest::zk(
                    ZkRequest::PkBfv(PkBfvProofRequest::new(
                        ArcBytes::from_bytes(&[1]),
                        e3_fhe_params::BfvPreset::InsecureThreshold512,
                        e3_zk_helpers::CiphernodesCommitteeSize::Minimum,
                    )),
                    correlation_id,
                    e3_id.clone(),
                ),
            ),
            test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            }),
        ));

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CommitteeFinalized
                    && data.reason == FailureReason::DKGInvalidShares
        ));
        assert!(actor.pending.is_empty());

        Ok(())
    }

    #[actix::test]
    async fn decryption_failure_helper_emits_e3_failed() -> Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
        let actor = ProofRequestActor::new(&bus, PrivateKeySigner::random());
        let e3_id = E3id::new("45", 1);

        actor.fail_decryption_round(
            e3_id.clone(),
            &test_ctx(E3Failed {
                e3_id: e3_id.clone(),
                failed_at_stage: E3Stage::CiphertextReady,
                reason: FailureReason::DecryptionInvalidShares,
            }),
            "test decryption failure",
        );

        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id
                    && data.failed_at_stage == E3Stage::CiphertextReady
                    && data.reason == FailureReason::DecryptionInvalidShares
        ));

        Ok(())
    }
}
