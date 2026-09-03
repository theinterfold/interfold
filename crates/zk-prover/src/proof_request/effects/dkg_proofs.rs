// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch C0 and threshold-share proof work and route compute results.

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_encryption_key_pending(
        &mut self,
        msg: TypedEvent<EncryptionKeyPending>,
    ) {
        let (msg, ec) = msg.into_components();

        // C0 posture: the key's transport preset alone decides C0
        // (`CkksProofPosture::c0` depends only on the transport, so any
        // param set yields the same answer for this preset). The
        // verification actor accepts proof-less keys for exactly the E3s
        // whose posture says so and nothing else.
        let c0_posture = e3_fhe_params::ckks_presets::CkksProofPosture::new(
            e3_fhe_params::ckks_presets::CKKS_CANONICAL_PARAM_SET,
            msg.params_preset,
        )
        .c0;
        if let e3_fhe_params::ckks_presets::ProofPosture::ProofFree(reason) = c0_posture {
            info!(
                "Publishing party {}'s encryption key WITHOUT a C0 proof: {reason}",
                msg.key.party_id
            );
            if let Err(err) = self.bus.publish(
                EncryptionKeyCreated {
                    e3_id: msg.e3_id,
                    key: msg.key,
                    external: false,
                },
                ec,
            ) {
                error!("Failed to publish EncryptionKeyCreated: {err}");
            }
            return;
        }

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

    pub(in crate::actors::proof_request) fn handle_threshold_share_pending(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
    ) {
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
            },
        );
        // If C0 proof arrived before meta, emit DKGInnerProofReady now
        if self.proof_aggregation_enabled {
            if let Some(c0_proof) = pending_c0 {
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

    pub(in crate::actors::proof_request) fn handle_compute_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) {
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
            ComputeResponseKind::Zk(ZkResponse::PkGenerationCkks(resp)) => {
                self.handle_pk_generation_ckks_proof_response(
                    &msg.correlation_id,
                    resp.proof.clone(),
                );
            }
            ComputeResponseKind::Zk(ZkResponse::RelinRound1Ckks(resp)) => {
                self.handle_relin_round1_proof_response(&msg.correlation_id, resp.proofs.clone());
            }
            _ => {}
        }
    }
}
