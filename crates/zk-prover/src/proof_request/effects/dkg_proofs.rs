// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch C0 and threshold-share proof work and route compute results.

use super::*;

impl ProofRequestActor {
    /// Re-seed `DKGInnerProofReady { seq: 0 }` from the durable own-C0 record.
    ///
    /// The read is async and the caller is a sync handler, so the publish happens from a
    /// spawned task straight onto the bus; the `NodeProofAggregator` subscribes there.
    pub(in crate::actors::proof_request) fn reseed_own_c0_from_store(
        &mut self,
        e3_id: E3id,
        party_id: u64,
        ec: EventContext<Sequenced>,
    ) {
        let Some(repo) = self.own_c0_repo(&e3_id) else {
            return;
        };
        if let Some(meta) = self.node_agg_meta.get_mut(&e3_id) {
            meta.c0_emitted = true;
        }
        let bus = self.bus.clone();
        tokio::spawn(async move {
            match repo.read().await {
                Ok(Some(record)) => {
                    info!(
                        "Re-seeding own C0 proof for E3 {} from the durable record (party {})",
                        e3_id, record.party_id
                    );
                    if record.party_id != party_id {
                        warn!(
                            "Own C0 record party {} differs from threshold share party {} for E3 {}",
                            record.party_id, party_id, e3_id
                        );
                    }
                    if let Err(err) = bus.publish(
                        DKGInnerProofReady {
                            e3_id: e3_id.clone(),
                            party_id,
                            proof: record.proof,
                            seq: 0,
                        },
                        ec,
                    ) {
                        error!("Failed to publish re-seeded DKGInnerProofReady for C0: {err}");
                    }
                }
                Ok(None) => warn!(
                    "No durable own C0 record for E3 {}; the node DKG fold will not complete",
                    e3_id
                ),
                Err(err) => error!("Failed to read own C0 record for E3 {}: {err}", e3_id),
            }
        });
    }
}

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_encryption_key_pending(
        &mut self,
        msg: TypedEvent<EncryptionKeyPending>,
    ) {
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

    pub(in crate::actors::proof_request) fn handle_threshold_share_pending(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        let sk_enc_count = msg.sk_share_encryption_requests.len();
        let e_sm_enc_count = msg.e_sm_share_encryption_requests.len();

        let total_expected = NodeAggregationMeta::total_expected_for(sk_enc_count, e_sm_enc_count);
        let (pending_c0, c0_already_emitted) = self
            .node_agg_meta
            .get(&e3_id)
            .map(|m| (m.pending_c0.clone(), m.c0_emitted))
            .unwrap_or((None, false));
        let c0_emitted = c0_already_emitted || pending_c0.is_some();
        self.node_agg_meta.insert(
            e3_id.clone(),
            NodeAggregationMeta {
                party_id: msg.full_share.party_id,
                total_expected,
                pending_c0: None,
                c0_emitted,
            },
        );
        // The seq layout is now known; release any C4 dispatch that arrived first.
        if let Some(held) = self.held_decryption_pending.remove(&e3_id) {
            info!(
                "Releasing held DecryptionShareProofsPending for E3 {} now that the seq layout is known",
                e3_id
            );
            self.handle_decryption_share_proofs_pending(held);
        }
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
            } else if !c0_already_emitted {
                // No C0 in memory and none emitted earlier in this process: this is a restart
                // with the C0 generated before the crash. Re-seed seq 0 from the durable record.
                self.reseed_own_c0_from_store(e3_id.clone(), msg.full_share.party_id, ec.clone());
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
                } else if let Some(adopted) =
                    self.adopt_orphaned_c4_response(&msg.e3_id, resp.dkg_input_type)
                {
                    // After a restart the effect gate replays the pre-crash `ComputeRequest`
                    // (old correlation id) and drops our re-driven one as a semantic
                    // duplicate. The response arrives under an id this process never
                    // registered. It is still the C4 proof we are waiting on — match it by
                    // kind against the pending dispatch instead of losing it.
                    self.handle_decryption_proof_response(&adopted, resp.proof.clone(), &ec);
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
}
