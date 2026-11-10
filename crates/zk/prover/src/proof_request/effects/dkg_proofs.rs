// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch C0 and threshold-share proof work and route compute results.

use crate::utils::total_expected_for;

use super::*;

impl ProofRequestActor {
    pub(in crate::actors::proof_request) fn handle_encryption_key_pending(
        &mut self,
        msg: TypedEvent<EncryptionKeyPending>,
    ) {
        let (msg, ec) = msg.into_components();
        // Terminal cleanup ran already; a late request must not leave pending work behind.
        if self.finished_e3s.contains(&msg.e3_id) {
            return;
        }
        if let Err(error) = msg
            .params_profile
            .ensure_admission_enabled()
            .and_then(|()| msg.params_profile.validate_committee(msg.committee_size))
        {
            error!(e3_id = %msg.e3_id, %error, "Unsupported C0 proof generation profile");
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
                msg.params_profile,
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
        ctx: &mut Context<Self>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        // Terminal cleanup ran already; a late request must not leave pending work behind.
        if self.finished_e3s.contains(&e3_id) {
            return;
        }

        if self.completed_threshold.contains(&e3_id) {
            debug!(
                e3_id = %e3_id,
                "Ignoring duplicate completed DKG proof work"
            );
            return;
        }

        if self.pending_threshold.contains_key(&e3_id) {
            let stale_count = self
                .threshold_correlation
                .values()
                .filter(|(pending_e3, _, _)| pending_e3 == &e3_id)
                .count();
            self.threshold_correlation
                .retain(|_, (pending_e3, _, _)| pending_e3 != &e3_id);
            warn!(
                e3_id = %e3_id,
                stale_correlations = stale_count,
                "Replacing replayed DKG proof work and invalidating its old responses"
            );
        }

        let sk_enc_count = msg.sk_share_encryption_requests.len();
        let e_sm_enc_count = msg.e_sm_share_encryption_requests.len();

        let total_expected = total_expected_for(sk_enc_count, e_sm_enc_count);
        self.node_agg_meta.insert(
            e3_id.clone(),
            NodeAggregationMeta {
                party_id: msg.full_share.party_id,
                total_expected,
            },
        );
        if let Some(held) = self.held_decryption_pending.remove(&e3_id) {
            self.handle_decryption_share_proofs_pending(held);
        }

        let mut pending = PendingThresholdProofs::new(
            e3_id.clone(),
            msg.full_share.clone(),
            ec.clone(),
            sk_enc_count,
            e_sm_enc_count,
            msg.recipient_party_ids,
        );

        // The node-fold collector persists every inner proof before accepting it.
        // Rehydrate the proof-request actor from that canonical sequence map so a
        // process restart does not regenerate a completed C1-C3 batch.
        let recovered = self
            .recovered_inner_proofs
            .remove(&e3_id)
            .unwrap_or_default();
        let dispatch = plan_threshold_dispatch(
            msg.proof_request,
            msg.sk_share_computation_request,
            msg.e_sm_share_computation_request,
            msg.sk_share_encryption_requests,
            msg.e_sm_share_encryption_requests,
        );
        for item in &dispatch {
            if let Some(proof) = recovered.get(&item.seq) {
                pending.store_proof(&item.kind, proof.clone());
            }
        }
        let recovered_count = pending.total_received();

        self.pending_threshold.insert(e3_id.clone(), pending);

        // C1/C2/C3 in canonical seq order. Sequencing/kind assignment lives in the pure domain
        // planner; the actor allocates correlation ids and dispatches.
        let requests = dispatch
            .into_iter()
            .filter(|item| !recovered.contains_key(&item.seq))
            .map(|item| {
                let corr = CorrelationId::new();
                self.threshold_correlation
                    .insert(corr, (e3_id.clone(), item.kind, item.seq));
                ComputeRequest::zk(item.request, corr, e3_id.clone())
            })
            .collect();
        self.dispatch_threshold_requests(requests, ec, ctx);

        if recovered_count > 0 {
            info!(
                e3_id = %e3_id,
                recovered = recovered_count,
                total = self.pending_threshold[&e3_id].total_expected(),
                "Reused persisted threshold proofs after restart"
            );
        }

        if self.pending_threshold[&e3_id].is_complete() {
            let pending = self.pending_threshold[&e3_id].clone();
            if self.publish_threshold_share_with_proofs(pending) {
                self.pending_threshold.remove(&e3_id);
                self.completed_threshold.insert(e3_id);
            }
        }
    }

    /// Dispatches `requests` in order, one at a time, each once admission has room. The
    /// `ThresholdSharePending` that planned them holds admission capacity at least until its
    /// handler returns, so a large plan published from the handler saturates admission.
    fn dispatch_threshold_requests(
        &mut self,
        mut requests: VecDeque<ComputeRequest>,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        while let Some(request) = requests.pop_front() {
            // Replayed work, a failed dispatch or the E3's end removed this batch's correlations.
            if !self
                .threshold_correlation
                .contains_key(&request.correlation_id)
            {
                continue;
            }
            let correlation_id = request.correlation_id;
            let bus = self.bus.clone();
            let event = bus.event_from(request, Some(ec.clone()));
            ctx.spawn(
                async move { bus.naked_dispatch_async(event?).await }
                    .into_actor(self)
                    .map(move |result, actor, ctx| match result {
                        Ok(()) => actor.dispatch_threshold_requests(requests, ec, ctx),
                        Err(err) => actor.abandon_threshold_requests(&correlation_id, err),
                    }),
            );
            return;
        }
    }

    /// Admission closed or the event pipeline failed: drop the batch that `correlation_id`
    /// belongs to, unless replayed work replaced it or the E3 ended.
    fn abandon_threshold_requests(&mut self, correlation_id: &CorrelationId, err: anyhow::Error) {
        let Some((e3_id, _, _)) = self.threshold_correlation.get(correlation_id).cloned() else {
            return;
        };
        error!("Failed to publish threshold proof request: {err}");
        self.threshold_correlation
            .retain(|_, (eid, _, _)| *eid != e3_id);
        self.pending_threshold.remove(&e3_id);
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
            _ => {}
        }
    }
}
