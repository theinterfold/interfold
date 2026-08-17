// SPDX-License-Identifier: LGPL-3.0-only

//! DKG inner-proof collection and node-fold dispatch.

use super::*;

impl NodeProofAggregator {
    pub(in crate::actors::node_proof_aggregator) fn handle_threshold_share_pending(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        if !self.proof_aggregation_enabled {
            self.pending_inner_proofs.remove(&e3_id);
            info!(
                "NodeProofAggregator: test/CI skip flag active for E3 {}",
                e3_id
            );
            if let Err(err) = self.bus.publish(
                DKGRecursiveAggregationComplete {
                    e3_id: e3_id.clone(),
                    party_id: msg.full_share.party_id,
                    aggregated_proof: None,
                    fold_attestation: None,
                },
                ec,
            ) {
                error!(
                    "NodeProofAggregator: failed to publish skipped DKGRecursiveAggregationComplete for E3 {}: {err}",
                    e3_id
                );
            }
            return;
        }

        let sk_enc_count = msg.sk_share_encryption_requests.len();
        let e_sm_enc_count = msg.e_sm_share_encryption_requests.len();
        let total_expected = NodeDkgFoldMeta::total_expected_for(sk_enc_count, e_sm_enc_count);

        let committee = msg.proof_request.committee_size.values();
        let (committee_n, committee_h, n_moduli) =
            match build_pair_for_preset(msg.proof_request.params_preset) {
                Ok((threshold_params, _)) => {
                    (committee.n, committee.h, threshold_params.moduli().len())
                }
                Err(e) => {
                    self.pending_inner_proofs.remove(&e3_id);
                    error!(
                        "NodeProofAggregator: build_pair_for_preset failed for E3 {}: {e}",
                        e3_id
                    );
                    let _ = self.bus.publish(
                        E3Failed {
                            e3_id: e3_id.clone(),
                            failed_at_stage: E3Stage::CommitteeFinalized,
                            reason: FailureReason::DKGInvalidShares,
                        },
                        ec.clone(),
                    );
                    return;
                }
            };

        let meta = NodeDkgFoldMeta {
            party_id: msg.full_share.party_id,
            total_expected,
            sk_enc_count,
            e_sm_enc_count,
            sk_share_encryption_requests: msg.sk_share_encryption_requests.clone(),
            e_sm_share_encryption_requests: msg.e_sm_share_encryption_requests.clone(),
            committee_n,
            committee_h,
            n_moduli,
            params_preset: msg.proof_request.params_preset,
            committee_size: msg.proof_request.committee_size,
        };

        info!(
            "NodeProofAggregator: E3 {} party {} — expecting {} inner proofs (C0..C4) for NodeDkgFold",
            e3_id, meta.party_id, total_expected,
        );

        self.initialize_collection_state(e3_id, meta, ec);
    }

    pub(in crate::actors::node_proof_aggregator) fn handle_inner_proof_ready(
        &mut self,
        msg: TypedEvent<DKGInnerProofReady>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();

        let Some(state) = self.states.get_mut(&e3_id) else {
            let pending = self.pending_inner_proofs.entry(e3_id.clone()).or_default();
            pending.insert(msg.seq, msg.proof);
            warn!(
                "NodeProofAggregator: received DKGInnerProofReady for E3 {} before ThresholdSharePending — prebuffered seq={} (have {})",
                e3_id,
                msg.seq,
                pending.len()
            );
            return;
        };

        if state.fold_correlation.is_some() {
            warn!(
                "NodeProofAggregator: seq={} arrived while NodeDkgFold in flight — dropped",
                msg.seq
            );
            return;
        }

        state.buffer.insert(msg.seq, msg.proof);
        state.last_ec = ec;

        info!(
            "NodeProofAggregator: buffered seq={} for E3 {} (have {}/{})",
            msg.seq,
            e3_id,
            state.buffer.len(),
            state.meta.total_expected
        );

        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    pub(in crate::actors::node_proof_aggregator) fn initialize_collection_state(
        &mut self,
        e3_id: E3id,
        meta: NodeDkgFoldMeta,
        ec: EventContext<Sequenced>,
    ) {
        let mut buffer = self.pending_inner_proofs.remove(&e3_id).unwrap_or_default();
        if !buffer.is_empty() {
            info!(
                "NodeProofAggregator: recovered {} prebuffered inner proofs for E3 {}",
                buffer.len(),
                e3_id
            );
        }

        self.states.insert(
            e3_id.clone(),
            DkgProofCollectionState::new(meta, std::mem::take(&mut buffer), ec),
        );

        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    fn try_dispatch_node_dkg_fold(&mut self, e3_id: &E3id) {
        let state = match self.states.get_mut(e3_id) {
            Some(s) => s,
            None => return,
        };
        if !state.is_ready() {
            return;
        }

        let req = match state.build_fold_request() {
            Ok(req) => req,
            Err(err) => {
                let ec = state.last_ec.clone();
                let party_id = state.meta.party_id;
                error!(
                    "NodeProofAggregator: invalid C3 slot metadata for E3 {} party {}: {}",
                    e3_id, party_id, err
                );
                // Publish the terminal event before dropping the aggregation state;
                // only drop the state once the failure was actually published, so a
                // transient bus failure does not lose the terminal event.
                match self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::DKGInvalidShares,
                    },
                    ec,
                ) {
                    Ok(_) => {
                        self.states.remove(e3_id);
                    }
                    Err(err) => {
                        error!(
                            "NodeProofAggregator: failed to publish E3Failed for E3 {} — retaining state for retry: {err}",
                            e3_id
                        );
                    }
                }
                return;
            }
        };
        let corr = CorrelationId::new();
        let ec = state.last_ec.clone();
        let party_id = state.meta.party_id;

        state.fold_correlation = Some(corr);
        self.fold_correlation.insert(corr, e3_id.clone());

        info!(
            "NodeProofAggregator: dispatching NodeDkgFold for E3 {} party {}",
            e3_id, party_id
        );

        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(ZkRequest::NodeDkgFold(req), corr, e3_id.clone()),
            ec,
        ) {
            error!(
                "NodeProofAggregator: failed to publish NodeDkgFold for E3 {}: {err}",
                e3_id
            );
            let _ = self.states.get_mut(e3_id).map(|s| {
                s.fold_correlation = None;
            });
            self.fold_correlation.remove(&corr);
        }
    }

    pub(in crate::actors::node_proof_aggregator) fn handle_node_dkg_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
    ) {
        let Some(e3_id) = self.fold_correlation.remove(correlation_id) else {
            return;
        };

        let Some(state) = self.states.remove(&e3_id) else {
            error!(
                "NodeProofAggregator: NodeDkgFold response for unknown E3 {}",
                e3_id
            );
            return;
        };

        let party_id = state.meta.party_id;
        let committee_n = state.meta.committee_n;
        let committee_h = state.meta.committee_h;
        let n_moduli = state.meta.n_moduli;

        let fold_attestation = match extract_node_fold_agg_commits(
            &proof,
            committee_n,
            committee_h,
            n_moduli,
        ) {
            Ok((extracted_party, commits)) => {
                if extracted_party != party_id {
                    error!(
                        e3_id = %e3_id,
                        expected_party_id = party_id,
                        extracted_party_id = extracted_party,
                        "NodeFold public party_id does not match sortition party_id"
                    );
                    None
                } else if let Some(context) = self.dkg_fold_attestation_context_for(&e3_id) {
                    let payload = DkgFoldAttestationPayload {
                        e3_id: e3_id.clone(),
                        verifying_contract: context.verifying_contract,
                        registry: context.registry,
                        party_id,
                        agg_commits: commits,
                    };
                    match SignedDkgFoldAttestation::sign(payload, &self.signer) {
                        Ok(signed) => Some(signed),
                        Err(e) => {
                            error!(
                                e3_id = %e3_id,
                                party_id,
                                error = %e,
                                "failed to sign DkgFoldAttestation"
                            );
                            None
                        }
                    }
                } else {
                    error!(
                        e3_id = %e3_id,
                        party_id,
                        "NodeProofAggregator: cannot sign DkgFoldAttestation — CiphernodeRegistry.dkgFoldAttestationVerifier not configured"
                    );
                    None
                }
            }
            Err(e) => {
                error!(
                    e3_id = %e3_id,
                    party_id,
                    error = %e,
                    "failed to extract sk_agg/esm_agg from NodeFold proof"
                );
                None
            }
        };

        if fold_attestation.is_none() {
            error!(
                e3_id = %e3_id,
                party_id,
                "NodeDkgFold succeeded but fold attestation missing — failing E3"
            );
            if let Err(err) = self.bus.publish(
                E3Failed {
                    e3_id: e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::DKGInvalidShares,
                },
                state.last_ec,
            ) {
                error!(
                    "NodeProofAggregator: failed to publish E3Failed for E3 {}: {err}",
                    e3_id
                );
            }
            return;
        }

        info!(
            "NodeProofAggregator: NodeDkgFold complete for E3 {} party {} — publishing DKGRecursiveAggregationComplete",
            e3_id, party_id
        );

        if let Err(err) = self.bus.publish(
            DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id,
                aggregated_proof: Some(proof),
                fold_attestation,
            },
            state.last_ec,
        ) {
            error!(
                "NodeProofAggregator: failed to publish DKGRecursiveAggregationComplete for E3 {}: {err}",
                e3_id
            );
        }
    }
}
