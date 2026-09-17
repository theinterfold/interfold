// SPDX-License-Identifier: LGPL-3.0-only

//! DKG inner-proof collection and node-fold dispatch.

use super::*;
use e3_events::{LbfvGenerationFoldRequest, NodeDkgFoldV2Request};

impl NodeProofAggregator {
    pub(in crate::actors::node_proof_aggregator) fn handle_lbfv_document(
        &mut self,
        msg: TypedEvent<LbfvKeyShareDocumentCreated>,
    ) {
        let (msg, _) = msg.into_components();
        let e3_id = msg.document.e3_id().clone();
        let entry = self
            .generation_fold_rows
            .entry(e3_id.clone())
            .or_insert_with(|| LbfvGenerationRows {
                pk_proofs: Vec::new(),
                rlk_proofs: Vec::new(),
                trusted_limb_key_hash: e3_utils::ArcBytes::from_bytes(&[]),
            });
        match msg.document {
            LbfvKeyShareDocument::PublicKeyV1(document) => {
                entry.pk_proofs = document
                    .signed_row_proofs
                    .into_iter()
                    .map(|signed| signed.payload.proof)
                    .collect();
            }
            LbfvKeyShareDocument::RelinearizationKeyV1(document) => {
                entry.rlk_proofs = document
                    .signed_row_proofs
                    .into_iter()
                    .map(|signed| signed.payload.proof)
                    .collect();
                if let Some(proof) = entry.rlk_proofs.first() {
                    let signals: &[u8] = proof.public_signals.as_ref();
                    if signals.len() >= 9 * 32 {
                        entry.trusted_limb_key_hash =
                            e3_utils::ArcBytes::from_bytes(&signals[8 * 32..9 * 32]);
                    }
                }
            }
        }
        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    pub(in crate::actors::node_proof_aggregator) fn handle_threshold_share_pending(
        &mut self,
        msg: TypedEvent<ThresholdSharePending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        if self
            .recovery_index
            .entries
            .get(&e3_id)
            .is_some_and(|entry| entry.completed.is_some())
        {
            return;
        }

        if !self.proof_aggregation_enabled {
            self.pending_inner_proofs.remove(&e3_id);
            info!(
                "NodeProofAggregator: test-only proof aggregation is disabled for E3 {}",
                e3_id
            );
            let output = DKGRecursiveAggregationComplete {
                e3_id: e3_id.clone(),
                party_id: msg.full_share.party_id,
                aggregated_proof: None,
                fold_attestation: None,
            };
            if let Err(err) = self.persist_completed(&output, &ec) {
                error!("NodeProofAggregator: could not persist skipped fold for E3 {e3_id}: {err}");
                return;
            }
            if let Err(err) = self.bus.publish(output, ec) {
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

        if let Some(existing) = self.states.get(&e3_id) {
            if existing.meta != meta {
                error!("NodeProofAggregator: conflicting fold metadata for E3 {e3_id}");
                return;
            }
            self.try_dispatch_node_dkg_fold(&e3_id);
            return;
        }

        if let Err(err) = self.persist_meta(&e3_id, &meta, &ec) {
            error!("NodeProofAggregator: could not persist fold metadata for E3 {e3_id}: {err}");
            return;
        }

        self.initialize_collection_state(e3_id, meta, ec);
    }

    pub(in crate::actors::node_proof_aggregator) fn handle_inner_proof_ready(
        &mut self,
        msg: TypedEvent<DKGInnerProofReady>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        if self
            .recovery_index
            .entries
            .get(&e3_id)
            .is_some_and(|entry| entry.completed.is_some())
        {
            return;
        }

        let existing = self
            .states
            .get(&e3_id)
            .and_then(|state| state.buffer.get(&msg.seq))
            .or_else(|| {
                self.pending_inner_proofs
                    .get(&e3_id)
                    .and_then(|pending| pending.get(&msg.seq))
            });
        if let Some(existing) = existing {
            if existing != &msg.proof {
                if existing.circuit == msg.proof.circuit
                    && existing.public_signals == msg.proof.public_signals
                {
                    debug!(
                        "NodeProofAggregator: ignoring a re-proved statement at seq={} for E3 {e3_id}",
                        msg.seq
                    );
                } else {
                    error!(
                        "NodeProofAggregator: conflicting proof statement at seq={} for E3 {e3_id}",
                        msg.seq
                    );
                }
            }
            return;
        }
        if let Err(err) = self.persist_proof(&e3_id, msg.seq, &msg.proof, &ec) {
            error!(
                "NodeProofAggregator: could not persist proof seq={} for E3 {e3_id}: {err}",
                msg.seq
            );
            return;
        }

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

    pub(in crate::actors::node_proof_aggregator) fn try_dispatch_node_dkg_fold(
        &mut self,
        e3_id: &E3id,
    ) {
        let state = match self.states.get_mut(e3_id) {
            Some(s) => s,
            None => return,
        };
        if !state.is_ready() {
            return;
        }
        if state.fold_correlation.is_some() {
            return;
        }

        if state.meta.params_preset == e3_fhe_params::BfvPreset::SecureThreshold16384 {
            self.try_dispatch_v2_generation_fold(e3_id);
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

    fn try_dispatch_v2_generation_fold(&mut self, e3_id: &E3id) {
        let Some(rows) = self.generation_fold_rows.get(e3_id) else {
            return;
        };
        if rows.pk_proofs.len() != 5
            || rows.rlk_proofs.len() != 5
            || rows.trusted_limb_key_hash.is_empty()
        {
            return;
        }
        let Some(state) = self.states.get_mut(e3_id) else {
            return;
        };
        if state.fold_correlation.is_some() {
            return;
        }
        let next_row = *self
            .generation_fold_next_rows
            .entry(e3_id.clone())
            .or_insert(0);
        if next_row >= 5 {
            self.try_dispatch_v2_node_fold(e3_id);
            return;
        }
        let prior = self.generation_fold_accumulators.get(e3_id).cloned();
        let corr = CorrelationId::new();
        let ec = state.last_ec.clone();
        state.fold_correlation = Some(corr);
        self.fold_correlation.insert(corr, e3_id.clone());
        self.generation_fold_correlation.insert(corr, e3_id.clone());
        let request = LbfvGenerationFoldRequest {
            pk_proof: rows.pk_proofs[next_row as usize].clone(),
            rlk_proof: rows.rlk_proofs[next_row as usize].clone(),
            prior_accumulator: prior,
            row_index: next_row,
            trusted_limb_key_hash: rows.trusted_limb_key_hash.clone(),
            params_preset: state.meta.params_preset,
            committee_size: state.meta.committee_size,
        };
        if let Err(error) = self.bus.publish(
            ComputeRequest::zk(ZkRequest::LbfvGenerationFold(request), corr, e3_id.clone()),
            ec,
        ) {
            error!("NodeProofAggregator: failed to publish l-BFV generation fold for E3 {e3_id}: {error}");
            state.fold_correlation = None;
            self.fold_correlation.remove(&corr);
            self.generation_fold_correlation.remove(&corr);
        }
    }

    pub(in crate::actors::node_proof_aggregator) fn handle_generation_fold_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
    ) {
        let Some(e3_id) = self.generation_fold_correlation.remove(correlation_id) else {
            return;
        };
        self.fold_correlation.remove(correlation_id);
        if let Some(state) = self.states.get_mut(&e3_id) {
            state.fold_correlation = None;
        } else {
            return;
        }
        self.generation_fold_accumulators
            .insert(e3_id.clone(), proof);
        self.generation_fold_next_rows
            .entry(e3_id.clone())
            .and_modify(|row| *row += 1)
            .or_insert(1);
        self.try_dispatch_node_dkg_fold(&e3_id);
    }

    fn try_dispatch_v2_node_fold(&mut self, e3_id: &E3id) {
        let Some(state) = self.states.get_mut(e3_id) else {
            return;
        };
        if state.fold_correlation.is_some() {
            return;
        }
        let request = match state.build_fold_request() {
            Ok(request) => request,
            Err(error) => {
                error!("NodeProofAggregator: failed to build V2 node fold for E3 {e3_id}: {error}");
                return;
            }
        };
        let corr = CorrelationId::new();
        let ec = state.last_ec.clone();
        state.fold_correlation = Some(corr);
        self.fold_correlation.insert(corr, e3_id.clone());
        self.v2_legacy_correlation.insert(corr, e3_id.clone());
        if let Err(error) = self.bus.publish(
            ComputeRequest::zk(ZkRequest::NodeDkgFold(request), corr, e3_id.clone()),
            ec,
        ) {
            error!("NodeProofAggregator: failed to publish V2 node fold for E3 {e3_id}: {error}");
            state.fold_correlation = None;
            self.fold_correlation.remove(&corr);
            self.v2_legacy_correlation.remove(&corr);
        }
    }

    fn dispatch_v2_with_legacy_node_fold(&mut self, e3_id: &E3id, legacy_proof: Proof) {
        let Some(c1_proof) = self
            .states
            .get(e3_id)
            .and_then(|state| state.buffer.get(&1))
            .cloned()
        else {
            return;
        };
        let Some(state) = self.states.get_mut(e3_id) else {
            return;
        };
        let Some(generation_proof) = self.generation_fold_accumulators.get(e3_id).cloned() else {
            return;
        };
        let corr = CorrelationId::new();
        let ec = state.last_ec.clone();
        let request = NodeDkgFoldV2Request {
            legacy_node_fold_proof: legacy_proof,
            c1_proof,
            generation_proof,
            party_id: state.meta.party_id,
            params_preset: state.meta.params_preset,
            committee_size: state.meta.committee_size,
        };
        state.fold_correlation = Some(corr);
        self.fold_correlation.insert(corr, e3_id.clone());
        if let Err(error) = self.bus.publish(
            ComputeRequest::zk(ZkRequest::NodeDkgFoldV2(request), corr, e3_id.clone()),
            ec,
        ) {
            error!("NodeProofAggregator: failed to publish V2 node fold for E3 {e3_id}: {error}");
            state.fold_correlation = None;
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

        if self.v2_legacy_correlation.remove(correlation_id).is_some() {
            if let Some(state) = self.states.get_mut(&e3_id) {
                state.fold_correlation = None;
            }
            self.dispatch_v2_with_legacy_node_fold(&e3_id, proof);
            return;
        }

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

        let output = DKGRecursiveAggregationComplete {
            e3_id: e3_id.clone(),
            party_id,
            aggregated_proof: Some(proof),
            fold_attestation,
        };
        if let Err(err) = self.persist_completed(&output, &state.last_ec) {
            error!("NodeProofAggregator: could not persist completed fold for E3 {e3_id}: {err}");
            let mut state = state;
            state.fold_correlation = None;
            self.states.insert(e3_id, state);
            return;
        }
        if let Err(err) = self.bus.publish(output, state.last_ec) {
            error!(
                "NodeProofAggregator: failed to publish DKGRecursiveAggregationComplete for E3 {}: {err}",
                e3_id
            );
        }
    }
}
