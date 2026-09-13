// SPDX-License-Identifier: LGPL-3.0-only

//! Durable local l-BFV generation, proof collection, and publication effects.

use super::*;
use anyhow::ensure;

const LBFV_GENERATION_FAILURE: &str = "l-BFV key-share generation failed";

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn lbfv_bundle_ready(&self) -> Result<bool> {
        let Some(state) = self.lbfv_generation.get() else {
            return Ok(true);
        };
        state.validate_loaded()?;
        Ok(state.is_ready())
    }

    pub(in crate::actors::threshold_keyshare) fn start_lbfv_generation(
        &mut self,
        secret_key_bytes: SensitiveBytes,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.main_lbfv_work_failed()? {
            return Ok(());
        }
        let Some(state) = self.lbfv_generation.get() else {
            return Ok(());
        };
        state.validate_loaded()?;
        if state.is_ready() || state.failure.is_some() {
            return Ok(());
        }

        let request = if let Some(request) = state.generation_request {
            request
        } else {
            let params_preset = self
                .share_enc_preset
                .threshold_counterpart()
                .ok_or_else(|| anyhow!("l-BFV generation requires a threshold BFV preset"))?;
            let seed: [u8; 32] = rand::random();
            let generation_seed = SensitiveBytes::new(seed.to_vec(), &self.cipher)?;
            let mut request = GenLbfvKeySharesRequest {
                operation_id: LbfvOperationId([0; 32]),
                session_id: state.context.proof_session_id.0,
                party_id: state.context.party_id,
                secret_key_bytes,
                generation_seed,
                params_preset,
                ciphertext_level: state.context.proof_domain.ciphertext_level,
                key_level: state.context.proof_domain.key_level,
            };
            request.operation_id = request.expected_operation_id();
            request.validate_operation_id()?;
            self.lbfv_generation.try_mutate(&ec, |mut state| {
                state.record_generation_request(request.clone())?;
                Ok(state)
            })?;
            request
        };

        self.bus.publish(
            ComputeRequest::trbfv(
                TrBFVRequest::GenLbfvKeyShares(request),
                CorrelationId::new(),
                state.context.e3_id,
            ),
            ec,
        )
    }

    pub(in crate::actors::threshold_keyshare) fn handle_lbfv_generation_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        if self.main_lbfv_work_failed()? {
            return Ok(());
        }
        if !self.lbfv_generation.has() {
            return Ok(());
        }
        let (msg, ec) = msg.into_components();
        let ComputeResponseKind::TrBFV(TrBFVResponse::GenLbfvKeyShares(response)) = msg.response
        else {
            return Ok(());
        };
        let state = self.lbfv_generation.try_get()?;
        ensure!(
            msg.e3_id == state.context.e3_id,
            "l-BFV generation response has the wrong E3 ID"
        );
        if state.is_ready() || state.failure.is_some() {
            return Ok(());
        }
        self.lbfv_generation.try_mutate(&ec, |mut state| {
            state.record_generation_response(response.clone())?;
            Ok(state)
        })?;
        self.dispatch_pending_lbfv_proofs(ec)
    }

    pub(in crate::actors::threshold_keyshare) fn handle_lbfv_proof_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        if self.main_lbfv_work_failed()? {
            return Ok(());
        }
        if !self.lbfv_generation.has() {
            return Ok(());
        }
        let (msg, ec) = msg.into_components();
        let state = self.lbfv_generation.try_get()?;
        ensure!(
            msg.e3_id == state.context.e3_id,
            "l-BFV proof response has the wrong E3 ID"
        );
        if state.is_ready() || state.failure.is_some() {
            return Ok(());
        }

        match msg.response {
            ComputeResponseKind::Zk(ZkResponse::LbfvPkGeneration(response)) => {
                let signed = SignedProofPayload::sign(
                    ProofPayload {
                        e3_id: msg.e3_id,
                        proof_type: ProofType::LbfvPkGeneration,
                        proof: response.proof.clone(),
                    },
                    &self.signer,
                )?;
                self.lbfv_generation.try_mutate(&ec, |mut state| {
                    state.record_pk_row_proof(&response, signed)?;
                    Ok(state)
                })?;
            }
            ComputeResponseKind::Zk(ZkResponse::RlkGeneration(response)) => {
                let signed = SignedProofPayload::sign(
                    ProofPayload {
                        e3_id: msg.e3_id,
                        proof_type: ProofType::RlkGeneration,
                        proof: response.proof.clone(),
                    },
                    &self.signer,
                )?;
                self.lbfv_generation.try_mutate(&ec, |mut state| {
                    state.record_rlk_row_proof(&response, signed)?;
                    Ok(state)
                })?;
            }
            _ => return Ok(()),
        }

        self.try_finalize_lbfv_bundle(ec)
    }

    pub(in crate::actors::threshold_keyshare) fn record_lbfv_c1_proof(
        &mut self,
        signed: SignedProofPayload,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if self.main_lbfv_work_failed()? {
            return Ok(());
        }
        if !self.lbfv_generation.has() {
            return Ok(());
        }
        let state = self.lbfv_generation.try_get()?;
        if state.is_ready() || state.failure.is_some() {
            return Ok(());
        }
        self.lbfv_generation.try_mutate(&ec, |mut state| {
            state.record_c1_proof(signed)?;
            Ok(state)
        })?;
        self.try_finalize_lbfv_bundle(ec)
    }

    pub(in crate::actors::threshold_keyshare) fn resume_lbfv_generation(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(state) = self.lbfv_generation.get() else {
            return Ok(());
        };
        state.validate_loaded()?;
        if state.failure.is_some() {
            return Ok(());
        }
        if state.is_ready() {
            self.publish_lbfv_bundle(ec.clone())?;
            return self.try_finish_deferred_keyshare_publish(ec);
        }
        if state.build_documents()?.is_some() {
            return self.try_finalize_lbfv_bundle(ec);
        }
        if state.generation_response.is_some() {
            return self.dispatch_pending_lbfv_proofs(ec);
        }
        if let Some(request) = state.generation_request {
            return self.bus.publish(
                ComputeRequest::trbfv(
                    TrBFVRequest::GenLbfvKeyShares(request),
                    CorrelationId::new(),
                    state.context.e3_id,
                ),
                ec,
            );
        }

        if let KeyshareState::GeneratingThresholdShare(data) = self.state.try_get()?.state {
            if let Some(proof_data) = data.proof_request_data {
                return self.start_lbfv_generation(proof_data.sk_raw, ec);
            }
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn handle_lbfv_compute_error(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
    ) -> Result<()> {
        let is_lbfv = matches!(
            &msg.request().request,
            ComputeRequestKind::TrBFV(TrBFVRequest::GenLbfvKeyShares(_))
                | ComputeRequestKind::Zk(
                    ZkRequest::LbfvPkGeneration(_) | ZkRequest::RlkGeneration(_)
                )
        );
        if !self.lbfv_generation.has() || !is_lbfv {
            return Ok(());
        }
        let (msg, ec) = msg.into_components();
        let state = self.lbfv_generation.try_get()?;
        if msg.request().e3_id != state.context.e3_id {
            return Ok(());
        }
        let operation_id = match &msg.request().request {
            ComputeRequestKind::TrBFV(request) => request.lbfv_operation_id(),
            ComputeRequestKind::Zk(request) => request.lbfv_operation_id(),
        };
        let Some(operation_id) = operation_id else {
            return Ok(());
        };
        if !state.awaits_operation(operation_id)? {
            return Ok(());
        }
        self.fail_lbfv_generation(ec)
    }

    pub(in crate::actors::threshold_keyshare) fn fail_lbfv_generation(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if matches!(self.state.try_get()?.state, KeyshareState::Failed { .. }) {
            if let Err(error) = self.discard_pending_lbfv_generation() {
                error!("Failed to clear l-BFV generation secrets after the main failure: {error}");
            }
            return Ok(());
        }
        let state = self.lbfv_generation.try_get()?;
        self.state.try_mutate(&ec, |state| {
            state.new_state(KeyshareState::Failed {
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            })
        })?;
        if let Err(error) = self.lbfv_generation.try_mutate(&ec, |mut state| {
            state.record_failure(LBFV_GENERATION_FAILURE);
            Ok(state)
        }) {
            error!("Failed to clear l-BFV generation secrets after the main failure: {error}");
        }
        self.bus.publish(
            E3Failed {
                e3_id: state.context.e3_id,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            },
            ec,
        )
    }

    fn main_lbfv_work_failed(&mut self) -> Result<bool> {
        if !matches!(self.state.try_get()?.state, KeyshareState::Failed { .. }) {
            return Ok(false);
        }
        if let Err(error) = self.discard_pending_lbfv_generation() {
            error!("Failed to clear l-BFV generation secrets after the main failure: {error}");
        }
        Ok(true)
    }

    fn dispatch_pending_lbfv_proofs(&self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.lbfv_generation.try_get()?;
        state.validate_loaded()?;
        for identity in state.pending_proof_identities() {
            self.bus.publish(
                ComputeRequest::zk(
                    state.proof_request(identity)?,
                    CorrelationId::new(),
                    state.context.e3_id.clone(),
                ),
                ec.clone(),
            )?;
        }
        Ok(())
    }

    fn try_finalize_lbfv_bundle(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.lbfv_generation.try_get()?;
        if state.failure.is_some() {
            return Ok(());
        }
        if state.is_ready() {
            self.publish_lbfv_bundle(ec.clone())?;
            return self.try_finish_deferred_keyshare_publish(ec);
        }
        let Some((public_key, relinearization_key)) = state.build_documents()? else {
            return Ok(());
        };
        let manifest = SignedLbfvKeyShareManifest::sign(
            state.manifest_for_documents(&public_key, &relinearization_key)?,
            &self.signer,
        )?;
        self.lbfv_generation.try_mutate(&ec, |mut state| {
            state.record_bundle(
                public_key.clone(),
                relinearization_key.clone(),
                manifest.clone(),
            )?;
            Ok(state)
        })?;
        self.publish_lbfv_bundle(ec.clone())?;
        self.try_finish_deferred_keyshare_publish(ec)
    }

    fn publish_lbfv_bundle(&self, ec: EventContext<Sequenced>) -> Result<()> {
        let state = self.lbfv_generation.try_get()?;
        state.validate_loaded()?;
        ensure!(state.is_ready(), "l-BFV publication bundle is not ready");
        self.bus.publish(
            LbfvKeyShareDocumentCreated {
                document: state.public_key_document.unwrap(),
            },
            ec.clone(),
        )?;
        self.bus.publish(
            LbfvKeyShareDocumentCreated {
                document: state.relinearization_key_document.unwrap(),
            },
            ec.clone(),
        )?;
        self.bus.publish(
            LbfvKeyShareManifestPublished {
                manifest: state.signed_manifest.unwrap(),
            },
            ec,
        )
    }
}
