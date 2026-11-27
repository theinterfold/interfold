// SPDX-License-Identifier: LGPL-3.0-only

//! Durable local l-BFV generation, proof collection, and publication effects.

use super::*;
use anyhow::ensure;
use zeroize::Zeroizing;

const GENERATION_SEED_DOMAIN: &[u8] = b"interfold/lbfv-generation-seed/v1";

fn derive_generation_seed(
    session_id: &[u8; 32],
    party_id: u32,
    secret_key: &[u8],
) -> alloy::primitives::B256 {
    let mut material = Zeroizing::new(Vec::new());
    material.extend_from_slice(GENERATION_SEED_DOMAIN);
    material.extend_from_slice(session_id);
    material.extend_from_slice(&party_id.to_be_bytes());
    material.extend_from_slice(secret_key);
    alloy::primitives::keccak256(&*material)
}

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn lbfv_bundle_ready(&self) -> Result<bool> {
        Ok(self
            .lbfv_generation
            .get()
            .is_none_or(|state| state.is_ready()))
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
        if state.is_ready() || state.failure.is_some() {
            return Ok(());
        }

        let request = if let Some(request) = state.generation_request {
            request
        } else {
            let params_preset = self.params_profile.threshold_preset();
            // The seed is a function of the durable DKG secret and the proof session, so a replay
            // that lost this record regenerates the same request and the same operation ID.
            let seed = derive_generation_seed(
                &state.context.proof_session_id.0,
                state.context.party_id,
                &secret_key_bytes.access(&self.cipher)?,
            );
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
        if state
            .generation_request
            .as_ref()
            .is_some_and(|request| request.operation_id != response.operation_id)
        {
            warn!(
                e3_id = %msg.e3_id,
                "Ignoring an l-BFV generation response for another operation"
            );
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
        if state.generation_response.is_none() {
            warn!(
                e3_id = %msg.e3_id,
                "Ignoring an l-BFV row proof that arrived before its generation response"
            );
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

    pub(in crate::actors::threshold_keyshare) fn resume_lbfv_generation(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(state) = self.lbfv_generation.get() else {
            return Ok(());
        };
        if state.failure.is_some() {
            return Ok(());
        }
        if state.is_ready() {
            if !self.state.try_get()?.keyshare_published {
                self.publish_lbfv_bundle(ec.clone())?;
            }
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
        for identity in state.pending_proof_identities()? {
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

#[cfg(test)]
mod tests {
    use super::derive_generation_seed;

    #[test]
    fn generation_seed_is_stable_for_one_secret_and_session() {
        let session = [1u8; 32];
        let seed = derive_generation_seed(&session, 2, b"secret");

        assert_eq!(seed, derive_generation_seed(&session, 2, b"secret"));
        assert_ne!(seed, derive_generation_seed(&[2u8; 32], 2, b"secret"));
        assert_ne!(seed, derive_generation_seed(&session, 3, b"secret"));
        assert_ne!(seed, derive_generation_seed(&session, 2, b"other"));
    }
}
