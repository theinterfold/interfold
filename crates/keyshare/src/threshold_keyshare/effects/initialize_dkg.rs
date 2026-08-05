// SPDX-License-Identifier: LGPL-3.0-only

//! Ciphernode selection, BFV key setup, and initial TrBFV requests.

use super::*;

impl ThresholdKeyshare {
    /// Generate BFV keys for a selected ciphernode and publish `EncryptionKeyPending`.
    pub fn handle_ciphernode_selected(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        address: Addr<Self>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;
        if !matches!(state.state, KeyshareState::Init) {
            info!(
                e3_id = %state.e3_id,
                state = state.variant_name(),
                "Ignoring replayed CiphernodeSelected; keyshare already initialized"
            );
            return Ok(());
        }

        info!("CiphernodeSelected received.");
        // Ensure the collectors are created
        let _ = self.ensure_collector(address.clone());
        let _ = self.ensure_encryption_key_collector(address.clone());

        let BfvKeypairMaterial {
            sk_bfv: sk_bfv_encrypted,
            pk_bfv: pk_bfv_bytes,
        } = generate_bfv_keypair(&self.share_enc_preset, &self.cipher)?;

        let e3_id = state.e3_id.clone();

        self.state.try_mutate(&ec, |s| {
            s.new_state(KeyshareState::CollectingEncryptionKeys(
                CollectingEncryptionKeysData {
                    sk_bfv: sk_bfv_encrypted.clone(),
                    pk_bfv: pk_bfv_bytes.clone(),
                    ciphernode_selected: msg,
                },
            ))
        })?;

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            EncryptionKeyPending {
                e3_id,
                key: Arc::new(EncryptionKey::new(state.party_id, pk_bfv_bytes)),
                params_preset: self.share_enc_preset,
                committee_size,
            },
            ec,
        )?;

        Ok(())
    }

    /// 1a. AllEncryptionKeysCollected - All BFV keys received, start share generation
    pub fn handle_all_encryption_keys_collected(
        &mut self,
        msg: TypedEvent<AllEncryptionKeysCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!(
            "AllEncryptionKeysCollected - {} keys received",
            msg.keys.len()
        );

        let state = self.state.try_get()?;
        let current: CollectingEncryptionKeysData = state.clone().try_into()?;

        // Filter out any keys from parties expelled after collection started
        let filtered_keys: Vec<_> = if state.expelled_parties.is_empty() {
            msg.keys
        } else {
            msg.keys
                .into_iter()
                .filter(|k| !state.expelled_parties.contains(&k.party_id))
                .collect()
        };

        self.state.try_mutate(&ec, |s| {
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    sk_sss: None,
                    pk_share: None,
                    esi_sss: None,
                    e_sm_raw: None,
                    sk_bfv: current.sk_bfv,
                    pk_bfv: current.pk_bfv,
                    collected_encryption_keys: filtered_keys,
                    ciphernode_selected: Some(current.ciphernode_selected.clone()),
                    proof_request_data: None,
                },
            ))
        })?;

        self.handle_gen_pk_share_and_sk_sss_requested(TypedEvent::new(
            GenPkShareAndSkSss(current.ciphernode_selected),
            ec,
        ))?;

        Ok(())
    }

    /// 2. GenPkShareAndSkSss
    pub fn handle_gen_pk_share_and_sk_sss_requested(
        &self,
        msg: TypedEvent<GenPkShareAndSkSss>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("GenPkShareAndSkSss on ThresholdKeyshare");
        let CiphernodeSelected { e3_id, .. } = msg.0;
        let state = self
            .state
            .get()
            .ok_or(anyhow!("State not found on ThrehsoldKeyshare"))?;

        let trbfv_config: TrBFVConfig = state.get_trbfv_config();

        let crp = ArcBytes::from_bytes(
            &create_deterministic_crp_from_default_seed(&trbfv_config.params()).to_bytes(),
        );

        let threshold_preset = self
            .share_enc_preset
            .threshold_counterpart()
            .ok_or_else(|| anyhow!("No threshold counterpart for {:?}", self.share_enc_preset))?;
        let defaults = threshold_preset
            .search_defaults()
            .ok_or_else(|| anyhow!("No search defaults for {:?}", threshold_preset))?;

        let event = ComputeRequest::trbfv(
            TrBFVRequest::GenPkShareAndSkSss(GenPkShareAndSkSssRequest {
                trbfv_config,
                crp,
                lambda: threshold_preset.lambda_config(),
                num_ciphertexts: defaults.z as usize,
            }),
            CorrelationId::new(),
            e3_id,
        );

        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// 2a. GenPkShareAndSkSss result
    pub fn handle_gen_pk_share_and_sk_sss_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let (res, ec) = res.into_components();

        let state = self.state.try_get()?;
        match &state.state {
            KeyshareState::GeneratingThresholdShare(data)
                if data.pk_share.is_none()
                    && data.sk_sss.is_none()
                    && data.e_sm_raw.is_none()
                    && data.proof_request_data.is_none() => {}
            KeyshareState::GeneratingThresholdShare(_) => {
                info!("Ignoring duplicate GenPkShareAndSkSss response");
                return Ok(());
            }
            KeyshareState::AggregatingDecryptionKey(_)
            | KeyshareState::ReadyForDecryption(_)
            | KeyshareState::Decrypting(_)
            | KeyshareState::GeneratingDecryptionProof(_)
            | KeyshareState::Completed
            | KeyshareState::Failed { .. } => {
                info!(
                    state = state.variant_name(),
                    "Ignoring replayed GenPkShareAndSkSss response after DKG advanced"
                );
                return Ok(());
            }
            KeyshareState::Init | KeyshareState::CollectingEncryptionKeys(_) => {
                bail!("GenPkShareAndSkSss response received before GeneratingThresholdShare state");
            }
        }

        let output: GenPkShareAndSkSssResponse = res
            .try_into()
            .context("Error extracting data from compute process")?;

        let (pk_share, sk_sss, e_sm_raw) = (
            output.pk_share.clone(),
            output.sk_sss,
            output.e_sm_raw.clone(),
        );

        // Store proof request data for later use by ProofRequestActor
        let proof_request_data = ProofRequestData {
            pk0_share_raw: output.pk0_share_raw,
            sk_raw: output.sk_raw,
            eek_raw: output.eek_raw,
        };

        self.state.try_mutate(&ec, |s| {
            info!("try_store_pk_share_and_sk_sss");
            let current: GeneratingThresholdShareData = s.clone().try_into()?;
            s.new_state(KeyshareState::GeneratingThresholdShare(
                GeneratingThresholdShareData {
                    pk_share: Some(pk_share),
                    sk_sss: Some(sk_sss),
                    e_sm_raw: Some(e_sm_raw.clone()),
                    proof_request_data: Some(proof_request_data),
                    ..current
                },
            ))
        })?;

        // Fire gen_esi_sss with the e_sm_raw
        let current_state: GeneratingThresholdShareData = self.state.try_get()?.try_into()?;
        if let Some(ciphernode_selected) = current_state.ciphernode_selected {
            self.handle_gen_esi_sss_requested(TypedEvent::new(
                GenEsiSss {
                    ciphernode_selected,
                    e_sm_raw: current_state
                        .e_sm_raw
                        .expect("e_sm_raw should be set at this point"),
                },
                ec.clone(),
            ))?;
        }

        Ok(())
    }
}
