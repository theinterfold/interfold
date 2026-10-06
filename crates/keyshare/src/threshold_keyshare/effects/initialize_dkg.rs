// SPDX-License-Identifier: LGPL-3.0-only

//! Ciphernode selection, BFV key setup, and initial TrBFV requests.

use super::*;

/// The delay before a selection whose BFV keypair record failed records the keypair again.
pub(crate) const BFV_KEY_RECORD_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

impl ThresholdKeyshare {
    /// Generate BFV keys for a selected ciphernode and publish `EncryptionKeyPending`.
    pub fn handle_ciphernode_selected(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        ctx: &mut <Self as Actor>::Context,
    ) -> Result<()> {
        let address = ctx.address();
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

        // One clock reading decides the DKG start and the timing of both collectors.
        let now = crate::domain::timeout_policy::now_unix_secs();
        if past_dkg_deadline(state.dkg_deadline_unix_secs, now)? {
            warn!(
                e3_id = %state.e3_id,
                "Ignoring late DKG startup after the canonical deadline"
            );
            return Ok(());
        }

        info!("CiphernodeSelected received.");
        if let Err(error) = resolve_timeout(
            DkgTimeoutPhase::EncryptionKeyCollection,
            state.dkg_deadline_unix_secs,
            state.dkg_window_secs,
            now,
        ) {
            warn!(
                e3_id = %state.e3_id,
                %error,
                "Cannot start DKG after the encryption-key collection cutoff"
            );
            return Ok(());
        }

        // `handle_encryption_key_created` only records a peer key that arrives in `Init`.
        let collector = self.ensure_encryption_key_collector(address.clone(), &ec, now)?;
        self.replay_encryption_keys(&collector)?;
        self.ensure_collector(address.clone(), &ec, now)?;

        // Peers encrypt their DKG shares to the key that this node publishes, so a start that
        // lost the keyshare's snapshot reuses the recorded keypair instead of generating another.
        if let Some(key) = self.bfv_key.clone() {
            return self.collect_with_bfv_key(key, msg, ec);
        }
        // A keypair whose record failed is recorded again: the store can hold it without its
        // flush, and refuses another keypair.
        let key = match self.pending.bfv_key.take() {
            Some(key) => key,
            None => {
                let BfvKeypairMaterial { sk_bfv, pk_bfv } =
                    generate_bfv_keypair(&self.share_enc_preset, &self.cipher)?;
                BfvKeyIntent { sk_bfv, pk_bfv }
            }
        };
        // The keypair is on disk before anything uses it, and the actor handles no other message
        // until then.
        let keys = self.bfv_keys.clone();
        let recorded = key.clone();
        let retry = TypedEvent::new(msg.clone(), ec.clone());
        ctx.wait(
            async move { keys.record(&recorded).await }
                .into_actor(self)
                .map(move |result, actor, ctx| {
                    if let Err(error) = result {
                        // The selection runs again with the same keypair until the encryption-key
                        // cutoff refuses a fresh start.
                        warn!(%error, "Could not record this node's BFV keypair; retrying");
                        actor.pending.bfv_key = Some(key);
                        ctx.notify_later(retry, BFV_KEY_RECORD_RETRY);
                        return;
                    }
                    actor.bfv_key = Some(key.clone());
                    if let Err(error) = actor.collect_with_bfv_key(key, msg, ec.clone()) {
                        actor.bus.with_ec(&ec).err(EType::KeyGeneration, error);
                    }
                }),
        );
        Ok(())
    }

    /// Enter encryption-key collection with this node's recorded keypair, and publish its public
    /// key once effects run. In replay, resume publishes it when effects start.
    fn collect_with_bfv_key(
        &mut self,
        key: BfvKeyIntent,
        selected: CiphernodeSelected,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(&ec, |s| {
            s.new_state(KeyshareState::CollectingEncryptionKeys(
                CollectingEncryptionKeysData {
                    sk_bfv: key.sk_bfv.clone(),
                    pk_bfv: key.pk_bfv.clone(),
                    ciphernode_selected: selected,
                },
            ))
        })?;
        if self.effects_enabled {
            self.publish_own_encryption_key(ec)?;
        }
        Ok(())
    }

    /// Publish this node's encryption key for its proof. When replay has delivered another key of
    /// this node from the log, the node lost the secret of the key that its peers hold: it abstains
    /// instead of publishing a second key, and the protocol treats it as absent. A key from the log
    /// that arrives after this publication stops share generation at collection, if it reached the
    /// key collector first.
    pub(in crate::actors::threshold_keyshare) fn publish_own_encryption_key(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let KeyshareState::CollectingEncryptionKeys(data) = &state.state else {
            return Ok(());
        };
        if let Some(logged) = self
            .recovery
            .try_get()?
            .encryption_keys
            .get(&state.party_id)
        {
            if logged.key.pk_bfv != data.pk_bfv {
                error!(
                    e3_id = %state.e3_id,
                    party_id = state.party_id,
                    "The log holds another encryption key of this node, whose secret is lost. This \
                     node publishes no second key and takes no further part in this E3's DKG."
                );
                return Ok(());
            }
        }
        self.bus.publish(
            EncryptionKeyPending {
                e3_id: state.e3_id.clone(),
                key: Arc::new(EncryptionKey::new(state.party_id, data.pk_bfv.clone())),
                params_preset: self.share_enc_preset,
                committee_size: state.committee_size()?,
            },
            ec,
        )
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

        // The collected key of this node must be the one whose secret it holds. Another one means
        // that the node lost the secret of the key that its peers encrypt to: it starts no share
        // generation and takes no further part in this E3's DKG, which treats it as absent.
        if msg
            .keys
            .iter()
            .any(|key| key.party_id == state.party_id && key.pk_bfv != current.pk_bfv)
        {
            error!(
                e3_id = %state.e3_id,
                party_id = state.party_id,
                "The collected encryption key of this node is not the one whose secret it holds. \
                 This node takes no further part in this E3's DKG."
            );
            return self.stop_threshold_share_collector();
        }

        // Filter out any keys from parties expelled after collection started
        let filtered_keys: Vec<_> = if state.expelled_parties.is_empty() {
            msg.keys
        } else {
            msg.keys
                .into_iter()
                .filter(|k| !state.expelled_parties.contains(&k.party_id))
                .collect()
        };

        // Share generation needs H keys, including this node's key. An expulsion can leave fewer:
        // it can reach this actor after the collector completes, or empty the collector's wait list.
        let minimum_keys = state.committee_h()?;
        let has_own_key = filtered_keys
            .iter()
            .any(|key| key.party_id == state.party_id);
        if filtered_keys.len() < minimum_keys || !has_own_key {
            let missing_parties = (0..state.threshold_n)
                .filter(|party_id| {
                    !state.expelled_parties.contains(party_id)
                        && !filtered_keys.iter().any(|key| key.party_id == *party_id)
                })
                .collect();
            return self.fail_encryption_key_collection(EncryptionKeyCollectionFailed {
                e3_id: state.e3_id.clone(),
                reason: format!(
                    "{} usable encryption keys; share generation needs {} including this node's key",
                    filtered_keys.len(),
                    minimum_keys
                ),
                missing_parties,
            });
        }

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

        if let Some(response) = self.pending.gen_pk_response.take() {
            self.handle_gen_pk_share_and_sk_sss_response(response)?;
        } else {
            self.handle_gen_pk_share_and_sk_sss_requested(TypedEvent::new(
                GenPkShareAndSkSss(current.ciphernode_selected),
                ec,
            ))?;
        }

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
                if self.effects_enabled {
                    bail!(
                        "GenPkShareAndSkSss response received before GeneratingThresholdShare state"
                    );
                }
                Self::buffer_replayed_compute_response(
                    &mut self.pending.gen_pk_response,
                    res,
                    "GenPkShareAndSkSss",
                )?;
                info!(
                    e3_id = %state.e3_id,
                    "Holding replayed GenPkShareAndSkSss response until encryption keys recover"
                );
                return Ok(());
            }
        }

        let (res, ec) = res.into_components();

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

        if let Some(response) = self.pending.gen_esi_response.take() {
            self.handle_gen_esi_sss_response(response)?;
        } else {
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
        }

        Ok(())
    }
}
