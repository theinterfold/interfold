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

        // `handle_encryption_key_created` only records a peer key that arrives in `Init`. While
        // startup replays the event log, no collector starts: its deadline could end a collection
        // before replay delivers the recorded inputs. `resume_in_flight_work` builds both
        // collectors from the recorded inputs at `EffectsEnabled`.
        if self.effects_enabled {
            let collector = self.ensure_encryption_key_collector(address.clone(), &ec, now)?;
            self.replay_encryption_keys(&collector)?;
            self.ensure_collector(address.clone(), &ec, now)?;
        }

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
                    generate_bfv_keypair(&self.share_enc_preset()?, &self.cipher)?;
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
                params_profile: data.ciphernode_selected.params_profile,
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
        if let Some(collector) = self.decryption_key_collector.clone() {
            self.send_dealers_without_key(&collector);
        }

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
        let selected = msg.0;
        let e3_id = selected.e3_id.clone();
        let state = self
            .state
            .get()
            .ok_or(anyhow!("State not found on ThrehsoldKeyshare"))?;

        let trbfv_config: TrBFVConfig = state.get_trbfv_config();

        let crp = ArcBytes::from_bytes(
            &create_deterministic_crp_from_default_seed(&trbfv_config.params()).to_bytes(),
        );

        let threshold_preset = self.params_profile.threshold_preset();
        let defaults = threshold_preset
            .search_defaults()
            .ok_or_else(|| anyhow!("No search defaults for {:?}", threshold_preset))?;

        let request = GenPkShareAndSkSssRequest {
            trbfv_config,
            crp,
            lambda: threshold_preset.lambda_config(),
            num_ciphertexts: defaults.z as usize,
            synchronized: if self.params_profile.protocol()
                == e3_fhe_params::BfvDecryptionProtocol::Synchronized
            {
                let context =
                    crate::synchronized::proof_context(&selected, self.interfold_address)?;
                Some(
                    e3_trbfv::gen_pk_share_and_sk_sss::SynchronizedDkgGeneration {
                        profile: self.params_profile,
                        committee: state.committee_size()?,
                        owner: context.party_id,
                        setup_binding: crate::synchronized::setup_binding(&context, &e3_id)?,
                    },
                )
            } else {
                None
            },
        };
        // An l-BFV E3 sizes its smudging noise with the l-BFV depth and noise model, which its
        // request carries. A trBFV E3 keeps the request that earlier releases stored.
        let request = if e3_fhe_params::is_lbfv_path(threshold_preset) {
            TrBFVRequest::GenLbfvPkShareAndSkSss(GenLbfvPkShareAndSkSssRequest {
                request,
                mult_depth: defaults.mult_depth,
                preset: threshold_preset,
            })
        } else {
            TrBFVRequest::GenPkShareAndSkSss(request)
        };
        let event = ComputeRequest::trbfv(request, CorrelationId::new(), e3_id);

        self.bus.publish(event, ec)?;
        Ok(())
    }

    /// 2a. GenPkShareAndSkSss result
    pub fn handle_gen_pk_share_and_sk_sss_response(
        &mut self,
        res: TypedEvent<ComputeResponse>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let response_hash = if self.params_profile.protocol()
            == e3_fhe_params::BfvDecryptionProtocol::Synchronized
        {
            anyhow::ensure!(
                res.e3_id == state.e3_id,
                "synchronized native response belongs to another E3"
            );
            let output: GenPkShareAndSkSssResponse = res.clone().into_inner().try_into()?;
            let digest = alloy::primitives::keccak256(bincode::serialize(&output)?).into();
            if let Some(saved) = self.recovery.try_get()?.synchronized {
                anyhow::ensure!(
                    saved.generation_response_hash == digest,
                    "conflicting successful synchronized DKG response"
                );
            }
            Some(digest)
        } else {
            None
        };
        let ec = res.get_ctx().clone();
        match &state.state {
            KeyshareState::GeneratingThresholdShare(data)
                if data.pk_share.is_none()
                    && data.sk_sss.is_none()
                    && data.e_sm_raw.is_none()
                    && data.proof_request_data.is_none() => {}
            KeyshareState::GeneratingThresholdShare(data) => {
                if let Some(proof_data) = data.proof_request_data.clone() {
                    if let Err(error) = self.start_lbfv_generation(proof_data.sk_raw, ec) {
                        error!("Failed to start local l-BFV generation: {error}");
                    }
                }
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

        let is_sync =
            self.params_profile.protocol() == e3_fhe_params::BfvDecryptionProtocol::Synchronized;
        anyhow::ensure!(
            is_sync == output.outgoing_keys.is_some() && is_sync == output.e_sm_raw.is_none(),
            "key-generation response belongs to another DKG protocol"
        );
        if let Some(outgoing_keys) = &output.outgoing_keys {
            let selected = self
                .recovery
                .try_get()?
                .ciphernode_selected
                .ok_or_else(|| anyhow!("missing canonical DKG selection"))?;
            let context = crate::synchronized::proof_context(&selected, self.interfold_address)?;
            let material = crate::synchronized::SynchronizedDkgRecovery {
                context,
                generation_response_hash: response_hash.expect("synchronized response"),
                outgoing_keys: outgoing_keys.clone(),
                incoming_keys: None,
                dealer_ids: Vec::new(),
                sk_commitment: None,
                key_bundle: None,
                c2_statements: Default::default(),
                threshold_pk_shares: Default::default(),
            };
            material.validate(&selected, self.interfold_address, &self.cipher)?;
            self.recovery.try_mutate(&ec, |mut recovery| {
                if let Some(existing) = &recovery.synchronized {
                    anyhow::ensure!(
                        existing == &material,
                        "conflicting successful synchronized DKG keys"
                    );
                } else {
                    recovery.synchronized = Some(material);
                }
                recovery.last_ec = Some(ec.clone());
                Ok(recovery)
            })?;
        }

        let lbfv_secret_key = output.sk_raw.clone();
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
                    e_sm_raw: e_sm_raw.clone(),
                    esi_sss: if is_sync {
                        Some(Vec::new())
                    } else {
                        current.esi_sss.clone()
                    },
                    proof_request_data: Some(proof_request_data),
                    ..current
                },
            ))
        })?;

        if is_sync {
            let current: GeneratingThresholdShareData = self.state.try_get()?.try_into()?;
            return self.resume_generating_threshold_share(current, ec);
        }
        // A local failure keeps the durable state; a restart resumes the generation and the DKG
        // timeout ends the E3 without slashing when it never completes.
        if let Err(error) = self.start_lbfv_generation(lbfv_secret_key, ec.clone()) {
            error!("Failed to start local l-BFV generation: {error}");
        }

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
