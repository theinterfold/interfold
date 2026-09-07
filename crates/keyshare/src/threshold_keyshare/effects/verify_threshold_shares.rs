// SPDX-License-Identifier: LGPL-3.0-only

//! C2/C3 collection, verification dispatch, and result application.

use super::*;

impl ThresholdKeyshare {
    /// Verify the collected C2/C3 proofs before decryption-key aggregation.
    pub fn handle_all_threshold_shares_collected(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        // The collector is fed by peer shares and can finish before this node's own DKG has
        // advanced the state to `AggregatingDecryptionKey`. That happens whenever the node is
        // behind its peers: after a restart it can still be collecting encryption keys while
        // peers, who already have its key, finish and send their shares. Keep the message: the
        // collector has already cancelled its timeout and will not send it again, and dropping
        // it here would leave the DKG with no path to completion and no timer to fail it.
        if matches!(
            self.state.try_get()?.state,
            KeyshareState::CollectingEncryptionKeys(_) | KeyshareState::GeneratingThresholdShare(_)
        ) {
            info!(
                "AllThresholdSharesCollected arrived before own DKG reached aggregation; \
                 holding it until the state advances"
            );
            self.pending.early_all_shares_collected = Some(msg);
            return Ok(());
        }
        self.apply_all_threshold_shares_collected(msg)
    }

    /// Consume a held `AllThresholdSharesCollected` once the state can accept it.
    pub(in crate::actors::threshold_keyshare) fn flush_early_all_shares_collected(
        &mut self,
    ) -> Result<()> {
        if let Some(msg) = self.pending.early_all_shares_collected.take() {
            info!("Applying the held AllThresholdSharesCollected after own share generation");
            return self.apply_all_threshold_shares_collected(msg);
        }
        Ok(())
    }

    fn apply_all_threshold_shares_collected(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("AllThresholdSharesCollected");
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let own_party_id = state.party_id;

        // Filter out expelled parties before any processing. The collector may
        // have accepted shares before the expulsion arrived, so we scrub here.
        let expelled = &state.expelled_parties;
        let (shares, share_proofs): (Vec<_>, Vec<_>) = if expelled.is_empty() {
            (msg.shares, msg.share_proofs)
        } else {
            warn!(
                "Filtering {} expelled parties from AllThresholdSharesCollected for E3 {}: {:?}",
                expelled.len(),
                e3_id,
                expelled
            );
            msg.shares
                .into_iter()
                .zip(msg.share_proofs)
                .filter(|(s, _)| !expelled.contains(&s.party_id))
                .unzip()
        };

        // Expected proof counts come from local cached own shares (trusted source); the
        // collector excludes self from `shares`, so we cannot read them from there.
        let current: AggregatingDecryptionKey = state.clone().try_into()?;
        let own_sk_rows: Vec<Vec<u64>> =
            bincode::deserialize(&current.own_sk_share_raw.access_raw(&self.cipher)?)
                .context("Failed to deserialize own_sk_share_raw")?;
        let expected_c3a = own_sk_rows.len();
        let expected_num_esi = current.own_esi_shares_raw.len();
        let mut expected_c3b: usize = 0;
        for esi_raw in current.own_esi_shares_raw.iter() {
            let rows: Vec<Vec<u64>> = bincode::deserialize(&esi_raw.access_raw(&self.cipher)?)
                .context("Failed to deserialize own esi share")?;
            expected_c3b += rows.len();
        }

        // Build verification requests for other parties' proofs
        let mut party_proofs_to_verify: Vec<PartyProofsToVerify> = Vec::new();
        let mut no_proof_parties: HashSet<u64> = HashSet::new();
        let mut incomplete_proof_parties: HashSet<u64> = HashSet::new();
        for (share, proofs) in shares.iter().zip(share_proofs.iter()) {
            if share.party_id == own_party_id {
                continue;
            }

            let has_any_proof = proofs.signed_c2a_proof.is_some()
                || proofs.signed_c2b_proof.is_some()
                || !proofs.signed_c3a_proofs.is_empty()
                || !proofs.signed_c3b_proofs.is_empty();

            if !has_any_proof {
                no_proof_parties.insert(share.party_id);
                continue;
            }

            // Validate proof set completeness against trusted expected counts.
            // A malicious sender could omit proofs that would fail verification,
            // so we must check that all expected proofs are present.
            let is_complete = proofs.signed_c2a_proof.is_some()
                && proofs.signed_c2b_proof.is_some()
                && proofs.signed_c3a_proofs.len() == expected_c3a
                && proofs.signed_c3b_proofs.len() == expected_c3b
                && share.esi_sss.len() == expected_num_esi;

            if !is_complete {
                warn!(
                    "Party {} has incomplete proof set (c2a={}, c2b={}, c3a={}/{}, c3b={}/{}, esi={}/{}), treating as dishonest",
                    share.party_id,
                    proofs.signed_c2a_proof.is_some(),
                    proofs.signed_c2b_proof.is_some(),
                    proofs.signed_c3a_proofs.len(), expected_c3a,
                    proofs.signed_c3b_proofs.len(), expected_c3b,
                    share.esi_sss.len(), expected_num_esi,
                );
                incomplete_proof_parties.insert(share.party_id);
                continue;
            }

            // Complete proof set — collect for verification
            let mut signed_proofs = Vec::new();
            // SAFETY: is_complete guarantees c2a and c2b are Some
            signed_proofs.push(proofs.signed_c2a_proof.clone().unwrap());
            signed_proofs.push(proofs.signed_c2b_proof.clone().unwrap());
            signed_proofs.extend(proofs.signed_c3a_proofs.iter().cloned());
            signed_proofs.extend(proofs.signed_c3b_proofs.iter().cloned());

            party_proofs_to_verify.push(PartyProofsToVerify {
                sender_party_id: share.party_id,
                signed_proofs,
            });
        }

        // Store shares on the actor for use after verification completes (keep Arc to avoid deep clone)
        self.pending.shares = shares.to_vec();

        // Merge no-proof and incomplete-proof parties — both are dishonest
        let mut pre_dishonest: BTreeSet<u64> = BTreeSet::new();
        pre_dishonest.extend(incomplete_proof_parties);
        pre_dishonest.extend(no_proof_parties);
        if !pre_dishonest.is_empty() {
            warn!(
                "{} parties have missing/incomplete C2/C3 proofs for E3 {} — marking as pre-dishonest: {:?}",
                pre_dishonest.len(),
                e3_id,
                pre_dishonest
            );
        }

        if party_proofs_to_verify.is_empty() {
            // All non-self parties are dishonest (missing or incomplete proofs), none to verify
            let threshold = state.threshold_m;
            let total = state.threshold_n;
            let dishonest_count = (pre_dishonest.len() as u64).min(total);
            let honest_count = total - dishonest_count;

            if honest_count <= threshold {
                warn!(
                    "Too few honest parties for E3 {} ({} honest, need at least {}) after C2/C3 pre-dishonest filtering — cannot proceed",
                    e3_id, honest_count, threshold + 1
                );
                self.pending.shares.clear();
                self.bus.publish(
                    E3Failed {
                        e3_id: e3_id.clone(),
                        failed_at_stage: E3Stage::CommitteeFinalized,
                        reason: FailureReason::InsufficientCommitteeMembers,
                    },
                    ec,
                )?;
                return Ok(());
            }

            let dishonest_set: HashSet<u64> = pre_dishonest.into_iter().collect();
            return self.proceed_with_decryption_key_calculation(Some(dishonest_set), ec);
        }

        info!(
            "Dispatching C2/C3 share verification for E3 {} ({} parties, {} pre-dishonest)",
            e3_id,
            party_proofs_to_verify.len(),
            pre_dishonest.len()
        );

        let committee_size = CiphernodesCommitteeSize::from_threshold(
            state.threshold_m as usize,
            state.threshold_n as usize,
        )?;
        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::ShareProofs,
                share_proofs: party_proofs_to_verify,
                decryption_proofs: Vec::new(),
                pre_dishonest,
                params_preset: self.share_enc_preset,
                committee_size,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle ShareVerificationComplete from ShareVerificationActor.
    /// Dispatched for both C2/C3 and C4 verification.
    pub fn handle_share_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();

        match msg.kind {
            VerificationKind::ShareProofs => {
                // C2/C3 verification complete
                if msg.dishonest_parties.is_empty() {
                    info!(
                        "All parties passed C2/C3 verification for E3 {} — proceeding",
                        e3_id
                    );
                    self.proceed_with_decryption_key_calculation(None, ec)
                } else {
                    let threshold = state.threshold_m;
                    let total = state.threshold_n;
                    let dishonest_count = (msg.dishonest_parties.len() as u64).min(total);
                    let honest_count = total - dishonest_count;

                    if honest_count <= threshold {
                        warn!(
                            "Too few honest parties for E3 {} ({} honest, need at least {}) — cannot proceed",
                            e3_id, honest_count, threshold + 1
                        );
                        // Clear pending shares
                        self.pending.shares.clear();
                        self.bus.publish(
                            E3Failed {
                                e3_id: e3_id.clone(),
                                failed_at_stage: E3Stage::CommitteeFinalized,
                                reason: FailureReason::InsufficientCommitteeMembers,
                            },
                            ec,
                        )?;
                        return Ok(());
                    }

                    let dishonest_set: HashSet<u64> = msg.dishonest_parties.into_iter().collect();
                    info!(
                        "Proceeding with {} honest parties for E3 {} ({} dishonest excluded)",
                        honest_count,
                        e3_id,
                        dishonest_set.len()
                    );
                    self.proceed_with_decryption_key_calculation(Some(dishonest_set), ec)
                }
            }
            VerificationKind::DecryptionProofs => {
                // C4 verification complete — update honest set and publish KeyshareCreated
                if !msg.dishonest_parties.is_empty() {
                    self.state.try_mutate(&ec, |mut s| {
                        if let Some(ref mut honest) = s.honest_parties {
                            honest.retain(|pid| !msg.dishonest_parties.contains(pid));
                        }
                        Ok(s)
                    })?;

                    let state = self.state.try_get()?;
                    let threshold = state.threshold_m;
                    let honest_count = state
                        .honest_parties
                        .as_ref()
                        .map(|h| h.len() as u64)
                        .unwrap_or(0);

                    if honest_count <= threshold {
                        warn!(
                            "Too few honest parties after C4 for E3 {} ({} honest, need at least {})",
                            e3_id, honest_count, threshold + 1
                        );
                        self.bus.publish(
                            E3Failed {
                                e3_id: e3_id.clone(),
                                failed_at_stage: E3Stage::CommitteeFinalized,
                                reason: FailureReason::InsufficientCommitteeMembers,
                            },
                            ec,
                        )?;
                        return Ok(());
                    }

                    info!(
                        "Updated honest set after C4 for E3 {}: {} honest ({} removed)",
                        e3_id,
                        honest_count,
                        msg.dishonest_parties.len()
                    );
                } else {
                    info!(
                        "All parties passed C4 verification for E3 {} — publishing KeyshareCreated",
                        e3_id
                    );
                }

                self.publish_keyshare_created(ec)
            }
            _ => Ok(()),
        }
    }
}
