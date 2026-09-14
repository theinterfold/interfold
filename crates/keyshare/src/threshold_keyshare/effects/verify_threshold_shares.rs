// SPDX-License-Identifier: LGPL-3.0-only

//! C2/C3 collection, verification dispatch, and result application.

use super::*;

impl ThresholdKeyshare {
    /// Verify the collected C2/C3 proofs before decryption-key aggregation.
    pub fn handle_all_threshold_shares_collected(
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
            // Every received bundle is incomplete. This member holds no usable bundle, so it
            // reports an empty ready set. The round fails only when no `H`-member roster can
            // be formed from the committee's reports.
            warn!(
                "No complete C2/C3 proof set received for E3 {} — reporting an empty ready set",
                e3_id
            );
            return self.publish_dkg_ready(BTreeSet::new(), Some(ec));
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
                dkg_roster: None,
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
                // C2/C3 verification complete. The verified senders form this member's ready
                // set. The DKG roster is chosen from every member's ready set, so the
                // decryption key is not computed here.
                let dishonest: HashSet<u64> = msg.dishonest_parties.iter().copied().collect();
                let held: BTreeSet<u64> = self
                    .pending
                    .shares
                    .iter()
                    .map(|share| share.party_id)
                    .filter(|pid| *pid != state.party_id && !dishonest.contains(pid))
                    .collect();
                if dishonest.is_empty() {
                    info!(
                        "All parties passed C2/C3 verification for E3 {} — reporting ready set",
                        e3_id
                    );
                } else {
                    info!(
                        "Reporting ready set of {} parties for E3 {} ({} dishonest excluded)",
                        held.len(),
                        e3_id,
                        dishonest.len()
                    );
                }
                self.publish_dkg_ready(held, Some(ec))
            }
            VerificationKind::DecryptionProofs => {
                // C4 verification complete. A dishonest C4 inside the roster cannot simply
                // be dropped: the aggregator circuit checks every C4 row against every C2
                // row of the roster, so the honest set must stay the roster. Treat the
                // dishonest members like silent ones — leave their ready entries and
                // rotate the epoch. The accusation path slashes them separately.
                if !msg.dishonest_parties.is_empty() {
                    warn!(
                        "Dishonest C4 from {:?} inside the DKG roster for E3 {} — rotating the roster epoch",
                        msg.dishonest_parties, e3_id
                    );
                    self.decryption_key_shared_collector = None;
                    let dishonest: Vec<u64> = msg.dishonest_parties.iter().copied().collect();
                    return self.handle_roster_epoch_timeout(&dishonest, Some(ec));
                }

                info!(
                    "All parties passed C4 verification for E3 {} — publishing KeyshareCreated",
                    e3_id
                );
                self.publish_keyshare_created(ec)
            }
            _ => Ok(()),
        }
    }
}
