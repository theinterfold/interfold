// SPDX-License-Identifier: LGPL-3.0-only

//! C2/C3 collection, verification dispatch, and result application.

use super::*;
use e3_events::CircuitName;

/// Bound on C2/C3 results that wait for their share batch. A node sends at most one dispatch per
/// batch, and a batch grows at most once per dealer.
const MAX_PARKED_SHARE_VERDICTS: usize = 64;

impl ThresholdKeyshare {
    /// Verify the collected C2/C3 proofs before decryption-key aggregation.
    pub fn handle_all_threshold_shares_collected(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        info!("AllThresholdSharesCollected");
        let state = self.state.try_get()?;
        // Verification needs own shares; the recorded batch is verified after the transition.
        if matches!(
            state.state,
            KeyshareState::CollectingEncryptionKeys(_) | KeyshareState::GeneratingThresholdShare(_)
        ) {
            return Ok(());
        }
        let e3_id = state.get_e3_id();
        let own_party_id = state.party_id;
        let recovery = self.recovery.try_get()?;
        let own_c0 = recovery
            .encryption_keys
            .get(&own_party_id)
            .and_then(|event| event.key.signed_payload.as_ref())
            .ok_or_else(|| anyhow!("missing own verified C0 proof for DKG share validation"))?;
        let own_pk_field = CircuitName::PkBfv
            .output_layout()
            .extract_field(&own_c0.payload.proof.public_signals, "pk_commitment")
            .ok_or_else(|| anyhow!("own C0 proof has no public-key commitment"))?;
        let own_pk_commitment: [u8; 32] = own_pk_field.try_into()?;

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
        let mut wrong_recipient_key_parties: HashSet<u64> = HashSet::new();
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

            let recipient_key_matches = proofs
                .signed_c3a_proofs
                .iter()
                .chain(&proofs.signed_c3b_proofs)
                .all(|signed| {
                    c3_targets_public_key(&signed.payload.proof.public_signals, &own_pk_commitment)
                });
            if !recipient_key_matches {
                warn!(
                    "Party {} encrypted its DKG share for a different recipient key; excluding it from this node's readiness set",
                    share.party_id
                );
                wrong_recipient_key_parties.insert(share.party_id);
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
        pre_dishonest.extend(wrong_recipient_key_parties);
        if !pre_dishonest.is_empty() {
            warn!(
                "{} parties have missing/incomplete C2/C3 proofs for E3 {} — marking as pre-dishonest: {:?}",
                pre_dishonest.len(),
                e3_id,
                pre_dishonest
            );
        }

        if party_proofs_to_verify.is_empty() {
            warn!(
                e3_id = %e3_id,
                "No external DKG share proof passed local prechecks; dispatching the batch outcome"
            );
        }

        info!(
            "Dispatching C2/C3 share verification for E3 {} ({} parties, {} pre-dishonest)",
            e3_id,
            party_proofs_to_verify.len(),
            pre_dishonest.len()
        );

        let committee_size = state.committee_size()?;
        let dispatch = InterfoldEventData::from(ShareVerificationDispatched {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ShareProofs,
            share_proofs: party_proofs_to_verify,
            decryption_proofs: Vec::new(),
            pre_dishonest,
            params_preset: self.share_enc_preset,
            committee_size,
        });
        let dispatch_id = EventId::hash(&dispatch);
        self.bus.publish(dispatch, ec.clone())?;
        self.recovery.try_mutate(&ec, |mut recovery| {
            if !recovery.share_dispatch_ids.contains(&dispatch_id) {
                recovery.share_dispatch_ids.push(dispatch_id);
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;
        match self.pending.parked_share_verdicts.remove(&dispatch_id) {
            Some(verdict) => self.apply_share_verification(verdict),
            None => Ok(()),
        }
    }

    /// Whether a delivered verification result belongs to the current batch. A C2/C3 result
    /// applies only while the batch exists and only if its dispatch is one that this node sent for
    /// that batch. The recovery state keeps those dispatch IDs, so after a restart replay applies
    /// such a result where it applied before.
    ///
    /// A result after the C2/C3 phase ended (decryption-key calculation done, the DKG failed, or
    /// the key is on chain) changes nothing and is dropped. Any other result is kept and applies
    /// when this actor sends a dispatch with its ID. After a restart the batch can be missing until
    /// a collector rebuilds it, and a batch can be sent again with another payload when an
    /// expulsion came between. A result of an earlier batch would count the dealers that only the
    /// grown batch holds as verified.
    pub(in crate::actors::threshold_keyshare) fn share_verification_applies(
        &mut self,
        msg: &TypedEvent<ShareVerificationComplete>,
    ) -> Result<bool> {
        if msg.kind != VerificationKind::ShareProofs {
            return Ok(true);
        }
        let state = self.state.try_get()?;
        if self.canonical_key_published || !state.state.share_collection_is_open() {
            info!(
                e3_id = %msg.e3_id,
                state = state.variant_name(),
                "Dropping a C2/C3 result after the C2/C3 phase ended"
            );
            return Ok(false);
        }
        let dispatch_id = msg.get_ctx().causation_id();
        let recovery = self.recovery.try_get()?;
        if recovery.collected_threshold_share_ids.is_some()
            && recovery.share_dispatch_ids.contains(&dispatch_id)
        {
            return Ok(true);
        }
        if self.pending.parked_share_verdicts.len() >= MAX_PARKED_SHARE_VERDICTS
            && !self
                .pending
                .parked_share_verdicts
                .contains_key(&dispatch_id)
        {
            warn!(
                e3_id = %msg.e3_id,
                "Dropping a C2/C3 result: too many results wait for their share batch"
            );
            return Ok(false);
        }
        info!(
            e3_id = %msg.e3_id,
            "Keeping a C2/C3 result until this node sends its dispatch for the current share batch"
        );
        self.pending
            .parked_share_verdicts
            .entry(dispatch_id)
            .or_insert_with(|| msg.clone());
        Ok(false)
    }

    /// Save the ID of a logged C2/C3 dispatch that verifies the current batch, at the dispatch's
    /// own position in the log. The actor records a dispatch ID when it sends the dispatch, but
    /// that write can be lost: a batch that `EffectsEnabled` sends again has no logged cause that
    /// replay would run again, and its write uses the last saved context, which the store can
    /// refuse as stale. So the ID is saved here again, also when the actor already holds it:
    /// a later snapshot cut then keeps it, and replay from an earlier cut delivers the dispatch
    /// before its result, so the result applies where it applied before the restart. Only the ID
    /// is saved: nothing is published and no roster is accepted.
    pub(in crate::actors::threshold_keyshare) fn record_logged_share_dispatch(
        &mut self,
        dispatch: &ShareVerificationDispatched,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        if dispatch.kind != VerificationKind::ShareProofs || dispatch.e3_id != state.e3_id {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let dispatch_id = ec.id();
        let Some(batch) = recovery.collected_threshold_share_ids.as_ref() else {
            return Ok(());
        };
        let recorded = recovery.share_dispatch_ids.contains(&dispatch_id);
        let verified: BTreeSet<u64> = dispatch
            .share_proofs
            .iter()
            .map(|proofs| proofs.sender_party_id)
            .chain(dispatch.pre_dishonest.iter().copied())
            .collect();
        let batch: BTreeSet<u64> = batch
            .iter()
            .copied()
            .filter(|party_id| *party_id != state.party_id)
            .collect();
        if !recorded && !dispatch_verifies_batch(&verified, &batch, &state.expelled_parties) {
            return Ok(());
        }
        self.recovery.try_mutate(ec, |mut recovery| {
            if !recovery.share_dispatch_ids.contains(&dispatch_id) {
                recovery.share_dispatch_ids.push(dispatch_id);
            }
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })
    }

    /// Record a verification result, act on it, and grow the C2/C3 batch when possible.
    pub(in crate::actors::threshold_keyshare) fn apply_share_verification(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        self.record_share_verification(&msg)?;
        let ec = msg.get_ctx().clone();
        self.handle_share_verification_complete(msg)?;
        self.dispatch_expanded_threshold_share_batch(ec)
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
                    self.maybe_publish_dkg_ready(ec)
                } else {
                    let committee_h = state.committee_h()?;
                    let honest_count = self
                        .recovery
                        .try_get()?
                        .verified_dealer_ids
                        .as_ref()
                        .map_or(1, |ids| ids.len() + 1);

                    if honest_count < committee_h {
                        warn!(
                            "Too few locally verified DKG dealers for E3 {} ({} available, need at least {}) — this node cannot join the C4 roster",
                            e3_id, honest_count, committee_h
                        );
                        self.pending.shares.clear();
                        return Ok(());
                    }

                    info!(
                        "Proceeding with {} honest parties for E3 {} ({} dishonest excluded)",
                        honest_count,
                        e3_id,
                        msg.dishonest_parties.len()
                    );
                    self.maybe_publish_dkg_ready(ec)
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

fn c3_targets_public_key(public_signals: &[u8], expected: &[u8; 32]) -> bool {
    CircuitName::ShareEncryption
        .input_layout()
        .extract_field(public_signals, "expected_pk_commitment")
        == Some(expected.as_slice())
}

#[cfg(test)]
mod recipient_key_tests {
    use super::c3_targets_public_key;

    #[test]
    fn rejects_a_c3_placeholder_encrypted_for_another_node() {
        let own_pk = [0x11; 32];
        let mut signals = vec![0x22; 64];
        assert!(!c3_targets_public_key(&signals, &own_pk));
        signals[..32].copy_from_slice(&own_pk);
        assert!(c3_targets_public_key(&signals, &own_pk));
        assert!(!c3_targets_public_key(&signals[..31], &own_pk));
    }
}
