// SPDX-License-Identifier: LGPL-3.0-only

//! C4 verification and keyshare publication.

use super::*;

impl ThresholdKeyshare {
    /// Dispatch C4 verification for all collected DecryptionKeyShared events.
    /// Shares are provided by the DecryptionKeySharedCollector.
    pub(in crate::actors::threshold_keyshare) fn dispatch_c4_verification(
        &mut self,
        collected_shares: HashMap<u64, DecryptionKeyShared>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();

        info!(
            "All DecryptionKeyShared collected for E3 {} ({} shares)",
            e3_id,
            collected_shares.len()
        );

        let party_proofs: Vec<PartyShareDecryptionProofsToVerify> = collected_shares
            .iter()
            .map(|(&party_id, share)| PartyShareDecryptionProofsToVerify {
                sender_party_id: party_id,
                signed_sk_decryption_proof: share.signed_sk_decryption_proof.clone(),
            })
            .collect();

        if party_proofs.is_empty() {
            // Check threshold viability after removing pre-dishonest parties
            let state = self.state.try_get()?;
            let threshold = state.threshold_m;
            let honest_count = state
                .honest_parties
                .as_ref()
                .map(|h| h.len() as u64)
                .unwrap_or(0);

            if honest_count <= threshold {
                warn!(
                    "Too few honest parties after C4 pre-filtering for E3 {} ({} honest, need at least {})",
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

            info!("No C4 proofs to verify — publishing KeyshareCreated directly");
            return self.publish_keyshare_created(ec);
        }

        let pre_dishonest = BTreeSet::new();

        info!(
            "Dispatching C4 share verification for E3 {} ({} parties)",
            e3_id,
            party_proofs.len()
        );

        let committee_size = state.committee_size()?;
        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: e3_id.clone(),
                kind: VerificationKind::DecryptionProofs,
                share_proofs: Vec::new(),
                decryption_proofs: party_proofs,
                pre_dishonest,
                params_preset: self.share_enc_preset,
                committee_size,
                lbfv_context: None,
                verification_id: None,
            },
            ec,
        )?;
        Ok(())
    }

    /// Publish KeyshareCreated (Exchange #4) with pk_share and signed C1 proof.
    pub(in crate::actors::threshold_keyshare) fn publish_keyshare_created(
        &mut self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let address = state.get_address().to_owned();
        let party_id = state.get_party_id();
        let Some((pk_share, signed_pk_generation_proof)) =
            Self::keyshare_created_fields(&state.state)
        else {
            warn!(
                "Deferring KeyshareCreated for party {} E3 {} — not in ReadyForDecryption/Decrypting ({})",
                party_id,
                e3_id,
                state.state.variant_name()
            );
            self.pending.keyshare_publish = true;
            return Ok(());
        };

        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.keyshare_publish_authorized = true;
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;

        if !self.lbfv_bundle_ready()? {
            warn!(
                "Deferring KeyshareCreated for party {} E3 {} until the l-BFV bundle is ready",
                party_id, e3_id
            );
            self.pending.keyshare_publish = true;
            return Ok(());
        }

        if signed_pk_generation_proof.is_none() {
            warn!(
                "Deferring KeyshareCreated for party {} E3 {} — C1 proof not stored yet (PkGenerationProofSigned race)",
                party_id, e3_id
            );
            self.pending.keyshare_publish = true;
            return Ok(());
        }

        info!("Publishing Exchange #4 (KeyshareCreated) for E3 {}", e3_id);

        self.bus.publish(
            KeyshareCreated {
                pubkey: pk_share.clone(),
                e3_id: e3_id.clone(),
                node: address,
                party_id,
                signed_pk_generation_proof: signed_pk_generation_proof.clone(),
            },
            ec.clone(),
        )?;

        // Record that publishing was authorized and has occurred, so resume-after-crash
        // may safely re-publish (idempotent at the aggregator) without ever emitting a
        // keyshare for a state that had not yet passed C4 honest-set filtering.
        self.state.try_mutate(&ec, |mut s| {
            s.keyshare_published = true;
            Ok(s)
        })?;

        Ok(())
    }
}
