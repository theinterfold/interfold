// SPDX-License-Identifier: LGPL-3.0-only

//! C4 verification and keyshare publication.

use super::*;

impl ThresholdKeyshare {
    /// Route a C4 share. A peer's share passes `validation::admit_peer_decryption_key_share`, is
    /// saved for recovery, and goes to early buffering or to the C4 collector. This node's own share
    /// can complete C4 directly when it is the only honest party.
    pub(in crate::actors::threshold_keyshare) fn handle_decryption_key_shared(
        &mut self,
        data: DecryptionKeyShared,
        ec: EventContext<Sequenced>,
        self_addr: Addr<Self>,
    ) {
        if !data.external {
            return self.handle_own_decryption_key_share(data, ec);
        }
        let dealer = self
            .dkg_dealer_address(&data.e3_id, data.party_id)
            .ok()
            .flatten();
        let Some(state) = self.state.get() else {
            warn!(
                party_id = data.party_id,
                e3_id = %data.e3_id,
                "Dropping decryption key share without its dealer's signature"
            );
            return;
        };
        let recovery = match self.recovery.try_get() {
            Ok(recovery) => recovery,
            Err(err) => {
                error!("Failed to inspect DecryptionKeyShared recovery state: {err}");
                return;
            }
        };
        let admission = validation::admit_peer_decryption_key_share(
            &data,
            dealer,
            &state,
            &recovery,
            self.decryption_key_shared_collector.is_some(),
        );
        if let Err(rejection) = admission {
            use validation::DecryptionKeyShareRejection as Rejection;
            match rejection {
                Rejection::UnsignedDealer => warn!(
                    party_id = data.party_id,
                    e3_id = %data.e3_id,
                    "Dropping decryption key share without its dealer's signature"
                ),
                Rejection::ExpelledDealer => info!(
                    "Dropping DecryptionKeyShared from expelled party {}",
                    data.party_id
                ),
                Rejection::InvalidSender => warn!(
                    party_id = data.party_id,
                    e3_id = %data.e3_id,
                    "Dropping DecryptionKeyShared with an invalid sender party"
                ),
                Rejection::OutsideHonestCommittee => warn!(
                    party_id = data.party_id,
                    e3_id = %data.e3_id,
                    "Dropping DecryptionKeyShared from outside the honest committee"
                ),
                Rejection::CollectionComplete => trace!(
                    party_id = data.party_id,
                    e3_id = %data.e3_id,
                    "Ignoring DecryptionKeyShared after C4 collection completed"
                ),
            }
            return;
        }
        let recovered_event = TypedEvent::new(data.clone(), ec.clone());
        if let Err(err) = self.record_decryption_key_share(&recovered_event) {
            error!("Failed to persist DecryptionKeyShared recovery input: {err}");
            return;
        }
        let result = match &state.state {
            KeyshareState::AggregatingDecryptionKey(_) => {
                self.handle_early_decryption_key_share(data, ec)
            }
            KeyshareState::ReadyForDecryption(_) => self
                .ensure_decryption_key_shared_collector(self_addr)
                .map(|collector| {
                    collector.do_send(TypedEvent::new(data, ec));
                }),
            other => {
                trace!(
                    "DecryptionKeyShared from party {} in unexpected state {:?}, ignoring",
                    data.party_id,
                    other.variant_name()
                );
                Ok(())
            }
        };
        if let Err(err) = result {
            error!("Failed to handle DecryptionKeyShared: {err}");
        }
    }

    /// This node's own C4 share, published by ProofRequestActor. With no other honest party, it
    /// completes C4 and publishes `KeyshareCreated` directly.
    fn handle_own_decryption_key_share(
        &mut self,
        data: DecryptionKeyShared,
        ec: EventContext<Sequenced>,
    ) {
        let Some(state) = self.state.get() else {
            return;
        };
        if data.party_id != state.party_id
            || !matches!(state.state, KeyshareState::ReadyForDecryption(_))
        {
            return;
        }
        let others = state
            .honest_parties
            .as_ref()
            .map(|h| h.iter().filter(|&&pid| pid != state.party_id).count())
            .unwrap_or(0);
        if others == 0 {
            info!(
                "No other honest parties for E3 {} — publishing KeyshareCreated directly",
                data.e3_id
            );
            if let Err(err) = self.publish_keyshare_created(ec) {
                error!("Failed to publish KeyshareCreated: {err}");
            }
        }
    }

    /// Dispatch C4 verification for all collected DecryptionKeyShared events.
    /// Shares are provided by the DecryptionKeySharedCollector.
    pub(in crate::actors::threshold_keyshare) fn dispatch_c4_verification(
        &mut self,
        collected_shares: HashMap<u64, DecryptionKeyShared>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let e3_id = state.get_e3_id();
        let ready: ReadyForDecryption = state.clone().try_into()?;

        info!(
            "All DecryptionKeyShared collected for E3 {} ({} shares)",
            e3_id,
            collected_shares.len()
        );

        // Validate ESM proof count — each party must provide exactly
        // one C4b proof per smudging noise index.
        let expected_esm = ready.es_poly_sum.len();
        let mut c4_count_dishonest: HashSet<u64> = HashSet::new();
        let party_proofs: Vec<PartyShareDecryptionProofsToVerify> = collected_shares
            .iter()
            .filter_map(|(&party_id, share)| {
                if share.signed_e_sm_decryption_proofs.len() != expected_esm {
                    warn!(
                        "Party {} has wrong ESM proof count ({} vs expected {}) for E3 {} — treating as dishonest",
                        party_id,
                        share.signed_e_sm_decryption_proofs.len(),
                        expected_esm,
                        e3_id
                    );
                    c4_count_dishonest.insert(party_id);
                    None
                } else {
                    Some(PartyShareDecryptionProofsToVerify {
                        sender_party_id: party_id,
                        signed_sk_decryption_proof: share.signed_sk_decryption_proof.clone(),
                        signed_e_sm_decryption_proofs: share.signed_e_sm_decryption_proofs.clone(),
                    })
                }
            })
            .collect();

        // Evict pre-dishonest parties (wrong ESM count) from honest set
        if !c4_count_dishonest.is_empty() {
            self.state.try_mutate(&ec, |mut s| {
                if let Some(ref mut honest) = s.honest_parties {
                    honest.retain(|pid| !c4_count_dishonest.contains(pid));
                }
                Ok(s)
            })?;
        }

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

        let pre_dishonest: BTreeSet<u64> = c4_count_dishonest.into_iter().collect();

        info!(
            "Dispatching C4 share verification for E3 {} ({} parties, {} pre-dishonest)",
            e3_id,
            party_proofs.len(),
            pre_dishonest.len()
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
