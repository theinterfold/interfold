// SPDX-License-Identifier: LGPL-3.0-only

//! Route the per-E3 event envelope to typed keyshare handlers.

use super::*;

impl Handler<InterfoldEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphertextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PublicKeyAggregated(data) => {
                let committee_hash =
                    e3_committee_hash::hash_committee_addresses(&data.committee_addresses);
                let pk = ArcBytes::from_bytes(&data.pubkey);
                let _ = self.state.try_mutate(&ec, |mut s| {
                    s.aggregated_pk = Some(pk);
                    s.decryption_domain = Some(e3_committee_hash::DecryptionDomainContext {
                        interfold_address: self.interfold_address,
                        committee_hash,
                        committee_public_key: data.pk_commitment.into(),
                    });
                    Ok(s)
                });
            }
            InterfoldEventData::ThresholdShareCreated(data) => {
                let _ =
                    self.handle_threshold_share_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                let _ =
                    self.handle_encryption_key_created(TypedEvent::new(data, ec), ctx.address());
            }
            InterfoldEventData::PkGenerationProofSigned(data) => {
                let _ = self.handle_pk_generation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::DkgProofSigned(data) => {
                let _ = self.handle_share_computation_proof_signed(TypedEvent::new(data, ec));
            }
            InterfoldEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            InterfoldEventData::E3Failed(data) => {
                warn!(
                    "E3 failed: {:?}. Shutting down ThresholdKeyshare for e3_id={}",
                    data.reason, data.e3_id
                );
                self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
            }
            InterfoldEventData::E3StageChanged(data) => {
                use e3_events::E3Stage;
                match &data.new_stage {
                    E3Stage::Complete | E3Stage::Failed => {
                        info!("E3 reached terminal stage {:?}. Shutting down ThresholdKeyshare for e3_id={}", data.new_stage, data.e3_id);
                        self.notify_sync(ctx, E3RequestComplete { e3_id: data.e3_id });
                    }
                    _ => {
                        trace!(
                            "E3 stage changed to {:?} for e3_id={}",
                            data.new_stage,
                            data.e3_id
                        );
                    }
                }
            }
            InterfoldEventData::DecryptionKeyShared(data) => {
                if data.external {
                    // Route based on current state
                    if let Some(state) = self.state.get() {
                        if state.expelled_parties.contains(&data.party_id) {
                            info!(
                                "Dropping DecryptionKeyShared from expelled party {}",
                                data.party_id
                            );
                            return;
                        }
                        if data.party_id >= state.threshold_n || data.party_id == state.party_id {
                            warn!(
                                party_id = data.party_id,
                                e3_id = %data.e3_id,
                                "Dropping DecryptionKeyShared with an invalid sender party"
                            );
                            return;
                        }
                        if state
                            .honest_parties
                            .as_ref()
                            .is_some_and(|parties| !parties.contains(&data.party_id))
                        {
                            warn!(
                                party_id = data.party_id,
                                e3_id = %data.e3_id,
                                "Dropping DecryptionKeyShared from outside the honest committee"
                            );
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
                            KeyshareState::ReadyForDecryption(_) => {
                                // Delegate to the collector actor
                                if let Some(ref collector) = self.decryption_key_shared_collector {
                                    collector.do_send(TypedEvent::new(data, ec));
                                    Ok(())
                                } else {
                                    match self.classify_uncollected_share() {
                                        UncollectedShare::AlreadyCollected => debug!(
                                            "DecryptionKeyShared from party {} ignored — \
                                             collection already complete",
                                            data.party_id
                                        ),
                                        UncollectedShare::SoleHonestParty => warn!(
                                            "DecryptionKeyShared from party {} dropped — no collector (sole honest party)",
                                            data.party_id
                                        ),
                                    }
                                    Ok(())
                                }
                            }
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
                } else {
                    // Own DecryptionKeyShared published by ProofRequestActor.
                    // A3 fast-path: if no other honest parties, publish KeyshareCreated directly.
                    if let Some(state) = self.state.get() {
                        if data.party_id == state.party_id {
                            if let KeyshareState::ReadyForDecryption(_) = state.state {
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
                        }
                    }
                }
            }
            InterfoldEventData::DecryptionShareProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.handle_committee_member_expelled(data, ec);
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                self.handle_committee_member_excluded(data, ec);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                // Broadcast once at the end of boot sync. Re-drive any of this node's own
                // in-flight work that a crash may have interrupted (idempotent downstream).
                if let Err(err) = self.resume_in_flight_work(ec, ctx.address()) {
                    warn!("resume_in_flight_work failed: {err}");
                }
            }
            _ => (),
        }
    }
}
