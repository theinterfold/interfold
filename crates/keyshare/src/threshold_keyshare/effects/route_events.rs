// SPDX-License-Identifier: LGPL-3.0-only

//! Route the per-E3 event envelope to typed keyshare handlers.

use super::*;

impl Handler<InterfoldEvent> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::CiphernodeSelected(data) => {
                let timing = self.notify_sync(ctx, TypedEvent::new(data, ec));
                ctx.spawn(timing);
            }
            InterfoldEventData::CiphertextOutputPublished(data) => {
                self.observe_canonical_stage(&data.e3_id, &E3Stage::CiphertextReady);
                if let Err(error) = self.restore_public_key_context(&ec) {
                    self.bus.with_ec(&ec).err(EType::KeyGeneration, error);
                }
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PublicKeyAggregated(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_public_key_aggregated(data, &ec)
                });
            }
            InterfoldEventData::EvmLogObserved(_)
            | InterfoldEventData::CommitteePublicKeyChunkPublished(_) => {
                if ec.source() == e3_events::EventSource::Evm {
                    trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                        self.restore_public_key_context(&ec)?;
                        self.resume_decryption_work(ec.clone())
                    });
                }
            }
            InterfoldEventData::CommitteePublished(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_committee_published(data, &ec)
                });
            }
            InterfoldEventData::ThresholdShareCreated(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_threshold_share_created(TypedEvent::new(data, ec), ctx.address())
                });
            }
            InterfoldEventData::DKGRecursiveAggregationComplete(data) => {
                if self
                    .state
                    .get()
                    .is_some_and(|state| state.party_id == data.party_id)
                {
                    if let Err(error) = self.clear_pending_recovery_payload(&ec) {
                        error!(%error, "Could not clear completed DKG proof work");
                    }
                }
            }
            InterfoldEventData::ShareVerificationDispatched(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.record_logged_share_dispatch(&data, &ec)
                });
            }
            InterfoldEventData::DkgCoordination(data) => {
                let is_ready = matches!(data.kind, DkgCoordinationKind::Ready);
                let result = self
                    .record_dkg_coordination(data, ec.clone())
                    .and_then(|_| {
                        if is_ready && self.effects_enabled {
                            self.maybe_publish_roster_inputs_ready(ec.clone())?;
                            self.propose_dkg_roster(ec.clone())
                        } else {
                            Ok(())
                        }
                    });
                if let Err(err) = result {
                    error!("DKG roster coordination failed: {err}");
                    self.bus.with_ec(&ec).err(EType::KeyGeneration, err);
                }
            }
            InterfoldEventData::AggregatorChanged(data) => {
                if let Err(err) = self.handle_aggregator_changed(data, ec) {
                    error!("Could not update the DKG aggregator role: {err}");
                }
            }
            InterfoldEventData::EncryptionKeyCreated(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_encryption_key_created(TypedEvent::new(data, ec), ctx.address())
                });
            }
            InterfoldEventData::PkGenerationProofSigned(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_pk_generation_proof_signed(TypedEvent::new(data, ec))
                });
            }
            InterfoldEventData::DkgProofSigned(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_share_computation_proof_signed(TypedEvent::new(data, ec))
                });
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3Failed(data) => {
                warn!(
                    "E3 failed: {:?}. Shutting down ThresholdKeyshare for e3_id={}",
                    data.reason, data.e3_id
                );
                self.notify_sync(
                    ctx,
                    TypedEvent::new(E3RequestComplete { e3_id: data.e3_id }, ec),
                );
            }
            InterfoldEventData::E3StageChanged(data) => {
                self.observe_canonical_stage(&data.e3_id, &data.new_stage);
                match &data.new_stage {
                    E3Stage::Complete | E3Stage::Failed => {
                        info!("E3 reached terminal stage {:?}. Shutting down ThresholdKeyshare for e3_id={}", data.new_stage, data.e3_id);
                        self.notify_sync(
                            ctx,
                            TypedEvent::new(E3RequestComplete { e3_id: data.e3_id }, ec),
                        );
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
                self.handle_decryption_key_shared(data, ec, ctx.address())
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
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_committee_member_expelled(data, ec)
                });
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.handle_committee_member_excluded(data, ec)
                });
            }
            InterfoldEventData::EffectsEnabled(_) => {
                // Broadcast once at the end of boot sync. Re-drive any of this node's own
                // in-flight work that a crash may have interrupted (idempotent downstream).
                self.effects_enabled = true;
                if let Err(err) = self.resume_in_flight_work(ec.clone(), ctx.address()) {
                    warn!("resume_in_flight_work failed: {err}");
                }
                if let Err(err) = self.maybe_publish_roster_inputs_ready(ec.clone()) {
                    warn!("Could not signal DKG roster readiness: {err}");
                }
                if let Err(err) = self.propose_dkg_roster(ec) {
                    warn!("Could not propose the DKG roster: {err}");
                }
            }
            InterfoldEventData::ComputeRequest(data) => {
                trap(EType::KeyGeneration, &self.bus.with_ec(&ec), || {
                    self.record_logged_key_calculation(&data, &ec)
                });
            }
            _ => (),
        }
    }
}
