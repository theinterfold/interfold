// SPDX-License-Identifier: LGPL-3.0-only

//! Typed Actix handlers, failure mapping, and actor cleanup.

use super::*;

impl ThresholdKeyshare {
    fn persist_terminal_failure(
        &mut self,
        failed_at_stage: E3Stage,
        reason: FailureReason,
    ) -> Result<()> {
        self.state.try_mutate_without_context(|state| {
            state.new_state(KeyshareState::Failed {
                failed_at_stage,
                reason,
            })
        })
    }
}

impl Handler<TypedEvent<DecryptionShareProofSigned>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionShareProofSigned>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_decryption_share_proof_signed(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg, ctx.address()),
        )
    }
}

impl Handler<TypedEvent<CiphernodeSelected>> for ThresholdKeyshare {
    type Result = ResponseActFuture<Self, ()>;
    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if self
            .state
            .get()
            .is_some_and(|state| !matches!(state.state, KeyshareState::Init))
        {
            return Box::pin(async {}.into_actor(self));
        }
        let timing = self
            .state
            .get()
            .and_then(|state| state.dkg_deadline_unix_secs.zip(state.dkg_window_secs));
        if timing.is_some() {
            trap(
                EType::KeyGeneration,
                &self.bus.with_ec(msg.get_ctx()),
                || self.handle_ciphernode_selected(msg, ctx.address()),
            );
            return Box::pin(async {}.into_actor(self));
        }
        if self.selection_timing_pending {
            return Box::pin(async {}.into_actor(self));
        }

        self.selection_timing_pending = true;
        let reader = self.dkg_timing_reader.clone();
        let e3_id = msg.e3_id.clone();
        Box::pin(async move { reader(e3_id).await }.into_actor(self).map(
            move |result, actor, ctx| {
                actor.selection_timing_pending = false;
                let result = result.and_then(|(deadline, window)| {
                    anyhow::ensure!(deadline > 0 && window > 0, "invalid frozen DKG timing");
                    actor.state.try_mutate_without_context(|mut state| {
                        state.dkg_deadline_unix_secs = Some(deadline);
                        state.dkg_window_secs = Some(window);
                        Ok(state)
                    })?;
                    actor.handle_ciphernode_selected(msg.clone(), ctx.address())
                });
                if let Err(error) = result {
                    actor.bus.err(EType::KeyGeneration, error);
                    ctx.notify_later(msg, std::time::Duration::from_secs(15));
                }
            },
        ))
    }
}

impl Handler<TypedEvent<AllEncryptionKeysCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllEncryptionKeysCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_all_encryption_keys_collected(msg),
        )
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _: &mut Self::Context,
    ) -> Self::Result {
        if self
            .state
            .get()
            .is_some_and(|state| state.e3_id != msg.e3_id)
        {
            return;
        }
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                self.record_share_verification(&msg)?;
                self.handle_share_verification_complete(msg)
            },
        )
    }
}

impl Handler<TypedEvent<AllThresholdSharesCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllThresholdSharesCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                self.record_collected_threshold_shares(&msg)?;
                self.handle_all_threshold_shares_collected(msg)
            },
        )
    }
}

impl Handler<TypedEvent<CiphertextOutputPublished>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphertextOutputPublished>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_ciphertext_output_published(msg),
        )
    }
}

impl Handler<EncryptionKeyCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: EncryptionKeyCollectionFailed,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "Encryption key collection failed: {}",
                msg.reason
            );

            // Clear the collector reference since it's stopped
            self.encryption_key_collector = None;

            self.persist_terminal_failure(E3Stage::CommitteeFinalized, FailureReason::DKGTimeout)?;

            // Publish failure event to event bus for sync tracking
            self.bus.publish_without_context(msg.clone())?;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            })?;

            Ok(())
        })
    }
}

impl Handler<ThresholdShareCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: ThresholdShareCollectionFailed,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "Threshold share collection failed: {}",
                msg.reason
            );

            // Clear the collector reference since it's stopped
            self.decryption_key_collector = None;

            self.persist_terminal_failure(E3Stage::CommitteeFinalized, FailureReason::DKGTimeout)?;

            // Publish failure event to event bus for sync tracking
            self.bus.publish_without_context(msg.clone())?;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            })?;

            Ok(())
        })
    }
}

impl Handler<TypedEvent<AllDecryptionKeySharesCollected>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AllDecryptionKeySharesCollected>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let (msg, ec) = msg.into_components();
                self.decryption_key_shared_collector = None;
                self.dispatch_c4_verification(msg.shares, ec)
            },
        )
    }
}

impl Handler<DecryptionKeySharedCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: DecryptionKeySharedCollectionFailed,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::KeyGeneration, &self.bus.clone(), || {
            warn!(
                e3_id = %msg.e3_id,
                missing_parties = ?msg.missing_parties,
                "DecryptionKeyShared collection failed: {}",
                msg.reason
            );

            self.decryption_key_shared_collector = None;

            self.persist_terminal_failure(
                E3Stage::CommitteeFinalized,
                FailureReason::DecryptionTimeout,
            )?;

            self.bus.publish_without_context(E3Failed {
                e3_id: msg.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DecryptionTimeout,
            })?;

            Ok(())
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        event: TypedEvent<E3RequestComplete>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if let Err(error) = self.clear_large_recovery_payloads(event.get_ctx()) {
            error!(%error, "Could not clear terminal DKG recovery payloads");
            ctx.notify_later(event, std::time::Duration::from_secs(1));
            return;
        }
        self.encryption_key_collector = None;
        self.decryption_key_collector = None;
        self.decryption_key_shared_collector = None;
        self.pending = PendingKeyshareWork::default();
        self.notify_sync(ctx, Die);
    }
}

impl Handler<Die> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        warn!("ThresholdKeyshare is shutting down");
        ctx.stop();
    }
}
