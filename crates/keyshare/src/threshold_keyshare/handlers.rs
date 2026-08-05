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
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeSelected>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_ciphernode_selected(msg, ctx.address()),
        )
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
        trap(
            EType::KeyGeneration,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_share_verification_complete(msg),
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
            || self.handle_all_threshold_shares_collected(msg),
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
        ctx: &mut Self::Context,
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

            // Stop this actor since we can't proceed without all encryption keys
            ctx.stop();
            Ok(())
        })
    }
}

impl Handler<ThresholdShareCollectionFailed> for ThresholdKeyshare {
    type Result = ();
    fn handle(
        &mut self,
        msg: ThresholdShareCollectionFailed,
        ctx: &mut Self::Context,
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

            ctx.stop();
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
        ctx: &mut Self::Context,
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

            ctx.stop();
            Ok(())
        })
    }
}

impl Handler<E3RequestComplete> for ThresholdKeyshare {
    type Result = ();
    fn handle(&mut self, _: E3RequestComplete, ctx: &mut Self::Context) -> Self::Result {
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
