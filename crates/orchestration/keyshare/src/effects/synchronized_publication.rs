// SPDX-License-Identifier: LGPL-3.0-only

//! Local setup retention and consent effects. Peer proofs cannot authorize this node's signature.

use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use anyhow::ensure;
use e3_events::{EventSource, SynchronizedDkgConsentPublished, SynchronizedRecipientProofReady};

enum SetupDriveOutcome {
    Ready(Option<Box<SynchronizedSetupIntent>>),
    Retry(anyhow::Error),
    StoreClosed(anyhow::Error),
    InvalidSaved(anyhow::Error),
}

fn setup_store_failure(error: anyhow::Error) -> SetupDriveOutcome {
    if error.is::<bincode::Error>() {
        SetupDriveOutcome::InvalidSaved(error)
    } else if matches!(
        error.downcast_ref::<actix::MailboxError>(),
        Some(actix::MailboxError::Closed)
    ) {
        SetupDriveOutcome::StoreClosed(error)
    } else {
        SetupDriveOutcome::Retry(error)
    }
}

impl ThresholdKeyshare {
    pub(in crate::actors::threshold_keyshare) fn accept_synchronized_setup(
        &mut self,
        result: TypedEvent<SynchronizedRecipientProofReady>,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        self.params_profile.ensure_admission_enabled()?;
        self.accept_synchronized_setup_definition(result)?;
        self.drive_synchronized_setup(ctx)
    }

    pub(in crate::actors::threshold_keyshare) fn accept_synchronized_setup_definition(
        &mut self,
        result: TypedEvent<SynchronizedRecipientProofReady>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        ensure!(
            self.params_profile.protocol() == e3_fhe_params::BfvDecryptionProtocol::Synchronized
                && result.get_ctx().source() == EventSource::Local
                && result.e3_id == state.e3_id
                && u64::from(result.context.party_id) == state.party_id,
            "setup verdict has another source, request or owner"
        );
        if let Some(saved) = &self.synchronized_setup {
            ensure!(
                **saved.result() == *result,
                "conflicting local recipient verdict"
            );
            return Ok(());
        }
        if let Some(held) = &self.pending.synchronized_result {
            ensure!(**held == *result, "conflicting pending recipient verdict");
        } else {
            // Missing native prerequisites may catch up during replay. A candidate is not an
            // accepted setup until validation and the exclusive write both succeed.
            self.pending.synchronized_result = Some(result);
        }
        Ok(())
    }

    pub(in crate::actors::threshold_keyshare) fn drive_synchronized_setup(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        if self.params_profile.protocol() != e3_fhe_params::BfvDecryptionProtocol::Synchronized
            || !self.params_profile.admission_enabled()
            || self.ended
        {
            return Ok(());
        }
        self.params_profile.ensure_admission_enabled()?;
        self.drive_synchronized_setup_definition(ctx)
    }

    pub(in crate::actors::threshold_keyshare) fn drive_synchronized_setup_definition(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        if self.bus.is_shutting_down() {
            self.pending.synchronized_consent = None;
            self.cancel_synchronized_setup_retry(ctx);
            return Ok(());
        }
        if self.ended || self.synchronized_setup_blocked {
            return Ok(());
        }
        if self.synchronized_setup.is_some() {
            return self.publish_synchronized_consent_definition(ctx);
        }
        let recovery = self.recovery.try_get()?;
        let Some(selected) = recovery.ciphernode_selected else {
            return Ok(());
        };
        let candidate = self.pending.synchronized_result.clone().zip(
            recovery
                .synchronized
                .filter(|material| material.incoming_keys.is_some()),
        );
        let store = self.recovery_payloads.synchronized_setup();
        let interfold = self.interfold_address;
        let cipher = self.cipher.clone();
        ctx.wait(
            async move {
                let saved = match store.restore().await {
                    Ok(saved) => saved,
                    Err(error) => return Ok(setup_store_failure(error)),
                };
                let restored = saved.is_some();
                let intent = match saved {
                    Some(saved) => {
                        // A replayed candidate cannot block restoring the exclusive successful
                        // verdict, even if its proof is randomized differently.
                        if candidate.as_ref().is_some_and(|(result, _)| **saved.result() != **result) {
                            tracing::warn!(e3_id = %selected.e3_id, "ignoring candidate that differs from the durable recipient verdict");
                        }
                        Some(saved)
                    }
                    None => candidate
                        .map(|(result, material)| {
                            SynchronizedSetupIntent::new(
                                (*selected).clone(),
                                material,
                                result,
                                interfold,
                                &cipher,
                            )
                        })
                        .transpose()?,
                };
                if let Some(intent) = &intent {
                    let validate = || -> Result<()> {
                        ensure!(
                            intent.selected() == &*selected,
                            "saved setup differs from the canonical selection"
                        );
                        intent.validate(interfold, &cipher)
                    };
                    if let Err(error) = validate() {
                        return if restored {
                            Ok(SetupDriveOutcome::InvalidSaved(error))
                        } else {
                            Err(error)
                        };
                    }
                    if let Err(error) = store.record(intent).await {
                        return Ok(setup_store_failure(error));
                    }
                }
                Ok::<_, anyhow::Error>(SetupDriveOutcome::Ready(intent.map(Box::new)))
            }
            .into_actor(self)
            .map(|result, actor, ctx| actor.finish_synchronized_setup_drive(result, ctx)),
        );
        Ok(())
    }

    fn finish_synchronized_setup_drive(
        &mut self,
        result: Result<SetupDriveOutcome>,
        ctx: &mut actix::Context<Self>,
    ) {
        if self.bus.is_shutting_down() {
            self.cancel_synchronized_setup_retry(ctx);
            return;
        }
        match result {
            Ok(SetupDriveOutcome::Ready(intent)) => {
                self.synchronized_setup_failures = 0;
                self.cancel_synchronized_setup_retry(ctx);
                if let Some(intent) = intent {
                    self.synchronized_setup = Some(*intent);
                    self.pending.synchronized_result = None;
                    if let Err(error) = self.publish_synchronized_consent_definition(ctx) {
                        self.bus.err(EType::KeyGeneration, error);
                    }
                }
            }
            Ok(SetupDriveOutcome::Retry(error)) => {
                self.synchronized_setup_failures =
                    self.synchronized_setup_failures.saturating_add(1);
                if self.synchronized_setup_failures == 1 {
                    self.bus.err(EType::KeyGeneration, error);
                } else {
                    tracing::warn!(%error, "setup storage still unavailable; retry retained");
                }
                self.retry_synchronized_setup(ctx);
            }
            Ok(SetupDriveOutcome::StoreClosed(error)) => {
                self.synchronized_setup_blocked = true;
                self.cancel_synchronized_setup_retry(ctx);
                self.bus.err(
                    EType::KeyGeneration,
                    error
                        .context("setup storage is closed; check storage health before restarting"),
                );
            }
            Ok(SetupDriveOutcome::InvalidSaved(error)) => {
                self.synchronized_setup_blocked = true;
                self.pending.synchronized_result = None;
                self.cancel_synchronized_setup_retry(ctx);
                self.bus.err(
                    EType::KeyGeneration,
                    error
                        .context("saved setup cannot be decoded or validated; preserve node state"),
                );
            }
            Err(error) => {
                self.pending.synchronized_result = None;
                self.bus.err(EType::KeyGeneration, error);
            }
        }
    }

    fn cancel_synchronized_setup_retry(&mut self, ctx: &mut actix::Context<Self>) {
        if let Some(retry) = self.synchronized_setup_retry.take() {
            ctx.cancel_future(retry);
        }
    }

    pub(super) fn discard_synchronized_consent(&mut self, ctx: &mut actix::Context<Self>) {
        // A pending consent implies the intent was flushed; never cancel a storage retry here.
        if self.pending.synchronized_consent.take().is_some() {
            self.cancel_synchronized_setup_retry(ctx);
        }
    }

    fn retry_synchronized_setup(&mut self, ctx: &mut actix::Context<Self>) {
        if !self.effects_enabled
            || self.ended
            || self.bus.is_shutting_down()
            || self.synchronized_setup_retry.is_some()
        {
            return;
        }
        let delay = e3_utils::backoff_delay(
            std::time::Duration::from_secs(1),
            self.synchronized_setup_failures,
            std::time::Duration::from_secs(30),
        );
        self.synchronized_setup_retry = Some(ctx.run_later(delay, |actor, ctx| {
            actor.synchronized_setup_retry = None;
            if !actor.effects_enabled || actor.ended {
                return;
            }
            if let Err(error) = actor.drive_synchronized_setup_definition(ctx) {
                actor.bus.err(EType::KeyGeneration, error);
            }
        }));
    }

    fn publish_synchronized_consent_definition(
        &mut self,
        ctx: &mut actix::Context<Self>,
    ) -> Result<()> {
        if !self.effects_enabled || self.ended || self.synchronized_consent_published {
            return Ok(());
        }
        let Some(intent) = &self.synchronized_setup else {
            return Ok(());
        };
        let e3 = &intent.selected().e3_id;
        // A canonical publication ends consent work, but keeps the local setup for every recipient.
        if self.canonical_key_published || self.canonical_keys.get(e3).is_some() {
            self.discard_synchronized_consent(ctx);
            return Ok(());
        }
        if self.canonical_keys.synchronized_context(e3).is_none()
            || self.synchronized_setup_retry.is_some()
        {
            return Ok(());
        }
        let consent = match self.pending.synchronized_consent.take() {
            Some(consent) => consent,
            None => {
                let Some(attestation) = intent.consent(
                    self.interfold_address,
                    &self.canonical_keys,
                    &self.signer,
                    &self.cipher,
                )?
                else {
                    // A validated outside-H intent has no consent to deliver.
                    self.synchronized_consent_published = true;
                    return Ok(());
                };
                SynchronizedDkgConsentPublished { attestation }
            }
        };
        match self
            .bus
            .publish(consent.clone(), intent.result().get_ctx().clone())
        {
            Ok(()) => {
                self.synchronized_consent_published = true;
                self.synchronized_setup_failures = 0;
            }
            Err(error) if error.is::<e3_events::AdmissionClosed>() => {}
            Err(error) => {
                self.pending.synchronized_consent = Some(consent);
                self.synchronized_setup_failures =
                    self.synchronized_setup_failures.saturating_add(1);
                if self.synchronized_setup_failures == 1 {
                    tracing::warn!(%e3, %error, "consent admission refused; retained flushed intent");
                }
                self.retry_synchronized_setup(ctx);
            }
        }
        Ok(())
    }
}
