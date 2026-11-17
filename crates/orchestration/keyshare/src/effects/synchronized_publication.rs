// SPDX-License-Identifier: LGPL-3.0-only

//! Local setup retention and consent effects. Peer proofs cannot authorize this node's signature.

use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use anyhow::ensure;
use e3_events::{EventSource, SynchronizedDkgConsentPublished, SynchronizedRecipientProofReady};

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
        if self.ended {
            return Ok(());
        }
        let recovery = self.recovery.try_get()?;
        let Some(selected) = recovery.ciphernode_selected else {
            return Ok(());
        };
        let candidate = match (&self.pending.synchronized_result, recovery.synchronized) {
            (Some(result), Some(material)) if material.incoming_keys.is_some() => {
                match SynchronizedSetupIntent::new(
                    (*selected).clone(),
                    material,
                    result.clone(),
                    self.interfold_address,
                    &self.cipher,
                ) {
                    Ok(intent) => Some(intent),
                    Err(error) => {
                        self.pending.synchronized_result = None;
                        return Err(error);
                    }
                }
            }
            _ => None,
        };
        let store = self.recovery_payloads.synchronized_setup();
        let interfold = self.interfold_address;
        let cipher = self.cipher.clone();
        ctx.wait(
            async move {
                let saved = store.restore().await?;
                let intent = match (saved, candidate) {
                    (Some(saved), candidate) => {
                        if let Some(candidate) = candidate {
                            ensure!(
                                **saved.result() == **candidate.result(),
                                "conflicting durable recipient verdict"
                            );
                        }
                        Some(saved)
                    }
                    (None, candidate) => candidate,
                };
                if let Some(intent) = &intent {
                    ensure!(
                        intent.selected() == &*selected,
                        "saved setup differs from the canonical selection"
                    );
                    intent.validate(interfold, &cipher)?;
                    store.record(intent).await?;
                }
                Ok::<_, anyhow::Error>(intent)
            }
            .into_actor(self)
            .map(|result, actor, _| match result {
                Ok(Some(intent)) => {
                    actor.synchronized_setup = Some(intent);
                    actor.pending.synchronized_result = None;
                    if let Err(error) = actor.publish_synchronized_consent_definition() {
                        actor.bus.err(EType::KeyGeneration, error);
                    }
                }
                Ok(None) => {}
                Err(error) => actor.bus.err(EType::KeyGeneration, error),
            }),
        );
        Ok(())
    }

    fn publish_synchronized_consent_definition(&mut self) -> Result<()> {
        if !self.effects_enabled || self.ended || self.synchronized_consent_published {
            return Ok(());
        }
        let Some(intent) = &self.synchronized_setup else {
            return Ok(());
        };
        let e3 = &intent.selected().e3_id;
        // A canonical publication ends consent work, but keeps the local setup for every recipient.
        if self.canonical_key_published
            || self.canonical_keys.get(e3).is_some()
            || self.canonical_keys.synchronized_context(e3).is_none()
        {
            return Ok(());
        }
        if let Some(attestation) = intent.consent(
            self.interfold_address,
            &self.canonical_keys,
            &self.signer,
            &self.cipher,
        )? {
            self.bus.publish(
                SynchronizedDkgConsentPublished { attestation },
                intent.result().get_ctx().clone(),
            )?;
        }
        self.synchronized_consent_published = true;
        Ok(())
    }
}
