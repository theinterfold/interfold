// SPDX-License-Identifier: LGPL-3.0-only

//! Exclusive local recipient verdict, retained until the E3 ends. This record is the downstream
//! setup authority; a signed peer setup is not a substitute for the collector's local verdict.

use super::*;
use e3_events::{SynchronizedRecipientProofReady, TypedEvent};
use e3_request::canonical_key::CanonicalPublicKeys;
use e3_zk_config::{synchronized::public_signals::PublicSignals, CircuitName};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SynchronizedSetupIntent {
    version: u8,
    selected: CiphernodeSelected,
    material: SynchronizedDkgRecovery,
    result: TypedEvent<SynchronizedRecipientProofReady>,
}

impl SynchronizedSetupIntent {
    /// Called only after the local node collector has admitted its correlated worker result.
    pub(crate) fn new(
        selected: CiphernodeSelected,
        material: SynchronizedDkgRecovery,
        result: TypedEvent<SynchronizedRecipientProofReady>,
        interfold: Address,
        cipher: &Cipher,
    ) -> Result<Self> {
        let intent = Self {
            version: 1,
            selected,
            material,
            result,
        };
        intent.validate(interfold, cipher)?;
        Ok(intent)
    }

    pub(crate) fn validate(&self, interfold: Address, cipher: &Cipher) -> Result<()> {
        use e3_events::EventContextAccessors;
        ensure!(
            self.version == 1
                && self.result.get_ctx().source() == e3_events::EventSource::Local
                && self.result.e3_id == self.selected.e3_id
                && self.result.context == self.material.context
                && self.result.proof.circuit == CircuitName::NodesFold,
            "setup intent is not this recipient's local verdict"
        );
        self.material
            .validate_setup(&self.selected, interfold, &self.result.setup, cipher)?;
        let config = e3_zk_config::synchronized::Configs::for_profile(
            self.selected.params_profile,
            CiphernodesCommitteeSize::from_threshold(
                self.selected.threshold_m,
                self.selected.threshold_n,
            )?,
        )?;
        let public = PublicSignals::decode(
            &config,
            self.result.proof.circuit,
            &self.result.proof.public_signals,
        )?;
        let setup = &self.result.setup;
        ensure!(
            public.binding() == Some(setup.binding)
                && public.party_id() == Some(setup.recipient)
                && public.dealers().as_deref() == Some(setup.dealers.as_slice())
                && public.threshold_keys() == Some(setup.threshold_keys.as_slice())
                && public.dealer_batch() == Some(setup.dealer_batch)
                && public.sk_commitment() == Some(setup.sk_commitment)
                && public.key_bundle() == Some(setup.key_bundle),
            "local recipient proof differs from the setup verdict"
        );
        self.material.publication_key(&self.selected, setup)?;
        Ok(())
    }

    pub(crate) fn selected(&self) -> &CiphernodeSelected {
        &self.selected
    }
    pub(crate) fn result(&self) -> &TypedEvent<SynchronizedRecipientProofReady> {
        &self.result
    }

    pub(crate) fn consent(
        &self,
        interfold: Address,
        keys: &CanonicalPublicKeys,
        signer: &alloy::signers::local::PrivateKeySigner,
        cipher: &Cipher,
    ) -> Result<Option<e3_events::SignedSynchronizedDkgAttestation>> {
        self.validate(interfold, cipher)?;
        if !self
            .result
            .setup
            .dealers
            .contains(&self.result.setup.recipient)
        {
            return Ok(None);
        }
        let key = self
            .material
            .publication_key(&self.selected, &self.result.setup)?;
        Ok(Some(self.material.attest_publication(
            &self.selected,
            interfold,
            keys,
            &self.result.setup,
            &key,
            signer,
            cipher,
        )?))
    }

    /// Recheck confirmed authority on every access. The saved local verdict alone never authorizes
    /// downstream use, and an outside-H recipient keeps its own SK/key-bundle anchors.
    pub fn confirmed_setup(
        &self,
        interfold: Address,
        keys: &CanonicalPublicKeys,
        cipher: &Cipher,
    ) -> Result<ConfirmedSynchronizedDkgSetup<'_>> {
        self.validate(interfold, cipher)?;
        self.material
            .confirmed_setup(&self.selected, interfold, keys, &self.result.setup, cipher)
    }
}
