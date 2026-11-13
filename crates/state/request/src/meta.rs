// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    DkgFoldAttestationContextRepositoryFactory, E3Context, E3ContextSnapshot, E3Extension,
    MetaRepositoryFactory, TypedKey,
};
use anyhow::*;
use async_trait::async_trait;
use e3_committee::CiphernodesCommitteeSize;
use e3_data::RepositoriesFactory;
use e3_events::{
    CiphernodeSelected, DkgFoldAttestationContext, E3Requested, Event, InterfoldEvent,
    InterfoldEventData, Seed, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset, BfvProfile};
use e3_utils::utility_types::ArcBytes;

pub const META_KEY: TypedKey<E3Meta> = TypedKey::new("meta");
const DKG_FOLD_ATTESTATION_CONTEXT_NAME: &str = "dkg_fold_attestation_context";
pub const DKG_FOLD_ATTESTATION_CONTEXT_KEY: TypedKey<DkgFoldAttestationContext> =
    TypedKey::new(DKG_FOLD_ATTESTATION_CONTEXT_NAME);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct E3Meta {
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub seed: Seed,
    pub params_profile: BfvProfile,
    pub crypto_config_id: [u8; 32],
    pub params: ArcBytes,
    pub error_size: ArcBytes,
}

impl E3Meta {
    /// Recheck the saved request binding before restored work can use it: this release must admit
    /// the profile, and the saved identity must match it.
    pub fn validate_configuration(&self) -> Result<()> {
        self.params_profile.ensure_admission_enabled()?;
        self.validate_identity()
    }

    /// Check that the saved configuration ID and parameter bytes match the profile and committee,
    /// whether or not this release admits the profile.
    ///
    /// Confirmed-chain ingestion also runs this check on each request that it admits, so the ID is
    /// looked up in the identity table, and the parameter pair is built only to name the expected
    /// ID.
    pub fn validate_identity(&self) -> Result<()> {
        let committee =
            CiphernodesCommitteeSize::from_threshold(self.threshold_m, self.threshold_n)?;
        // The lookup can resolve another profile that shares the registry slot, so compare the
        // resolved profile and not only the success of the lookup.
        let resolved = BfvProfile::from_crypto_config_id(
            self.params_profile.param_set(),
            committee,
            self.crypto_config_id.into(),
        );
        if resolved.ok() != Some(self.params_profile) {
            // Fails with the unsupported-committee error when the profile does not support the
            // committee.
            let expected_id = self.params_profile.crypto_config_id(committee)?;
            bail!(
                "BFV configuration ID does not match profile {} and committee {committee}; expected {expected_id}",
                self.params_profile
            );
        }
        let params = BfvParamSet::from(self.params_profile.threshold_preset()).build();
        ensure!(
            self.params[..] == encode_bfv_params(&params)[..],
            "BFV parameter bytes do not match profile {}",
            self.params_profile
        );
        Ok(())
    }

    pub fn share_enc_preset(&self) -> Result<BfvPreset> {
        Ok(self.params_profile.dkg_preset()?)
    }
}

impl From<&E3Requested> for E3Meta {
    fn from(request: &E3Requested) -> Self {
        Self {
            threshold_m: request.threshold_m,
            threshold_n: request.threshold_n,
            seed: request.seed,
            params_profile: request.params_profile,
            crypto_config_id: request.crypto_config_id,
            params: request.params.clone(),
            error_size: request.error_size.clone(),
        }
    }
}

impl From<&CiphernodeSelected> for E3Meta {
    fn from(selection: &CiphernodeSelected) -> Self {
        Self {
            threshold_m: selection.threshold_m,
            threshold_n: selection.threshold_n,
            seed: selection.seed,
            params_profile: selection.params_profile,
            crypto_config_id: selection.crypto_config_id,
            params: selection.params.clone(),
            error_size: selection.error_size.clone(),
        }
    }
}

pub struct E3MetaExtension;

impl E3MetaExtension {
    pub fn create() -> Box<Self> {
        Box::new(Self {})
    }
}

#[async_trait]
impl E3Extension for E3MetaExtension {
    fn on_event(&self, ctx: &mut crate::E3Context, event: &InterfoldEvent) {
        if let InterfoldEventData::DkgFoldAttestationContextEstablished(data) = event.get_data() {
            if data.schema_version != DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION {
                return;
            }
            ctx.repositories()
                .dkg_fold_attestation_context(&data.e3_id)
                .write(data);
            ctx.set_dependency(DKG_FOLD_ATTESTATION_CONTEXT_KEY, data.context);
            return;
        }

        let InterfoldEventData::E3Requested(data) = event.get_data() else {
            return;
        };
        // Meta doesn't implement Checkpoint so we are going to store it manually
        let meta = E3Meta::from(data);
        ctx.repositories().meta(&data.e3_id).write(&meta);
        ctx.set_dependency(META_KEY, meta);
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        if snapshot.contains("meta") {
            let value = ctx
                .repositories()
                .meta(&ctx.e3_id)
                .read()
                .await?
                .ok_or_else(|| anyhow!("missing metadata for active E3 {}", ctx.e3_id))?;
            // The context of an E3 that ended before startup only completes, so a profile that
            // this release no longer admits does not stop startup. Any other context resumes work.
            let validation = if ctx.completes_on_restart() {
                value.validate_identity()
            } else {
                value.validate_configuration()
            };
            validation
                .with_context(|| format!("invalid saved BFV configuration for E3 {}", ctx.e3_id))?;
            ctx.set_dependency(META_KEY, value);
        }

        if snapshot.contains(DKG_FOLD_ATTESTATION_CONTEXT_NAME) {
            let value = ctx
                .repositories()
                .dkg_fold_attestation_context(&ctx.e3_id)
                .read()
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "missing DKG fold attestation context for active E3 {}",
                        ctx.e3_id
                    )
                })?;
            ensure!(
                value.schema_version == DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
                "unsupported DKG fold attestation context schema version {}",
                value.schema_version
            );
            ctx.set_dependency(DKG_FOLD_ATTESTATION_CONTEXT_KEY, value.context);
        }

        Ok(())
    }
}
