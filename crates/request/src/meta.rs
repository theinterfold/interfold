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
use e3_data::RepositoriesFactory;
use e3_events::{
    DkgFoldAttestationContext, E3Requested, Event, InterfoldEvent, InterfoldEventData, Seed,
    DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::BfvPreset;
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
    pub params_preset: BfvPreset,
    pub params: ArcBytes,
    pub error_size: ArcBytes,
    /// FHE scheme bound by the E3 program on-chain.
    #[serde(default)]
    pub scheme: e3_events::E3Scheme,
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
        let E3Requested {
            threshold_m,
            threshold_n,
            seed,
            e3_id,
            params_preset,
            params,
            error_size,
            scheme,
            ..
        } = data.clone();

        // Meta doesn't implement Checkpoint so we are going to store it manually
        let meta = E3Meta {
            threshold_m,
            threshold_n,
            seed,
            params_preset,
            params,
            error_size,
            scheme,
        };
        ctx.repositories().meta(&e3_id).write(&meta);
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
