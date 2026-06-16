// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    ThresholdKeyshare, ThresholdKeyshareParams, ThresholdKeyshareRepositoryFactory,
    ThresholdKeyshareState,
};
use actix::Actor;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, RepositoriesFactory};
use e3_events::{prelude::*, BusHandle, EType, InterfoldEvent, InterfoldEventData};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};

use crate::KeyshareState;
use std::sync::Arc;

pub struct ThresholdKeyshareExtension {
    bus: BusHandle,
    cipher: Arc<Cipher>,
    address: String,
}

impl ThresholdKeyshareExtension {
    pub fn create(bus: &BusHandle, cipher: &Arc<Cipher>, address: &str) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            cipher: cipher.to_owned(),
            address: address.to_owned(),
        })
    }
}

const ERROR_KEYSHARE_META_MISSING: &str =
    "Could not create ThresholdKeyshare because the meta instance it depends on was not set on the context.";

#[async_trait]
impl E3Extension for ThresholdKeyshareExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        // if this is NOT a CiphernodeSelected event then ignore
        let InterfoldEventData::CiphernodeSelected(data) = evt.get_data() else {
            return;
        };

        if ctx.get_event_recipient("threshold_keyshare").is_some() {
            return;
        }

        let e3_id = data.clone().e3_id;
        let party_id = data.clone().party_id;
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus
                .err(EType::KeyGeneration, anyhow!(ERROR_KEYSHARE_META_MISSING));
            return;
        };
        let repo = ctx.repositories().threshold_keyshare(&e3_id);
        let container = repo.send(Some(ThresholdKeyshareState::new(
            e3_id.clone(),
            party_id,
            KeyshareState::Init,
            meta.threshold_m as u64,
            meta.threshold_n as u64,
            meta.params.clone(),
            self.address.clone(),
            meta.proof_aggregation_enabled,
        )));

        // New container with None
        ctx.set_event_recipient(
            "threshold_keyshare",
            Some(
                ThresholdKeyshare::new(ThresholdKeyshareParams {
                    bus: self.bus.clone(),
                    cipher: self.cipher.clone(),
                    state: container,
                    share_enc_preset: meta
                        .params_preset
                        .dkg_counterpart()
                        .unwrap_or(meta.params_preset),
                })
                .start()
                .into(),
            ),
        );
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        // No keyshare on the snapshot -> bail
        if !snapshot.contains("threshold_keyshare") {
            return Ok(());
        };
        // Get the saved state as a persistable
        let state = ctx
            .repositories()
            .threshold_keyshare(&snapshot.e3_id)
            .load()
            .await?;

        // No Snapshot returned from the state -> bail
        if !state.has() {
            return Ok(());
        };

        // Derive DKG preset from persisted E3Meta
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            return Err(anyhow!(ERROR_KEYSHARE_META_MISSING));
        };
        let share_enc_preset = meta
            .params_preset
            .dkg_counterpart()
            .unwrap_or(meta.params_preset);

        // Construct from snapshot
        let value = ThresholdKeyshare::new(ThresholdKeyshareParams {
            bus: self.bus.clone(),
            cipher: self.cipher.clone(),
            state,
            share_enc_preset,
        })
        .start()
        .into();

        // send to context
        ctx.set_event_recipient("threshold_keyshare", Some(value));

        Ok(())
    }
}
