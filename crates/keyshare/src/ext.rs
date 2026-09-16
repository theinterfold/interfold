// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    DkgTimingReader, ThresholdKeyshare, ThresholdKeyshareParams, ThresholdKeyshareRecoveryPayloads,
    ThresholdKeyshareRecoveryState, ThresholdKeyshareRepositoryFactory, ThresholdKeyshareState,
    THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
};
use actix::Actor;
use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, RepositoriesFactory};
use e3_events::{prelude::*, BusHandle, EType, InterfoldEvent, InterfoldEventData, TypedEvent};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};

use crate::KeyshareState;
use std::{collections::HashMap, sync::Arc};

pub struct ThresholdKeyshareExtension {
    bus: BusHandle,
    cipher: Arc<Cipher>,
    address: String,
    interfold_addresses: HashMap<u64, Address>,
    dkg_timing_reader: DkgTimingReader,
    signer: PrivateKeySigner,
}

impl ThresholdKeyshareExtension {
    pub fn create(
        bus: &BusHandle,
        cipher: &Arc<Cipher>,
        address: &str,
        interfold_addresses: HashMap<u64, Address>,
        dkg_timing_reader: DkgTimingReader,
        signer: PrivateKeySigner,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            cipher: cipher.to_owned(),
            address: address.to_owned(),
            interfold_addresses,
            dkg_timing_reader,
            signer,
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
        let Some(interfold_address) = self.interfold_addresses.get(&e3_id.chain_id()).copied()
        else {
            self.bus.err(
                EType::KeyGeneration,
                anyhow!(
                    "Interfold address not configured for chain {}",
                    e3_id.chain_id()
                ),
            );
            return;
        };
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
        )));
        let recovery = ctx
            .repositories()
            .threshold_keyshare_recovery(&e3_id)
            .send(Some(ThresholdKeyshareRecoveryState {
                ciphernode_selected: Some(TypedEvent::new(data.clone(), evt.get_ctx().clone())),
                last_ec: Some(evt.get_ctx().clone()),
                ..Default::default()
            }));
        let recovery_payloads = ThresholdKeyshareRecoveryPayloads::new(
            ctx.repositories()
                .threshold_keyshare_recovery_payloads(&e3_id),
        );

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
                    interfold_address,
                    recovery,
                    recovery_payloads,
                    dkg_timing_reader: self.dkg_timing_reader.clone(),
                    signer: self.signer.clone(),
                    effects_enabled: true,
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
        let recovery = ctx
            .repositories()
            .threshold_keyshare_recovery(&snapshot.e3_id)
            .load()
            .await?;
        ensure!(
            recovery.has(),
            "threshold-keyshare for E3 {} has no restart recovery record",
            snapshot.e3_id
        );
        ensure!(
            recovery.get().is_some_and(|value| {
                value.schema_version == THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION
            }),
            "unsupported threshold-keyshare recovery schema for E3 {}",
            snapshot.e3_id
        );
        let recovery_value = recovery
            .get()
            .context("threshold-keyshare recovery record disappeared during hydration")?;
        let recovery_payloads = ThresholdKeyshareRecoveryPayloads::load(
            ctx.repositories()
                .threshold_keyshare_recovery_payloads(&snapshot.e3_id),
            &recovery_value,
        )
        .await?;

        // Derive DKG preset from persisted E3Meta
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            return Err(anyhow!(ERROR_KEYSHARE_META_MISSING));
        };
        let share_enc_preset = meta
            .params_preset
            .dkg_counterpart()
            .unwrap_or(meta.params_preset);
        let interfold_address = self
            .interfold_addresses
            .get(&snapshot.e3_id.chain_id())
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "Interfold address not configured for chain {}",
                    snapshot.e3_id.chain_id()
                )
            })?;

        // Construct from snapshot
        let value = ThresholdKeyshare::new(ThresholdKeyshareParams {
            bus: self.bus.clone(),
            cipher: self.cipher.clone(),
            state,
            share_enc_preset,
            interfold_address,
            recovery,
            recovery_payloads,
            dkg_timing_reader: self.dkg_timing_reader.clone(),
            signer: self.signer.clone(),
            effects_enabled: false,
        })
        .start()
        .into();

        // send to context
        ctx.set_event_recipient("threshold_keyshare", Some(value));

        Ok(())
    }
}
