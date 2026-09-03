// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `E3Extension` that constructs (and hydrates) the per-E3
//! `ThresholdKeyshare` actor.

use crate::actors::threshold_keyshare::effects::ckks_ceremony_log::CeremonyChunkLog;
use crate::{
    CkksCeremonyRecovery, ThresholdKeyshare, ThresholdKeyshareParams,
    ThresholdKeyshareRecoveryState, ThresholdKeyshareRepositoryFactory, ThresholdKeyshareState,
    THRESHOLD_KEYSHARE_RECOVERY_SCHEMA_VERSION,
};
use actix::Actor;
use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, RepositoriesFactory};
use e3_events::{prelude::*, BusHandle, EType, InterfoldEvent, InterfoldEventData, TypedEvent};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, META_KEY};
use std::path::PathBuf;

use crate::KeyshareState;
use std::{collections::HashMap, sync::Arc};

/// Builds a `ThresholdKeyshare` actor for every `CiphernodeSelected` E3
/// on this node and re-hydrates it on restart.
pub struct ThresholdKeyshareExtension {
    bus: BusHandle,
    cipher: Arc<Cipher>,
    address: String,
    interfold_addresses: HashMap<u64, Address>,
    /// Node-local directory for CKKS artifacts (joint relin keys). `None`
    /// on nodes without a persistent data dir (in-process tests).
    ckks_artifacts_dir: Option<PathBuf>,
    /// The ZK backend's circuits directory: the fail-closed CKKS artifact
    /// gate checks every circuit the E3's proof posture needs is staged
    /// here at `CiphernodeSelected`. `None` = no ZK backend (in-process
    /// tests): the presence check is skipped, the posture still applies.
    zk_circuits_dir: Option<PathBuf>,
}

impl ThresholdKeyshareExtension {
    /// Create the extension. `ckks_artifacts_dir` is where the node writes
    /// CKKS ceremony outputs (derived from its data dir by the builder).
    pub fn create(
        bus: &BusHandle,
        cipher: &Arc<Cipher>,
        address: &str,
        interfold_addresses: HashMap<u64, Address>,
        ckks_artifacts_dir: Option<PathBuf>,
    ) -> Box<Self> {
        Self::create_with_circuits(
            bus,
            cipher,
            address,
            interfold_addresses,
            ckks_artifacts_dir,
            None,
        )
    }

    /// [`Self::create`] with the ZK backend's circuits directory for the
    /// fail-closed CKKS artifact gate.
    pub fn create_with_circuits(
        bus: &BusHandle,
        cipher: &Arc<Cipher>,
        address: &str,
        interfold_addresses: HashMap<u64, Address>,
        ckks_artifacts_dir: Option<PathBuf>,
        zk_circuits_dir: Option<PathBuf>,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            cipher: cipher.to_owned(),
            address: address.to_owned(),
            interfold_addresses,
            ckks_artifacts_dir,
            zk_circuits_dir,
        })
    }
}

const ERROR_KEYSHARE_META_MISSING: &str =
    "Could not create ThresholdKeyshare because the meta instance it depends on was not set on the context.";

/// Resolve the DKG share-transport preset for this E3 — a PURE function of
/// the persisted `E3Meta`, so every node (and every restart) derives the
/// same preset. BFV E3s keep the plain `dkg_counterpart()`. CKKS E3s
/// escalate to the WIDE transport preset when any CKKS ciphertext modulus
/// exceeds the standard counterpart's plaintext modulus (dealt share
/// coefficients travel as BFV plaintexts mod `t_dkg`; the sign-extraction
/// ladder's 45-bit base needs `InsecureDkgWide512`). The zk-prover's
/// `ProofVerificationActor` derives the same value from the same inputs.
fn share_enc_preset_for_meta(meta: &e3_request::E3Meta) -> Result<e3_fhe_params::BfvPreset> {
    let standard = meta
        .params_preset
        .dkg_counterpart()
        .unwrap_or(meta.params_preset);
    if meta.scheme != e3_events::E3Scheme::Ckks {
        return Ok(standard);
    }
    e3_fhe_params::ckks_presets::ckks_dkg_transport_preset_from_bytes(standard, &meta.params)
        .map_err(|e| anyhow!("no DKG transport preset carries this CKKS ladder: {e}"))
}

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
        let share_enc_preset = match share_enc_preset_for_meta(meta) {
            Ok(preset) => preset,
            Err(e) => {
                self.bus.err(EType::KeyGeneration, e);
                return;
            }
        };
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
        // Fresh E3: an empty ceremony log (CKKS only; harmless for BFV).
        let ckks_ceremony =
            (meta.scheme == e3_events::E3Scheme::Ckks).then(|| CkksCeremonyRecovery {
                log: CeremonyChunkLog::fresh(
                    ctx.repositories().threshold_keyshare_ckks_ceremony(&e3_id),
                ),
                replay: Vec::new(),
            });

        // New container with None
        ctx.set_event_recipient(
            "threshold_keyshare",
            Some(
                ThresholdKeyshare::new(ThresholdKeyshareParams {
                    bus: self.bus.clone(),
                    cipher: self.cipher.clone(),
                    state: container,
                    share_enc_preset,
                    interfold_address,
                    recovery,
                    ckks_artifacts_dir: self.ckks_artifacts_dir.clone(),
                    zk_circuits_dir: self.zk_circuits_dir.clone(),
                    ckks_ceremony,
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

        // Derive DKG preset from persisted E3Meta
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            return Err(anyhow!(ERROR_KEYSHARE_META_MISSING));
        };
        let share_enc_preset = share_enc_preset_for_meta(meta)?;
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
        // CKKS: load the durable ceremony chunk log so a restart
        // mid-ceremony can re-feed the machine's non-snapshot buffers.
        let ckks_ceremony = if meta.scheme == e3_events::E3Scheme::Ckks {
            let (log, replay) = CeremonyChunkLog::open(
                ctx.repositories()
                    .threshold_keyshare_ckks_ceremony(&snapshot.e3_id),
            )
            .await?;
            Some(CkksCeremonyRecovery { log, replay })
        } else {
            None
        };

        // Construct from snapshot
        let value = ThresholdKeyshare::new(ThresholdKeyshareParams {
            bus: self.bus.clone(),
            cipher: self.cipher.clone(),
            state,
            share_enc_preset,
            interfold_address,
            recovery,
            ckks_artifacts_dir: self.ckks_artifacts_dir.clone(),
            zk_circuits_dir: self.zk_circuits_dir.clone(),
            ckks_ceremony,
        })
        .start()
        .into();

        // send to context
        ctx.set_event_recipient("threshold_keyshare", Some(value));

        Ok(())
    }
}
