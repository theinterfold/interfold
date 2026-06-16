// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::sync::Arc;

use crate::actors::DecryptionshareCreatedBuffer;
use crate::actors::KeyshareCreatedFilterBuffer;
use crate::domain::committee::committee_addresses_from_nodes;
use crate::{
    PublicKeyAggregator, PublicKeyAggregatorParams, PublicKeyAggregatorState,
    PublicKeyRepositoryFactory, ThresholdPlaintextAggregator, ThresholdPlaintextAggregatorParams,
    ThresholdPlaintextAggregatorState, TrBfvPlaintextRepositoryFactory,
};
use actix::{Actor, Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use e3_data::{AutoPersist, Persistable, RepositoriesFactory};
use e3_events::{prelude::*, CiphernodeSelected, E3id};
use e3_events::{BusHandle, EType, InterfoldEvent, InterfoldEventData};
use e3_fhe::ext::FHE_KEY;
use e3_fhe::Fhe;
use e3_fhe_params::BfvPreset;
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, TypedKey, META_KEY};
use e3_sortition::Sortition;
use e3_zk_helpers::CiphernodesCommitteeSize;

/// Full finalized committee (`PublicKeyAggregated.committee_addresses`, length `N`)
/// for `committee_hash_*` binding in downstream ZK requests.
pub const COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> = TypedKey::new("committee_addresses");

/// Honest subset of the committee (`PublicKeyAggregated.honest_committee_addresses`, length `H`)
/// for decryption-share collection gating.
pub const HONEST_COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> =
    TypedKey::new("honest_committee_addresses");

pub struct PublicKeyAggregatorExtension {
    bus: BusHandle,
}

impl PublicKeyAggregatorExtension {
    pub fn create(bus: &BusHandle) -> Box<Self> {
        Box::new(Self { bus: bus.clone() })
    }
}

const ERROR_PUBKEY_FHE_MISSING:&str = "Could not create PublicKeyAggregator because the fhe instance it depends on was not set on the context.";
const ERROR_PUBKEY_META_MISSING:&str = "Could not create PublicKeyAggregator because the meta instance it depends on was not set on the context.";

#[async_trait]
impl E3Extension for PublicKeyAggregatorExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        // Create the public-key aggregation pipeline only for finalized committee members.
        let InterfoldEventData::CiphernodeSelected(data) = evt.get_data() else {
            return;
        };

        if ctx.get_event_recipient("publickey").is_some() {
            return;
        }

        let Some(fhe) = ctx.get_dependency(FHE_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_FHE_MISSING),
            );
            return;
        };
        let CiphernodeSelected {
            e3_id,
            threshold_n,
            threshold_m,
            seed,
            params_preset,
            ..
        } = data.clone();
        let repo = ctx.repositories().publickey(&e3_id);
        let sync_state = repo.send(Some(PublicKeyAggregatorState::init(
            threshold_n,
            threshold_m,
            seed,
        )));

        let committee_size = match CiphernodesCommitteeSize::from_threshold(
            threshold_m,
            threshold_n,
        ) {
            Ok(c) => c,
            Err(e) => {
                self.bus.err(
                    EType::PublickeyAggregation,
                    anyhow!("Unknown committee size for E3 {e3_id} (threshold_m={threshold_m}, threshold_n={threshold_n}): {e}"),
                );
                return;
            }
        };
        let value = create_publickey_aggregator(
            fhe.clone(),
            self.bus.clone(),
            e3_id,
            sync_state,
            params_preset,
            committee_size,
        );

        ctx.set_event_recipient("publickey", Some(value));
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        // No ID on the snapshot -> bail
        if !snapshot.contains("publickey") {
            return Ok(());
        };

        let repo = ctx.repositories().publickey(&ctx.e3_id);
        let sync_state = repo.load().await?;

        // No Snapshot returned from the store -> bail
        if !sync_state.has() {
            return Ok(());
        };

        // Get deps
        let Some(fhe) = ctx.get_dependency(FHE_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_FHE_MISSING),
            );

            return Ok(());
        };
        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow!(ERROR_PUBKEY_META_MISSING),
            );

            return Ok(());
        };
        let committee_size =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n).map_err(
                |e| {
                    anyhow!(
                        "Unknown committee size (threshold_m={}, threshold_n={}): {e}",
                        meta.threshold_m,
                        meta.threshold_n
                    )
                },
            )?;
        let value = create_publickey_aggregator(
            fhe.clone(),
            self.bus.clone(),
            ctx.e3_id.clone(),
            sync_state,
            meta.params_preset,
            committee_size,
        );

        // send to context
        ctx.set_event_recipient("publickey", Some(value));

        Ok(())
    }
}

fn create_publickey_aggregator(
    fhe: Arc<Fhe>,
    bus: BusHandle,
    e3_id: E3id,
    sync_state: Persistable<PublicKeyAggregatorState>,
    params_preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> Recipient<InterfoldEvent> {
    KeyshareCreatedFilterBuffer::new(
        PublicKeyAggregator::new(
            PublicKeyAggregatorParams {
                fhe,
                bus,
                e3_id,
                params_preset,
                committee_size,
            },
            sync_state,
        )
        .start(),
    )
    .start()
    .into()
}

pub struct ThresholdPlaintextAggregatorExtension {
    bus: BusHandle,
    sortition: Addr<Sortition>,
}

impl ThresholdPlaintextAggregatorExtension {
    pub fn create(bus: &BusHandle, sortition: &Addr<Sortition>) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            sortition: sortition.clone(),
        })
    }
}

const ERROR_TRBFV_PLAINTEXT_META_MISSING:&str = "Could not create ThresholdPlaintextAggregator because the meta instance it depends on was not set on the context.";
const ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because committee addresses were not set (expected PublicKeyAggregated before CiphertextOutputPublished).";
const ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because honest committee addresses were not set (expected non-empty PublicKeyAggregated.honest_committee_addresses).";

fn load_committee_addresses(ctx: &E3Context, e3_id: &E3id) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(COMMITTEE_ADDRESSES_KEY) {
        return Ok(addrs.clone());
    }
    // Restart/hydrate path: read from persisted public-key aggregator state.
    let repo = ctx.repositories().publickey(e3_id);
    let state = futures::executor::block_on(repo.read())?;
    let Some(state) = state else {
        return Err(anyhow!(ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING));
    };
    if let Some(addrs) = state.committee_addresses() {
        return Ok(addrs.to_vec());
    }
    let nodes = state
        .committee_nodes()
        .ok_or_else(|| anyhow!(ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING))?;
    committee_addresses_from_nodes(nodes)
}

fn load_honest_committee_addresses(ctx: &E3Context, e3_id: &E3id) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY) {
        if addrs.is_empty() {
            return Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING));
        }
        return Ok(addrs.clone());
    }
    let repo = ctx.repositories().publickey(e3_id);
    let state = futures::executor::block_on(repo.read())?;
    let Some(state) = state else {
        return Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING));
    };
    if let Some(addrs) = state.honest_committee_addresses() {
        return Ok(addrs.to_vec());
    }
    Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING))
}

#[async_trait]
impl E3Extension for ThresholdPlaintextAggregatorExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        if let InterfoldEventData::PublicKeyAggregated(data) = evt.get_data() {
            let addrs = if !data.committee_addresses.is_empty() {
                Ok(data.committee_addresses.clone())
            } else {
                committee_addresses_from_nodes(&data.nodes)
            };
            match addrs {
                Ok(addrs) => {
                    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs);
                    if data.honest_committee_addresses.is_empty() {
                        self.bus.err(
                            EType::PlaintextAggregation,
                            anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING),
                        );
                        return;
                    }
                    ctx.set_dependency(
                        HONEST_COMMITTEE_ADDRESSES_KEY,
                        data.honest_committee_addresses.clone(),
                    );
                }
                Err(e) => {
                    self.bus.err(EType::PlaintextAggregation, e);
                }
            }
            return;
        }

        if ctx.get_event_recipient("threshold_keyshare").is_none() {
            return;
        }

        if ctx.get_event_recipient("plaintext").is_some() {
            return;
        }

        // Save plaintext aggregator for finalized committee members.
        let InterfoldEventData::CiphertextOutputPublished(data) = evt.get_data() else {
            return;
        };

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );
            return;
        };

        let e3_id = data.e3_id.clone();
        let committee_addresses = match load_committee_addresses(ctx, &e3_id) {
            Ok(addrs) => addrs,
            Err(e) => {
                self.bus.err(EType::PlaintextAggregation, e);
                return;
            }
        };
        let honest_committee_addresses = match load_honest_committee_addresses(ctx, &e3_id) {
            Ok(addrs) => addrs,
            Err(e) => {
                self.bus.err(EType::PlaintextAggregation, e);
                return;
            }
        };

        let repo = ctx.repositories().trbfv_plaintext(&e3_id);
        let sync_state = repo.send(Some(ThresholdPlaintextAggregatorState::init(
            meta.threshold_m as u64,
            meta.threshold_n as u64,
            meta.seed,
            data.ciphertext_output.clone(),
            meta.params.clone(),
        )));

        ctx.set_event_recipient(
            "plaintext",
            Some(
                DecryptionshareCreatedBuffer::new(
                    ThresholdPlaintextAggregator::new(
                        ThresholdPlaintextAggregatorParams {
                            bus: self.bus.clone(),
                            sortition: self.sortition.clone(),
                            e3_id: e3_id.clone(),
                            params_preset: meta.params_preset,
                            committee_size: match CiphernodesCommitteeSize::from_threshold(
                                meta.threshold_m,
                                meta.threshold_n,
                            ) {
                                Ok(c) => c,
                                Err(e) => {
                                    self.bus.err(
                                        EType::PlaintextAggregation,
                                        anyhow!("Unknown committee size for E3 {e3_id} (threshold_m={}, threshold_n={}): {e}", meta.threshold_m, meta.threshold_n),
                                    );
                                    return;
                                }
                            },
                            proof_aggregation_enabled: meta.proof_aggregation_enabled,
                            committee_addresses,
                            honest_committee_addresses,
                        },
                        sync_state,
                    )
                    .start(),
                )
                .start()
                .into(),
            ),
        );
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        // No ID on the snapshot -> bail
        if !snapshot.contains("plaintext") {
            return Ok(());
        }

        let repo = ctx.repositories().trbfv_plaintext(&snapshot.e3_id);
        let sync_state = repo.load().await?;

        // No Snapshot returned from the store -> bail
        if !sync_state.has() {
            return Ok(());
        };

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );

            return Ok(());
        };

        let committee_addresses = load_committee_addresses(ctx, &ctx.e3_id)?;
        let honest_committee_addresses = load_honest_committee_addresses(ctx, &ctx.e3_id)?;

        let value = ThresholdPlaintextAggregator::new(
            ThresholdPlaintextAggregatorParams {
                bus: self.bus.clone(),
                sortition: self.sortition.clone(),
                e3_id: ctx.e3_id.clone(),
                params_preset: meta.params_preset,
                committee_size: CiphernodesCommitteeSize::from_threshold(
                    meta.threshold_m,
                    meta.threshold_n,
                )
                .map_err(|e| {
                    anyhow!(
                        "Unknown committee size (threshold_m={}, threshold_n={}): {e}",
                        meta.threshold_m,
                        meta.threshold_n
                    )
                })?,
                proof_aggregation_enabled: meta.proof_aggregation_enabled,
                committee_addresses,
                honest_committee_addresses,
            },
            sync_state,
        )
        .start();

        // send to context
        ctx.set_event_recipient(
            "plaintext",
            Some(DecryptionshareCreatedBuffer::new(value).start().into()),
        );

        Ok(())
    }
}
