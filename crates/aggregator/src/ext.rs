// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::actors::DecryptionshareCreatedBuffer;
use crate::actors::KeyshareCreatedFilterBuffer;
use crate::domain::committee::{
    committee_addresses_from_nodes, committee_addresses_in_party_order,
};
use crate::{
    PublicKeyAggregator, PublicKeyAggregatorParams, PublicKeyAggregatorRecoveryState,
    PublicKeyAggregatorState, PublicKeyRepositoryFactory, ThresholdPlaintextAggregator,
    ThresholdPlaintextAggregatorParams, ThresholdPlaintextAggregatorState,
    TrBfvPlaintextRepositoryFactory, PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION,
    THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
};
use actix::{Actor, Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use e3_data::{AutoPersist, Persistable, RepositoriesFactory};
use e3_events::{
    prelude::*, CiphernodeSelected, CiphertextOutputPublished, E3id, EventContext, Sequenced,
};
use e3_events::{BusHandle, EType, InterfoldEvent, InterfoldEventData};
use e3_fhe::ext::FHE_KEY;
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_request::{
    E3Context, E3ContextSnapshot, E3Extension, TypedKey, DKG_FOLD_ATTESTATION_CONTEXT_KEY, META_KEY,
};
use e3_sortition::{FinalizedCommitteesRepositoryFactory, Sortition};
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::{BTreeSet, HashMap};

/// Full finalized committee (`PublicKeyAggregated.committee_addresses`, length `N`)
/// for `committee_hash_*` binding in downstream ZK requests.
pub const COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> = TypedKey::new("committee_addresses");

/// Honest subset of the committee (`PublicKeyAggregated.honest_committee_addresses`, length `H`)
/// for decryption-share collection gating.
pub const HONEST_COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> =
    TypedKey::new("honest_committee_addresses");
const ACTIVE_AGGREGATOR_KEY: TypedKey<bool> = TypedKey::new("active_aggregator");
const PENDING_CIPHERTEXT_OUTPUT_KEY: TypedKey<CiphertextOutputPublished> =
    TypedKey::new("pending_ciphertext_output");
const HONEST_PARTY_IDS_KEY: TypedKey<BTreeSet<u64>> = TypedKey::new("honest_party_ids");

/// Restores the selector's active-aggregator decision before per-E3 actors hydrate.
///
/// The selector owns this derived role. Passing its recovered snapshot into the context avoids
/// creating a new durable `AggregatorChanged` event on every process start.
pub struct AggregatorRoleExtension {
    initial_roles: HashMap<E3id, bool>,
}

impl AggregatorRoleExtension {
    pub fn create(initial_roles: HashMap<E3id, bool>) -> Box<Self> {
        Box::new(Self { initial_roles })
    }
}

#[async_trait]
impl E3Extension for AggregatorRoleExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        if let InterfoldEventData::AggregatorChanged(data) = evt.get_data() {
            ctx.set_dependency(ACTIVE_AGGREGATOR_KEY, data.is_aggregator);
        }
    }

    async fn hydrate(&self, ctx: &mut E3Context, _snapshot: &E3ContextSnapshot) -> Result<()> {
        if let Some(is_aggregator) = self.initial_roles.get(&ctx.e3_id).copied() {
            ctx.set_dependency(ACTIVE_AGGREGATOR_KEY, is_aggregator);
        }
        Ok(())
    }
}

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

        let Some(fhe) = ctx.get_dependency(FHE_KEY).cloned() else {
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
            committee,
            ..
        } = data.clone();
        let dkg_fold_attestation_context = ctx
            .get_dependency(DKG_FOLD_ATTESTATION_CONTEXT_KEY)
            .copied();
        let committee_addresses = match committee_addresses_from_node_strings(&committee) {
            Ok(addresses) if addresses.len() == threshold_n => addresses,
            Ok(addresses) => {
                self.bus.err(
                    EType::PublickeyAggregation,
                    anyhow!(
                        "Could not create PublicKeyAggregator for E3 {e3_id}: selected event has {} committee addresses; expected {threshold_n}.",
                        addresses.len()
                    ),
                );
                return;
            }
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, committee_addresses.clone());
        let canonical_party_nodes = party_nodes_from_committee_addresses(&committee_addresses);
        let repo = ctx.repositories().publickey(&e3_id);
        let sync_state = repo.send(Some(PublicKeyAggregatorState::init(
            threshold_n,
            threshold_m,
            seed,
            canonical_party_nodes,
        )));
        let recovery = ctx
            .repositories()
            .publickey_recovery(&e3_id)
            .send(Some(PublicKeyAggregatorRecoveryState::default()));

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
            PublicKeyAggregatorParams {
                fhe,
                bus: self.bus.clone(),
                e3_id,
                params_preset,
                committee_size,
                dkg_fold_attestation_context,
                recovery,
                initial_is_aggregator: load_is_active_aggregator(ctx),
                effects_enabled: true,
            },
            sync_state,
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
        let recovered_state = sync_state.try_get()?;
        remember_committee_dependencies_from_publickey_state(ctx, &recovered_state)?;
        let recovery_repo = ctx.repositories().publickey_recovery(&ctx.e3_id);
        let recovery = recovery_repo.load().await?;
        let recovery = if recovery.has() {
            recovery
        } else {
            ensure!(
                !matches!(recovered_state, PublicKeyAggregatorState::Complete { .. }),
                "public-key aggregation for E3 {} completed without a recovery publication record",
                ctx.e3_id
            );
            recovery_repo.send(Some(PublicKeyAggregatorRecoveryState::default()))
        };
        ensure!(
            recovery.get().is_some_and(
                |state| state.schema_version == PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION
            ),
            "unsupported public-key recovery schema for E3 {}",
            ctx.e3_id
        );

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
            PublicKeyAggregatorParams {
                fhe: fhe.clone(),
                bus: self.bus.clone(),
                e3_id: ctx.e3_id.clone(),
                params_preset: meta.params_preset,
                committee_size,
                dkg_fold_attestation_context: ctx
                    .get_dependency(DKG_FOLD_ATTESTATION_CONTEXT_KEY)
                    .copied(),
                recovery,
                initial_is_aggregator: load_is_active_aggregator(ctx),
                effects_enabled: false,
            },
            sync_state,
        );

        // send to context
        ctx.set_event_recipient("publickey", Some(value));

        Ok(())
    }
}

fn create_publickey_aggregator(
    params: PublicKeyAggregatorParams,
    sync_state: Persistable<PublicKeyAggregatorState>,
) -> Recipient<InterfoldEvent> {
    KeyshareCreatedFilterBuffer::new(PublicKeyAggregator::new(params, sync_state).start())
        .start()
        .into()
}

pub struct ThresholdPlaintextAggregatorExtension {
    bus: BusHandle,
    sortition: Addr<Sortition>,
    proof_aggregation_enabled: bool,
}

impl ThresholdPlaintextAggregatorExtension {
    pub fn create(
        bus: &BusHandle,
        sortition: &Addr<Sortition>,
        proof_aggregation_enabled: bool,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            sortition: sortition.clone(),
            proof_aggregation_enabled,
        })
    }

    fn try_start_plaintext(
        &self,
        ctx: &mut E3Context,
        data: &CiphertextOutputPublished,
        ec: &EventContext<Sequenced>,
    ) -> bool {
        if ctx.get_event_recipient("threshold_keyshare").is_none() {
            tracing::warn!(
                e3_id = %data.e3_id,
                "Deferring ThresholdPlaintextAggregator creation: threshold_keyshare recipient is not ready"
            );
            return false;
        }

        if ctx.get_event_recipient("plaintext").is_some() {
            return true;
        }

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );
            return false;
        };

        let e3_id = data.e3_id.clone();
        let committee_addresses = match load_committee_addresses(ctx) {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!(
                    e3_id = %e3_id,
                    "Deferring ThresholdPlaintextAggregator creation: {e}"
                );
                return false;
            }
        };
        let honest_committee_addresses = match load_honest_committee_addresses(ctx) {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::warn!(
                    e3_id = %e3_id,
                    "Deferring ThresholdPlaintextAggregator creation: {e}"
                );
                return false;
            }
        };
        let initial_is_aggregator = load_is_active_aggregator(ctx);

        let repo = ctx.repositories().trbfv_plaintext(&e3_id);
        let sync_state = repo.send(Some(ThresholdPlaintextAggregatorState::init(
            meta.threshold_m as u64,
            meta.threshold_n as u64,
            meta.seed,
            data.ciphertext_output.clone(),
            meta.params.clone(),
        )));
        let recovery = ctx
            .repositories()
            .trbfv_plaintext_recovery(&e3_id)
            .send(Some(crate::new_threshold_plaintext_recovery(ec.clone())));

        ctx.set_event_recipient(
            "plaintext",
            Some(create_decryptionshare_buffer(
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
                                return false;
                            }
                        },
                        proof_aggregation_enabled: self.proof_aggregation_enabled,
                        initial_is_aggregator,
                        effects_enabled: true,
                        committee_addresses,
                        honest_committee_addresses,
                        recovery,
                    },
                    sync_state,
                )
                .start(),
            )),
        );

        true
    }
}

const ERROR_TRBFV_PLAINTEXT_META_MISSING:&str = "Could not create ThresholdPlaintextAggregator because the meta instance it depends on was not set on the context.";
const ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because committee addresses were not set (expected PublicKeyAggregated or CommitteePublished before CiphertextOutputPublished).";
const ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because honest committee addresses were not set (expected non-empty PublicKeyAggregated.honest_committee_addresses or recovered public-key state).";

fn load_committee_addresses(ctx: &E3Context) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(COMMITTEE_ADDRESSES_KEY) {
        return Ok(addrs.clone());
    }
    Err(anyhow!(ERROR_TRBFV_PLAINTEXT_COMMITTEE_MISSING))
}

fn load_honest_committee_addresses(ctx: &E3Context) -> Result<Vec<Address>> {
    if let Some(addrs) = ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY) {
        if addrs.is_empty() {
            return Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING));
        }
        return Ok(addrs.clone());
    }
    Err(anyhow!(ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING))
}

fn addresses_for_sorted_party_ids(party_nodes: &HashMap<u64, String>) -> Result<Vec<Address>> {
    let mut party_ids: Vec<u64> = party_nodes.keys().copied().collect();
    party_ids.sort_unstable();
    committee_addresses_in_party_order(&party_ids, party_nodes)
}

fn party_nodes_from_committee_addresses(committee_addresses: &[Address]) -> HashMap<u64, String> {
    committee_addresses
        .iter()
        .enumerate()
        .map(|(party_id, node)| (party_id as u64, node.to_string()))
        .collect()
}

fn publickey_state_committee_addresses(
    state: &PublicKeyAggregatorState,
) -> Result<Option<Vec<Address>>> {
    match state {
        PublicKeyAggregatorState::Complete {
            committee_addresses,
            ..
        } if !committee_addresses.is_empty() => Ok(Some(committee_addresses.clone())),
        PublicKeyAggregatorState::GeneratingC5Proof { party_nodes, .. }
            if !party_nodes.is_empty() =>
        {
            Ok(Some(addresses_for_sorted_party_ids(party_nodes)?))
        }
        PublicKeyAggregatorState::Collecting {
            canonical_party_nodes,
            ..
        }
        | PublicKeyAggregatorState::VerifyingC1 {
            canonical_party_nodes,
            ..
        } if !canonical_party_nodes.is_empty() => {
            Ok(Some(addresses_for_sorted_party_ids(canonical_party_nodes)?))
        }
        _ => Ok(None),
    }
}

fn publickey_state_honest_committee_addresses(
    state: &PublicKeyAggregatorState,
) -> Result<Option<Vec<Address>>> {
    match state {
        PublicKeyAggregatorState::Complete {
            honest_committee_addresses,
            ..
        } if !honest_committee_addresses.is_empty() => Ok(Some(honest_committee_addresses.clone())),
        PublicKeyAggregatorState::GeneratingC5Proof {
            party_nodes,
            honest_party_ids,
            ..
        } if !honest_party_ids.is_empty() => {
            let party_ids: Vec<u64> = honest_party_ids.iter().copied().collect();
            Ok(Some(committee_addresses_in_party_order(
                &party_ids,
                party_nodes,
            )?))
        }
        _ => Ok(None),
    }
}

fn honest_addresses_from_party_ids(
    committee_addresses: &[Address],
    honest_party_ids: &BTreeSet<u64>,
) -> Result<Vec<Address>> {
    ensure!(
        !honest_party_ids.is_empty(),
        "cannot recover honest committee from an empty honest party set"
    );

    honest_party_ids
        .iter()
        .map(|party_id| {
            let index = usize::try_from(*party_id)
                .map_err(|_| anyhow!("party_id {party_id} does not fit in usize"))?;
            committee_addresses.get(index).copied().ok_or_else(|| {
                anyhow!(
                    "honest party_id {party_id} is out of bounds for committee of {} nodes",
                    committee_addresses.len()
                )
            })
        })
        .collect()
}

fn committee_addresses_from_node_strings(nodes: &[String]) -> Result<Vec<Address>> {
    nodes
        .iter()
        .map(|node| {
            node.parse::<Address>()
                .map_err(|e| anyhow!("invalid committee node address {node}: {e}"))
        })
        .collect()
}

fn remember_committee_dependencies_from_publickey_state(
    ctx: &mut E3Context,
    state: &PublicKeyAggregatorState,
) -> Result<()> {
    if let Some(addrs) = publickey_state_committee_addresses(state)? {
        ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs);
    }
    if let Some(addrs) = publickey_state_honest_committee_addresses(state)? {
        ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, addrs);
    }
    Ok(())
}

async fn recover_committee_dependencies_from_publickey_state(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    let repo = ctx.repositories().publickey(e3_id);
    if let Some(state) = repo.read().await? {
        remember_committee_dependencies_from_publickey_state(ctx, &state)?;
    }
    Ok(())
}

async fn recover_committee_dependencies_from_sortition_state(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    if ctx.get_dependency(COMMITTEE_ADDRESSES_KEY).is_some() {
        return Ok(());
    }

    let repo = ctx.repositories().finalized_committees();
    let Some(committees) = repo.read().await? else {
        return Ok(());
    };
    let Some(committee) = committees.get(e3_id) else {
        return Ok(());
    };

    let addresses = committee_addresses_from_node_strings(committee.members())?;
    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addresses);
    Ok(())
}

async fn recover_honest_committee_dependencies_from_keyshare_state(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    let repo = ctx.repositories().threshold_keyshare(e3_id);
    let Some(state) = repo.read().await? else {
        return Ok(());
    };
    let Some(honest_party_ids) = state.honest_parties.clone() else {
        return Ok(());
    };

    ctx.set_dependency(HONEST_PARTY_IDS_KEY, honest_party_ids);
    remember_honest_committee_from_cached_party_ids(ctx, e3_id)?;
    Ok(())
}

fn remember_honest_committee_from_cached_party_ids(
    ctx: &mut E3Context,
    e3_id: &E3id,
) -> Result<()> {
    if ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY).is_some() {
        return Ok(());
    }

    let Some(committee_addresses) = ctx.get_dependency(COMMITTEE_ADDRESSES_KEY).cloned() else {
        return Ok(());
    };
    let Some(honest_party_ids) = ctx.get_dependency(HONEST_PARTY_IDS_KEY).cloned() else {
        return Ok(());
    };

    let honest_committee_addresses =
        honest_addresses_from_party_ids(&committee_addresses, &honest_party_ids)?;
    tracing::info!(
        e3_id = %e3_id,
        honest_party_ids = ?honest_party_ids,
        honest_committee_len = honest_committee_addresses.len(),
        "Recovered honest committee addresses from persisted threshold keyshare state"
    );
    ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, honest_committee_addresses);
    Ok(())
}

fn remember_committee_published(ctx: &mut E3Context, e3_id: &E3id, nodes: &[String]) -> Result<()> {
    let addrs = committee_addresses_from_node_strings(nodes)?;
    let addrs_len = addrs.len();
    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs.clone());

    // In committees where every on-chain member is also part of the honest circuit set,
    // CommitteePublished is sufficient to recover the honest roster. For N > H we keep
    // the honest dependency from PublicKeyAggregated / public-key state.
    if let Some(meta) = ctx.get_dependency(META_KEY) {
        let committee =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)
                .map(|size| size.values());
        if committee.is_ok_and(|committee| committee.h == addrs_len) {
            ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, addrs);
        }
    }

    remember_honest_committee_from_cached_party_ids(ctx, e3_id)?;
    Ok(())
}

fn load_is_active_aggregator(ctx: &E3Context) -> bool {
    ctx.get_dependency(ACTIVE_AGGREGATOR_KEY)
        .copied()
        .unwrap_or(false)
}

fn create_decryptionshare_buffer(
    dest: Addr<ThresholdPlaintextAggregator>,
) -> Recipient<InterfoldEvent> {
    DecryptionshareCreatedBuffer::new(dest).start().into()
}

#[async_trait]
impl E3Extension for ThresholdPlaintextAggregatorExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        if let InterfoldEventData::AggregatorChanged(_) = evt.get_data() {
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
            }
            return;
        }

        if matches!(evt.get_data(), InterfoldEventData::CiphernodeSelected(_)) {
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
            }
            return;
        }

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
                    if let Some(ciphertext) =
                        ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned()
                    {
                        self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
                    }
                }
                Err(e) => {
                    self.bus.err(EType::PlaintextAggregation, e);
                }
            }
            return;
        }

        if let InterfoldEventData::CommitteePublished(data) = evt.get_data() {
            if let Err(e) = remember_committee_published(ctx, &data.e3_id, &data.nodes) {
                self.bus.err(EType::PlaintextAggregation, e);
            }
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
            }
            return;
        }

        // Save plaintext aggregator for finalized committee members.
        let InterfoldEventData::CiphertextOutputPublished(data) = evt.get_data() else {
            return;
        };
        ctx.set_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY, data.clone());
        self.try_start_plaintext(ctx, data, evt.get_ctx());
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        let e3_id = ctx.e3_id.clone();
        recover_committee_dependencies_from_sortition_state(ctx, &e3_id).await?;
        recover_committee_dependencies_from_publickey_state(ctx, &e3_id).await?;
        recover_honest_committee_dependencies_from_keyshare_state(ctx, &e3_id).await?;

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
        let recovery = ctx
            .repositories()
            .trbfv_plaintext_recovery(&snapshot.e3_id)
            .load()
            .await?;
        ensure!(
            recovery.has(),
            "plaintext aggregation for E3 {} has no restart recovery record",
            ctx.e3_id
        );
        ensure!(
            recovery.get().is_some_and(|state| {
                state.schema_version == THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION
            }),
            "unsupported plaintext recovery schema for E3 {}",
            ctx.e3_id
        );

        let Some(meta) = ctx.get_dependency(META_KEY) else {
            self.bus.err(
                EType::PlaintextAggregation,
                anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING),
            );

            return Ok(());
        };

        let committee_addresses = load_committee_addresses(ctx)?;
        let honest_committee_addresses = load_honest_committee_addresses(ctx)?;
        let initial_is_aggregator = load_is_active_aggregator(ctx);

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
                proof_aggregation_enabled: self.proof_aggregation_enabled,
                initial_is_aggregator,
                effects_enabled: false,
                committee_addresses,
                honest_committee_addresses,
                recovery,
            },
            sync_state,
        )
        .start();

        // send to context
        ctx.set_event_recipient("plaintext", Some(create_decryptionshare_buffer(value)));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use e3_data::{DataStore, InMemStore};
    use e3_events::{Committee, OrderedSet, Seed};
    use e3_fhe::Fhe;
    use e3_fhe_params::BfvPreset;
    use e3_request::{ContextRepositoryFactory, E3ContextParams, E3Meta};
    use e3_test_helpers::get_common_setup;
    use e3_utils::ArcBytes;
    use std::{
        collections::{BTreeSet, HashMap},
        sync::Arc,
    };

    fn generating_c5_state() -> PublicKeyAggregatorState {
        let party_nodes = HashMap::from([
            (
                2u64,
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            ),
            (
                0u64,
                "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".to_string(),
            ),
            (
                1u64,
                "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
            ),
        ]);

        PublicKeyAggregatorState::GeneratingC5Proof {
            public_key: ArcBytes::from_bytes(&[1, 2, 3]),
            keyshare_bytes: vec![],
            nodes: OrderedSet::new(),
            party_nodes,
            dkg_node_proofs: HashMap::new(),
            dkg_fold_attestations: HashMap::new(),
            honest_party_ids: BTreeSet::from([0, 2]),
            dishonest_parties: BTreeSet::from([1]),
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            dkg_aggregation_correlation: None,
            dkg_aggregated_proof: None,
            c5_proof_pending: None,
            last_ec: None,
            nodes_fold_accumulator: None,
            nodes_fold_completed_slots: 0,
            nodes_fold_step_correlation: None,
        }
    }

    #[test]
    fn recovers_full_committee_addresses_from_generating_c5_state() -> Result<()> {
        let state = generating_c5_state();

        let addresses = publickey_state_committee_addresses(&state)?.expect("addresses");

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn recovers_full_committee_addresses_from_collecting_state() -> Result<()> {
        let committee_addresses = vec![
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ];
        let state = PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            party_nodes_from_committee_addresses(&committee_addresses),
        );

        let recovered = publickey_state_committee_addresses(&state)?.expect("addresses");

        assert_eq!(recovered, committee_addresses);
        Ok(())
    }

    #[actix::test]
    async fn hydration_uses_the_recovered_role() -> Result<()> {
        let e3_id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut ctx = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        let snapshot = E3ContextSnapshot {
            e3_id: e3_id.clone(),
            recipients: Vec::new(),
            dependencies: Vec::new(),
        };

        AggregatorRoleExtension::create(HashMap::from([(e3_id, true)]))
            .hydrate(&mut ctx, &snapshot)
            .await?;

        assert_eq!(ctx.get_dependency(ACTIVE_AGGREGATOR_KEY), Some(&true));
        Ok(())
    }

    #[actix::test]
    async fn publickey_hydration_restores_committee_dependencies_first() -> Result<()> {
        let (bus, rng, seed, params, crp, _errors, _history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
        let e3_id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut ctx = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        ctx.set_dependency(FHE_KEY, Arc::new(Fhe::new(params, crp, rng)));
        ctx.set_dependency(
            META_KEY,
            E3Meta {
                threshold_m: 1,
                threshold_n: 3,
                seed,
                params_preset: BfvPreset::InsecureThreshold512,
                params: ArcBytes::from_bytes(&[]),
                error_size: ArcBytes::from_bytes(&[]),
            },
        );

        let committee_addresses = vec![
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ];
        let honest_committee_addresses = committee_addresses[..2].to_vec();
        let state = PublicKeyAggregatorState::Complete {
            public_key: ArcBytes::from_bytes(&[1, 2, 3]),
            keyshares: OrderedSet::new(),
            nodes: OrderedSet::new(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: honest_committee_addresses.clone(),
        };
        ctx.repositories()
            .publickey(&e3_id)
            .write_sync(&state)
            .await?;
        ctx.repositories()
            .publickey_recovery(&e3_id)
            .write_sync(&PublicKeyAggregatorRecoveryState {
                pending_publication: Some(e3_events::PublicKeyAggregated {
                    pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
                    e3_id: e3_id.clone(),
                    nodes: OrderedSet::new(),
                    committee_addresses: committee_addresses.clone(),
                    honest_committee_addresses: honest_committee_addresses.clone(),
                    pk_commitment: [0; 32],
                    dkg_aggregator_proof: None,
                    dkg_attestation_bundle: None,
                }),
                ..Default::default()
            })
            .await?;
        let snapshot = E3ContextSnapshot {
            e3_id,
            recipients: vec!["publickey".to_string()],
            dependencies: Vec::new(),
        };

        PublicKeyAggregatorExtension::create(&bus)
            .hydrate(&mut ctx, &snapshot)
            .await?;

        assert_eq!(
            ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
            Some(&committee_addresses)
        );
        assert_eq!(
            ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY),
            Some(&honest_committee_addresses)
        );
        assert!(ctx.get_event_recipient("publickey").is_some());
        Ok(())
    }

    #[actix::test]
    async fn recovers_full_committee_from_finalized_sortition_state() -> Result<()> {
        let e3_id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut ctx = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        let committee_nodes = vec![
            "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".to_string(),
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
        ];
        ctx.repositories()
            .finalized_committees()
            .write_sync(&HashMap::from([(
                e3_id.clone(),
                Committee::new(committee_nodes),
            )]))
            .await?;

        recover_committee_dependencies_from_sortition_state(&mut ctx, &e3_id).await?;

        assert_eq!(
            ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
            Some(&vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ])
        );
        Ok(())
    }

    #[test]
    fn recovers_honest_committee_addresses_from_generating_c5_state() -> Result<()> {
        let state = generating_c5_state();

        let addresses =
            publickey_state_honest_committee_addresses(&state)?.expect("honest addresses");

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn recovers_honest_committee_addresses_from_keyshare_party_ids() -> Result<()> {
        let committee = vec![
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ];

        let addresses = honest_addresses_from_party_ids(&committee, &BTreeSet::from([0, 2]))?;

        assert_eq!(
            addresses,
            vec![
                address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
                address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_honest_party_id_outside_full_committee() {
        let committee = vec![address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65")];

        let err = honest_addresses_from_party_ids(&committee, &BTreeSet::from([1])).unwrap_err();

        assert!(err
            .to_string()
            .contains("honest party_id 1 is out of bounds"));
    }
}
