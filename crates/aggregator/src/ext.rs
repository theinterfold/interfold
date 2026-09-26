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
    LbfvAggregationStateV1, LbfvContributionCollectionStateV1, LbfvContributionRepositoryFactory,
    LbfvPublicKeyPublicationStateV1, PublicKeyAggregator, PublicKeyAggregatorParams,
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState, PublicKeyRepositoryFactory,
    ThresholdPlaintextAggregator, ThresholdPlaintextAggregatorParams,
    ThresholdPlaintextAggregatorState, TrBfvPlaintextRepositoryFactory,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION, THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
};
use actix::{Actor, Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use e3_data::{AutoPersist, Persistable, RepositoriesFactory};
use e3_events::{
    prelude::*, CiphernodeSelected, CiphertextOutputPublished, E3id, EventContext, OrderedSet,
    Sequenced,
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
    interfold_addresses: HashMap<u64, Address>,
    signer: Address,
}

impl PublicKeyAggregatorExtension {
    pub fn create(
        bus: &BusHandle,
        interfold_addresses: HashMap<u64, Address>,
        signer: Address,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            interfold_addresses,
            signer,
        })
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
        let lbfv_collection = match initial_lbfv_collection(
            data,
            &self.interfold_addresses,
            self.signer,
            committee_size,
        ) {
            Ok(Some(state)) => Some(
                ctx.repositories()
                    .publickey_lbfv_collection(&e3_id)
                    .send(Some(state)),
            ),
            Ok(None) => None,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        let lbfv_aggregation = if lbfv_collection.is_some() {
            Some(
                ctx.repositories()
                    .publickey_lbfv_aggregation(&e3_id)
                    .send(None),
            )
        } else {
            None
        };
        let lbfv_publication = if lbfv_collection.is_some() {
            Some(
                ctx.repositories()
                    .publickey_lbfv_publication(&e3_id)
                    .send(Some(LbfvPublicKeyPublicationStateV1::new(e3_id.clone()))),
            )
        } else {
            None
        };
        let local_party_id = u32::try_from(data.party_id)
            .map_err(|_| anyhow!("local l-BFV party ID does not fit u32 for E3 {e3_id}"));
        let local_party_id = match local_party_id {
            Ok(party_id) => party_id,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
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
                lbfv_collection,
                repositories: ctx.repositories(),
                local_party_id,
                lbfv_aggregation,
                lbfv_publication,
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
        let lbfv_collection = load_lbfv_collection(
            ctx,
            &recovered_state,
            meta,
            &self.interfold_addresses,
            self.signer,
            committee_size,
        )
        .await?;
        let (local_party_id, lbfv_aggregation, lbfv_publication) = if lbfv_collection.is_some() {
            let committee =
                publickey_state_committee_addresses(&recovered_state)?.ok_or_else(|| {
                    anyhow!(
                        "public-key state for E3 {} has no finalized committee",
                        ctx.e3_id
                    )
                })?;
            let local_party_id = committee
                .iter()
                .position(|address| *address == self.signer)
                .ok_or_else(|| {
                    anyhow!(
                        "local signer is not in the finalized committee for E3 {}",
                        ctx.e3_id
                    )
                })?;
            let local_party_id = u32::try_from(local_party_id)
                .map_err(|_| anyhow!("local party ID does not fit u32 for E3 {}", ctx.e3_id))?;
            (
                local_party_id,
                load_lbfv_aggregation(ctx, meta).await?,
                Some(load_lbfv_publication(ctx).await?),
            )
        } else {
            (0, None, None)
        };
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
                lbfv_collection,
                repositories: ctx.repositories(),
                local_party_id,
                lbfv_aggregation,
                lbfv_publication,
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

async fn load_lbfv_aggregation(
    ctx: &E3Context,
    meta: &e3_request::E3Meta,
) -> Result<Option<Persistable<LbfvAggregationStateV1>>> {
    if !e3_fhe_params::supports_lbfv(meta.params_preset) {
        return Ok(None);
    }
    let repository = ctx.repositories().publickey_lbfv_aggregation(&ctx.e3_id);
    let state = repository.load().await?;
    if let Some(state) = state.get() {
        state.validate_loaded()?;
        ensure!(
            state.e3_id == ctx.e3_id,
            "persisted l-BFV aggregation state belongs to another E3"
        );
    }
    Ok(Some(state))
}

async fn load_lbfv_publication(
    ctx: &E3Context,
) -> Result<Persistable<LbfvPublicKeyPublicationStateV1>> {
    let repository = ctx.repositories().publickey_lbfv_publication(&ctx.e3_id);
    let state = repository
        .load_or_default(LbfvPublicKeyPublicationStateV1::new(ctx.e3_id.clone()))
        .await?;
    let persisted = state
        .get()
        .ok_or_else(|| anyhow!("secure-16384 publication sidecar is empty"))?;
    persisted.validate_loaded()?;
    ensure!(
        persisted.e3_id == ctx.e3_id,
        "persisted l-BFV publication state belongs to another E3"
    );
    Ok(state)
}

fn initial_lbfv_collection(
    selection: &CiphernodeSelected,
    interfold_addresses: &HashMap<u64, Address>,
    signer: Address,
    committee_size: CiphernodesCommitteeSize,
) -> Result<Option<LbfvContributionCollectionStateV1>> {
    if !e3_fhe_params::supports_lbfv(selection.params_preset) {
        return Ok(None);
    }
    let interfold_address = interfold_addresses
        .get(&selection.e3_id.chain_id())
        .copied()
        .ok_or_else(|| {
            anyhow!(
                "Interfold address not configured for chain {}",
                selection.e3_id.chain_id()
            )
        })?;
    let generation = e3_keyshare::LbfvGenerationStateV1::from_selection(
        selection,
        interfold_address,
        signer,
        e3_config::current_node_release().protocol_version,
    )?;
    Ok(Some(LbfvContributionCollectionStateV1::new(
        selection.e3_id.clone(),
        generation.context.proof_domain,
        generation.committee,
        committee_size.values().h,
        selection.params_preset,
    )?))
}

async fn load_lbfv_collection(
    ctx: &E3Context,
    public_key_state: &PublicKeyAggregatorState,
    meta: &e3_request::E3Meta,
    interfold_addresses: &HashMap<u64, Address>,
    signer: Address,
    committee_size: CiphernodesCommitteeSize,
) -> Result<Option<Persistable<LbfvContributionCollectionStateV1>>> {
    if !e3_fhe_params::supports_lbfv(meta.params_preset) {
        return Ok(None);
    }
    let repository = ctx.repositories().publickey_lbfv_collection(&ctx.e3_id);
    let mut collection = repository.load().await?;
    if !collection.has() && matches!(public_key_state, PublicKeyAggregatorState::Complete { .. }) {
        // A completed state without an l-BFV sidecar is a legacy classic-BFV
        // snapshot. Do not reinterpret it as an incomplete l-BFV workflow.
        return Ok(None);
    }
    let Some(committee) = publickey_state_committee_addresses(public_key_state)? else {
        return Ok(None);
    };
    let party_id = committee
        .iter()
        .position(|address| *address == signer)
        .ok_or_else(|| {
            anyhow!(
                "local signer is not in the finalized committee for E3 {}",
                ctx.e3_id
            )
        })?;
    let selection = CiphernodeSelected {
        e3_id: ctx.e3_id.clone(),
        threshold_m: meta.threshold_m,
        threshold_n: meta.threshold_n,
        seed: meta.seed,
        error_size: meta.error_size.clone(),
        params_preset: meta.params_preset,
        params: meta.params.clone(),
        party_id: party_id as u64,
        committee: committee.iter().map(ToString::to_string).collect(),
    };
    let expected =
        initial_lbfv_collection(&selection, interfold_addresses, signer, committee_size)?
            .expect("secure preset creates an l-BFV collection");
    if !collection.has() {
        // The synchronous extension hook cannot await its initial snapshot enqueue. Reconstruct the
        // empty sidecar from the durable public-key context if a crash interrupts that first write.
        repository.write_sync(&expected).await?;
        collection = repository.load().await?;
    }
    let persisted = collection.get().ok_or_else(|| {
        anyhow!(
            "secure-16384 public-key aggregation for E3 {} has no l-BFV collection record after reconstruction",
            ctx.e3_id
        )
    })?;
    persisted.validate_loaded()?;
    ensure!(
        persisted.e3_id == expected.e3_id
            && persisted.proof_domain == expected.proof_domain
            && persisted.proof_session_id == expected.proof_session_id
            && persisted.committee == expected.committee
            && persisted.committee_h == expected.committee_h,
        "persisted l-BFV collection context does not match E3 {}",
        ctx.e3_id
    );
    ensure!(
        persisted.committee.get(party_id) == Some(&signer),
        "persisted l-BFV collection signer slot does not match E3 {}",
        ctx.e3_id
    );
    Ok(Some(collection))
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

fn remember_public_key_aggregated(
    ctx: &mut E3Context,
    committee_addresses: &[Address],
    nodes: &OrderedSet<String>,
    honest_committee_addresses: &[Address],
) -> Result<()> {
    let addrs = if !committee_addresses.is_empty() {
        committee_addresses.to_vec()
    } else {
        committee_addresses_from_nodes(nodes)?
    };
    ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, addrs);
    ensure!(
        !honest_committee_addresses.is_empty(),
        ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING
    );
    ctx.set_dependency(
        HONEST_COMMITTEE_ADDRESSES_KEY,
        honest_committee_addresses.to_vec(),
    );
    Ok(())
}

fn remember_lbfv_public_key_aggregated(
    ctx: &mut E3Context,
    data: &e3_events::LbfvPublicKeyAggregated,
) -> Result<()> {
    ensure!(
        data.e3_id == ctx.e3_id,
        "secure-16384 public-key event belongs to another E3"
    );
    ensure!(
        data.dkg_aggregator_v2_proof.circuit == e3_events::CircuitName::DkgAggregatorV2,
        "secure-16384 public-key event has the wrong recursive circuit"
    );
    remember_public_key_aggregated(
        ctx,
        &data.committee_addresses,
        &data.nodes,
        &data.honest_committee_addresses,
    )
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
            match remember_public_key_aggregated(
                ctx,
                &data.committee_addresses,
                &data.nodes,
                &data.honest_committee_addresses,
            ) {
                Ok(()) => {
                    if let Some(ciphertext) =
                        ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned()
                    {
                        self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
                    }
                }
                Err(e) => self.bus.err(EType::PlaintextAggregation, e),
            }
            return;
        }

        if let InterfoldEventData::LbfvPublicKeyAggregated(data) = evt.get_data() {
            match remember_lbfv_public_key_aggregated(ctx, data) {
                Ok(()) => {
                    if let Some(ciphertext) =
                        ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned()
                    {
                        self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx());
                    }
                }
                Err(e) => self.bus.err(EType::PlaintextAggregation, e),
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

    fn secure_public_key_intent(
        e3_id: E3id,
        circuit: e3_events::CircuitName,
    ) -> e3_events::LbfvPublicKeyAggregated {
        let committee_addresses = vec![
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ];
        e3_events::LbfvPublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
            e3_id,
            nodes: OrderedSet::new(),
            committee_addresses: committee_addresses.clone(),
            honest_committee_addresses: committee_addresses[..2].to_vec(),
            pk_commitment: [7; 32],
            dkg_aggregator_v2_proof: e3_events::Proof::new(
                circuit,
                ArcBytes::from_bytes(&[4]),
                ArcBytes::from_bytes(&[5]),
            ),
            dkg_attestation_bundle: Some(ArcBytes::from_bytes(&[6])),
        }
    }

    #[actix::test]
    async fn secure_public_key_intent_restores_plaintext_committee_dependencies() -> Result<()> {
        let e3_id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut ctx = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        let event = secure_public_key_intent(e3_id, e3_events::CircuitName::DkgAggregatorV2);

        remember_lbfv_public_key_aggregated(&mut ctx, &event)?;

        assert_eq!(
            ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
            Some(&event.committee_addresses)
        );
        assert_eq!(
            ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY),
            Some(&event.honest_committee_addresses)
        );
        Ok(())
    }

    #[actix::test]
    async fn secure_public_key_intent_rejects_wrong_identity_and_circuit() {
        let e3_id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut ctx = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        let wrong_e3 =
            secure_public_key_intent(E3id::new("43", 1), e3_events::CircuitName::DkgAggregatorV2);
        assert!(remember_lbfv_public_key_aggregated(&mut ctx, &wrong_e3).is_err());

        let wrong_circuit = secure_public_key_intent(e3_id, e3_events::CircuitName::PkAggregation);
        assert!(remember_lbfv_public_key_aggregated(&mut ctx, &wrong_circuit).is_err());
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

    #[test]
    fn secure_collection_uses_the_keyshare_generation_domain() -> Result<()> {
        let signer = address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let interfold = Address::repeat_byte(0x11);
        let selection = CiphernodeSelected {
            e3_id: E3id::new("7", 1),
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            error_size: ArcBytes::from_bytes(&[1]),
            params_preset: BfvPreset::SecureThreshold16384,
            params: ArcBytes::from_bytes(b"secure-16384-params"),
            party_id: 1,
            committee: vec![
                Address::ZERO.to_string(),
                signer.to_string(),
                Address::repeat_byte(0xff).to_string(),
            ],
        };
        let generation = e3_keyshare::LbfvGenerationStateV1::from_selection(
            &selection,
            interfold,
            signer,
            e3_config::current_node_release().protocol_version,
        )?;

        let collection = initial_lbfv_collection(
            &selection,
            &HashMap::from([(1, interfold)]),
            signer,
            CiphernodesCommitteeSize::Minimum,
        )?
        .expect("secure collection");

        assert_eq!(collection.proof_domain, generation.context.proof_domain);
        assert_eq!(
            collection.proof_session_id,
            generation.context.proof_session_id
        );
        assert_eq!(collection.committee, generation.committee);
        Ok(())
    }

    #[actix::test]
    async fn secure_hydration_reconstructs_a_missing_initial_collection() -> Result<()> {
        let (bus, rng, seed, params, crp, _errors, _history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold.into()))?;
        let e3_id = E3id::new("42", 1);
        let signer = address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let committee = vec![Address::ZERO, signer, Address::repeat_byte(0xff)];
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
                params_preset: BfvPreset::SecureThreshold16384,
                params: ArcBytes::from_bytes(b"secure-16384-params"),
                error_size: ArcBytes::from_bytes(&[1]),
            },
        );
        ctx.repositories()
            .publickey(&e3_id)
            .write_sync(&PublicKeyAggregatorState::init(
                3,
                1,
                seed,
                party_nodes_from_committee_addresses(&committee),
            ))
            .await?;
        ctx.repositories()
            .publickey_recovery(&e3_id)
            .write_sync(&PublicKeyAggregatorRecoveryState::default())
            .await?;
        let snapshot = E3ContextSnapshot {
            e3_id: e3_id.clone(),
            recipients: vec!["publickey".to_string()],
            dependencies: Vec::new(),
        };

        PublicKeyAggregatorExtension::create(
            &bus,
            HashMap::from([(1, Address::repeat_byte(0x11))]),
            signer,
        )
        .hydrate(&mut ctx, &snapshot)
        .await?;

        let collection = ctx
            .repositories()
            .publickey_lbfv_collection(&e3_id)
            .read()
            .await?
            .expect("reconstructed l-BFV collection");
        collection.validate_loaded()?;
        assert_eq!(collection.committee, committee);
        assert!(ctx.get_event_recipient("publickey").is_some());
        Ok(())
    }

    #[actix::test]
    async fn secure_hydration_rejects_a_mismatched_proof_domain() -> Result<()> {
        let (bus, rng, seed, params, crp, _errors, _history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold.into()))?;
        let e3_id = E3id::new("42", 1);
        let signer = address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let committee = vec![Address::ZERO, signer, Address::repeat_byte(0xff)];
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
                params_preset: BfvPreset::SecureThreshold16384,
                params: ArcBytes::from_bytes(b"secure-16384-params"),
                error_size: ArcBytes::from_bytes(&[1]),
            },
        );
        let publickey = PublicKeyAggregatorState::init(
            3,
            1,
            seed,
            party_nodes_from_committee_addresses(&committee),
        );
        ctx.repositories()
            .publickey(&e3_id)
            .write_sync(&publickey)
            .await?;
        ctx.repositories()
            .publickey_recovery(&e3_id)
            .write_sync(&PublicKeyAggregatorRecoveryState::default())
            .await?;
        let mismatched_domain = e3_committee_hash::LbfvProofDomainContext {
            protocol_version: e3_config::current_node_release().protocol_version,
            chain_id: 1,
            interfold_address: Address::repeat_byte(0x22),
            e3_id: alloy::primitives::U256::from(42),
            crypto_config_id: alloy::primitives::B256::repeat_byte(0x33),
            finalized_committee_hash: e3_committee_hash::hash_committee_addresses(&committee),
            lbfv_constants_version: 1,
            ciphertext_level: 0,
            key_level: 0,
        };
        ctx.repositories()
            .publickey_lbfv_collection(&e3_id)
            .write_sync(&LbfvContributionCollectionStateV1::new(
                e3_id.clone(),
                mismatched_domain,
                committee,
                2,
                BfvPreset::SecureThreshold16384,
            )?)
            .await?;
        let snapshot = E3ContextSnapshot {
            e3_id,
            recipients: vec!["publickey".to_string()],
            dependencies: Vec::new(),
        };

        let error = PublicKeyAggregatorExtension::create(
            &bus,
            HashMap::from([(1, Address::repeat_byte(0x11))]),
            signer,
        )
        .hydrate(&mut ctx, &snapshot)
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("persisted l-BFV collection context does not match"));
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
            get_common_setup(Some(BfvPreset::InsecureThreshold.into()))?;
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
                params_preset: BfvPreset::InsecureThreshold,
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

        PublicKeyAggregatorExtension::create(&bus, HashMap::new(), Address::ZERO)
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
