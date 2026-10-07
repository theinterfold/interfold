// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::actors::DecryptionshareCreatedBuffer;
use crate::actors::KeyshareCreatedFilterBuffer;
use crate::domain::committee::committee_addresses_in_party_order;
use crate::{
    LbfvAggregationStateV1, LbfvContributionCollectionStateV1, LbfvContributionRepositoryFactory,
    LbfvPublicKeyPublicationStateV1, PublicKeyAggregator, PublicKeyAggregatorParams,
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState, PublicKeyRepositoryFactory,
    ThresholdPlaintextAggregator, ThresholdPlaintextAggregatorParams,
    ThresholdPlaintextAggregatorState, TrBfvPlaintextRepositoryFactory,
    PUBLIC_KEY_AGGREGATOR_RECOVERY_SCHEMA_VERSION, THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
};
use actix::{
    Actor, ActorContext, ActorFutureExt, Addr, AsyncContext, Context, Handler, Recipient,
    WrapFuture,
};
use alloy::primitives::Address;
use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use e3_data::{AutoPersist, Persistable, RepositoriesFactory};
use e3_events::{
    prelude::*, CiphernodeSelected, CiphertextOutputPublished, E3Stage, E3id, EventContext,
    EventStoreQueryBy, SeqAgg, Sequenced,
};
use e3_events::{BusHandle, EType, InterfoldEvent, InterfoldEventData};
use e3_fhe::ext::FHE_KEY;
use e3_keyshare::canonical_key::CanonicalPublicKeys;
use e3_request::{
    E3Context, E3ContextSnapshot, E3Extension, E3LifecycleRepositoryFactory, TypedKey,
    DKG_FOLD_ATTESTATION_CONTEXT_KEY, META_KEY,
};
use e3_sortition::Sortition;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::HashMap;

/// Full finalized committee from the chain (length `N`)
/// for `committee_hash_*` binding in downstream ZK requests.
pub const COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> = TypedKey::new("committee_addresses");

/// Honest subset from the chain DKG anchors (length `H`)
/// for decryption-share collection gating.
pub const HONEST_COMMITTEE_ADDRESSES_KEY: TypedKey<Vec<Address>> =
    TypedKey::new("honest_committee_addresses");
const ACTIVE_AGGREGATOR_KEY: TypedKey<bool> = TypedKey::new("active_aggregator");
const PENDING_CIPHERTEXT_OUTPUT_KEY: TypedKey<CiphertextOutputPublished> =
    TypedKey::new("pending_ciphertext_output");

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
                initial_stage: E3Stage::CommitteeFinalized,
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
        // The lifecycle projection belongs to the node root, not the per-E3 context scope.
        let initial_stage = ctx
            .repositories()
            .store
            .base("")
            .repositories()
            .e3_lifecycle()
            .read()
            .await?
            .and_then(|stages| stages.get(&ctx.e3_id).cloned())
            .unwrap_or(E3Stage::None);
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
                initial_stage,
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
    canonical_keys: CanonicalPublicKeys,
    eventstore: Recipient<EventStoreQueryBy<SeqAgg>>,
}

impl ThresholdPlaintextAggregatorExtension {
    pub fn create(
        bus: &BusHandle,
        sortition: &Addr<Sortition>,
        proof_aggregation_enabled: bool,
        canonical_keys: CanonicalPublicKeys,
        eventstore: Recipient<EventStoreQueryBy<SeqAgg>>,
    ) -> Box<Self> {
        Box::new(Self {
            bus: bus.clone(),
            sortition: sortition.clone(),
            proof_aggregation_enabled,
            canonical_keys,
            eventstore,
        })
    }

    fn remember_canonical_committee(&self, ctx: &mut E3Context) -> bool {
        let Some(key) = self.canonical_keys.get(&ctx.e3_id) else {
            return false;
        };
        ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, key.committee);
        ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, key.honest_committee);
        true
    }

    fn defer_recovered_plaintext(
        &self,
        ctx: &mut E3Context,
        initial: ThresholdPlaintextAggregatorState,
        state: Persistable<ThresholdPlaintextAggregatorState>,
        recovery: Persistable<crate::ThresholdPlaintextAggregatorRecoveryState>,
    ) -> Result<()> {
        let meta = ctx
            .get_dependency(META_KEY)
            .ok_or_else(|| anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING))?
            .clone();
        let committee_size =
            CiphernodesCommitteeSize::from_threshold(meta.threshold_m, meta.threshold_n)?;
        let value = DeferredPlaintextAggregator {
            bus: self.bus.clone(),
            sortition: self.sortition.clone(),
            keys: self.canonical_keys.clone(),
            eventstore: self.eventstore.clone(),
            repositories: ctx.repositories(),
            e3_id: ctx.e3_id.clone(),
            params_preset: meta.params_preset,
            committee_size,
            proof_aggregation_enabled: self.proof_aggregation_enabled,
            initial_is_aggregator: load_is_active_aggregator(ctx),
            initial,
            recovered: Some((state, recovery)),
            pending_range: None,
            effects_enabled: None,
            dest: None,
        };
        ctx.set_event_recipient("plaintext", Some(value.start().recipient()));
        Ok(())
    }

    fn try_start_plaintext(
        &self,
        ctx: &mut E3Context,
        data: &CiphertextOutputPublished,
        ec: &EventContext<Sequenced>,
        effects_enabled: bool,
    ) -> bool {
        if !self.remember_canonical_committee(ctx) {
            return false;
        }
        let Some(key) = self.canonical_keys.get(&ctx.e3_id) else {
            return false;
        };
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
                        effects_enabled,
                        committee_addresses,
                        honest_committee_addresses,
                        decryption_domain: key.domain(key.interfold_address),
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
    "Could not create ThresholdPlaintextAggregator because committee addresses were not set (expected canonical chain key publication).";
const ERROR_TRBFV_PLAINTEXT_HONEST_COMMITTEE_MISSING: &str =
    "Could not create ThresholdPlaintextAggregator because honest committee addresses were not set (expected canonical chain DKG anchors).";

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

fn party_nodes_from_committee_addresses(committee_addresses: &[Address]) -> HashMap<u64, String> {
    committee_addresses
        .iter()
        .enumerate()
        .map(|(party_id, node)| (party_id as u64, node.to_string()))
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
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx(), true);
            }
            return;
        }

        if matches!(evt.get_data(), InterfoldEventData::CiphernodeSelected(_)) {
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx(), true);
            }
            return;
        }

        if let InterfoldEventData::PublicKeyAggregated(data) = evt.get_data() {
            let Some(key) = self.canonical_keys.get(&ctx.e3_id) else {
                return;
            };
            if !key.accepts(data) {
                return;
            }
            self.remember_canonical_committee(ctx);
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx(), true);
            }
            return;
        }

        if let InterfoldEventData::LbfvPublicKeyAggregated(data) = evt.get_data() {
            // The l-BFV aggregator announces its key with this event. The chain-bound canonical
            // key stays the authority: the event only triggers a start when it matches that key.
            if data.e3_id != ctx.e3_id
                || data.dkg_aggregator_v2_proof.circuit != e3_events::CircuitName::DkgAggregatorV2
            {
                self.bus.err(
                    EType::PlaintextAggregation,
                    anyhow!("secure-16384 public-key event has the wrong E3 or recursive circuit"),
                );
                return;
            }
            let Some(key) = self.canonical_keys.get(&ctx.e3_id) else {
                return;
            };
            let publication = e3_events::PublicKeyAggregated {
                pubkey: data.pubkey.clone(),
                e3_id: data.e3_id.clone(),
                nodes: data.nodes.clone(),
                committee_addresses: data.committee_addresses.clone(),
                honest_committee_addresses: data.honest_committee_addresses.clone(),
                pk_commitment: data.pk_commitment,
                dkg_aggregator_proof: Some(data.dkg_aggregator_v2_proof.clone()),
                dkg_attestation_bundle: data.dkg_attestation_bundle.clone(),
            };
            if !key.accepts(&publication) {
                return;
            }
            self.remember_canonical_committee(ctx);
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx(), true);
            }
            return;
        }

        if matches!(
            evt.get_data(),
            InterfoldEventData::CommitteePublished(_)
                | InterfoldEventData::EvmLogObserved(_)
                | InterfoldEventData::CommitteePublicKeyChunkPublished(_)
                | InterfoldEventData::E3StageChanged(_)
        ) {
            if evt.source() == e3_events::EventSource::Net {
                return;
            }
            self.remember_canonical_committee(ctx);
            if let Some(ciphertext) = ctx.get_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY).cloned() {
                self.try_start_plaintext(ctx, &ciphertext, evt.get_ctx(), true);
            }
            return;
        }

        // Save plaintext aggregator for finalized committee members.
        let InterfoldEventData::CiphertextOutputPublished(data) = evt.get_data() else {
            return;
        };
        ctx.set_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY, data.clone());
        self.try_start_plaintext(ctx, data, evt.get_ctx(), true);
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        self.remember_canonical_committee(ctx);

        let mut ciphertext = None;
        crate::actors::visit_plaintext_history(&self.eventstore, &ctx.e3_id, |event| {
            if let InterfoldEventData::CiphertextOutputPublished(data) = event.get_data() {
                if event.source() != e3_events::EventSource::Net && ciphertext.is_none() {
                    ciphertext = Some((data.clone(), event.get_ctx().clone()));
                }
            }
            Ok(())
        })
        .await?;
        if let Some((data, _)) = &ciphertext {
            ctx.set_dependency(PENDING_CIPHERTEXT_OUTPUT_KEY, data.clone());
        }

        let repo = ctx.repositories().trbfv_plaintext(&snapshot.e3_id);
        let sync_state = repo.load().await?;
        if !sync_state.has() {
            if let Some((data, ec)) = &ciphertext {
                if ctx.get_event_recipient("threshold_keyshare").is_some() {
                    let meta = ctx
                        .get_dependency(META_KEY)
                        .ok_or_else(|| anyhow!(ERROR_TRBFV_PLAINTEXT_META_MISSING))?;
                    let initial = ThresholdPlaintextAggregatorState::init(
                        meta.threshold_m as u64,
                        meta.threshold_n as u64,
                        meta.seed,
                        data.ciphertext_output.clone(),
                        meta.params.clone(),
                    );
                    let state = repo.send(Some(initial.clone()));
                    let recovery = ctx
                        .repositories()
                        .trbfv_plaintext_recovery(&ctx.e3_id)
                        .send(Some(crate::new_threshold_plaintext_recovery(ec.clone())));
                    self.defer_recovered_plaintext(ctx, initial, state, recovery)?;
                }
            }
            return Ok(());
        }
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

        let ciphertext_output = match &ciphertext {
            Some((data, _)) => data.ciphertext_output.clone(),
            None => match sync_state.try_get()? {
                ThresholdPlaintextAggregatorState::Collecting(state) => state.ciphertext_output,
                ThresholdPlaintextAggregatorState::VerifyingC6(state) => state.ciphertext_output,
                ThresholdPlaintextAggregatorState::Computing(state) => state.ciphertext_output,
                _ => return Err(anyhow!("missing ciphertext history for E3 {}", ctx.e3_id)),
            },
        };
        let initial = ThresholdPlaintextAggregatorState::init(
            meta.threshold_m as u64,
            meta.threshold_n as u64,
            meta.seed,
            ciphertext_output,
            meta.params.clone(),
        );

        let Some(key) = self.canonical_keys.get(&ctx.e3_id) else {
            tracing::warn!(e3_id = %ctx.e3_id, "Keeping plaintext snapshot dormant until chain key authority arrives");
            return self.defer_recovered_plaintext(ctx, initial, sync_state, recovery);
        };
        let committee_addresses = load_committee_addresses(ctx)?;
        let honest_committee_addresses = load_honest_committee_addresses(ctx)?;
        let initial_is_aggregator = load_is_active_aggregator(ctx);

        let mut value = ThresholdPlaintextAggregator::new(
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
                decryption_domain: key.domain(key.interfold_address),
                recovery,
            },
            sync_state,
        );
        value
            .repair_recovered_state(initial, &self.eventstore, &ctx.repositories())
            .await?;

        // send to context
        ctx.set_event_recipient(
            "plaintext",
            Some(create_decryptionshare_buffer(value.start())),
        );

        Ok(())
    }
}

/// Holds saved state and a history range until chain authority permits recovery.
struct DeferredPlaintextAggregator {
    bus: BusHandle,
    sortition: Addr<Sortition>,
    keys: CanonicalPublicKeys,
    eventstore: Recipient<EventStoreQueryBy<SeqAgg>>,
    repositories: e3_data::Repositories,
    e3_id: E3id,
    params_preset: e3_fhe_params::BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    proof_aggregation_enabled: bool,
    initial_is_aggregator: bool,
    initial: ThresholdPlaintextAggregatorState,
    recovered: Option<(
        Persistable<ThresholdPlaintextAggregatorState>,
        Persistable<crate::ThresholdPlaintextAggregatorRecoveryState>,
    )>,
    pending_range: Option<std::ops::RangeInclusive<u64>>,
    effects_enabled: Option<InterfoldEvent>,
    dest: Option<Recipient<InterfoldEvent>>,
}

impl DeferredPlaintextAggregator {
    fn try_resume(&mut self, ctx: &mut Context<Self>) {
        let Some(key) = self.keys.get(&self.e3_id) else {
            return;
        };
        let Some((state, recovery)) = self.recovered.take() else {
            return;
        };
        let mut value = ThresholdPlaintextAggregator::new(
            ThresholdPlaintextAggregatorParams {
                bus: self.bus.clone(),
                sortition: self.sortition.clone(),
                e3_id: self.e3_id.clone(),
                params_preset: self.params_preset,
                committee_size: self.committee_size,
                proof_aggregation_enabled: self.proof_aggregation_enabled,
                initial_is_aggregator: self.initial_is_aggregator,
                effects_enabled: false,
                decryption_domain: key.domain(key.interfold_address),
                committee_addresses: key.committee,
                honest_committee_addresses: key.honest_committee,
                recovery,
            },
            state,
        );
        let initial = self.initial.clone();
        let store = self.eventstore.clone();
        let repositories = self.repositories.clone();
        let pending_range = self.pending_range.take();
        let effects_enabled = self.effects_enabled.take();
        let e3_id = self.e3_id.clone();
        ctx.wait(
            async move {
                value
                    .repair_recovered_state(initial, &store, &repositories)
                    .await?;
                let dest = value.start();
                if let Some(range) = pending_range {
                    crate::actors::visit_plaintext_history_range(&store, &e3_id, range, |event| {
                        let dest = dest.clone();
                        async move { Ok(dest.send(event).await?) }
                    })
                    .await?;
                }
                if let Some(event) = effects_enabled {
                    dest.send(event).await?;
                }
                Ok::<_, anyhow::Error>(create_decryptionshare_buffer(dest))
            }
            .into_actor(self)
            .map(|result, actor, ctx| match result {
                Ok(dest) => actor.dest = Some(dest),
                Err(error) => {
                    actor.bus.err(EType::PlaintextAggregation, error);
                    ctx.stop();
                }
            }),
        );
    }
}

impl Actor for DeferredPlaintextAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(e3_utils::MAILBOX_LIMIT);
        self.try_resume(ctx);
    }
}

impl Handler<InterfoldEvent> for DeferredPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, event: InterfoldEvent, ctx: &mut Self::Context) {
        if let Some(dest) = &self.dest {
            let dest = dest.clone();
            ctx.wait(async move { dest.send(event).await }.into_actor(self).map(
                |result, actor, _| {
                    if let Err(error) = result {
                        actor.bus.err(EType::PlaintextAggregation, error.into());
                    }
                },
            ));
        } else if matches!(
            event.get_data(),
            InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_)
        ) || matches!(
            event.get_data(),
            // An ended E3's aggregation does not resume, also when its context stays for
            // accusation work.
            InterfoldEventData::E3StageChanged(stage)
                if stage.e3_id == self.e3_id && stage.new_stage.is_terminal()
        ) {
            ctx.stop();
        } else {
            if matches!(event.get_data(), InterfoldEventData::EffectsEnabled(_)) {
                self.effects_enabled = Some(event);
            } else if event.get_e3_id().as_ref() == Some(&self.e3_id) {
                self.pending_range = Some(match self.pending_range.take() {
                    Some(range) => {
                        (*range.start()).min(event.seq())..=(*range.end()).max(event.seq())
                    }
                    None => event.seq()..=event.seq(),
                });
            }
            self.try_resume(ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use e3_data::{DataStore, InMemStore};
    use e3_events::Seed;
    use e3_fhe::Fhe;
    use e3_fhe_params::BfvPreset;
    use e3_request::{ContextRepositoryFactory, E3ContextParams, E3Meta};
    use e3_test_helpers::get_common_setup;
    use e3_utils::ArcBytes;
    use std::{collections::HashMap, sync::Arc};

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
    async fn plaintext_dependencies_use_chain_rosters_across_restart() -> Result<()> {
        use e3_bfv_client::{client::generate_public_key, compute_pk_commitment};
        use e3_data::{PersistableData, Repository};
        use e3_events::{EventSource, OrderedSet, PublicKeyAggregated, Unsequenced};
        use e3_fhe_params::{BfvParamSet, BfvPreset};
        use e3_keyshare::canonical_key::CanonicalPublicKey;
        use e3_request::{E3Meta, META_KEY};
        use e3_sortition::{CiphernodeSelector, SortitionParams};
        use e3_utils::ArcBytes;

        fn persist<T: PersistableData>(value: T) -> Persistable<T> {
            Repository::new(DataStore::from_in_mem(&InMemStore::new(false).start()))
                .send(Some(value))
        }
        let (bus, _, seed, _, _, _, _) =
            e3_test_helpers::get_common_setup(Some(BfvPreset::InsecureThreshold.into()))?;
        let selector = CiphernodeSelector::new(
            &bus,
            persist(Default::default()),
            persist(Default::default()),
            "node",
        )
        .start();
        let sortition = Sortition::new(SortitionParams {
            admission: persist(Default::default()),
            bus: bus.clone(),
            backends: persist(Default::default()),
            node_state: persist(Default::default()),
            bond_owners: persist(Default::default()),
            recovery: persist(Default::default()),
            finalized_committees: persist(Default::default()),
            ciphernode_selector: selector,
            address: "node".into(),
            submitted_e3s: Default::default(),
        })
        .start();
        let id = E3id::new("81", 1);
        let preset = BfvPreset::InsecureThreshold;
        let params = BfvParamSet::from(preset);
        let public_key = generate_public_key(
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )?;
        let commitment = compute_pk_commitment(
            public_key.clone(),
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )?;
        let committee = vec![
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            Address::repeat_byte(3),
        ];
        let honest = vec![committee[0], committee[2]];
        let canonical = CanonicalPublicKey {
            pk_commitment: commitment,
            committee: committee.clone(),
            honest_committee: honest.clone(),
            params_preset: preset,
            committee_size: CiphernodesCommitteeSize::Minimum,
            interfold_address: Address::repeat_byte(9),
            sk_agg_commits: vec![],
            esm_agg_commits: vec![],
        };
        let publication = PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&public_key),
            e3_id: id.clone(),
            nodes: OrderedSet::new(),
            committee_addresses: committee.clone(),
            honest_committee_addresses: honest.clone(),
            pk_commitment: commitment,
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        };
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        // A completed aggregation snapshot has the released layout, but is not chain authority.
        store
            .repositories()
            .publickey(&id)
            .write_sync(&PublicKeyAggregatorState::Complete {
                public_key: ArcBytes::from_bytes(&[7]),
                keyshares: OrderedSet::new(),
                nodes: OrderedSet::new(),
                committee_addresses: vec![Address::ZERO],
                honest_committee_addresses: vec![Address::ZERO],
            })
            .await?;
        for restart in [false, true] {
            let mut ctx = E3Context::from_params(E3ContextParams {
                repository: store.repositories().context(&id),
                e3_id: id.clone(),
                extensions: Arc::new(vec![]),
            });
            ctx.set_dependency(
                META_KEY,
                E3Meta {
                    threshold_m: 1,
                    threshold_n: 3,
                    seed,
                    params_preset: preset,
                    params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(
                        &params.build_arc(),
                    )),
                    error_size: ArcBytes::from_bytes(&[]),
                },
            );
            let snapshot = E3ContextSnapshot {
                e3_id: id.clone(),
                recipients: if restart {
                    vec!["plaintext".into()]
                } else {
                    vec![]
                },
                dependencies: vec![],
            };
            let keys = CanonicalPublicKeys::default();
            let canonical = canonical.clone();
            keys.insert(id.clone(), canonical)?;
            let mut eventstore = e3_events::EventStore::new(
                e3_data::InMemSequenceIndex::new(),
                e3_data::InMemEventLog::new(),
            )?;
            let ciphertext_event = eventstore
                .store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    CiphertextOutputPublished {
                        e3_id: id.clone(),
                        ciphertext_output: vec![ArcBytes::from_bytes(&[8])],
                        ciphertext_commitment: [0; 32],
                    }
                    .into(),
                    None,
                    1,
                    None,
                    EventSource::Local,
                ))?
                .unwrap();
            let eventstore =
                e3_events::EventStoreRouter::new(HashMap::from([(1, eventstore.start())]))
                    .start()
                    .recipient();
            let extension = ThresholdPlaintextAggregatorExtension::create(
                &bus, &sortition, false, keys, eventstore,
            );
            if restart {
                let mut saved = ThresholdPlaintextAggregatorState::init(
                    1,
                    3,
                    seed,
                    vec![ArcBytes::from_bytes(&[8])],
                    ArcBytes::from_bytes(&[]),
                );
                if let ThresholdPlaintextAggregatorState::Collecting(state) = &mut saved {
                    state.shares.insert(2, vec![ArcBytes::from_bytes(&[6])]);
                }
                ctx.repositories()
                    .trbfv_plaintext(&id)
                    .write_sync(&saved)
                    .await?;
                ctx.repositories()
                    .trbfv_plaintext_recovery(&id)
                    .write_sync(&crate::new_threshold_plaintext_recovery(
                        ciphertext_event.get_ctx().clone(),
                    ))
                    .await?;
                ctx.set_dependency(COMMITTEE_ADDRESSES_KEY, vec![Address::ZERO]);
                ctx.set_dependency(HONEST_COMMITTEE_ADDRESSES_KEY, vec![Address::ZERO]);
                extension.hydrate(&mut ctx, &snapshot).await?;
                assert_eq!(
                    ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
                    Some(&committee)
                );
                assert_eq!(
                    ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY),
                    Some(&honest)
                );
                assert!(
                    ctx.get_event_recipient("plaintext").is_some(),
                    "existing plaintext actor must hydrate"
                );
                let restored = ctx
                    .repositories()
                    .trbfv_plaintext(&id)
                    .read()
                    .await?
                    .unwrap();
                let ThresholdPlaintextAggregatorState::Collecting(restored) = restored else {
                    panic!("expected share collection");
                };
                assert!(
                    restored.shares.is_empty(),
                    "unsigned retained shares must be removed"
                );
            }
            extension.on_event(
                &mut ctx,
                &InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    publication.clone().into(),
                    None,
                    1,
                    None,
                    EventSource::Net,
                )
                .into_sequenced(1),
            );
            assert_eq!(
                ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
                Some(&committee)
            );
            assert_eq!(
                ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY),
                Some(&honest)
            );
            for variant in 0..3 {
                let mut other = publication.clone();
                match variant {
                    0 => {
                        other.pk_commitment = [7; 32];
                        other.committee_addresses = vec![Address::ZERO];
                        other.honest_committee_addresses = vec![Address::ZERO];
                    }
                    1 => other.committee_addresses.swap(0, 1),
                    _ => other.honest_committee_addresses = committee[..2].to_vec(),
                }
                extension.on_event(
                    &mut ctx,
                    &InterfoldEvent::<Unsequenced>::new_with_timestamp(
                        other.into(),
                        None,
                        2 + variant,
                        None,
                        EventSource::Net,
                    )
                    .into_sequenced(2 + variant as u64),
                );
                assert_eq!(
                    ctx.get_dependency(COMMITTEE_ADDRESSES_KEY),
                    Some(&committee),
                    "committee changed after restart={restart}"
                );
                assert_eq!(
                    ctx.get_dependency(HONEST_COMMITTEE_ADDRESSES_KEY),
                    Some(&honest),
                    "honest roster changed after restart={restart}"
                );
            }
            ctx.set_event_recipient(
                "threshold_keyshare",
                Some(
                    e3_events::HistoryCollector::<InterfoldEvent>::new()
                        .start()
                        .recipient(),
                ),
            );
            extension.on_event(
                &mut ctx,
                &InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    CiphertextOutputPublished {
                        e3_id: id.clone(),
                        ciphertext_output: vec![ArcBytes::from_bytes(&[8])],
                        ciphertext_commitment: [0; 32],
                    }
                    .into(),
                    None,
                    6,
                    Some(1),
                    EventSource::Evm,
                )
                .into_sequenced(6),
            );
            assert!(ctx.get_event_recipient("plaintext").is_some());
        }
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
}
