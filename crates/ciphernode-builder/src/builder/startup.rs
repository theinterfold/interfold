// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The order of the startup steps. Storage preflight runs before any actor can write durable
//! state, the lifecycle is reconciled before restart decisions read it, and effects resume only
//! after the sync barrier. Each phase takes the output of the phase before it.

use super::{sortition::setup_sortition, CiphernodeBuilder, EventSystemType};
use crate::{
    finalized_lifecycle::reconcile_restored_contexts, recovery::backfill_restart_state,
    CiphernodeHandle,
};
use actix::{Actor, Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use e3_aggregator::{
    CommitteeFinalizer, CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory,
};
use e3_data::{DataStore, Repositories, RepositoriesFactory};
use e3_event_system::{global_eventstore_cache::EventStoreReader, EventSystem};
use e3_events::{
    hlc::Hlc, AggregateConfig, AggregateId, BusHandle, DkgFoldAttestationContext, E3Stage, E3id,
    EventBus, EventBusConfig, EventStoreQueryBy, EventSubscriber, EventType, InterfoldEvent,
    SeqAgg,
};
use e3_evm::{
    ensure_node_release, resolve_slashing_managers, Chains, EvmChainGatewayHandle,
    GatewayFailureReceiver, ProviderCache, ProviderConfig, ReadOnly, WriteEnabled,
};
use e3_logger::attach_protocol_logger;
use e3_request::{
    canonical_key::CanonicalPublicKeys, ensure_request_router_checkpoint,
    load_dkg_fold_attestation_contexts, E3LifecycleCoordinator, E3LifecycleRepositoryFactory,
};
use e3_sortition::{CiphernodeSelectorState, Sortition};
use e3_sync::{
    preflight_node_role, preflight_schema_version, reconcile_request_router_checkpoint,
    sync_with_net_ready, NodeRole,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::info;

/// The opened storage, after the schema and role preflight and the router checkpoint
/// reconciliation.
pub(super) struct Storage {
    pub chains: Chains,
    pub event_system: EventSystem,
    pub store: DataStore,
    pub eventstore: EventStoreReader,
    pub seq_eventstore: Recipient<EventStoreQueryBy<SeqAgg>>,
    pub repositories: Arc<Repositories>,
    /// One aggregate per enabled chain.
    pub aggregate_config: AggregateConfig,
    /// The aggregates of the event store.
    pub eventstore_aggregate_config: AggregateConfig,
}

/// The restart inputs, read after the lifecycle is reconciled with the finalized chain
/// lifecycle.
#[derive(Default)]
pub(super) struct Restart {
    /// Failed E3s that keep their contexts only for accusation or slashing work.
    pub kept_failures: HashSet<E3id>,
    pub committee_finalizer: CommitteeFinalizerRecoveryState,
    pub lifecycle_stages: HashMap<E3id, E3Stage>,
    pub dkg_fold_contexts_by_e3: HashMap<E3id, DkgFoldAttestationContext>,
}

/// The node address, the enabled bus, and providers that can sign.
pub(super) struct Live {
    pub addr: String,
    pub bus: BusHandle,
    pub provider_cache: ProviderCache<WriteEnabled>,
}

/// The key and committee state that the protocol actors resume from.
pub(super) struct Protocol {
    pub canonical_keys: CanonicalPublicKeys,
    /// E3s that the canonical key projection confirmed as terminal.
    pub terminal_plaintext_e3s: HashSet<E3id>,
    pub sortition: Addr<Sortition>,
    pub selector_state: CiphernodeSelectorState,
    /// The party ID of this node in each restored committee.
    pub selected_party_ids: HashMap<E3id, u64>,
    /// The SlashingManager of each configured chain, in `chains` order.
    pub slashing_managers: Vec<Option<Address>>,
}

impl CiphernodeBuilder {
    pub async fn build(self) -> anyhow::Result<CiphernodeHandle> {
        // Keep the startup state out of the caller's future.
        Box::pin(self.build_inner()).await
    }

    async fn build_inner(mut self) -> anyhow::Result<CiphernodeHandle> {
        self.ensure_startup_options()?;
        let local_bus =
            EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();

        // Optional event collector for debugging / testing.
        let history = if self.collect_history {
            info!("Setting up history collector");
            Some(EventBus::<InterfoldEvent>::history(&local_bus))
        } else {
            None
        };

        let (storage, mut provider_cache) = self.open_storage(local_bus).await?;
        let restart = self.restore(&storage, &mut provider_cache).await?;
        let mut live = self.go_live(&storage, provider_cache).await?;
        let protocol = self.start_protocol_core(&storage, &live).await?;

        // Setup EVM contract event listeners
        let (evm_config, evm_gateways) = self
            .setup_evm_system(&storage, &restart, &mut live, &protocol)
            .await?;

        // Fetch on-chain ZK/slashing configuration
        let chain_parameters = self.fetch_chain_parameters(&storage.chains).await?;

        // Setup protocol extensions (keyshare, aggregation, ZK, accusation, commitment)
        // Keep the startup future within the default thread stack.
        let e3_builder = Box::pin(self.setup_extensions(
            &storage,
            &restart,
            &mut live,
            &protocol,
            &chain_parameters,
        ))
        .await?;

        // Arm the one-shot before the network can publish the no-peer fast-path signal.
        let net_ready = live.bus.wait_for(EventType::NetReady);

        let Protocol {
            selected_party_ids, ..
        } = protocol;
        let network = self
            .start_network(&storage, &live.bus, selected_party_ids)
            .await?;

        // Attach the request router after network startup is registered. Recovered local
        // selections remain dormant until SyncEffect, after EffectsEnabled attaches consumers.
        e3_builder.build().await?;

        // Run the sync routine
        let gateway_failures: Vec<GatewayFailureReceiver> = evm_gateways
            .iter()
            .map(EvmChainGatewayHandle::failure_receiver)
            .collect();
        let mut persistence_health = storage.event_system.failure_receiver();
        tokio::select! {
            result = async { tokio::try_join!(
                sync_with_net_ready(
                    &live.bus,
                    &evm_config,
                    &storage.repositories,
                    &storage.aggregate_config,
                    &storage.seq_eventstore,
                    net_ready,
                ),
                futures::future::try_join_all(
                    evm_gateways.into_iter().map(EvmChainGatewayHandle::wait_until_live)
                ),
                network.buffer.wait_until_running(),
            ) } => { result?; }
            failure = async {
                loop {
                    if let Some(reason) = persistence_health.borrow_and_update().clone() {
                        break reason;
                    }
                    if persistence_health.changed().await.is_err() {
                        break "event storage health monitor stopped".to_string();
                    }
                }
            } => anyhow::bail!("fatal event storage failure during startup: {failure}"),
        }

        Ok(CiphernodeHandle {
            address: live.addr,
            store: storage.store,
            bus: live.bus,
            history,
            peer_id: network.peer_id,
            net_interface: network.kind,
            network_status: network.status,
            eventstore: storage.eventstore,
            aggregate_ids: storage.eventstore_aggregate_config.indexed_ids(),
            persistence_health: storage.event_system.failure_receiver(),
            gateway_failures,
        })
    }

    fn ensure_startup_options(&self) -> Result<()> {
        ensure!(
            self.multithread_concurrent_jobs != Some(0),
            "the detected memory limit cannot safely run one prover job in addition to the node; increase the host or cgroup memory limit"
        );
        ensure!(
            self.max_buffered_evm_events > 0,
            "max_buffered_evm_events must be greater than zero"
        );
        ensure!(
            self.max_buffered_net_events > 0,
            "max_buffered_net_events must be greater than zero"
        );
        ensure!(
            self.max_buffered_net_bytes > 0,
            "max_buffered_net_bytes must be greater than zero"
        );
        Ok(())
    }

    /// Connect to the enabled chains, open the stores, and check them before any actor can write
    /// durable state.
    async fn open_storage(
        &mut self,
        local_bus: Addr<EventBus<InterfoldEvent>>,
    ) -> Result<(Storage, ProviderCache<ReadOnly>)> {
        // Connect to the enabled chains and derive one event store aggregate per chain.
        let mut provider_cache = if let Some(signer) = self.signer.take() {
            ProviderCache::new().with_signer(signer)
        } else {
            ProviderCache::new()
        };
        let chains = Chains::resolve(&self.chains, &mut provider_cache).await?;
        let aggregate_config = chains.aggregate_config();
        #[cfg(feature = "test-helpers")]
        let eventstore_aggregate_config = self
            .eventstore_aggregate_config_override
            .take()
            .unwrap_or_else(|| aggregate_config.clone());
        #[cfg(not(feature = "test-helpers"))]
        let eventstore_aggregate_config = aggregate_config.clone();

        // The event log replays the correlation IDs of earlier boots: keep this boot's IDs above
        // them before replay starts.
        if let EventSystemType::Persisted { log_path, .. } = &self.event_system {
            e3_events::reserve_correlation_ids(&log_path.with_file_name("correlation-ids"))?;
        }

        // Build the event system (store + eventstore)
        let event_system = self.create_event_system(local_bus, &eventstore_aggregate_config);
        let store = event_system.store()?;
        let eventstore = event_system.eventstore_reader()?;
        let seq_eventstore = eventstore.seq();
        let repositories = Arc::new(store.repositories());

        // Establish storage compatibility before signers, actors, or forked runtime events can
        // create durable state. Running this only inside `sync` is too late: actor startup can
        // make a fresh store non-empty and cause it to look like unversioned legacy data.
        let new_directory =
            preflight_schema_version(&repositories, &eventstore_aggregate_config, &seq_eventstore)
                .await?;
        preflight_node_role(&repositories, new_directory, self.role()).await?;
        ensure_request_router_checkpoint(&repositories, aggregate_config.aggregates()).await?;
        reconcile_request_router_checkpoint(
            &repositories,
            aggregate_config.aggregates(),
            &seq_eventstore,
        )
        .await?;

        let storage = Storage {
            chains,
            event_system,
            store,
            eventstore,
            seq_eventstore,
            repositories,
            aggregate_config,
            eventstore_aggregate_config,
        };
        Ok((storage, provider_cache))
    }

    /// Reconcile the lifecycle with finalized chain state, then read the restart inputs.
    async fn restore(
        &self,
        storage: &Storage,
        provider_cache: &mut ProviderCache<ReadOnly>,
    ) -> Result<Restart> {
        let repositories = &storage.repositories;
        // Reconcile the lifecycle with finalized chain state before any restart decision reads
        // it, so the work of an E3 that is finished on chain does not resume.
        let kept_failures = reconcile_restored_contexts(
            repositories,
            storage.aggregate_config.aggregates(),
            &storage.seq_eventstore,
            &self.chains,
            provider_cache,
        )
        .await?;
        let committee_finalizer = backfill_restart_state(
            repositories,
            &storage.seq_eventstore,
            &storage.chains.enabled_ids(),
            self.role() == NodeRole::Full,
        )
        .await?;
        let lifecycle_stages = repositories
            .e3_lifecycle()
            .read()
            .await?
            .unwrap_or_default();
        let dkg_fold_contexts_by_e3 = load_dkg_fold_attestation_contexts(repositories).await?;
        Ok(Restart {
            kept_failures,
            committee_finalizer,
            lifecycle_stages,
            dkg_fold_contexts_by_e3,
        })
    }

    /// Check the node release on each registry chain, resolve the node address, and enable the
    /// bus with a clock above every durable event timestamp.
    async fn go_live(
        &self,
        storage: &Storage,
        provider_cache: ProviderCache<ReadOnly>,
    ) -> Result<Live> {
        let mut provider_cache = provider_cache
            .with_write_support(Arc::clone(&self.cipher), Arc::clone(&storage.repositories));

        if self.role() == NodeRole::Full {
            for chain in storage.chains.enabled() {
                let contracts = &chain.config.contracts;
                let provider = provider_cache.ensure_write_provider(&chain.config).await?;
                ensure_node_release(
                    provider,
                    contracts.interfold.address()?,
                    contracts.bonding_registry.address()?,
                    contracts.ciphernode_registry.address()?,
                )
                .await?;
            }
        }

        // Resolve node address and enable the bus
        let addr = provider_cache.ensure_signer().await?.address().to_string();
        let bus = storage
            .event_system
            .enable_handle_with_hlc(event_clock(&addr, &storage.chains.enabled_ids()))
            .await?;

        if self.logging {
            let logger_name = self.name.as_deref().unwrap_or("ciphernode");
            attach_protocol_logger(logger_name, &bus);
        }

        Ok(Live {
            addr,
            bus,
            provider_cache,
        })
    }

    /// Recover the canonical keys, then attach sortition, the lifecycle coordinator, and the
    /// committee finalizer, and resolve the SlashingManager of each chain.
    async fn start_protocol_core(&self, storage: &Storage, live: &Live) -> Result<Protocol> {
        let Live { addr, bus, .. } = live;
        let repositories = &storage.repositories;
        let canonical_keys = CanonicalPublicKeys::default();
        let mut terminal_plaintext_e3s = HashSet::new();
        if self.role() == NodeRole::Full {
            let mut key_chains = HashMap::new();
            for chain in storage.chains.iter() {
                if let Some(chain_id) = chain.chain_id() {
                    key_chains.insert(chain_id, chain.config().contracts.interfold.address()?);
                }
            }
            let aggregates = storage
                .eventstore_aggregate_config
                .indexed_ids()
                .into_iter()
                .filter(|id| key_chains.contains_key(&(*id as u64)))
                .map(AggregateId::new)
                .collect::<Vec<_>>();
            let mut projection = e3_evm::canonical_key::CanonicalKeyProjection::new(
                canonical_keys.clone(),
                key_chains,
            );
            let hydrating_contexts =
                e3_request::RouterRepositoryFactory::request_router_checkpoint(
                    repositories.as_ref(),
                )
                .read()
                .await?
                .map(|checkpoint| checkpoint.contexts.into_iter().collect())
                .unwrap_or_default();
            projection
                .recover(&storage.seq_eventstore, &aggregates, hydrating_contexts)
                .await?;
            terminal_plaintext_e3s = projection.confirmed_terminal_e3s();
            projection.attach(bus).await?;
        }

        // Setup sortition
        let (sortition, selector_state) = setup_sortition(bus, repositories, addr).await?;
        let selected_party_ids: HashMap<E3id, u64> = selector_state
            .committees
            .iter()
            .filter_map(|(e3_id, committee)| {
                committee
                    .party_id_for(addr)
                    .map(|party_id| (e3_id.clone(), party_id))
            })
            .collect();

        // Setup the durable E3 lifecycle coordinator (additive observer that
        // tracks each E3's stage for restart-resume awareness and shutdown).
        E3LifecycleCoordinator::attach(bus, storage.store.clone()).await?;

        if self.role() == NodeRole::Full {
            let mut finalizer_providers = HashMap::new();
            for chain in storage.chains.enabled() {
                let factory =
                    ProviderConfig::for_chain(&chain.config)?.into_read_provider_factory();
                finalizer_providers.insert(chain.chain_id, factory);
            }
            CommitteeFinalizer::attach_with_recovery(
                bus,
                repositories.committee_finalizer_recovery(),
                finalizer_providers,
            )
            .await?;
        }

        // Only a full node signs accusation votes and submits slash proposals.
        let slashing_managers = if self.role() == NodeRole::Full {
            resolve_slashing_managers(&storage.chains).await?
        } else {
            storage.chains.iter().map(|_| None).collect()
        };

        Ok(Protocol {
            canonical_keys,
            terminal_plaintext_e3s,
            sortition,
            selector_state,
            selected_party_ids,
            slashing_managers,
        })
    }

    fn create_event_system(
        &self,
        bus: Addr<EventBus<InterfoldEvent>>,
        aggregate_config: &AggregateConfig,
    ) -> EventSystem {
        let base = match self.event_system.clone() {
            EventSystemType::Persisted { kv_path, log_path } => {
                EventSystem::persisted(log_path, kv_path)
            }
            EventSystemType::InMem => EventSystem::in_mem(),
        };
        base.with_event_bus(bus)
            .with_aggregate_config(aggregate_config.clone())
            .with_global_shared_store(self.shared_stores)
            .with_global_shared_eventstore(self.shared_stores)
    }
}

fn event_clock(node_id: &str, chain_ids: &[u64]) -> Hlc {
    let clock = Hlc::from_str(node_id);
    // Local EVM tests advance block timestamps. Public chains keep the default drift fence.
    if !chain_ids.is_empty()
        && chain_ids
            .iter()
            .all(|chain_id| matches!(chain_id, 1_337 | 31_337))
    {
        return clock.with_max_drift(u64::MAX);
    }
    clock
}

#[cfg(test)]
mod tests {
    use super::event_clock;
    use e3_events::hlc::{HlcError, HlcMethods, HlcTimestamp};

    #[test]
    fn local_event_clock_allows_time_travel_only_on_dev_chains() {
        let future_timestamp = |clock: &e3_events::hlc::Hlc| {
            let now = clock.tick().unwrap();
            HlcTimestamp::new(now.ts + 3_600_000_000, 0, now.node + 1)
        };

        let local = event_clock("local", &[31_337]);
        assert!(local.receive(&future_timestamp(&local)).is_ok());

        let public = event_clock("public", &[1]);
        assert!(matches!(
            public.receive(&future_timestamp(&public)),
            Err(HlcError::DriftExceeded { .. })
        ));
    }
}
