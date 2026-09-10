// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    recovery::{
        backfill_restart_state, reconcile_committee_snapshots, recovered_ciphernode_selections,
    },
    CiphernodeHandle, EventSystem, EvmSystemChainBuilder, NetInterfaceKind, ProviderCache,
    WriteEnabled,
};
use actix::{Actor, Addr};
use alloy::primitives::Address;
use anyhow::{ensure, Result};
use derivative::Derivative;
use e3_aggregator::ext::{
    AggregatorRoleExtension, PublicKeyAggregatorExtension, ThresholdPlaintextAggregatorExtension,
};
use e3_aggregator::{
    CommitteeFinalizer, CommitteeFinalizerRecoveryState, CommitteeFinalizerRepositoryFactory,
};
use e3_config::{chain_config::ChainConfig, NetworkProfile};
use e3_crypto::Cipher;
use e3_data::{InMemStore, RepositoriesFactory};
use e3_events::{hlc::Hlc, DkgFoldAttestationContext};
use e3_events::{
    AggregateConfig, AggregateId, BusHandle, E3Stage, E3id, EventBus, EventBusConfig,
    EventSubscriber, EventType, EvmEventConfig, InterfoldEvent,
};
use e3_evm::{
    ensure_node_release, fetch_accusation_vote_validity, fetch_randomness_providers,
    BondingRegistrySolReader, CiphernodeRegistrySol, CiphernodeRegistrySolReader,
    DataAvailabilityCoordinator, DataAvailabilityRepositoryFactory, EvmChainGatewayHandle,
    InterfoldSolReader, InterfoldSolWriter, ProviderConfig, RandomnessProviderSolReader,
    SlashingManagerSolReader, SlashingManagerSolWriter, SlashingWriterRepositoryFactory,
};
use e3_fhe::ext::FheExtension;
use e3_keyshare::ext::ThresholdKeyshareExtension;
use e3_logger::attach_protocol_logger;
use e3_multithread::{Multithread, MultithreadReport, TaskPool};
use e3_net::{
    create_channel_bridge_with_application_event_capacity, setup_libp2p_keypair,
    setup_net_interface, setup_net_with_limits_and_interests, NetRepositoryFactory, NetworkPolicy,
};
use e3_request::{
    ensure_request_router_checkpoint, load_dkg_fold_attestation_contexts, E3LifecycleCoordinator,
    E3LifecycleRepositoryFactory, E3Router,
};
use e3_slashing::{AccusationManagerExtension, CommitmentConsistencyCheckerExtension};
use e3_sortition::{
    AggregatorFailoverRepositoryFactory, CiphernodeSelector, CiphernodeSelectorFactory,
    CiphernodeSelectorState, FinalizedCommitteesRepositoryFactory, GetCiphernodeSelectorState,
    NodeStateRepositoryFactory, Sortition, SortitionAttachParams, SortitionBackend,
    SortitionRecoveryRepositoryFactory, SortitionRepositoryFactory,
};
use e3_sync::{preflight_schema_version, reconcile_request_router_checkpoint, sync_with_net_ready};
use e3_utils::SharedRng;
use e3_zk_prover::{setup_zk_actors, ZkActorRecovery, ZkBackend};
use libp2p::PeerId;
use std::time::Duration;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
enum EventSystemType {
    Persisted { log_path: PathBuf, kv_path: PathBuf },
    InMem,
}

struct EvmStartupRecovery<'a> {
    dkg_fold_contexts_by_e3: &'a HashMap<E3id, DkgFoldAttestationContext>,
    active_aggregators: &'a HashMap<E3id, bool>,
    selected_party_ids: &'a HashMap<E3id, u64>,
    lifecycle_stages: &'a HashMap<E3id, E3Stage>,
    committee_finalizer: &'a CommitteeFinalizerRecoveryState,
}

/// Build a ciphernode configuration.
///
/// Follows a builder pattern. Production nodes are assembled via
/// [`entrypoint::start`](e3_entrypoint::start); tests and benchmarks use the same
/// builder with in-memory stores and forked buses.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CiphernodeBuilder {
    address: Option<String>,
    #[cfg(feature = "test-helpers")]
    eventstore_aggregate_config_override: Option<AggregateConfig>,
    chains: Vec<ChainConfig>,
    #[derivative(Debug = "ignore")]
    cipher: Arc<Cipher>,
    contract_components: ContractComponents,
    event_system: EventSystemType,
    in_mem_store: Option<Addr<InMemStore>>,
    keyshare: Option<KeyshareKind>,
    logging: bool,
    max_buffered_evm_events: usize,
    max_buffered_net_bytes: usize,
    max_buffered_net_events: usize,
    name: Option<String>,
    multithread_cache: Option<Addr<Multithread>>,
    multithread_concurrent_jobs: Option<usize>,
    multithread_report: Option<Addr<MultithreadReport>>,
    proof_aggregation_enabled: bool,
    pubkey_agg: bool,
    rng: SharedRng,
    sortition_backend: SortitionBackend,
    source_bus: Option<BusMode<Addr<EventBus<InterfoldEvent>>>>,
    task_pool: Option<TaskPool>,
    threads: Option<usize>,
    signer: Option<alloy::signers::local::PrivateKeySigner>,
    threshold_plaintext_agg: bool,
    zk_backend: Option<ZkBackend>,
    net_config: Option<NetConfig>,
    global_shared_store: bool,
    global_shared_eventstore: bool,
    collect_history: bool,
    collect_errors: bool,
}

// Simple Net Configuration
#[derive(Debug)]
struct NetConfig {
    pub peers: Vec<String>,
    pub quic_port: u16,
    pub network: NetworkProfile,
}

impl NetConfig {
    pub fn new(network: NetworkProfile, peers: Vec<String>, quic_port: u16) -> Self {
        Self {
            peers,
            quic_port,
            network,
        }
    }
}

#[derive(Default, Debug)]
pub struct ContractComponents {
    interfold_reader: bool,
    interfold: bool,
    ciphernode_registry: bool,
    bonding_registry: bool,
    slashing_manager: bool,
}

#[derive(Clone, Debug)]
pub enum BusMode<T> {
    Forked(T),
    Source(T),
}

#[derive(Clone, Debug)]
pub enum KeyshareKind {
    Threshold,
}

impl CiphernodeBuilder {
    /// Create a new ciphernode builder.
    pub fn new(rng: SharedRng, cipher: Arc<Cipher>) -> Self {
        Self {
            address: None,
            #[cfg(feature = "test-helpers")]
            eventstore_aggregate_config_override: None,
            chains: vec![],
            cipher,
            contract_components: ContractComponents::default(),
            event_system: EventSystemType::InMem,
            in_mem_store: None,
            keyshare: None,
            logging: false,
            max_buffered_evm_events: 100_000,
            max_buffered_net_bytes: 256 * 1024 * 1024,
            max_buffered_net_events: 1_024,
            name: None,
            multithread_cache: None,
            multithread_concurrent_jobs: None,
            multithread_report: None,
            proof_aggregation_enabled: true,
            pubkey_agg: false,
            rng,
            sortition_backend: SortitionBackend::score(),
            source_bus: None,
            task_pool: None,
            threads: None,
            signer: None,
            threshold_plaintext_agg: false,
            net_config: None,
            zk_backend: None,
            global_shared_store: false,
            global_shared_eventstore: false,
            collect_history: false,
            collect_errors: false,
        }
    }

    /// Use the given bus for all events. No new bus is created.
    pub fn with_source_bus(mut self, bus: &Addr<EventBus<InterfoldEvent>>) -> Self {
        self.source_bus = Some(BusMode::Source(bus.clone()));
        self
    }

    /// Fork events from the given source bus to a local bus. Events from the
    /// source are forwarded to the local bus created for this instance.
    /// Useful for tests and monitoring subscribers that need an isolated
    /// event stream that mirrors the source.
    pub fn with_forked_bus(mut self, bus: &Addr<EventBus<InterfoldEvent>>) -> Self {
        self.source_bus = Some(BusMode::Forked(bus.clone()));
        self
    }

    /// Set the node name for dashboard display and log attribution.
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Use the TrBFV feature
    pub fn with_trbfv(mut self) -> Self {
        self.keyshare = Some(KeyshareKind::Threshold);
        self
    }

    /// Use the given in-mem datastore. This is useful for injecting a store dump.
    pub fn with_in_mem_datastore(mut self, store: &Addr<InMemStore>) -> Self {
        self.in_mem_store = Some(store.to_owned());
        self
    }

    /// Subscribe a [`HistoryCollector`] to the event bus for inspecting all events.
    /// Useful for tests, benchmarks, and debugging.
    pub fn with_history_collector(mut self) -> Self {
        self.collect_history = true;
        self
    }

    /// Subscribe a [`HistoryCollector`] to only `InterfoldError` events.
    /// Useful for tests and debugging.
    pub fn with_error_collector(mut self) -> Self {
        self.collect_errors = true;
        self
    }

    /// Add persistence information for storing events and data. Without persistence information
    /// the node will run in memory by default.
    pub fn with_persistence(mut self, log_path: &PathBuf, kv_path: &PathBuf) -> Self {
        self.event_system = EventSystemType::Persisted {
            log_path: log_path.to_owned(),
            kv_path: kv_path.to_owned(),
        };
        self
    }

    /// Use the node configuration on these specific chains. This will overwrite any previously
    /// given chains.
    pub fn with_chains(mut self, chains: &[ChainConfig]) -> Self {
        self.chains = chains.to_vec();
        self
    }

    /// Add event stores for aggregates that have no EVM provider in an in-process test.
    #[cfg(feature = "test-helpers")]
    pub fn with_eventstore_aggregate_config_for_testing(mut self, config: AggregateConfig) -> Self {
        self.eventstore_aggregate_config_override = Some(config);
        self
    }

    /// Resolve the slashing manager address from ChainConfig. All chains are
    /// checked (enabled or not) since this is just config, not RPC-dependent.
    fn resolve_slashing_manager(&self) -> Result<Address> {
        self.chains
            .iter()
            .find_map(|c| c.contracts.slashing_manager.as_ref())
            .map(|c| c.address())
            .transpose()?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "`slashing_manager` contract address is required in chain config — \
                     it is the EIP-712 `verifyingContract` for accusation vote signatures"
                )
            })
    }

    /// Fetch `CiphernodeRegistry.accusationVoteValidity()` for one chain (off-chain
    /// vote freshness window in seconds). Returns `0` when the registry has
    /// disabled slashing (governance emergency stop). The actor will then refuse
    /// to stamp votes that would be rejected on chain.
    ///
    /// The `u256` returned by the registry is clamped to `u64`. The contract
    /// has no upper bound but `u64::MAX` seconds is already ~5.8 × 10¹¹ years —
    /// any value that doesn't fit in `u64` is treated as "effectively infinite"
    /// by saturating at `u64::MAX`, matching the on-chain `block.timestamp`
    /// comparison.
    async fn fetch_accusation_vote_validity_from_registry(
        provider_cache: &mut ProviderCache<WriteEnabled>,
        chain: &ChainConfig,
    ) -> Result<u64> {
        let provider = provider_cache.ensure_read_provider(chain).await?;
        let registry = chain.contracts.ciphernode_registry.address()?;
        let validity = fetch_accusation_vote_validity(provider.provider(), registry).await?;
        let secs = match validity {
            Some(v) => {
                let clamped: u64 = v.try_into().unwrap_or(u64::MAX);
                info!(
                    chain = %chain.name,
                    registry = %registry,
                    accusation_vote_validity_secs = clamped,
                    "loaded accusationVoteValidity from CiphernodeRegistry"
                );
                clamped
            }
            None => {
                tracing::warn!(
                    chain = %chain.name,
                    registry = %registry,
                    "CiphernodeRegistry.accusationVoteValidity is 0; the off-chain \
                     accusation manager will not produce votes (governance-disabled \
                     or pre-initialized registry)"
                );
                0
            }
        };
        Ok(secs)
    }

    /// Log data actor events
    pub fn with_logging(mut self) -> Self {
        self.logging = true;
        self
    }

    /// Do public key aggregation
    pub fn with_pubkey_aggregation(mut self) -> Self {
        self.pubkey_agg = true;
        self
    }

    /// Skip recursive proof aggregation for tests and CI.
    ///
    /// This only changes local ciphernode work. Contracts still verify the final DKG and
    /// decryption proof payloads, so this setting is only useful with test deployments whose
    /// configured mock verifiers accept the non-empty C5/C7 placeholder payloads.
    #[cfg(feature = "test-only-skip-proof-aggregation")]
    pub fn with_proof_aggregation_disabled_for_testing(mut self) -> Self {
        self.proof_aggregation_enabled = false;
        self
    }

    /// Connect rayon work to the given threadpool
    pub fn with_shared_taskpool(mut self, pool: &TaskPool) -> Self {
        self.task_pool = Some(pool.clone());
        self
    }

    /// Shared MultithreadReport for benchmarking
    pub fn with_shared_multithread_report(mut self, report: &Addr<MultithreadReport>) -> Self {
        self.multithread_report = Some(report.clone());
        self
    }

    /// Setup how many threads to use within the multithread actor for it's rayon based workload
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = Some(threads);
        self
    }

    /// This will provide one thread for the actor model and use all other threads for
    /// rayon based workloads
    pub fn with_max_threads(mut self) -> Self {
        self.threads = Some(Multithread::get_max_threads_minus(1));
        self
    }

    /// Configure the Rayon compute pool for production workloads.
    ///
    /// Reserves `reserve_threads` CPUs for Actix / networking, uses the remainder for Rayon, and
    /// allows up to `concurrent_jobs` CPU-bound tasks at once (ZK + TrBFV). When `concurrent_jobs`
    /// is `None`, uses all available compute threads.
    pub fn with_multithread_config(
        mut self,
        reserve_threads: usize,
        concurrent_jobs: Option<usize>,
    ) -> Self {
        let max_threads = Multithread::get_max_threads_minus(reserve_threads);
        let jobs = concurrent_jobs.unwrap_or(max_threads).max(1);
        let pool_threads = jobs.min(max_threads).max(1);
        info!(
            "Multithread pool: rayon_threads={pool_threads}, max_concurrent_jobs={jobs}, reserve_threads={reserve_threads}"
        );
        self.threads = Some(pool_threads);
        self.multithread_concurrent_jobs = Some(jobs);
        self
    }

    /// This will save the given number of threads from being used by the rayon threadpool
    pub fn with_max_threads_minus(mut self, threads: usize) -> Self {
        self.threads = Some(Multithread::get_max_threads_minus(threads));
        self
    }

    /// Set the number of concurrent jobs defaults to 1
    pub fn with_multithread_concurrent_jobs(mut self, jobs: usize) -> Self {
        self.multithread_concurrent_jobs = if jobs >= 1 { Some(jobs) } else { None };
        self
    }

    /// Bound decoded EVM events retained per chain while initial sync orders historical and live
    /// observations. Exhaustion fails startup instead of silently dropping chain history.
    pub fn with_max_buffered_evm_events(mut self, limit: usize) -> Self {
        self.max_buffered_evm_events = limit;
        self
    }

    /// Bound count and estimated bytes retained from the network while initial synchronization is
    /// in progress. Exhaustion fails startup rather than dropping protocol input.
    pub fn with_network_buffer_limits(mut self, max_events: usize, max_bytes: usize) -> Self {
        self.max_buffered_net_events = max_events;
        self.max_buffered_net_bytes = max_bytes;
        self
    }

    /// Setup a ThresholdPlaintextAggregator
    pub fn with_threshold_plaintext_aggregation(mut self) -> Self {
        self.threshold_plaintext_agg = true;
        self
    }

    /// Enable ZK proof generation with the given backend.
    pub fn with_zkproof(mut self, backend: ZkBackend) -> Self {
        self.zk_backend = Some(backend);
        self
    }

    /// Pre-populate the signer cache with the given signer.
    /// The signer is used for EVM transactions and EIP-712 signatures.
    pub fn with_signer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Use score-based sortition (recommended)
    pub fn with_sortition_score(mut self) -> Self {
        self.sortition_backend = SortitionBackend::score();
        self
    }

    /// Setup an Interfold contract reader for every evm chain provided
    pub fn with_contract_interfold_reader(mut self) -> Self {
        self.contract_components.interfold_reader = true;
        self
    }

    /// Setup an Interfold contract reader and writer for every evm chain provided
    pub fn with_contract_interfold_full(mut self) -> Self {
        self.contract_components.interfold = true;
        self
    }

    /// Setup a writable BondingRegistry for every evm chain provided
    pub fn with_contract_bonding_registry(mut self) -> Self {
        self.contract_components.bonding_registry = true;
        self
    }
    /// Setup a CiphernodeRegistry listener for every evm chain provided
    pub fn with_contract_ciphernode_registry(mut self) -> Self {
        self.contract_components.ciphernode_registry = true;
        self
    }

    /// Setup a SlashingManager writer for submitting slash proposals on-chain.
    /// Requires the `slashing_manager` contract address to be configured.
    pub fn with_contract_slashing_manager(mut self) -> Self {
        self.contract_components.slashing_manager = true;
        self
    }

    /// Share the store this ciphernode uses with socket server commands
    pub fn with_shared_store(mut self) -> Self {
        self.global_shared_store = true;
        self
    }

    /// Share the eventstore this ciphernode uses with socket server commands
    pub fn with_shared_eventstore(mut self) -> Self {
        self.global_shared_eventstore = true;
        self
    }

    /// Setup net package components.
    pub fn with_net(mut self, peers: Vec<String>, quic_port: u16) -> Self {
        self.net_config = Some(NetConfig::new(NetworkProfile::local(), peers, quic_port));
        self
    }

    /// Set up networking for an explicit Interfold network profile.
    pub fn with_network(
        mut self,
        network: NetworkProfile,
        peers: Vec<String>,
        quic_port: u16,
    ) -> Self {
        self.net_config = Some(NetConfig::new(network, peers, quic_port));
        self
    }

    fn create_local_bus() -> Addr<EventBus<InterfoldEvent>> {
        EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start()
    }

    /// Create aggregate configuration from configured chains
    async fn create_aggregate_config(
        &self,
        provider_cache: &mut ProviderCache,
    ) -> Result<(AggregateConfig, Vec<u64>)> {
        let mut chain_providers = Vec::new();
        let mut chain_ids = Vec::new();
        for chain in self.chains.iter().filter(|c| c.enabled.unwrap_or(true)) {
            let provider = provider_cache.ensure_read_provider(chain).await?;
            chain_providers.push((chain.clone(), provider.chain_id()));
            chain_ids.push(provider.chain_id());
        }

        let delays = create_aggregate_delays(&chain_providers)?;
        Ok((AggregateConfig::new(delays), chain_ids))
    }

    pub async fn build(mut self) -> anyhow::Result<CiphernodeHandle> {
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
        let local_bus = self.resolve_bus();

        // Optional event collectors for debugging / testing.
        let history = if self.collect_history {
            info!("Setting up history collector");
            Some(EventBus::<InterfoldEvent>::history(&local_bus))
        } else {
            None
        };
        let errors = if self.collect_errors {
            info!("Setting up error collector");
            Some(EventBus::<InterfoldEvent>::error(&local_bus))
        } else {
            None
        };

        // Create provider cache and aggregate config
        let mut provider_cache = if let Some(signer) = self.signer.take() {
            ProviderCache::new().with_signer(signer)
        } else {
            ProviderCache::new()
        };
        let (aggregate_config, resolved_chain_ids) =
            self.create_aggregate_config(&mut provider_cache).await?;
        #[cfg(feature = "test-helpers")]
        let eventstore_aggregate_config = self
            .eventstore_aggregate_config_override
            .take()
            .unwrap_or_else(|| aggregate_config.clone());
        #[cfg(not(feature = "test-helpers"))]
        let eventstore_aggregate_config = aggregate_config.clone();

        // Build the event system (store + eventstore)
        let event_system = self.create_event_system(local_bus, &eventstore_aggregate_config);
        let store = event_system.store()?;
        let eventstore = event_system.eventstore_reader()?;
        let seq_eventstore = eventstore.seq();
        let repositories = Arc::new(store.repositories());

        // Establish storage compatibility before signers, actors, or forked runtime events can
        // create durable state. Running this only inside `sync` is too late: actor startup can
        // make a fresh store non-empty and cause it to look like unversioned legacy data.
        preflight_schema_version(&repositories, &eventstore_aggregate_config, &seq_eventstore)
            .await?;
        ensure_request_router_checkpoint(&repositories, aggregate_config.aggregates()).await?;
        reconcile_request_router_checkpoint(
            &repositories,
            aggregate_config.aggregates(),
            &seq_eventstore,
        )
        .await?;
        let committee_finalizer_recovery = backfill_restart_state(
            &repositories,
            &seq_eventstore,
            &resolved_chain_ids,
            self.contract_components.slashing_manager,
        )
        .await?;
        let lifecycle_stages = repositories
            .e3_lifecycle()
            .read()
            .await?
            .unwrap_or_default();
        let dkg_fold_contexts_by_e3 = load_dkg_fold_attestation_contexts(&repositories).await?;

        let mut provider_cache =
            provider_cache.with_write_support(Arc::clone(&self.cipher), Arc::clone(&repositories));

        if self.contract_components.ciphernode_registry {
            for chain in self
                .chains
                .iter()
                .filter(|chain| chain.enabled.unwrap_or(true))
            {
                let provider = provider_cache.ensure_write_provider(chain).await?;
                ensure_node_release(
                    provider,
                    chain.contracts.interfold.address()?,
                    chain.contracts.bonding_registry.address()?,
                    chain.contracts.ciphernode_registry.address()?,
                )
                .await?;
            }
        }

        // Resolve node address and enable the bus
        let addr = provider_cache.ensure_signer().await?.address().to_string();
        let bus = event_system
            .handle()?
            .enable_with_hlc(event_clock(&addr, &resolved_chain_ids));

        if self.logging {
            let logger_name = self.name.as_deref().unwrap_or("ciphernode");
            attach_protocol_logger(logger_name, &bus);
        }

        // Setup sortition
        let (sortition, _ciphernode_selector, selector_state) =
            self.setup_sortition(&bus, &repositories, &addr).await?;
        let selected_party_ids: HashMap<E3id, u64> = selector_state
            .committees
            .iter()
            .filter_map(|(e3_id, committee)| {
                committee
                    .party_id_for(&addr)
                    .map(|party_id| (e3_id.clone(), party_id))
            })
            .collect();

        // Setup the durable E3 lifecycle coordinator (additive observer that
        // tracks each E3's stage for restart-resume awareness and shutdown).
        E3LifecycleCoordinator::attach(&bus, store.clone()).await?;

        if self.pubkey_agg {
            let mut finalizer_providers = HashMap::new();
            for chain in self
                .chains
                .iter()
                .filter(|chain| chain.enabled.unwrap_or(true))
            {
                let provider = provider_cache.ensure_read_provider(chain).await?;
                finalizer_providers.insert(provider.chain_id(), provider);
            }
            CommitteeFinalizer::attach_with_recovery(
                &bus,
                repositories.committee_finalizer_recovery(),
                finalizer_providers,
            )
            .await?;
        }

        // Setup EVM contract event listeners
        let (evm_config, evm_gateways) = self
            .setup_evm_system(
                &mut provider_cache,
                &bus,
                &repositories,
                EvmStartupRecovery {
                    dkg_fold_contexts_by_e3: &dkg_fold_contexts_by_e3,
                    active_aggregators: &selector_state.is_aggregator,
                    selected_party_ids: &selected_party_ids,
                    lifecycle_stages: &lifecycle_stages,
                    committee_finalizer: &committee_finalizer_recovery,
                },
            )
            .await?;

        // Fetch on-chain ZK/slashing configuration
        let (dkg_fold_context_by_chain, accusation_vote_validity_by_chain) =
            self.fetch_chain_configuration(&mut provider_cache).await?;

        // Setup protocol extensions (keyshare, aggregation, ZK, accusation, commitment)
        let e3_builder = self
            .setup_extensions(
                &bus,
                store.clone(),
                &mut provider_cache,
                &sortition,
                &addr,
                &dkg_fold_context_by_chain,
                &dkg_fold_contexts_by_e3,
                &accusation_vote_validity_by_chain,
                &selector_state,
                &lifecycle_stages,
            )
            .await?;

        // Arm the one-shot before the network can publish the no-peer fast-path signal.
        let net_ready = bus.wait_for(EventType::NetReady);

        // Setup networking
        let network = self.network_policy(&resolved_chain_ids)?;
        let (peer_id, interface, net_kind) = self.setup_networking(&store, &network).await?;
        let network_status = interface.status();
        let net_buffer = setup_net_with_limits_and_interests(
            &network,
            bus.clone(),
            eventstore.ts(),
            interface,
            self.max_buffered_net_events,
            self.max_buffered_net_bytes,
            selected_party_ids,
        )?;

        // Attach the request router after network startup is registered. Recovered local
        // selections remain dormant until SyncEffect, after EffectsEnabled attaches consumers.
        e3_builder.build().await?;

        // Run the sync routine
        tokio::try_join!(
            sync_with_net_ready(
                &bus,
                &evm_config,
                &repositories,
                &aggregate_config,
                &seq_eventstore,
                net_ready,
            ),
            wait_for_evm_gateways(evm_gateways),
            net_buffer.wait_until_running(),
        )?;

        Ok(CiphernodeHandle {
            address: addr.to_owned(),
            store,
            bus,
            history,
            errors,
            peer_id,
            net_interface: net_kind,
            network_status,
            eventstore,
            aggregate_ids: eventstore_aggregate_config.indexed_ids(),
        })
    }

    // ── build() sub-functions ──────────────────────────────────────────

    fn resolve_bus(&self) -> Addr<EventBus<InterfoldEvent>> {
        match self.source_bus {
            Some(BusMode::Forked(ref bus)) => {
                let local_bus = Self::create_local_bus();
                info!("Setting up Event pipe");
                EventBus::pipe(bus, &local_bus);
                local_bus
            }
            Some(BusMode::Source(ref bus)) => bus.clone(),
            None => Self::create_local_bus(),
        }
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
            EventSystemType::InMem => {
                if let Some(ref store) = self.in_mem_store {
                    EventSystem::in_mem_from_store(store)
                } else {
                    EventSystem::in_mem()
                }
            }
        };
        base.with_event_bus(bus)
            .with_aggregate_config(aggregate_config.clone())
            .with_global_shared_store(self.global_shared_store)
            .with_global_shared_eventstore(self.global_shared_eventstore)
    }

    async fn setup_sortition(
        &self,
        bus: &BusHandle,
        repositories: &e3_data::Repositories,
        addr: &str,
    ) -> Result<(
        Addr<Sortition>,
        Addr<CiphernodeSelector>,
        CiphernodeSelectorState,
    )> {
        let lifecycle = repositories
            .e3_lifecycle()
            .read()
            .await?
            .unwrap_or_default();
        let selector_store = repositories.ciphernode_selector();
        let mut selector_snapshot = selector_store.read().await?.unwrap_or_default();
        let committees_repo = repositories.finalized_committees();
        let mut committees = committees_repo.read().await?.unwrap_or_default();
        let (selector_changed, committees_changed) =
            reconcile_committee_snapshots(&mut selector_snapshot, &mut committees, &lifecycle)?;
        if selector_changed {
            selector_store.write_sync(&selector_snapshot).await?;
        }
        if committees_changed {
            committees_repo.write_sync(&committees).await?;
        }
        let ciphernode_selector = CiphernodeSelector::attach(
            bus,
            selector_store,
            repositories.aggregator_failover(),
            lifecycle.clone(),
            addr,
        )
        .await?;
        let selector_state = ciphernode_selector
            .send(GetCiphernodeSelectorState)
            .await??;
        let sortition = Sortition::attach(SortitionAttachParams {
            bus,
            backends_store: repositories.sortition(),
            node_state_store: repositories.node_state(),
            recovery_store: repositories.sortition_recovery(),
            committees_store: committees_repo,
            default_backend: self.sortition_backend.clone(),
            ciphernode_selector: ciphernode_selector.clone(),
            address: addr,
        })
        .await?;
        Ok((sortition, ciphernode_selector, selector_state))
    }

    async fn setup_evm_system(
        &self,
        provider_cache: &mut ProviderCache<WriteEnabled>,
        bus: &BusHandle,
        repositories: &e3_data::Repositories,
        recovery: EvmStartupRecovery<'_>,
    ) -> Result<(EvmEventConfig, Vec<EvmChainGatewayHandle>)> {
        setup_evm_system(
            &self.chains,
            provider_cache,
            bus,
            repositories,
            &self.contract_components,
            self.max_buffered_evm_events,
            recovery,
        )
        .await
    }

    /// Fetch DKG fold attestation verifier and accusation vote validity from on-chain
    /// registries. Requires enabled chains with RPC configured.
    async fn fetch_chain_configuration(
        &self,
        provider_cache: &mut ProviderCache<WriteEnabled>,
    ) -> Result<(
        HashMap<u64, Option<DkgFoldAttestationContext>>,
        HashMap<u64, u64>,
    )> {
        let needs_zk = self.keyshare.is_some() || (self.pubkey_agg && self.keyshare.is_none());

        let mut dkg_fold_context_by_chain = HashMap::new();
        if needs_zk {
            // Synthetic runs have no committee-finalized log to carry request-time addresses.
            // Use static configuration only when the chain itself is disabled.
            for chain in self.chains.iter().filter(|c| !c.enabled.unwrap_or(true)) {
                let Some(chain_id) = chain.chain_id else {
                    continue;
                };
                if let Some(ref contract) = chain.contracts.dkg_fold_attestation_verifier {
                    if let (Ok(registry), Ok(verifying_contract)) = (
                        chain.contracts.ciphernode_registry.address(),
                        contract.address(),
                    ) {
                        dkg_fold_context_by_chain.entry(chain_id).or_insert(Some(
                            DkgFoldAttestationContext {
                                registry,
                                verifying_contract,
                            },
                        ));
                    }
                }
            }
        }

        let mut accusation_vote_validity_by_chain: HashMap<u64, u64> = HashMap::new();
        if !self.chains.is_empty() {
            for chain in self.chains.iter().filter(|c| c.enabled.unwrap_or(true)) {
                let provider = provider_cache.ensure_read_provider(chain).await?;
                let chain_id = provider.chain_id();
                validate_chain_id(chain, chain_id)?;
                let validity =
                    Self::fetch_accusation_vote_validity_from_registry(provider_cache, chain)
                        .await?;
                accusation_vote_validity_by_chain.insert(chain_id, validity);
            }
        }

        Ok((dkg_fold_context_by_chain, accusation_vote_validity_by_chain))
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_extensions(
        &mut self,
        bus: &BusHandle,
        store: e3_data::DataStore,
        provider_cache: &mut ProviderCache<WriteEnabled>,
        sortition: &Addr<Sortition>,
        addr: &str,
        dkg_fold_context_by_chain: &HashMap<u64, Option<DkgFoldAttestationContext>>,
        dkg_fold_contexts_by_e3: &HashMap<e3_events::E3id, DkgFoldAttestationContext>,
        accusation_vote_validity_by_chain: &HashMap<u64, u64>,
        selector_state: &CiphernodeSelectorState,
        lifecycle_stages: &HashMap<E3id, E3Stage>,
    ) -> Result<e3_request::E3RouterBuilder> {
        let recovered_selections = recovered_ciphernode_selections(selector_state, addr)?;
        let mut e3_builder =
            E3Router::builder(bus, store.clone()).with_recovered_selections(recovered_selections);
        e3_builder = e3_builder.with(AggregatorRoleExtension::create(
            selector_state.is_aggregator.clone(),
        ));
        let repositories = store.repositories();
        let persisted_committees = repositories
            .finalized_committees()
            .read()
            .await?
            .unwrap_or_default();
        let persisted_e3_metadata = repositories
            .ciphernode_selector()
            .read()
            .await?
            .map(|state| state.e3_cache)
            .unwrap_or_default();
        let zk_recovery = ZkActorRecovery::new(
            persisted_committees.clone(),
            persisted_e3_metadata,
            dkg_fold_contexts_by_e3.clone(),
        );

        // ── Threshold keyshare + ZK actors ──
        if let Some(KeyshareKind::Threshold) = self.keyshare {
            let _ = self.ensure_multithread(bus, lifecycle_stages);
            let backend = self
                .zk_backend
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("ZK backend is required for threshold keyshare"))?;
            backend.ensure_installed().await?;
            let _signer = provider_cache.ensure_signer().await?;

            let mut interfold_addresses = HashMap::new();
            for chain in self.chains.iter().filter(|c| c.enabled.unwrap_or(true)) {
                let provider = provider_cache.ensure_read_provider(chain).await?;
                let chain_id = provider.chain_id();
                validate_chain_id(chain, chain_id)?;
                interfold_addresses.insert(chain_id, chain.contracts.interfold.address()?);
            }
            for chain in self.chains.iter().filter(|c| !c.enabled.unwrap_or(true)) {
                if let Some(chain_id) = chain.chain_id {
                    interfold_addresses.insert(chain_id, chain.contracts.interfold.address()?);
                }
            }

            info!("Setting up ThresholdKeyshareExtension");
            e3_builder = e3_builder.with(ThresholdKeyshareExtension::create(
                bus,
                &self.cipher,
                addr,
                interfold_addresses,
            ));

            info!("Setting up ZK actors");
            setup_zk_actors(
                bus,
                backend,
                _signer,
                dkg_fold_context_by_chain.clone(),
                zk_recovery.clone(),
                self.proof_aggregation_enabled,
            );
        }

        // ── Public key aggregation ──
        if self.pubkey_agg {
            info!("Setting up FheExtension");
            e3_builder = e3_builder.with(FheExtension::create(bus, &self.rng));

            info!("Setting up PublicKeyAggregationExtension");
            let _ = self.ensure_multithread(bus, lifecycle_stages);
            e3_builder = e3_builder.with(PublicKeyAggregatorExtension::create(bus));

            if self.keyshare.is_none() {
                let backend = self
                    .zk_backend
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("ZK backend is required for aggregator"))?;
                let signer = provider_cache.ensure_signer().await?;
                info!("Setting up ZK actors for aggregator");
                setup_zk_actors(
                    bus,
                    backend,
                    signer,
                    dkg_fold_context_by_chain.clone(),
                    zk_recovery,
                    self.proof_aggregation_enabled,
                );
            }
        }

        // ── Threshold plaintext aggregation ──
        if self.threshold_plaintext_agg {
            info!("Setting up ThresholdPlaintextAggregatorExtension");
            let _ = self.ensure_multithread(bus, lifecycle_stages);
            e3_builder = e3_builder.with(ThresholdPlaintextAggregatorExtension::create(
                bus,
                sortition,
                self.proof_aggregation_enabled,
            ));
        }

        // ── Accusation manager ──
        {
            let accusation_deadline_skew_secs = parse_env_u64("ACCUSATION_DEADLINE_SKEW_SECS", 30);
            let signer = provider_cache.ensure_signer().await?;
            let slashing_manager_addr = self.resolve_slashing_manager()?;
            info!(
                chains = accusation_vote_validity_by_chain.len(),
                accusation_deadline_skew_secs, "Setting up AccusationManagerExtension"
            );
            e3_builder = e3_builder.with(AccusationManagerExtension::create(
                bus,
                signer,
                slashing_manager_addr,
                accusation_vote_validity_by_chain.clone(),
                accusation_deadline_skew_secs,
                persisted_committees,
            ));
        }

        // ── Commitment consistency checker ──
        {
            info!("Setting up CommitmentConsistencyCheckerExtension");
            e3_builder = e3_builder.with(CommitmentConsistencyCheckerExtension::create(
                bus,
                e3_zk_prover::default_links,
            ));
        }

        Ok(e3_builder)
    }

    async fn setup_networking(
        &self,
        store: &e3_data::DataStore,
        network: &NetworkPolicy,
    ) -> Result<(PeerId, e3_net::NetInterfaceHandle, NetInterfaceKind)> {
        if let Some(ref net_config) = self.net_config {
            let repositories = store.repositories();
            let keypair = setup_libp2p_keypair(repositories.libp2p_keypair(), &self.cipher).await?;
            let peer_id = keypair.peer_id();
            let interface = setup_net_interface(
                network.clone(),
                keypair,
                net_config.peers.clone(),
                net_config.quic_port,
                self.max_buffered_net_events,
            )?;
            Ok((peer_id, interface, NetInterfaceKind::Libp2p))
        } else {
            let (interface, channel_bridge) =
                create_channel_bridge_with_application_event_capacity(self.max_buffered_net_events);
            let peer_id = PeerId::random();
            Ok((
                peer_id,
                interface,
                NetInterfaceKind::ChannelBridge(channel_bridge),
            ))
        }
    }

    fn network_policy(&self, chain_ids: &[u64]) -> Result<NetworkPolicy> {
        let profile = self
            .net_config
            .as_ref()
            .map(|config| config.network.clone())
            .unwrap_or_else(NetworkProfile::local);
        let enabled_chains: Vec<_> = self
            .chains
            .iter()
            .filter(|chain| chain.enabled.unwrap_or(true))
            .collect();
        ensure!(
            enabled_chains.len() == chain_ids.len(),
            "resolved chain IDs do not match the enabled chain configuration"
        );
        if enabled_chains.is_empty() && profile.name() == "local" {
            return Ok(NetworkPolicy::local_unrestricted());
        }
        let mut deployments = Vec::with_capacity(enabled_chains.len());
        for (chain, chain_id) in enabled_chains.into_iter().zip(chain_ids.iter().copied()) {
            deployments.push((chain_id, chain.contracts.interfold.address()?.into_array()));
        }
        NetworkPolicy::new(profile, deployments)
    }

    fn ensure_multithread(
        &mut self,
        bus: &BusHandle,
        lifecycle_stages: &HashMap<E3id, E3Stage>,
    ) -> Addr<Multithread> {
        if let Some(cached) = self.multithread_cache.clone() {
            return cached;
        }

        info!("Setting up multithread actor...");

        let task_pool = self.task_pool.clone().unwrap_or_else(|| {
            let pool_threads = self.threads.unwrap_or(1);
            let concurrent_jobs = self.multithread_concurrent_jobs.unwrap_or(1);
            let pool_threads = concurrent_jobs.min(pool_threads).max(1);
            Multithread::create_taskpool(pool_threads, concurrent_jobs)
        });

        let addr = if let Some(ref backend) = self.zk_backend {
            info!("Multithread actor with ZK prover");
            Multithread::attach_with_zk(
                bus,
                self.rng.clone(),
                self.cipher.clone(),
                task_pool,
                self.multithread_report.clone(),
                backend,
                lifecycle_stages.clone(),
            )
        } else {
            Multithread::attach(
                bus,
                self.rng.clone(),
                self.cipher.clone(),
                task_pool,
                self.multithread_report.clone(),
                lifecycle_stages.clone(),
            )
        };

        self.multithread_cache = Some(addr.clone());
        addr
    }
}

/// Parse a `u64` env var, returning `default_val` on any error.
fn parse_env_u64(name: &str, default_val: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    value = %raw,
                    error = %err,
                    "invalid {}; falling back to default ({})",
                    name, default_val
                );
                default_val
            }
        },
        Err(_) => default_val,
    }
}

/// Validate chain ID matches expected configuration
fn validate_chain_id(chain: &ChainConfig, actual_chain_id: u64) -> Result<()> {
    if let Some(expected_chain_id) = chain.chain_id {
        if actual_chain_id != expected_chain_id {
            return Err(anyhow::anyhow!(
                "Chain '{}' validation failed: expected chain_id {}, but provider returned chain_id {}",
                chain.name, expected_chain_id, actual_chain_id
            ));
        }
    }
    Ok(())
}

fn validate_vrf_chain_id(chain_id: u64) -> Result<()> {
    ensure!(
        matches!(chain_id, 1 | 1_337 | 31_337 | 11_155_111),
        "VRF sortition supports Ethereum mainnet, Sepolia, and local development chains only; received chain_id {chain_id}"
    );
    Ok(())
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

/// Build delay configuration for a specific chain
fn create_aggregate_delay(chain: &ChainConfig, actual_chain_id: u64) -> (AggregateId, Duration) {
    let aggregate_id = AggregateId::from_chain_id(Some(actual_chain_id));
    let finalization_ms = chain.finalization_ms.unwrap_or(0);
    (aggregate_id, Duration::from_millis(finalization_ms))
}

/// Build delays configuration from chain providers
fn create_aggregate_delays(
    chain_providers: &[(ChainConfig, u64)],
) -> Result<HashMap<AggregateId, Duration>> {
    let mut delays = HashMap::new();

    for (chain, actual_chain_id) in chain_providers.iter().cloned() {
        // Validate chain_id if specified in configuration
        validate_chain_id(&chain, actual_chain_id)?;

        // Add delay if configured
        let (aggregate_id, delay_us) = create_aggregate_delay(&chain, actual_chain_id);
        delays.insert(aggregate_id, delay_us);
    }

    Ok(delays)
}

async fn setup_evm_system(
    chains: &[ChainConfig],
    provider_cache: &mut ProviderCache<WriteEnabled>,
    bus: &BusHandle,
    repositories: &e3_data::Repositories,
    contract_components: &ContractComponents,
    max_buffered_evm_events: usize,
    recovery: EvmStartupRecovery<'_>,
) -> Result<(EvmEventConfig, Vec<EvmChainGatewayHandle>)> {
    let EvmStartupRecovery {
        dkg_fold_contexts_by_e3,
        active_aggregators,
        selected_party_ids,
        lifecycle_stages,
        committee_finalizer,
    } = recovery;
    let mut evm_config = EvmEventConfig::new();
    let mut gateways = Vec::new();
    for chain in chains.iter().filter(|chain| chain.enabled.unwrap_or(true)) {
        let provider = provider_cache.ensure_read_provider(chain).await?;
        let chain_id = provider.chain_id();
        if contract_components.interfold && chain.data_availability.is_none() {
            anyhow::bail!(
                "chain '{}' has Interfold enabled but no data_availability reader; protocol v3 nodes must be able to retrieve proof-backed ciphertext outputs",
                chain.name
            );
        }
        DataAvailabilityCoordinator::attach(
            bus,
            chain_id,
            chain.data_availability.as_ref(),
            repositories.data_availability_recovery(chain_id),
        )
        .await?;
        if contract_components.ciphernode_registry {
            validate_vrf_chain_id(chain_id)?;
        }
        // Delay ingestion until the configured number of confirmations is present.
        let ingestion_confirmations = chain.ingestion_confirmations()?;
        evm_config.insert(chain_id, chain.try_into()?);

        let rpc_url = chain.rpc_url()?;
        let provider_factory =
            ProviderConfig::new(rpc_url, chain.rpc_auth.clone()).into_read_provider_factory();

        let mut system = EvmSystemChainBuilder::new(bus, &provider);
        system
            .with_provider_factory(provider_factory.clone())
            .with_buffer_limit(max_buffered_evm_events);

        if contract_components.interfold {
            let write_provider = provider_cache.ensure_write_provider(chain).await?;
            let contract = &chain.contracts.interfold;
            let chain_active_aggregators = active_aggregators
                .iter()
                .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                .map(|(e3_id, active)| (e3_id.clone(), *active))
                .collect();
            let chain_party_ids = selected_party_ids
                .iter()
                .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                .map(|(e3_id, party_id)| (e3_id.clone(), *party_id))
                .collect();
            let chain_request_registries = dkg_fold_contexts_by_e3
                .iter()
                .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                .map(|(e3_id, context)| (e3_id.clone(), context.registry))
                .collect();
            let chain_failure_stages = lifecycle_stages
                .iter()
                .filter(|(e3_id, stage)| {
                    e3_id.chain_id() == chain_id
                        && matches!(
                            stage,
                            E3Stage::Requested
                                | E3Stage::CommitteeFinalized
                                | E3Stage::KeyPublished
                                | E3Stage::CiphertextReady
                        )
                })
                .map(|(e3_id, stage)| (e3_id.clone(), stage.clone()))
                .collect();
            let chain_failure_settlements = lifecycle_stages
                .iter()
                .filter(|(e3_id, stage)| e3_id.chain_id() == chain_id && **stage == E3Stage::Failed)
                .map(|(e3_id, _)| e3_id.clone())
                .collect();
            InterfoldSolWriter::attach_with_recovery(
                bus,
                write_provider.clone(),
                contract.address()?,
                chain_active_aggregators,
                chain_party_ids,
                chain_request_registries,
                chain_failure_stages,
                chain_failure_settlements,
            );
            system.with_contract(contract.address()?, move |next| {
                InterfoldSolReader::setup(&next).recipient()
            });
        }

        if contract_components.interfold_reader {
            let contract = &chain.contracts.interfold;

            system.with_contract(contract.address()?, move |next| {
                InterfoldSolReader::setup(&next).recipient()
            });
        }

        if contract_components.bonding_registry {
            let contract = &chain.contracts.bonding_registry;
            system.with_contract(contract.address()?, move |next| {
                BondingRegistrySolReader::setup(&next).recipient()
            });
        }

        if contract_components.ciphernode_registry {
            let contract = &chain.contracts.ciphernode_registry;
            let contract_address = contract.address()?;
            let registry_provider = provider.clone();
            let registry_provider_factory = provider_factory.clone();

            system.with_contract(contract_address, move |next| {
                CiphernodeRegistrySolReader::setup_with_factory(
                    &next,
                    registry_provider,
                    Some(registry_provider_factory),
                    ingestion_confirmations,
                )
                .recipient()
            });

            let randomness_addresses = fetch_randomness_providers(
                provider.provider(),
                contract_address,
                contract.deploy_block().unwrap_or(0),
            )
            .await?;
            if randomness_addresses.is_empty() {
                return Err(anyhow::anyhow!(
                    "ciphernode registry {} has no randomness provider configured",
                    contract_address
                ));
            }
            for randomness_address in randomness_addresses {
                let randomness_read_provider = provider.clone();
                system.with_contract(randomness_address, move |next| {
                    RandomnessProviderSolReader::setup(
                        &next,
                        randomness_read_provider,
                        contract_address,
                    )
                    .recipient()
                });
            }

            // TODO: Should we not let this pass and just use '?'?
            // Above if we include interfold in the config and we don't have a wallet it will fail
            match provider_cache
                    .ensure_write_provider(chain)
                    .await
                {
                    Ok(write_provider) => {
                        let request_registries = dkg_fold_contexts_by_e3
                            .iter()
                            .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                            .map(|(e3_id, context)| (e3_id.clone(), context.registry))
                            .collect();
                        let chain_active_aggregators = active_aggregators
                            .iter()
                            .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                            .map(|(e3_id, active)| (e3_id.clone(), *active))
                            .collect();
                        let chain_recovered_tickets = committee_finalizer
                            .tickets
                            .iter()
                            .filter(|(e3_id, _)| e3_id.chain_id() == chain_id)
                            .map(|(e3_id, ticket)| (e3_id.clone(), ticket.clone()))
                            .collect();
                        CiphernodeRegistrySol::attach_writer_with_recovery(
                            bus,
                            write_provider.clone(),
                            contract.address()?,
                            request_registries,
                            chain_active_aggregators,
                            chain_recovered_tickets,
                        );
                        info!("CiphernodeRegistrySolWriter attached for publishing committees");
                    }
                    Err(e) => error!(
                        "Failed to create write provider (likely no wallet configured), skipping writer attachment: {}",
                        e
                    )
                }
        }

        if contract_components.slashing_manager {
            let contract = chain.contracts.slashing_manager.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Slashing manager is enabled but no contract address configured for chain {}",
                    chain.name
                )
            })?;

            // Reader: read SlashExecuted events from chain
            let contract_addr = contract.address()?;
            system.with_contract(contract_addr, move |next| {
                SlashingManagerSolReader::setup(&next).recipient()
            });

            // Writer: submit proposeSlash transactions
            match provider_cache.ensure_write_provider(chain).await {
                Ok(write_provider) => {
                    match SlashingManagerSolWriter::attach_with_recovery(
                        bus,
                        write_provider.clone(),
                        contract_addr,
                        repositories.slashing_writer_recovery(chain_id),
                    )
                    .await
                    {
                        Ok(_) => {
                            info!("SlashingManagerSolWriter attached for fault submission");
                        }
                        Err(e) => {
                            error!("Failed to attach SlashingManagerSolWriter, skipping: {}", e)
                        }
                    }
                }
                Err(e) => error!(
                    "Failed to create write provider for SlashingManager, skipping: {}",
                    e
                ),
            }
        }

        gateways.push(system.build_with_readiness());
    }

    Ok((evm_config, gateways))
}

async fn wait_for_evm_gateways(gateways: Vec<EvmChainGatewayHandle>) -> Result<()> {
    futures::future::try_join_all(
        gateways
            .into_iter()
            .map(EvmChainGatewayHandle::wait_until_live),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        create_aggregate_delay, event_clock, reconcile_committee_snapshots,
        recovered_ciphernode_selections, validate_vrf_chain_id,
    };
    use e3_config::{
        chain_config::ChainConfig,
        contract::{Contract, ContractAddresses},
        rpc::RpcAuth,
    };
    use e3_events::{
        hlc::{HlcError, HlcMethods, HlcTimestamp},
        Committee, E3Stage, E3id, Seed,
    };
    use e3_fhe_params::BfvPreset;
    use e3_request::E3Meta;
    use e3_sortition::CiphernodeSelectorState;
    use e3_utils::ArcBytes;
    use std::collections::HashMap;
    use std::time::Duration;

    fn chain_with_finalization_ms(finalization_ms: Option<u64>) -> ChainConfig {
        let contract = || Contract::AddressOnly(Address::ZERO.to_string());
        ChainConfig {
            enabled: Some(true),
            name: "test".to_owned(),
            rpc_url: "http://127.0.0.1:8545".to_owned(),
            rpc_auth: RpcAuth::default(),
            contracts: ContractAddresses {
                interfold: contract(),
                ciphernode_registry: contract(),
                bonding_registry: contract(),
                e3_program: None,
                fee_token: None,
                slashing_manager: None,
                dkg_fold_attestation_verifier: None,
                faucet: None,
            },
            finalization_ms,
            chain_id: Some(1),
            data_availability: None,
        }
    }

    use alloy::primitives::Address;

    #[test]
    fn aggregate_delay_preserves_large_millisecond_values_without_overflow() {
        let (_, delay) = create_aggregate_delay(&chain_with_finalization_ms(Some(u64::MAX)), 1);

        assert_eq!(delay, Duration::from_millis(u64::MAX));
    }

    #[test]
    fn aggregate_delay_defaults_to_zero() {
        let (_, delay) = create_aggregate_delay(&chain_with_finalization_ms(None), 1);

        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn supports_ethereum_vrf_chains() {
        for chain_id in [1, 11_155_111, 31_337, 1_337] {
            assert!(validate_vrf_chain_id(chain_id).is_ok());
        }
    }

    #[test]
    fn rejects_arbitrum_vrf_chains() {
        let error = validate_vrf_chain_id(42_161).expect_err("Arbitrum must be rejected");

        assert!(error.to_string().contains("Ethereum mainnet"));
    }

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

    #[test]
    fn startup_reconciles_committees() {
        let selector_only = E3id::new("1", 1);
        let finalized_only = E3id::new("2", 1);
        let terminal = E3id::new("3", 1);
        let metadata = || E3Meta {
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::default(),
            error_size: ArcBytes::default(),
        };
        let committee = Committee::new(vec![
            "0x1111111111111111111111111111111111111111".to_string()
        ]);
        let mut selector = CiphernodeSelectorState {
            e3_cache: HashMap::from([
                (selector_only.clone(), metadata()),
                (finalized_only.clone(), metadata()),
                (terminal.clone(), metadata()),
            ]),
            committees: HashMap::from([
                (selector_only.clone(), committee.clone()),
                (terminal.clone(), committee.clone()),
            ]),
            ..Default::default()
        };
        let mut finalized = HashMap::from([
            (finalized_only.clone(), committee.clone()),
            (terminal.clone(), committee.clone()),
        ]);

        assert_eq!(
            reconcile_committee_snapshots(
                &mut selector,
                &mut finalized,
                &HashMap::from([(terminal.clone(), E3Stage::Complete)]),
            )
            .unwrap(),
            (true, true)
        );
        assert_eq!(selector.committees.get(&finalized_only), Some(&committee));
        assert_eq!(finalized.get(&selector_only), Some(&committee));
        assert!(!selector.e3_cache.contains_key(&terminal));
        assert!(!finalized.contains_key(&terminal));
    }

    #[test]
    fn startup_recovers_local_selection() {
        let e3_id = E3id::new("8", 1);
        let address = "0x1111111111111111111111111111111111111111";
        let metadata = E3Meta {
            threshold_m: 2,
            threshold_n: 3,
            seed: Seed([7; 32]),
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::from_bytes(&[1, 2]),
            error_size: ArcBytes::from_bytes(&[3, 4]),
        };
        let selector = CiphernodeSelectorState {
            e3_cache: HashMap::from([(e3_id.clone(), metadata.clone())]),
            committees: HashMap::from([(
                e3_id.clone(),
                Committee::new(vec![
                    address.to_uppercase(),
                    "0x2222222222222222222222222222222222222222".to_owned(),
                ]),
            )]),
            ..Default::default()
        };

        let selections = recovered_ciphernode_selections(&selector, address).unwrap();

        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].e3_id, e3_id);
        assert_eq!(selections[0].party_id, 0);
        assert_eq!(selections[0].threshold_m, metadata.threshold_m);
        assert_eq!(selections[0].params, metadata.params);
    }

    #[test]
    fn startup_rejects_committee_conflicts() {
        let e3_id = E3id::new("9", 1);
        let mut selector = CiphernodeSelectorState {
            e3_cache: HashMap::from([(
                e3_id.clone(),
                E3Meta {
                    threshold_m: 1,
                    threshold_n: 3,
                    seed: Seed([0; 32]),
                    params_preset: BfvPreset::InsecureThreshold512,
                    params: ArcBytes::default(),
                    error_size: ArcBytes::default(),
                },
            )]),
            committees: HashMap::from([(
                e3_id.clone(),
                Committee::new(vec!["0x1111111111111111111111111111111111111111".to_owned()]),
            )]),
            ..Default::default()
        };
        let mut finalized = HashMap::from([(
            e3_id,
            Committee::new(vec!["0x2222222222222222222222222222222222222222".to_owned()]),
        )]);

        let error = reconcile_committee_snapshots(&mut selector, &mut finalized, &HashMap::new())
            .unwrap_err();

        assert!(error.to_string().contains("snapshots disagree"));
    }
}
