// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    CiphernodeHandle, EventSystem, EvmSystemChainBuilder, NetInterfaceKind, ProviderCache,
    WriteEnabled,
};
use actix::{Actor, Addr};
use alloy::primitives::Address;
use anyhow::Result;
use derivative::Derivative;
use e3_aggregator::ext::{PublicKeyAggregatorExtension, ThresholdPlaintextAggregatorExtension};
use e3_aggregator::CommitteeFinalizer;
use e3_config::chain_config::ChainConfig;
use e3_crypto::Cipher;
use e3_data::{InMemStore, RepositoriesFactory};
use e3_events::{
    AggregateConfig, AggregateId, BusHandle, EventBus, EventBusConfig, EvmEventConfig,
    InterfoldEvent,
};
use e3_evm::{
    fetch_accusation_vote_validity, fetch_dkg_fold_attestation_verifier, BondingRegistrySolReader,
    CiphernodeRegistrySol, CiphernodeRegistrySolReader, InterfoldSolReader, InterfoldSolWriter,
    ProviderConfig, SlashingManagerSolReader, SlashingManagerSolWriter,
};
use e3_fhe::ext::FheExtension;
use e3_keyshare::ext::ThresholdKeyshareExtension;
use e3_multithread::{Multithread, MultithreadReport, TaskPool};
use e3_net::{
    create_channel_bridge, setup_libp2p_keypair, setup_net, setup_net_interface,
    NetRepositoryFactory,
};
use e3_request::E3LifecycleCoordinator;
use e3_request::E3Router;
use e3_slashing::{AccusationManagerExtension, CommitmentConsistencyCheckerExtension};
use e3_sortition::{
    CiphernodeSelector, CiphernodeSelectorFactory, EmitPersistedAggregatorState,
    FinalizedCommitteesRepositoryFactory, NodeStateRepositoryFactory, Sortition, SortitionBackend,
    SortitionRepositoryFactory,
};
use e3_sync::sync;
use e3_utils::SharedRng;
use e3_zk_prover::{setup_zk_actors, ZkBackend};
use libp2p::PeerId;
use std::time::Duration;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
enum EventSystemType {
    Persisted { log_path: PathBuf, kv_path: PathBuf },
    InMem,
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
    chains: Vec<ChainConfig>,
    #[derivative(Debug = "ignore")]
    cipher: Arc<Cipher>,
    contract_components: ContractComponents,
    event_system: EventSystemType,
    in_mem_store: Option<Addr<InMemStore>>,
    keyshare: Option<KeyshareKind>,
    logging: bool,
    multithread_cache: Option<Addr<Multithread>>,
    multithread_concurrent_jobs: Option<usize>,
    multithread_report: Option<Addr<MultithreadReport>>,
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
}

impl NetConfig {
    pub fn new(peers: Vec<String>, quic_port: u16) -> Self {
        Self { peers, quic_port }
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
            chains: vec![],
            cipher,
            contract_components: ContractComponents::default(),
            event_system: EventSystemType::InMem,
            in_mem_store: None,
            keyshare: None,
            logging: false,
            multithread_cache: None,
            multithread_concurrent_jobs: None,
            multithread_report: None,
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

    /// Fetch `CiphernodeRegistry.dkgFoldAttestationVerifier()` for one chain (EIP-712 verifying contract).
    async fn fetch_fold_verifier(
        provider_cache: &mut ProviderCache<WriteEnabled>,
        chain: &ChainConfig,
    ) -> Result<Option<Address>> {
        let provider = provider_cache.ensure_read_provider(chain).await?;
        let registry = chain.contracts.ciphernode_registry.address()?;
        let verifier = fetch_dkg_fold_attestation_verifier(provider.provider(), registry).await?;
        if verifier.is_none() {
            tracing::warn!(
                chain = %chain.name,
                registry = %registry,
                "CiphernodeRegistry.dkgFoldAttestationVerifier is not set on-chain; \
                 nodes will not sign DKG fold attestations when proof aggregation is enabled"
            );
        } else if let Some(addr) = verifier {
            info!(
                chain = %chain.name,
                registry = %registry,
                verifier = %addr,
                "loaded dkgFoldAttestationVerifier from CiphernodeRegistry"
            );
        }
        Ok(verifier)
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
        self.net_config = Some(NetConfig::new(peers, quic_port));
        self
    }

    fn create_local_bus() -> Addr<EventBus<InterfoldEvent>> {
        EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start()
    }

    /// Create aggregate configuration from configured chains
    async fn create_aggregate_config(
        &self,
        provider_cache: &mut ProviderCache,
    ) -> Result<AggregateConfig> {
        let mut chain_providers = Vec::new();
        for chain in self.chains.iter().filter(|c| c.enabled.unwrap_or(true)) {
            let provider = provider_cache.ensure_read_provider(chain).await?;
            chain_providers.push((chain.clone(), provider.chain_id()));
        }

        let delays = create_aggregate_delays(&chain_providers)?;
        Ok(AggregateConfig::new(delays))
    }

    pub async fn build(mut self) -> anyhow::Result<CiphernodeHandle> {
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
        let aggregate_config = self.create_aggregate_config(&mut provider_cache).await?;

        // Build the event system (store + eventstore)
        let event_system = self.create_event_system(local_bus, &aggregate_config);
        let store = event_system.store()?;
        let eventstore = event_system.eventstore_reader()?;
        let repositories = Arc::new(store.repositories());
        let mut provider_cache =
            provider_cache.with_write_support(Arc::clone(&self.cipher), Arc::clone(&repositories));

        // Resolve node address and enable the bus
        let addr = provider_cache.ensure_signer().await?.address().to_string();
        let bus = event_system.handle()?.enable(&addr);

        // Setup sortition
        let (sortition, ciphernode_selector) =
            self.setup_sortition(&bus, &repositories, &addr).await?;

        // Setup the durable E3 lifecycle coordinator (additive observer that
        // tracks each E3's stage for restart-resume awareness and shutdown).
        E3LifecycleCoordinator::attach(&bus, store.clone()).await?;

        // Setup EVM contract event listeners
        let evm_config = self.setup_evm_system(&mut provider_cache, &bus).await?;

        // Fetch on-chain ZK/slashing configuration
        let (dkg_fold_verifier_by_chain, accusation_vote_validity_by_chain) =
            self.fetch_chain_configuration(&mut provider_cache).await?;

        // Setup protocol extensions (keyshare, aggregation, ZK, accusation, commitment)
        let e3_builder = self
            .setup_extensions(
                &bus,
                store.clone(),
                &mut provider_cache,
                &sortition,
                &addr,
                &dkg_fold_verifier_by_chain,
                &accusation_vote_validity_by_chain,
            )
            .await?;

        e3_builder.build().await?;
        ciphernode_selector.do_send(EmitPersistedAggregatorState);

        // Setup networking
        let topic = "interfold-gossip";
        let (peer_id, interface, net_kind) = self.setup_networking(&store, topic).await?;
        setup_net(topic, bus.clone(), eventstore.ts(), interface)?;

        // Run the sync routine
        sync(
            &bus,
            &evm_config,
            &repositories,
            &aggregate_config,
            &eventstore.seq(),
        )
        .await?;

        Ok(CiphernodeHandle::new(
            addr.to_owned(),
            store,
            bus,
            history,
            errors,
            peer_id,
            net_kind,
        ))
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
    ) -> Result<(Addr<Sortition>, Addr<CiphernodeSelector>)> {
        let ciphernode_selector =
            CiphernodeSelector::attach(bus, repositories.ciphernode_selector(), addr).await?;
        let sortition = Sortition::attach(
            bus,
            repositories.sortition(),
            repositories.node_state(),
            repositories.finalized_committees(),
            self.sortition_backend.clone(),
            ciphernode_selector.clone(),
            addr,
        )
        .await?;
        Ok((sortition, ciphernode_selector))
    }

    async fn setup_evm_system(
        &self,
        provider_cache: &mut ProviderCache<WriteEnabled>,
        bus: &BusHandle,
    ) -> Result<EvmEventConfig> {
        setup_evm_system(
            &self.chains,
            provider_cache,
            bus,
            &self.contract_components,
            self.pubkey_agg,
        )
        .await
    }

    /// Fetch DKG fold attestation verifier and accusation vote validity from on-chain
    /// registries. Requires enabled chains with RPC configured.
    async fn fetch_chain_configuration(
        &self,
        provider_cache: &mut ProviderCache<WriteEnabled>,
    ) -> Result<(HashMap<u64, Option<Address>>, HashMap<u64, u64>)> {
        let needs_zk = self.keyshare.is_some() || (self.pubkey_agg && self.keyshare.is_none());

        let mut dkg_fold_verifier_by_chain: HashMap<u64, Option<Address>> = HashMap::new();
        if needs_zk {
            for chain in self.chains.iter().filter(|c| c.enabled.unwrap_or(true)) {
                let provider = provider_cache.ensure_read_provider(chain).await?;
                let chain_id = provider.chain_id();
                validate_chain_id(chain, chain_id)?;
                let verifier = Self::fetch_fold_verifier(provider_cache, chain).await?;
                dkg_fold_verifier_by_chain.insert(chain_id, verifier);
            }
            // For disabled chains with a statically-configured verifier address (e.g. benchmark),
            // populate from config so ZK actors can function without an RPC connection.
            for chain in self.chains.iter().filter(|c| !c.enabled.unwrap_or(true)) {
                let Some(chain_id) = chain.chain_id else {
                    continue;
                };
                if let Some(ref contract) = chain.contracts.dkg_fold_attestation_verifier {
                    if let Ok(addr) = contract.address() {
                        dkg_fold_verifier_by_chain
                            .entry(chain_id)
                            .or_insert(Some(addr));
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

        Ok((
            dkg_fold_verifier_by_chain,
            accusation_vote_validity_by_chain,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_extensions(
        &mut self,
        bus: &BusHandle,
        store: e3_data::DataStore,
        provider_cache: &mut ProviderCache<WriteEnabled>,
        sortition: &Addr<Sortition>,
        addr: &str,
        dkg_fold_verifier_by_chain: &HashMap<u64, Option<Address>>,
        accusation_vote_validity_by_chain: &HashMap<u64, u64>,
    ) -> Result<e3_request::E3RouterBuilder> {
        let mut e3_builder = E3Router::builder(bus, store.clone());

        // ── Threshold keyshare + ZK actors ──
        if let Some(KeyshareKind::Threshold) = self.keyshare {
            let _ = self.ensure_multithread(bus);
            let backend = self
                .zk_backend
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("ZK backend is required for threshold keyshare"))?;
            backend.ensure_installed().await?;
            let _signer = provider_cache.ensure_signer().await?;

            info!("Setting up ThresholdKeyshareExtension");
            e3_builder =
                e3_builder.with(ThresholdKeyshareExtension::create(bus, &self.cipher, addr));

            info!("Setting up ZK actors");
            setup_zk_actors(bus, backend, _signer, dkg_fold_verifier_by_chain.clone());
        }

        // ── Public key aggregation ──
        if self.pubkey_agg {
            info!("Setting up FheExtension");
            e3_builder = e3_builder.with(FheExtension::create(bus, &self.rng));

            info!("Setting up PublicKeyAggregationExtension");
            let _ = self.ensure_multithread(bus);
            e3_builder = e3_builder.with(PublicKeyAggregatorExtension::create(bus));

            if self.keyshare.is_none() {
                let backend = self
                    .zk_backend
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("ZK backend is required for aggregator"))?;
                let signer = provider_cache.ensure_signer().await?;
                info!("Setting up ZK actors for aggregator");
                setup_zk_actors(bus, backend, signer, dkg_fold_verifier_by_chain.clone());
            }
        }

        // ── Threshold plaintext aggregation ──
        if self.threshold_plaintext_agg {
            info!("Setting up ThresholdPlaintextAggregatorExtension");
            let _ = self.ensure_multithread(bus);
            e3_builder = e3_builder.with(ThresholdPlaintextAggregatorExtension::create(
                bus, sortition,
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
        topic: &str,
    ) -> Result<(PeerId, e3_net::NetInterfaceHandle, NetInterfaceKind)> {
        if let Some(ref net_config) = self.net_config {
            let repositories = store.repositories();
            let keypair = setup_libp2p_keypair(repositories.libp2p_keypair(), &self.cipher).await?;
            let peer_id = keypair.peer_id();
            let interface = setup_net_interface(
                topic,
                keypair,
                net_config.peers.clone(),
                net_config.quic_port,
            )?;
            Ok((peer_id, interface, NetInterfaceKind::Libp2p))
        } else {
            let (interface, channel_bridge) = create_channel_bridge();
            let peer_id = PeerId::random();
            Ok((
                peer_id,
                interface,
                NetInterfaceKind::ChannelBridge(channel_bridge),
            ))
        }
    }

    fn ensure_multithread(&mut self, bus: &BusHandle) -> Addr<Multithread> {
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
            )
        } else {
            Multithread::attach(
                bus,
                self.rng.clone(),
                self.cipher.clone(),
                task_pool,
                self.multithread_report.clone(),
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

/// Build delay configuration for a specific chain
fn create_aggregate_delay(chain: &ChainConfig, actual_chain_id: u64) -> (AggregateId, Duration) {
    let aggregate_id = AggregateId::from_chain_id(Some(actual_chain_id));
    let finalization_ms = chain.finalization_ms.unwrap_or(0);
    let delay_us = finalization_ms * 1000; // ms → microseconds
    (aggregate_id, Duration::from_micros(delay_us))
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
    contract_components: &ContractComponents,
    pubkey_agg: bool,
) -> Result<EvmEventConfig> {
    let mut evm_config = EvmEventConfig::new();
    for chain in chains.iter().filter(|chain| chain.enabled.unwrap_or(true)) {
        let provider = provider_cache.ensure_read_provider(chain).await?;
        let chain_id = provider.chain_id();
        evm_config.insert(chain_id, chain.try_into()?);

        let rpc_url = chain.rpc_url()?;
        let provider_factory =
            ProviderConfig::new(rpc_url, chain.rpc_auth.clone()).into_read_provider_factory();

        let mut system = EvmSystemChainBuilder::new(bus, &provider);
        system.with_provider_factory(provider_factory);

        if contract_components.interfold {
            let write_provider = provider_cache.ensure_write_provider(chain).await?;
            let contract = &chain.contracts.interfold;
            InterfoldSolWriter::attach(bus, write_provider.clone(), contract.address()?);
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

            system.with_contract(contract.address()?, move |next| {
                CiphernodeRegistrySolReader::setup(&next).recipient()
            });

            // TODO: Should we not let this pass and just use '?'?
            // Above if we include interfold in the config and we don't have a wallet it will fail
            match provider_cache
                    .ensure_write_provider(chain)
                    .await
                {
                    Ok(write_provider) => {
                        CiphernodeRegistrySol::attach_writer(
                            bus,
                            write_provider.clone(),
                            contract.address()?,
                        );
                        info!("CiphernodeRegistrySolWriter attached for publishing committees");

                        if pubkey_agg {
                            info!("Attaching CommitteeFinalizer for score sortition");
                            CommitteeFinalizer::attach(bus);
                        }
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
                    match SlashingManagerSolWriter::attach(
                        bus,
                        write_provider.clone(),
                        contract_addr,
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

        system.build();
    }

    Ok(evm_config)
}
