// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Ciphernode assembly: [`CiphernodeBuilder`] holds the node options, and the child modules run
//! the startup steps that [`CiphernodeBuilder::build`] orders.

mod chain_parameters;
mod evm;
mod extensions;
mod net;
mod restart;
mod sortition;
mod startup;

use actix::Addr;
use derivative::Derivative;
use e3_config::{chain_config::ChainConfig, NetworkProfile};
use e3_crypto::Cipher;
#[cfg(feature = "test-helpers")]
use e3_events::AggregateConfig;
#[cfg(feature = "test-helpers")]
use e3_keyshare::DkgTimingReader;
use e3_multithread::{Multithread, MultithreadReport};
use e3_sync::NodeRole;
use e3_task_pool::TaskPool;
use e3_utils::SharedRng;
use e3_zk_prover::ZkBackend;
use std::{path::PathBuf, sync::Arc};
use tracing::{info, warn};

#[derive(Clone, Debug)]
enum EventSystemType {
    Persisted { log_path: PathBuf, kv_path: PathBuf },
    InMem,
}

/// Build a ciphernode configuration.
///
/// [`CiphernodeBuilder::full`] and [`CiphernodeBuilder::bootstrap`] choose the work that the node
/// runs; the other methods set its options. Production nodes are assembled via
/// [`entrypoint::start`](e3_entrypoint::start); tests and benchmarks use the same builder with
/// in-memory stores.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CiphernodeBuilder {
    #[cfg(feature = "test-helpers")]
    eventstore_aggregate_config_override: Option<AggregateConfig>,
    #[cfg(feature = "test-helpers")]
    #[derivative(Debug = "ignore")]
    dkg_timing_reader_override: Option<DkgTimingReader>,
    chains: Vec<ChainConfig>,
    #[derivative(Debug = "ignore")]
    cipher: Arc<Cipher>,
    event_system: EventSystemType,
    /// Directory of the ingestion heartbeat files, one per chain, for a local health check.
    ingestion_heartbeat_dir: Option<PathBuf>,
    logging: bool,
    max_buffered_evm_events: usize,
    max_buffered_net_bytes: usize,
    max_buffered_net_events: usize,
    name: Option<String>,
    multithread_concurrent_jobs: Option<usize>,
    multithread_report: Option<Addr<MultithreadReport>>,
    profile: NodeProfile,
    proof_aggregation_enabled: bool,
    rng: SharedRng,
    task_pool: Option<TaskPool>,
    threads: Option<usize>,
    signer: Option<alloy::signers::local::PrivateKeySigner>,
    net_config: Option<NetConfig>,
    /// Share the store and the event store with socket server commands.
    shared_stores: bool,
    collect_history: bool,
}

/// The work that a node runs.
#[derive(Debug)]
enum NodeProfile {
    /// Committee work: the threshold keyshare, public key and plaintext aggregation with ZK
    /// proofs, accusations, and the Interfold, BondingRegistry, CiphernodeRegistry, and
    /// SlashingManager readers and writers.
    Full { zk_backend: Box<ZkBackend> },
    /// Networking and the Interfold contract reader only.
    Bootstrap,
}

#[derive(Debug)]
struct NetConfig {
    peers: Vec<String>,
    quic_port: u16,
    network: NetworkProfile,
}

impl CiphernodeBuilder {
    /// Build a full node, which joins committees and generates proofs with `zk_backend`.
    pub fn full(rng: SharedRng, cipher: Arc<Cipher>, zk_backend: ZkBackend) -> Self {
        Self::new(
            rng,
            cipher,
            NodeProfile::Full {
                zk_backend: Box::new(zk_backend),
            },
        )
    }

    /// Build a bootstrap node. It installs no accusation or commitment-check extensions, so it
    /// signs no protocol messages. It starts without peer history when no peer can serve it. Its
    /// data directory is stamped as a bootstrap node's, and a full node refuses to start on it.
    pub fn bootstrap(rng: SharedRng, cipher: Arc<Cipher>) -> Self {
        Self::new(rng, cipher, NodeProfile::Bootstrap)
    }

    fn new(rng: SharedRng, cipher: Arc<Cipher>, profile: NodeProfile) -> Self {
        Self {
            #[cfg(feature = "test-helpers")]
            eventstore_aggregate_config_override: None,
            #[cfg(feature = "test-helpers")]
            dkg_timing_reader_override: None,
            chains: vec![],
            cipher,
            event_system: EventSystemType::InMem,
            logging: false,
            max_buffered_evm_events: 100_000,
            ingestion_heartbeat_dir: None,
            max_buffered_net_bytes: 256 * 1024 * 1024,
            max_buffered_net_events: 1_024,
            name: None,
            multithread_concurrent_jobs: None,
            multithread_report: None,
            profile,
            proof_aggregation_enabled: true,
            rng,
            task_pool: None,
            threads: None,
            signer: None,
            net_config: None,
            shared_stores: false,
            collect_history: false,
        }
    }

    fn role(&self) -> NodeRole {
        match self.profile {
            NodeProfile::Full { .. } => NodeRole::Full,
            NodeProfile::Bootstrap => NodeRole::Bootstrap,
        }
    }

    /// Set the node name for dashboard display and log attribution.
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Subscribe a [`HistoryCollector`] to the event bus for inspecting all events.
    /// Useful for tests, benchmarks, and debugging.
    pub fn with_history_collector(mut self) -> Self {
        self.collect_history = true;
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

    /// Supply frozen timing for a synthetic E3 with no enabled chain provider.
    #[cfg(feature = "test-helpers")]
    pub fn with_dkg_timing_reader_for_testing(mut self, reader: DkgTimingReader) -> Self {
        self.dkg_timing_reader_override = Some(reader);
        self
    }

    /// Log data actor events
    pub fn with_logging(mut self) -> Self {
        self.logging = true;
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

    /// Configure the Rayon compute pool for production workloads.
    ///
    /// Reserves `reserve_threads` CPUs for Actix and networking. The scheduler limits concurrent
    /// ZK and TrBFV work by the requested job count, available CPUs, and detected host or cgroup
    /// memory. An omitted job count uses the production default of two.
    pub fn with_multithread_config(
        mut self,
        reserve_threads: usize,
        concurrent_jobs: Option<usize>,
    ) -> Self {
        let max_threads = Multithread::get_max_threads_minus(reserve_threads);
        let capacity =
            e3_multithread::ComputeCapacity::detect(concurrent_jobs.unwrap_or(2), max_threads);
        let jobs = capacity.effective_jobs;
        // Job admission protects memory. The Rayon worker count controls how much CPU each
        // admitted job can use, so keep the two limits independent.
        let pool_threads = max_threads;
        if jobs < capacity.requested_jobs {
            warn!(
                requested_jobs = capacity.requested_jobs,
                effective_jobs = jobs,
                cpu_job_limit = capacity.cpu_jobs,
                memory_job_limit = capacity.memory_jobs,
                "Reduced compute concurrency to fit detected CPU and memory limits"
            );
        }
        info!(
            requested_jobs = capacity.requested_jobs,
            max_concurrent_jobs = jobs,
            rayon_threads = pool_threads,
            reserve_threads,
            memory_limit_mib = capacity
                .memory_limit_bytes
                .map(|bytes| bytes / (1024 * 1024)),
            memory_job_limit = capacity.memory_jobs,
            "Configured memory-aware compute scheduler"
        );
        self.threads = Some(pool_threads);
        self.multithread_concurrent_jobs = Some(jobs);
        self
    }

    /// Set the number of concurrent jobs defaults to 1
    pub fn with_multithread_concurrent_jobs(mut self, jobs: usize) -> Self {
        self.multithread_concurrent_jobs = if jobs >= 1 { Some(jobs) } else { None };
        self
    }

    /// Bound the events retained while initial sync orders historical and live observations:
    /// `evm_events` decoded EVM events per chain, and `net_events` events of at most `net_bytes`
    /// estimated bytes from the network. Exhaustion fails startup instead of dropping protocol
    /// input.
    pub fn with_startup_buffer_limits(
        mut self,
        evm_events: usize,
        net_events: usize,
        net_bytes: usize,
    ) -> Self {
        self.max_buffered_evm_events = evm_events;
        self.max_buffered_net_events = net_events;
        self.max_buffered_net_bytes = net_bytes;
        self
    }

    /// Write an ingestion heartbeat file per chain under `dir`, for a local health check.
    pub fn with_ingestion_heartbeat(mut self, dir: PathBuf) -> Self {
        self.ingestion_heartbeat_dir = Some(dir);
        self
    }

    /// Pre-populate the signer cache with the given signer.
    /// The signer is used for EVM transactions and EIP-712 signatures.
    pub fn with_signer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Share the store and the event store of this ciphernode with socket server commands.
    pub fn with_shared_stores(mut self) -> Self {
        self.shared_stores = true;
        self
    }

    /// Set up networking for an explicit Interfold network profile.
    pub fn with_network(
        mut self,
        network: NetworkProfile,
        peers: Vec<String>,
        quic_port: u16,
    ) -> Self {
        self.net_config = Some(NetConfig {
            peers,
            quic_port,
            network,
        });
        self
    }
}
