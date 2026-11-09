// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Drives one full E3 (committee selection, DKG, public key, encryption, threshold decryption)
//! across real ciphernodes joined by a simulated network, and checks its outcome.
//!
//! [`run`] asserts what a correct run must produce: the key and plaintext, the accepted DKG
//! roster, and the absence of faults. It does not assert how the nodes' actors order their events,
//! and the DKG window it gives the nodes is far beyond the flow timeouts, so no progress deadline
//! fires during a run. The timings and proofs the benchmark reports are returned in [`Run`].

use super::history::{
    aggregator_role_histories, collect_honest_run_faults, wait_for_event, wait_for_event_on_any,
    wait_until,
};
use super::nodes::{
    committee_node_indices, determine_committee, setup_score_sortition_environment, NodeFactory,
    CHAIN_ID, DKG_FOLD_ATTESTATION_VERIFIER, TICKET_PRICE,
};
use super::zk_fixture::{active_committee, setup_test_zk_backend};
use crate::ciphernode_system::{CiphernodeHistory, CiphernodeSystem, CiphernodeSystemBuilder};
use actix::{Actor, Addr};
use alloy::primitives::{Address, U256};
use alloy::sol_types::SolEvent;
use anyhow::{bail, Context, Result};
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_crypto::Cipher;
use e3_event_system::EventSystem;
use e3_events::{
    prelude::*, AggregateConfig, AggregateId, BusHandle, CiphertextOutputPublished,
    CommitteeRequested, DkgFoldAttestationContextEstablished, E3Requested, E3id, EventSource,
    InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof, PublicKeyAggregated, Seed,
    DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset, DEFAULT_BFV_PRESET};
use e3_multithread::{FlattenedReport, Multithread, MultithreadReport, ToReport};
use e3_sortition::calculate_buffer_size;
use e3_test_support::{create_seed_from_u64, with_tracing};
use e3_trbfv::helpers::calculate_error_size;
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{BfvParameters, Ciphertext, PublicKey};
use fhe_traits::{DeserializeParametrized, Serialize};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// Seed of the per-node RNGs; every node draws a different stream from it.
const NODE_RNG_BASE: u64 = 42;
/// Logical CPUs kept outside the shared Rayon pool.
const RESERVED_THREADS: usize = 2;
/// Votes each synthetic voter casts, so the number of tallies the decryption must return. SS has
/// one committed noise set, so the run exercises one output rather than reuse it across tallies.
const VOTES_PER_VOTER: usize = 1;
const VOTERS: usize = 30;

/// Proof system and parameter family a run uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Insecure,
    Secure,
}

impl Preset {
    /// The preset for a benchmark mode, which is `insecure` or `secure`.
    pub fn from_mode(mode: &str) -> Result<Self> {
        match mode {
            "insecure" => Ok(Preset::Insecure),
            "secure" => Ok(Preset::Secure),
            other => bail!("unsupported BENCHMARK_MODE {other:?}: expected `insecure` or `secure`"),
        }
    }

    pub fn bfv_preset(self) -> BfvPreset {
        match self {
            Preset::Insecure => DEFAULT_BFV_PRESET,
            Preset::Secure => BfvPreset::SecureThreshold8192,
        }
    }

    /// Noir artifact directory under `circuits/bin/`.
    pub fn subdir(self) -> &'static str {
        match self {
            Preset::Insecure => "insecure-64",
            Preset::Secure => "secure-8192",
        }
    }

    /// Collection timeouts (encryption keys, threshold shares, decryption key shares) that the
    /// secure proofs need; insecure runs take the nodes' defaults or the caller's environment.
    fn collection_timeouts_secs(self, small_committee: bool) -> Option<(u64, u64, u64)> {
        match (self, small_committee) {
            (Preset::Insecure, _) => None,
            (Preset::Secure, true) => Some((7_200, 46_000, 46_000)),
            (Preset::Secure, false) => Some((1_800, 7_200, 7_200)),
        }
    }

    /// How long a run waits for the public key and for the plaintext. These bound the harness
    /// only; protocol deadlines come from the synthetic DKG window.
    fn flow_timeouts(self, small_committee: bool) -> (Duration, Duration) {
        let (pubkey, plaintext) = match (self, small_committee) {
            (Preset::Insecure, _) => (5_000, 1_000),
            (Preset::Secure, true) => (45_000, 6_000),
            (Preset::Secure, false) => (15_000, 3_000),
        };
        (Duration::from_secs(pubkey), Duration::from_secs(plaintext))
    }
}

/// A fault the run injects at a known protocol point.
#[derive(Debug, Clone, Copy)]
pub enum Fault {
    None,
    /// The committee party disconnects once it has published its encryption key (C0) and the
    /// others have seen it. It can no longer share its DKG material, so the aggregator must
    /// select a roster without it.
    OfflineAfterC0 {
        party_id: usize,
    },
}

impl Fault {
    fn offline_party(self) -> Option<usize> {
        match self {
            Fault::None => None,
            Fault::OfflineAfterC0 { party_id } => Some(party_id),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub preset: Preset,
    pub fault: Fault,
    /// Frozen DKG window given to every node. `None` derives a window far beyond the flow
    /// timeouts, so no protocol deadline can fire during the run.
    pub dkg_window: Option<Duration>,
    /// Jobs the shared Rayon pool runs at once.
    pub concurrent_jobs: usize,
}

impl Scenario {
    /// The committee has a standby party (N > H); the run completes with every party online
    /// and the standby party still deals its C4 share.
    pub fn standby_node() -> Self {
        Self {
            preset: Preset::Insecure,
            fault: Fault::None,
            dkg_window: Some(Duration::from_secs(1200)),
            concurrent_jobs: 1,
        }
    }

    /// Party `party_id` goes offline after C0 and the run completes without it.
    pub fn offline_after_c0(party_id: usize) -> Self {
        Self {
            fault: Fault::OfflineAfterC0 { party_id },
            ..Self::standby_node()
        }
    }

    /// Every party online, with the DKG window left open.
    pub fn benchmark(preset: Preset, concurrent_jobs: usize) -> Self {
        Self {
            preset,
            fault: Fault::None,
            dkg_window: None,
            concurrent_jobs,
        }
    }
}

/// The committee, proof system and node pool a run used, for the benchmark report.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub preset: Preset,
    pub lambda: usize,
    pub proof_aggregation_enabled: bool,
    pub concurrent_jobs: usize,
    pub committee_n: usize,
    pub committee_h: usize,
    pub committee_t: usize,
    pub nodes_spawned: usize,
}

/// Wall-clock durations of the phases of one run.
#[derive(Debug, Clone, Default)]
pub struct Timings {
    pub setup: Duration,
    pub committee_setup: Duration,
    pub committee_finalization: Duration,
    /// Committee finalized until the observer sees the public key.
    pub shares_to_pubkey: Duration,
    /// E3 request until the observer sees the public key.
    pub request_to_pubkey: Duration,
    pub ciphertext_generation: Duration,
    pub fhe_application: Duration,
    pub ciphertext_to_plaintext: Duration,
    pub whole: Duration,
}

/// What a finished run hands to the benchmark.
pub struct Run {
    pub config: RunConfig,
    pub timings: Timings,
    pub e3_id: E3id,
    pub dkg_aggregator_proof: Proof,
    pub decryption_aggregator_proofs: Vec<Proof>,
    /// Histories of the parties that held the public-key aggregator role, joined.
    pub pubkey_role_events: Vec<InterfoldEvent>,
    /// History of the party that published the plaintext.
    pub plaintext_aggregator_events: Vec<InterfoldEvent>,
    pub multithread: FlattenedReport,
}

fn proof_aggregation_enabled() -> bool {
    let value = std::env::var("CIPHERNODE_SKIP_PROOF_AGGREGATION")
        .unwrap_or_else(|_| "false".into())
        .to_ascii_lowercase();
    match value.as_str() {
        "1" | "true" | "yes" | "on" => false,
        "0" | "false" | "no" | "off" => true,
        _ => panic!("CIPHERNODE_SKIP_PROOF_AGGREGATION must be a boolean, got {value:?}"),
    }
}

/// Restores the collection-timeout variables a secure run overrides.
struct TimeoutEnvGuard(Vec<(&'static str, Option<OsString>)>);

impl TimeoutEnvGuard {
    const VARS: [&'static str; 3] = [
        "E3_ENCRYPTION_KEY_COLLECTION_TIMEOUT_SECS",
        "E3_THRESHOLD_SHARE_COLLECTION_TIMEOUT_SECS",
        "E3_DECRYPTION_KEY_SHARED_COLLECTION_TIMEOUT_SECS",
    ];

    fn set(timeouts: Option<(u64, u64, u64)>) -> Self {
        let guard = Self(
            Self::VARS
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect(),
        );
        if let Some((enc, threshold, dec_shared)) = timeouts {
            for (name, secs) in Self::VARS.into_iter().zip([enc, threshold, dec_shared]) {
                std::env::set_var(name, secs.to_string());
            }
        }
        guard
    }
}

impl Drop for TimeoutEnvGuard {
    fn drop(&mut self) {
        for (name, original) in &self.0 {
            match original {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// What a run has once its committee is final.
struct Request {
    requested_at: Instant,
    request_block: u64,
    /// Node index of each committee party, in party order.
    committee: Vec<usize>,
    /// The party the fault takes offline, if any.
    offline_party: Option<usize>,
}

impl Request {
    fn offline_node(&self) -> Option<usize> {
        self.offline_party
            .and_then(|party| self.committee.get(party).copied())
    }

    /// Node indices of the committee parties still online.
    fn connected(&self) -> Vec<usize> {
        self.committee
            .iter()
            .enumerate()
            .filter(|(party, _)| Some(*party) != self.offline_party)
            .map(|(_, &node)| node)
            .collect()
    }
}

/// Everything the phases of one run share.
struct Env {
    scenario: Scenario,
    config: RunConfig,
    /// How long the run waits for the public key and for the plaintext.
    pubkey_timeout: Duration,
    plaintext_timeout: Duration,
    dkg_window_secs: u64,
    params: Arc<BfvParameters>,
    encoded_params: ArcBytes,
    error_size: ArcBytes,
    seed: Seed,
    e3_id: E3id,
    nodes: CiphernodeSystem,
    /// Stands in for the chain: whatever it publishes reaches every node's own durable event
    /// pipeline.
    bus: BusHandle,
    multithread_report: Addr<MultithreadReport>,
    timings: Timings,
    // Held until the run ends.
    _timeout_env: TimeoutEnvGuard,
    _zk_temp: tempfile::TempDir,
    _system: EventSystem,
}

impl Env {
    /// Node 0 observes only: it is never registered for sortition.
    fn collector_address(&self) -> String {
        self.nodes[0].address()
    }

    fn registered_addresses(&self) -> Vec<String> {
        self.nodes
            .iter()
            .skip(1)
            .map(|node| node.address())
            .collect()
    }

    /// Settles in-flight deliveries so every node's history is complete.
    async fn flush_nodes(&self) -> Result<()> {
        for node in self.nodes.iter() {
            node.bus().flush_event_pipeline().await?;
        }
        Ok(())
    }

    async fn build(scenario: &Scenario) -> Result<Self> {
        let setup = Instant::now();
        let preset = scenario.preset;
        let bfv_preset = preset.bfv_preset();
        // The committee comes from the build stamp: the circuits in `circuits/bin/` were compiled
        // for one committee, and `pnpm build:circuits --committee <name>` switches it.
        let committee_size = active_committee();
        let small_committee = committee_size == e3_committee::CiphernodesCommitteeSize::Small;
        let timeout_env = TimeoutEnvGuard::set(preset.collection_timeouts_secs(small_committee));
        let (pubkey_timeout, plaintext_timeout) = preset.flow_timeouts(small_committee);
        // Nodes get this frozen deadline: the scenario has no enabled EVM provider, and
        // production nodes read it from the contract.
        let dkg_window_secs = scenario
            .dkg_window
            .map(|window| window.as_secs())
            .unwrap_or_else(|| pubkey_timeout.as_secs().saturating_mul(10))
            .max(1);
        let committee = committee_size.values();
        let participants = committee.n + calculate_buffer_size(committee.threshold, committee.n);
        let params = BfvParamSet::from(bfv_preset).build_arc();
        let error_size = calculate_error_size(
            params.clone(),
            committee.n,
            committee.threshold,
            bfv_preset.lambda()?,
        )?;
        let config = RunConfig {
            preset,
            lambda: bfv_preset.metadata().lambda,
            proof_aggregation_enabled: proof_aggregation_enabled(),
            concurrent_jobs: scenario.concurrent_jobs,
            committee_n: committee.n,
            committee_h: committee.h,
            committee_t: committee.threshold,
            nodes_spawned: participants + 1,
        };
        println!(
            "trbfv scenario: {scenario:?}, proof_aggregation={}, committee={committee_size}",
            config.proof_aggregation_enabled
        );

        let (zk_backend, zk_temp) = setup_test_zk_backend(preset.subdir()).await?;
        let pool_threads = Multithread::get_max_threads_minus(RESERVED_THREADS);
        let multithread_report =
            MultithreadReport::new(pool_threads, scenario.concurrent_jobs).start();
        let aggregate_config =
            AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
        let system = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(aggregate_config.clone());
        let bus = system.handle()?.enable("test");
        let factory = NodeFactory {
            rng_base: NODE_RNG_BASE,
            cipher: Arc::new(Cipher::from_password("I am the music man.").await?),
            zk_backend,
            task_pool: Multithread::create_taskpool(pool_threads, scenario.concurrent_jobs),
            concurrent_jobs: scenario.concurrent_jobs,
            multithread_report: multithread_report.clone(),
            aggregate_config,
            dkg_timing_reader: dkg_timing_reader(dkg_window_secs),
            proof_aggregation_enabled: config.proof_aggregation_enabled,
            trigger: bus.clone(),
            next_salt: Default::default(),
        };
        let nodes = CiphernodeSystemBuilder::new()
            .add_group(1, || factory.build("collector"))
            .add_group(
                u32::try_from(participants).expect("participant count fits in u32"),
                || factory.build("participant"),
            )
            .simulate_libp2p()
            .build()
            .await?;

        Ok(Self {
            scenario: scenario.clone(),
            config,
            pubkey_timeout,
            plaintext_timeout,
            dkg_window_secs,
            encoded_params: ArcBytes::from_bytes(&encode_bfv_params(&params)),
            params,
            error_size: ArcBytes::from_bytes(&BigUint::to_bytes_be(&error_size)),
            seed: Seed(create_seed_from_u64(123)),
            e3_id: E3id::new("0", CHAIN_ID),
            nodes,
            bus,
            multithread_report,
            timings: Timings {
                setup: setup.elapsed(),
                ..Default::default()
            },
            _timeout_env: timeout_env,
            _zk_temp: zk_temp,
            _system: system,
        })
    }
}

/// The frozen DKG window every node reads: it opens when the first node asks.
fn dkg_timing_reader(window_secs: u64) -> e3_keyshare::DkgTimingReader {
    let start = Arc::new(OnceLock::<u64>::new());
    Arc::new(move |_| {
        let deadline = *start.get_or_init(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(window_secs)
        });
        Box::pin(async move { Ok((deadline, window_secs)) })
    })
}

pub async fn run(scenario: &Scenario) -> Result<Run> {
    let whole_test = Instant::now();
    let _tracing = with_tracing("info");
    let mut env = Env::build(scenario).await?;

    register_operators(&mut env).await?;
    let request = request_and_finalize_committee(&mut env).await?;
    inject_fault(&env, &request).await?;

    let key = await_public_key(&mut env, &request).await?;
    let dkg_aggregator_proof = check_public_key(&env, &key)?;
    record_chain_observation(&env, &request, &key, &dkg_aggregator_proof).await?;

    let decrypted = encrypt_and_decrypt(&mut env, &request, &key).await?;
    let pubkey_role_events = audit_histories(&env, &request, &key).await?;

    let multithread = env.multithread_report.send(ToReport).await?;
    println!("{multithread}");
    env.timings.whole = whole_test.elapsed();

    Ok(Run {
        config: env.config,
        timings: env.timings,
        e3_id: env.e3_id,
        dkg_aggregator_proof,
        decryption_aggregator_proofs: decrypted.proofs,
        pubkey_role_events,
        plaintext_aggregator_events: decrypted.history.to_vec(),
        multithread,
    })
}

// ---- Setup and request ---------------------------------------------------------------------

async fn register_operators(env: &mut Env) -> Result<()> {
    let started = Instant::now();
    let registered = env.registered_addresses();
    anyhow::ensure!(
        registered.len() >= env.config.committee_n,
        "need at least {} registered nodes for committee N, got {}",
        env.config.committee_n,
        registered.len()
    );
    println!(
        "{} registered nodes, committee N={}, collector (observer): {}",
        registered.len(),
        env.config.committee_n,
        env.collector_address()
    );
    setup_score_sortition_environment(&env.bus, &registered).await?;
    env.timings.committee_setup = started.elapsed();
    Ok(())
}

async fn request_and_finalize_committee(env: &mut Env) -> Result<Request> {
    let requested_at = Instant::now();
    let request_block = publish_e3_request(env).await?;
    let committee = finalize_committee(env).await?;
    Ok(Request {
        requested_at,
        request_block,
        committee,
        offline_party: env.scenario.fault.offline_party(),
    })
}

/// Publishes the E3 request as the chain would, and returns its block.
async fn publish_e3_request(env: &Env) -> Result<u64> {
    let request_block = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 1;
    let (threshold_m, threshold_n) = (env.config.committee_t, env.config.committee_n);
    env.bus.publish_without_context(CommitteeRequested {
        e3_id: env.e3_id.clone(),
        seed: env.seed,
        threshold: [threshold_m, threshold_n],
        request_block,
        committee_deadline: request_block + 30,
        ticket_price: U256::from(TICKET_PRICE),
        chain_id: CHAIN_ID,
    })?;
    env.bus.publish_from_remote(
        E3Requested {
            e3_id: env.e3_id.clone(),
            threshold_m,
            threshold_n,
            seed: env.seed,
            request_block,
            error_size: env.error_size.clone(),
            params_preset: env.config.preset.bfv_preset(),
            params: env.encoded_params.clone(),
        },
        0,
        Some(request_block),
        EventSource::Evm,
    )?;
    if env.config.proof_aggregation_enabled {
        // No live registry event exists here. Seed the request-time signing context so the
        // public-key aggregator can validate every synthetic NodeFold attestation.
        env.bus
            .publish_without_context(DkgFoldAttestationContextEstablished {
                schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
                e3_id: env.e3_id.clone(),
                context: e3_events::DkgFoldAttestationContext {
                    registry: Address::ZERO,
                    verifying_contract: DKG_FOLD_ATTESTATION_VERIFIER.parse()?,
                },
            })?;
    }
    sleep(Duration::from_millis(500)).await;
    Ok(request_block)
}

/// Publishes the committee the sortition picks once every node has seen the request, and returns
/// the node index of each party.
async fn finalize_committee(env: &mut Env) -> Result<Vec<usize>> {
    let finalized = determine_committee(
        &env.e3_id,
        env.seed,
        env.config.committee_t,
        env.config.committee_n,
        &env.registered_addresses(),
        &env.collector_address(),
    )?;
    let committee = committee_node_indices(&env.nodes, &finalized.committee)?;

    wait_until(&env.nodes, 0, "E3Requested", env.pubkey_timeout, |data| {
        matches!(data, InterfoldEventData::E3Requested(_))
    })
    .await?;
    let finalizing = Instant::now();
    env.bus.publish_without_context(finalized)?;
    wait_until(
        &env.nodes,
        0,
        "CommitteeFinalized",
        env.pubkey_timeout,
        |data| matches!(data, InterfoldEventData::CommitteeFinalized(f) if f.e3_id == env.e3_id),
    )
    .await?;
    env.timings.committee_finalization = finalizing.elapsed();
    Ok(committee)
}

// ---- Fault ---------------------------------------------------------------------------------

async fn inject_fault(env: &Env, request: &Request) -> Result<()> {
    let Some(party_id) = request.offline_party else {
        return Ok(());
    };
    let node_index = request
        .offline_node()
        .context("offline party is outside the finalized committee")?;
    let timeout = env
        .pubkey_timeout
        .min(Duration::from_secs(env.dkg_window_secs));
    let published_c0 = |data: &InterfoldEventData| {
        matches!(
            data,
            InterfoldEventData::EncryptionKeyCreated(key)
                if key.e3_id == env.e3_id && key.key.party_id == party_id as u64
        )
    };
    wait_until(
        &env.nodes,
        node_index,
        "the offline party's C0",
        timeout,
        published_c0,
    )
    .await?;
    // A peer must hold the key too, or the party would leave before anyone could use it.
    let witness_index = request
        .committee
        .iter()
        .enumerate()
        .find_map(|(party, &node)| (party != party_id).then_some(node))
        .context("committee has no other party to observe C0")?;
    wait_until(
        &env.nodes,
        witness_index,
        "the offline party's C0 on a peer",
        timeout,
        published_c0,
    )
    .await?;
    env.nodes.disconnect_node(node_index).await?;
    println!("Disconnected committee party {party_id} at node index {node_index} after C0");
    Ok(())
}

// ---- Public key ----------------------------------------------------------------------------

async fn await_public_key(env: &mut Env, request: &Request) -> Result<PublicKeyAggregated> {
    let waiting = Instant::now();
    let key = wait_for_event(
        &env.nodes,
        0,
        "PublicKeyAggregated",
        env.pubkey_timeout,
        |data| match data {
            InterfoldEventData::PublicKeyAggregated(key) if key.e3_id == env.e3_id => {
                Some(key.clone())
            }
            _ => None,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("FAILURE in the public-key flow: {e}"))?;
    env.timings.shares_to_pubkey = waiting.elapsed();
    env.timings.request_to_pubkey = request.requested_at.elapsed();
    Ok(key)
}

/// Returns the final DKG proof the event carries.
fn check_public_key(env: &Env, key: &PublicKeyAggregated) -> Result<Proof> {
    let h = env.config.committee_h;
    assert_eq!(
        key.nodes.len(),
        h,
        "PublicKeyAggregated must list H={h} honest nodes"
    );
    let proof = key
        .dkg_aggregator_proof
        .clone()
        .context("PublicKeyAggregated must always carry a final DKG proof payload")?;
    assert!(
        key.dkg_attestation_bundle
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty()),
        "PublicKeyAggregated must always carry a non-empty DKG attestation payload"
    );
    Ok(proof)
}

/// The synthetic registry records the same confirmed observation as chain ingestion.
async fn record_chain_observation(
    env: &Env,
    request: &Request,
    key: &PublicKeyAggregated,
    dkg_proof: &Proof,
) -> Result<()> {
    let observation = e3_evm::ICiphernodeRegistry::CommitteeProofPublished {
        e3Id: U256::ZERO,
        nodes: key.committee_addresses.clone(),
        pkCommitment: key.pk_commitment.into(),
        proof: e3_evm::encode_zk_proof(dkg_proof)?,
    }
    .encode_log_data();
    env.bus.publish_from_remote(
        e3_events::EvmLogObserved {
            contract: "CiphernodeRegistry".into(),
            chain_id: CHAIN_ID,
            e3_id: Some(env.e3_id.clone()),
            event_name: "CommitteeProofPublished".into(),
            known: true,
            signature: Some(e3_evm::ICiphernodeRegistry::CommitteeProofPublished::SIGNATURE.into()),
            topics: observation
                .topics()
                .iter()
                .map(ToString::to_string)
                .collect(),
            data: ArcBytes::from_bytes(&observation.data),
        },
        0,
        Some(request.request_block + 1),
        EventSource::Evm,
    )?;
    env.bus
        .publish_without_context(e3_events::CommitteePublished {
            e3_id: env.e3_id.clone(),
            nodes: key
                .committee_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
            public_key: key.pubkey.clone(),
            proof: ArcBytes::from_bytes(&[]),
        })?;
    env.bus.flush_event_pipeline().await?;
    env.flush_nodes().await
}

// ---- Encryption and decryption -------------------------------------------------------------

/// The party that published the plaintext, and the decryption proofs it carried.
struct Decrypted {
    history: CiphernodeHistory,
    proofs: Vec<Proof>,
}

async fn encrypt_and_decrypt(
    env: &mut Env,
    request: &Request,
    key: &PublicKeyAggregated,
) -> Result<Decrypted> {
    let pubkey = PublicKey::from_bytes(&key.pubkey, &env.params)?;
    let (outputs, votes) = encrypt_votes(env, &pubkey);
    let (history, plaintext) = decrypt(env, request, outputs).await?;
    assert_eq!(
        plaintext.decryption_aggregator_proofs.len(),
        VOTES_PER_VOTER,
        "PlaintextAggregated must carry one decryption proof per tally"
    );
    check_tally(&env.params, &plaintext.decrypted_output, &votes);
    Ok(Decrypted {
        history,
        proofs: plaintext.decryption_aggregator_proofs,
    })
}

/// Encrypts every voter's votes and runs the application over them. Returns the output
/// ciphertexts and the plain votes.
fn encrypt_votes(env: &mut Env, pubkey: &PublicKey) -> (Vec<Arc<Ciphertext>>, Vec<Vec<u64>>) {
    let generating = Instant::now();
    println!("Generating inputs this takes some time...");
    let (inputs, votes) =
        e3_bfv_test_support::generate_ciphertexts(pubkey, VOTERS, VOTES_PER_VOTER);
    env.timings.ciphertext_generation = generating.elapsed();

    let running = Instant::now();
    println!("Running application to generate outputs...");
    let outputs = e3_bfv_test_support::run_application(&inputs, pubkey, VOTES_PER_VOTER);
    env.timings.fhe_application = running.elapsed();
    (outputs, votes)
}

/// Publishes the output ciphertexts and waits for the plaintext.
async fn decrypt(
    env: &mut Env,
    request: &Request,
    outputs: Vec<Arc<Ciphertext>>,
) -> Result<(CiphernodeHistory, PlaintextAggregated)> {
    let publishing = Instant::now();
    let ciphertexts = outputs
        .into_iter()
        .map(|ct| ArcBytes::from_bytes(&(*ct).clone().to_bytes()))
        .collect::<Vec<ArcBytes>>();
    println!("Publishing CiphertextOutputPublished...");
    env.bus.publish_without_context(CiphertextOutputPublished {
        ciphertext_output: ciphertexts,
        e3_id: env.e3_id.clone(),
        ciphertext_commitment: [0u8; 32],
    })?;

    // PlaintextAggregated is a local publication intent, so only the party that aggregates holds
    // it. A party demoted in the key phase is skipped for this one, so any connected committee
    // member can be that party.
    println!("Waiting for PlaintextAggregated");
    let (node_index, history, plaintext) = wait_for_event_on_any(
        &env.nodes,
        &request.connected(),
        "PlaintextAggregated",
        env.plaintext_timeout,
        |data| match data {
            InterfoldEventData::PlaintextAggregated(event) if event.e3_id == env.e3_id => {
                Some(event.clone())
            }
            _ => None,
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("FAILURE in the plaintext flow: {e}"))?;
    env.timings.ciphertext_to_plaintext = publishing.elapsed();
    println!("PlaintextAggregated observed on node {node_index}");
    Ok((history, plaintext))
}

/// The decrypted tallies must equal the sum of every voter's votes.
fn check_tally(params: &BfvParameters, decrypted: &[ArcBytes], votes: &[Vec<u64>]) {
    let results: Vec<u64> = decrypted
        .iter()
        .map(|a| decode_bytes_to_vec_u64(&a.extract_bytes()).expect("error decoding bytes"))
        .map(|r| *r.first().unwrap())
        .collect();
    let plaintext_modulus = params.plaintext();
    let mut expected_result = [0u64; VOTES_PER_VOTER];
    for vals in votes {
        for (expected, vote) in expected_result.iter_mut().zip(vals) {
            *expected = (*expected + vote) % plaintext_modulus;
        }
    }
    assert_eq!(
        results.as_slice(),
        expected_result.as_slice(),
        "Threshold decryption must return every expected tally"
    );
    for (i, (res, exp)) in results.iter().zip(expected_result.iter()).enumerate() {
        println!("Tally {i} result = {res} / {exp}");
    }
}

// ---- Audits over the finished run's histories ----------------------------------------------

/// Checks the finished run's histories, and returns the joined histories of the parties that held
/// the public-key aggregator role.
async fn audit_histories(
    env: &Env,
    request: &Request,
    key: &PublicKeyAggregated,
) -> Result<Vec<InterfoldEvent>> {
    // A successor can take the aggregator role late, so the holders are read now, not when the
    // key appeared.
    env.flush_nodes().await?;
    let holders = aggregator_role_histories(&env.nodes, &request.connected(), &env.e3_id).await?;
    let role_events: Vec<InterfoldEvent> = holders
        .iter()
        .flat_map(|(_, history)| history.iter().cloned())
        .collect();

    let roster = accepted_roster(&role_events, &env.e3_id);
    check_roster_built_key(&roster, key);
    if let Some(party) = request.offline_party {
        assert!(
            !roster.contains(&(party as u64)),
            "disconnected party was selected for the DKG roster"
        );
    }
    await_standby_share(env, request, &roster).await?;

    let holder_nodes: Vec<usize> = holders.iter().map(|(node, _)| *node).collect();
    check_key_submissions(env, &holder_nodes, key).await?;
    check_no_faults(env, request).await?;
    Ok(role_events)
}

/// The DKG roster every aggregator-role holder accepted; they must agree.
fn accepted_roster(events: &[InterfoldEvent], e3_id: &E3id) -> Vec<u64> {
    let rosters: Vec<&Vec<u64>> = events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::CommitmentRosterSelected(data) if data.e3_id == *e3_id => {
                Some(&data.party_ids)
            }
            _ => None,
        })
        .collect();
    assert!(
        !rosters.is_empty(),
        "aggregator did not accept a DKG roster"
    );
    assert!(
        rosters.iter().all(|roster| *roster == rosters[0]),
        "aggregator accepted conflicting DKG rosters"
    );
    rosters[0].clone()
}

/// The accepted roster is the one the published key was built from.
fn check_roster_built_key(roster: &[u64], key: &PublicKeyAggregated) {
    let selected_addresses: Vec<Address> = roster
        .iter()
        .map(|&party_id| key.committee_addresses[party_id as usize])
        .collect();
    assert_eq!(selected_addresses, key.honest_committee_addresses);
}

/// The aggregator can publish before a standby party's share lands; the standby party still has
/// to deal it, since it replaces a roster member that drops out.
async fn await_standby_share(env: &Env, request: &Request, roster: &[u64]) -> Result<()> {
    if !env.config.proof_aggregation_enabled || request.offline_party.is_some() {
        return Ok(());
    }
    let standby_party_id = (0..env.config.committee_n)
        .find(|party_id| !roster.contains(&(*party_id as u64)))
        .context("DKG roster has no standby party")?;
    wait_until(
        &env.nodes,
        request.committee[standby_party_id],
        "standby party C4 share",
        env.pubkey_timeout.min(Duration::from_secs(300)),
        |data| {
            matches!(
                data,
                InterfoldEventData::DecryptionKeyShared(share)
                    if share.e3_id == env.e3_id && share.party_id == standby_party_id as u64
            )
        },
    )
    .await
}

/// The runtime lets a demoted holder finish and submit the key it computed, and the chain keeps
/// the first valid submission. Every submission must therefore be the key the committee goes on
/// to use. A holder's own submission is `Local`; peers forward copies.
async fn check_key_submissions(
    env: &Env,
    holders: &[usize],
    key: &PublicKeyAggregated,
) -> Result<()> {
    let mut submissions = 0;
    for &node_index in holders {
        for event in env.nodes.get_history(node_index).await?.iter() {
            if let (EventSource::Local, InterfoldEventData::PublicKeyAggregated(data)) =
                (event.source(), event.get_data())
            {
                if data.e3_id == env.e3_id {
                    submissions += 1;
                    assert!(
                        data.pubkey == key.pubkey,
                        "role holder {node_index} submitted a public key that differs from the one the committee used"
                    );
                }
            }
        }
    }
    assert!(submissions > 0, "no role holder submitted the public key");
    Ok(())
}

/// No node may have accused, expelled, or failed anyone, or logged an actor error. The
/// disconnected node cannot collect its own DKG shares, so it can fail locally without failing the
/// E3.
async fn check_no_faults(env: &Env, request: &Request) -> Result<()> {
    let offline_node = request.offline_node();
    let mut faults = Vec::new();
    for (index, node) in env.nodes.iter().enumerate() {
        if Some(index) == offline_node {
            continue;
        }
        let context = if index == 0 {
            "observer node 0".to_string()
        } else {
            format!("participant node {index} ({})", node.address())
        };
        faults.extend(collect_honest_run_faults(
            &env.nodes.get_history(index).await?,
            &env.e3_id,
            &context,
        ));
    }
    assert!(
        faults.is_empty(),
        "honest-run safeguard failures:\n{}",
        faults.join("\n")
    );
    Ok(())
}
