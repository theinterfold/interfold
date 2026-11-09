// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Drives one full E3 (committee selection, DKG, public key, encryption, threshold decryption)
//! across real ciphernodes joined by a simulated network, and returns what it [`Observations`].
//!
//! [`run`] builds the nodes, executes the phases, injects the scenario's [`Fault`], and waits for
//! the shares its [`Expect`] names. It does not judge the outcome: [`super::assertions::check`]
//! does, over the observations. It does not assert how the nodes' actors order their events, and
//! the DKG window it gives the nodes is far beyond the flow timeouts, so no progress deadline
//! fires during a run. The timings and proofs the benchmark reports are in the observations too.

use super::history::{
    aggregator_role_histories, key_roster, wait_for_event, wait_for_event_on_any, wait_until,
};
use super::nodes::{
    committee_node_indices, determine_committee, setup_score_sortition_environment, NodeFactory,
    CHAIN_ID, DKG_FOLD_ATTESTATION_VERIFIER, TICKET_PRICE,
};
use super::scenario::{Expect, Fault, OwedShare, Preset, Scenario, VOTES_PER_VOTER};
use super::zk_fixture::{active_committee, setup_test_zk_backend};
use crate::ciphernode_system::{CiphernodeHistory, CiphernodeSystem, CiphernodeSystemBuilder};
use actix::{Actor, Addr};
use alloy::primitives::{Address, U256};
use alloy::sol_types::SolEvent;
use anyhow::{Context, Result};
use e3_crypto::Cipher;
use e3_event_system::EventSystem;
use e3_events::{
    prelude::*, AggregateConfig, AggregateId, BusHandle, CiphertextOutputPublished,
    CommitteeRequested, DkgFoldAttestationContextEstablished, E3Requested, E3id, EventSource,
    InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof, PublicKeyAggregated, Seed,
    DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet};
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
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// Seed of the per-node RNGs; every node draws a different stream from it.
const NODE_RNG_BASE: u64 = 42;
/// Logical CPUs kept outside the shared Rayon pool.
const RESERVED_THREADS: usize = 2;
const VOTERS: usize = 30;

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

impl RunConfig {
    /// Whether the scenario's standby party owes a C4 share: the aggregated proofs need every
    /// dealt share.
    pub fn standby_share_owed(&self, expect: &Expect) -> bool {
        expect.standby_deals && self.proof_aggregation_enabled
    }
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

/// One node's history at the end of the run.
pub struct NodeHistory {
    pub index: usize,
    pub address: String,
    pub history: CiphernodeHistory,
}

/// The standby party (outside the DKG roster, N > H) and whether it dealt its C4 share.
pub struct Standby {
    pub party_id: usize,
    pub share_dealt: bool,
}

/// What a finished run observed: the outcome the assertions evaluate, and the timings and proofs
/// the benchmark reports.
pub struct Observations {
    pub config: RunConfig,
    pub timings: Timings,
    pub e3_id: E3id,
    pub params: Arc<BfvParameters>,
    pub key: PublicKeyAggregated,
    /// The party ids of the honest committee the published key lists, in the key's order.
    pub roster: Vec<u64>,
    pub dkg_aggregator_proof: Proof,
    pub plaintext: PlaintextAggregated,
    /// Every voter's votes, which the plaintext must decrypt to the sum of.
    pub votes: Vec<Vec<u64>>,
    /// History of the party that published the plaintext.
    pub plaintext_aggregator_events: Vec<InterfoldEvent>,
    /// Histories of the parties that held the public-key aggregator role.
    pub role_holders: Vec<(usize, CiphernodeHistory)>,
    pub nodes: Vec<NodeHistory>,
    /// The node a fault took offline, if any.
    pub offline_node: Option<usize>,
    /// Set when the scenario expects the standby party to deal, and the run aggregates proofs.
    pub standby: Option<Standby>,
    /// The party a fault restarted, once it has.
    pub restarted: Option<Restarted>,
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

/// The party a fault restarted, and the node it runs on.
#[derive(Debug, Clone)]
pub struct Restarted {
    pub party_id: usize,
    pub node_index: usize,
    /// Whether it published the share `Expect::restarted_share` names. Not waited for, so false,
    /// when the scenario expects none.
    pub share_published: bool,
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
    /// Assembles every node, and rebuilds one from its persisted stores when a fault restarts it.
    factory: NodeFactory,
    /// The party a fault restarted, once it has.
    restarted: Option<Restarted>,
    /// Stands in for the chain: whatever it publishes reaches every node's own durable event
    /// pipeline.
    bus: BusHandle,
    multithread_report: Addr<MultithreadReport>,
    timings: Timings,
    // Held until the run ends.
    _timeout_env: TimeoutEnvGuard,
    _zk_temp: tempfile::TempDir,
    _persistence: Option<tempfile::TempDir>,
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

        let (zk_backend, zk_temp) = setup_test_zk_backend(bfv_preset, committee_size).await?;
        let pool_threads = Multithread::get_max_threads_minus(RESERVED_THREADS);
        let multithread_report =
            MultithreadReport::new(pool_threads, scenario.concurrent_jobs).start();
        let aggregate_config =
            AggregateConfig::new(HashMap::from([(AggregateId::new(1), Duration::ZERO)]));
        let system = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(aggregate_config.clone());
        let bus = system.handle()?.enable("test");
        // Nodes persist only when the scenario restarts one.
        let persistence = scenario
            .fault
            .restarts_a_node()
            .then(tempfile::tempdir)
            .transpose()?;
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
            persistence_root: persistence.as_ref().map(|dir| dir.path().to_path_buf()),
            restartable: Default::default(),
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
            factory,
            restarted: None,
            bus,
            multithread_report,
            timings: Timings {
                setup: setup.elapsed(),
                ..Default::default()
            },
            _timeout_env: timeout_env,
            _zk_temp: zk_temp,
            _persistence: persistence,
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

/// Runs one scenario and returns what it observed. It asserts nothing about the outcome:
/// [`super::assertions::check`] does.
pub async fn run(scenario: &Scenario) -> Result<Observations> {
    let whole_test = Instant::now();
    let _tracing = with_tracing("info");
    let mut env = Env::build(scenario).await?;

    register_operators(&mut env).await?;
    let request = request_and_finalize_committee(&mut env).await?;
    inject_fault(&mut env, &request).await?;

    let key = await_public_key(&mut env, &request).await?;
    let dkg_aggregator_proof = dkg_aggregator_proof(&key)?;
    record_chain_observation(&env, &request, &key, &dkg_aggregator_proof).await?;

    let decrypted = encrypt_and_decrypt(&mut env, &request, &key).await?;

    let role_holders = role_holders(&env, &request).await?;
    let roster = key_roster(&key);
    let standby = await_standby_share(&env, &request, &roster).await;
    let restarted = await_restarted_share(&env).await;
    let nodes = node_histories(&env).await?;

    let multithread = env.multithread_report.send(ToReport).await?;
    println!("{multithread}");
    env.timings.whole = whole_test.elapsed();

    Ok(Observations {
        config: env.config,
        timings: env.timings,
        e3_id: env.e3_id,
        params: env.params,
        key,
        roster,
        dkg_aggregator_proof,
        plaintext: decrypted.plaintext,
        votes: decrypted.votes,
        plaintext_aggregator_events: decrypted.history.to_vec(),
        role_holders,
        nodes,
        offline_node: request.offline_node(),
        standby,
        restarted,
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

/// The party that aggregates until a failover: the first in the committee's order.
const AGGREGATOR_PARTY: usize = 0;

/// Faults that fire before the public key is aggregated. Faults of the decrypt phase fire from
/// [`inject_decryption_fault`].
async fn inject_fault(env: &mut Env, request: &Request) -> Result<()> {
    match env.scenario.fault {
        Fault::OfflineAfterC0 { .. } => disconnect_after_c0(env, request).await,
        Fault::RestartDuringC4 { party_id } => restart_during_c4(env, request, party_id).await,
        Fault::None | Fault::RestartDuringC6 { .. } => Ok(()),
    }
}

/// Faults that fire once the ciphertext is published and the parties are decrypting it.
async fn inject_decryption_fault(
    env: &mut Env,
    request: &Request,
    key: &PublicKeyAggregated,
) -> Result<()> {
    match env.scenario.fault {
        Fault::RestartDuringC6 { party_id } => {
            restart_during_c6(env, request, party_id, &key_roster(key)).await
        }
        _ => Ok(()),
    }
}

async fn disconnect_after_c0(env: &Env, request: &Request) -> Result<()> {
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

/// Restarts a roster member while its C4 proof is pending. The proof request is on its event log
/// but no C4 share is, so the restarted node has to resume the request from its stores.
async fn restart_during_c4(env: &mut Env, request: &Request, preferred: usize) -> Result<()> {
    let timeout = env
        .pubkey_timeout
        .min(Duration::from_secs(env.dkg_window_secs));
    let aggregator = *request
        .committee
        .get(AGGREGATOR_PARTY)
        .context("committee has no aggregator")?;
    let roster = wait_for_event(
        &env.nodes,
        aggregator,
        "the aggregator's DKG roster",
        timeout,
        |data| match data {
            InterfoldEventData::CommitmentRosterSelected(selected)
                if selected.e3_id == env.e3_id =>
            {
                Some(selected.party_ids.clone())
            }
            _ => None,
        },
    )
    .await?;
    let party_id = restart_target(preferred, &roster)?;
    let node_index = party_node(request, party_id)?;
    wait_until(
        &env.nodes,
        node_index,
        "the restart party's pending C4 proof",
        timeout,
        |data| {
            matches!(
                data,
                InterfoldEventData::DecryptionShareProofsPending(pending)
                    if pending.e3_id == env.e3_id && pending.party_id == party_id as u64
            )
        },
    )
    .await?;
    let logged = restart_party(env, party_id, node_index, "C4").await?;
    anyhow::ensure!(
        !logged.iter().any(|event| matches!(
            event.get_data(),
            InterfoldEventData::DecryptionKeyShared(share)
                if share.e3_id == env.e3_id && share.party_id == party_id as u64
        )),
        "restart missed the C4 window: party {party_id} shared its C4 proofs before it stopped"
    );
    Ok(())
}

/// Restarts a roster member while its C6 proof is pending, after the ciphertext is published and
/// before it publishes its decryption share.
async fn restart_during_c6(
    env: &mut Env,
    request: &Request,
    preferred: usize,
    roster: &[u64],
) -> Result<()> {
    let party_id = restart_target(preferred, roster)?;
    let node_index = party_node(request, party_id)?;
    wait_until(
        &env.nodes,
        node_index,
        "the restart party's pending C6 proof",
        env.plaintext_timeout,
        |data| {
            matches!(
                data,
                InterfoldEventData::ShareDecryptionProofPending(pending)
                    if pending.e3_id == env.e3_id && pending.party_id == party_id as u64
            )
        },
    )
    .await?;
    let logged = restart_party(env, party_id, node_index, "C6").await?;
    anyhow::ensure!(
        !logged.iter().any(|event| matches!(
            event.get_data(),
            InterfoldEventData::DecryptionshareCreated(share)
                if share.e3_id == env.e3_id && share.party_id == party_id as u64
        )),
        "restart missed the C6 window: party {party_id} published its decryption share before it stopped"
    );
    Ok(())
}

/// `preferred` when the roster holds it and it is not the aggregator; otherwise the first roster
/// member that is not.
fn restart_target(preferred: usize, roster: &[u64]) -> Result<usize> {
    let eligible = |party: usize| party != AGGREGATOR_PARTY && roster.contains(&(party as u64));
    if eligible(preferred) {
        return Ok(preferred);
    }
    roster
        .iter()
        .map(|&party| party as usize)
        .find(|&party| eligible(party))
        .context("DKG roster has no non-aggregator party to restart")
}

fn party_node(request: &Request, party_id: usize) -> Result<usize> {
    request
        .committee
        .get(party_id)
        .copied()
        .context("restart party is outside the finalized committee")
}

/// Stops the party's node and rebuilds it from its persisted stores, and records the party for
/// the audits. Returns what the node logged before it stopped.
async fn restart_party(
    env: &mut Env,
    party_id: usize,
    node_index: usize,
    stage: &str,
) -> Result<CiphernodeHistory> {
    println!("Stopping committee party {party_id} at node index {node_index} during {stage}");
    let logged = env.factory.restart(&mut env.nodes, node_index).await?;
    println!(
        "Restarted committee party {party_id} at node index {node_index} during {stage}, \
         {} events logged before it stopped",
        logged.len()
    );
    env.restarted = Some(Restarted {
        party_id,
        node_index,
        share_published: false,
    });
    Ok(logged)
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

/// The final DKG proof the event carries. The registry observation the run records needs it, so a
/// key without one stops the run; the assertions check the rest of the key.
fn dkg_aggregator_proof(key: &PublicKeyAggregated) -> Result<Proof> {
    key.dkg_aggregator_proof
        .clone()
        .context("PublicKeyAggregated must always carry a final DKG proof payload")
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

/// The party that published the plaintext, what it carried, and the votes it must decrypt to.
struct Decrypted {
    history: CiphernodeHistory,
    plaintext: PlaintextAggregated,
    votes: Vec<Vec<u64>>,
}

async fn encrypt_and_decrypt(
    env: &mut Env,
    request: &Request,
    key: &PublicKeyAggregated,
) -> Result<Decrypted> {
    let pubkey = PublicKey::from_bytes(&key.pubkey, &env.params)?;
    let (outputs, votes) = encrypt_votes(env, &pubkey);
    let (history, plaintext) = decrypt(env, request, key, outputs).await?;
    Ok(Decrypted {
        history,
        plaintext,
        votes,
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
    key: &PublicKeyAggregated,
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
    inject_decryption_fault(env, request, key).await?;

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

// ---- Observations of the finished run ------------------------------------------------------

/// The histories of the parties that held the public-key aggregator role. A successor can take the
/// role late, so the holders are read now, not when the key appeared.
async fn role_holders(env: &Env, request: &Request) -> Result<Vec<(usize, CiphernodeHistory)>> {
    env.flush_nodes().await?;
    aggregator_role_histories(&env.nodes, &request.connected(), &env.e3_id).await
}

/// Waits for a share the scenario expects and records whether it arrived, so the assertions
/// decide what a missing share means. The wait's own error says what was observed instead.
async fn share_arrived(wait: impl Future<Output = Result<()>>, share: &str) -> bool {
    match wait.await {
        Ok(()) => true,
        Err(error) => {
            println!("{share} did not arrive: {error}");
            false
        }
    }
}

/// The aggregator can publish before a standby party's share lands, so the run waits for it when
/// the scenario expects the standby party to deal.
async fn await_standby_share(env: &Env, request: &Request, roster: &[u64]) -> Option<Standby> {
    if !env.config.standby_share_owed(&env.scenario.expect) {
        return None;
    }
    let party_id =
        (0..env.config.committee_n).find(|party_id| !roster.contains(&(*party_id as u64)))?;
    let share_dealt = share_arrived(
        wait_until(
            &env.nodes,
            request.committee[party_id],
            "standby party C4 share",
            env.pubkey_timeout.min(Duration::from_secs(300)),
            |data| {
                matches!(
                    data,
                    InterfoldEventData::DecryptionKeyShared(share)
                        if share.e3_id == env.e3_id && share.party_id == party_id as u64
                )
            },
        ),
        "standby party C4 share",
    )
    .await;
    Some(Standby {
        party_id,
        share_dealt,
    })
}

/// The restarted party, with whether it published the share the scenario expects of it. It had
/// not published it when it stopped, so the share is the restarted node's own.
async fn await_restarted_share(env: &Env) -> Option<Restarted> {
    let restarted = env.restarted.as_ref()?;
    let Some(owed) = env.scenario.expect.restarted_share else {
        return Some(restarted.clone());
    };
    let party = restarted.party_id as u64;
    let published = |data: &InterfoldEventData| match (owed, data) {
        (OwedShare::C4DecryptionKey, InterfoldEventData::DecryptionKeyShared(share)) => {
            share.e3_id == env.e3_id && share.party_id == party
        }
        (OwedShare::C6Decryption, InterfoldEventData::DecryptionshareCreated(share)) => {
            share.e3_id == env.e3_id && share.party_id == party
        }
        _ => false,
    };
    let share_published = share_arrived(
        wait_until(
            &env.nodes,
            restarted.node_index,
            "the restarted party's share",
            env.pubkey_timeout.min(Duration::from_secs(600)),
            published,
        ),
        "the restarted party's share",
    )
    .await;
    Some(Restarted {
        share_published,
        ..restarted.clone()
    })
}

/// Every node's history, for the fault scan.
async fn node_histories(env: &Env) -> Result<Vec<NodeHistory>> {
    let mut nodes = Vec::new();
    for (index, node) in env.nodes.iter().enumerate() {
        nodes.push(NodeHistory {
            index,
            address: node.address(),
            history: env.nodes.get_history(index).await?,
        });
    }
    Ok(nodes)
}
