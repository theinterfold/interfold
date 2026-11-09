// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Drives one full E3 (committee selection, DKG, public key, encryption, threshold decryption)
//! across real ciphernodes joined by a simulated network, and checks its outcome.
//!
//! [`run`] asserts what a correct run must produce: the key and plaintext, the accepted DKG
//! roster, and the absence of faults. It does not assert how the nodes' actors order their events;
//! the owning crates pin that. Failover and restart are also pinned there, deterministically, so
//! no scenario here waits for a progress deadline. The timings and proofs the benchmark reports
//! are returned in [`Run`].

use super::history::{
    aggregator_role_nodes, collect_honest_run_faults, wait_for_history_match,
    wait_for_history_match_any,
};
use super::nodes::{
    determine_committee, find_node_index_by_address, setup_score_sortition_environment,
    NodeFactory, DKG_FOLD_ATTESTATION_VERIFIER,
};
use super::zk_fixture::{active_committee, setup_test_zk_backend};
use crate::ciphernode_system::CiphernodeSystemBuilder;
use actix::Actor;
use alloy::primitives::{Address, U256};
use anyhow::{Context, Result};
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_crypto::Cipher;
use e3_event_system::EventSystem;
use e3_events::{
    prelude::*, AggregateConfig, AggregateId, CiphertextOutputPublished, CommitteeFinalized,
    CommitteeRequested, DkgFoldAttestationContextEstablished, E3Requested, E3id, EventSource,
    InterfoldEvent, InterfoldEventData, PlaintextAggregated, Proof, Seed,
    DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset, DEFAULT_BFV_PRESET};
use e3_multithread::{FlattenedReport, Multithread, MultithreadReport, ToReport};
use e3_sortition::calculate_buffer_size;
use e3_test_support::{create_seed_from_u64, with_tracing};
use e3_trbfv::helpers::calculate_error_size;
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::PublicKey;
use fhe_traits::{DeserializeParametrized, Serialize};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

/// Seed of the per-node RNGs; every node draws a different stream from it.
const NODE_RNG_BASE: u64 = 42;
const CHAIN_ID: u64 = 1;
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
    /// Any mode other than `secure` selects the insecure parameters.
    pub fn from_mode(mode: &str) -> Self {
        if mode == "secure" {
            Preset::Secure
        } else {
            Preset::Insecure
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

pub async fn run(scenario: &Scenario) -> Result<Run> {
    let whole_test = Instant::now();
    let _guard = with_tracing("info");
    let mut timings = Timings::default();

    // Nodes get this frozen deadline: the scenario has no enabled EVM provider, and production
    // nodes read it from the contract.
    let setup = Instant::now();
    let preset = scenario.preset;
    let bfv_preset = preset.bfv_preset();
    let committee_size = active_committee();
    let small_committee = committee_size == e3_committee::CiphernodesCommitteeSize::Small;
    let _timeout_env = TimeoutEnvGuard::set(preset.collection_timeouts_secs(small_committee));
    let (pubkey_flow_timeout, plaintext_flow_timeout) = preset.flow_timeouts(small_committee);
    let dkg_window_secs = scenario
        .dkg_window
        .map(|window| window.as_secs())
        .unwrap_or_else(|| pubkey_flow_timeout.as_secs().saturating_mul(10))
        .max(1);
    let dkg_start = Arc::new(std::sync::OnceLock::<u64>::new());
    let dkg_timing_reader: e3_keyshare::DkgTimingReader = Arc::new(move |_| {
        let deadline = *dkg_start.get_or_init(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(dkg_window_secs)
        });
        Box::pin(async move { Ok((deadline, dkg_window_secs)) })
    });

    // The committee comes from the build stamp: the circuits in `circuits/bin/` were compiled
    // for one committee, and `pnpm build:circuits --committee <name>` switches it.
    let committee_params = committee_size.values();
    let threshold_m = committee_params.threshold;
    let threshold_n = committee_params.n;
    let committee_h = committee_params.h;
    let participant_count = threshold_n + calculate_buffer_size(threshold_m, threshold_n);
    let params_raw = BfvParamSet::from(bfv_preset).build_arc();
    let params = ArcBytes::from_bytes(&encode_bfv_params(&params_raw));
    let lambda = bfv_preset.lambda()?;
    let seed = Seed(create_seed_from_u64(123));
    let error_size = ArcBytes::from_bytes(&BigUint::to_bytes_be(&calculate_error_size(
        params_raw.clone(),
        threshold_n,
        threshold_m,
        lambda,
    )?));

    let proof_aggregation_enabled = proof_aggregation_enabled();
    let (zk_backend, _zk_temp) = setup_test_zk_backend(preset.subdir()).await?;
    let pool_threads = Multithread::get_max_threads_minus(RESERVED_THREADS);
    let multithread_report = MultithreadReport::new(pool_threads, scenario.concurrent_jobs).start();

    // The trigger bus stands in for the chain: whatever it publishes reaches every node's own
    // durable event pipeline.
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
        dkg_timing_reader,
        proof_aggregation_enabled,
        trigger: bus.clone(),
        next_salt: Default::default(),
    };

    // Node 0 observes only: it is never registered for sortition. Every other node runs the
    // same binary, and the pool holds N plus the sortition buffer.
    let nodes = CiphernodeSystemBuilder::new()
        .add_group(1, || factory.build("collector"))
        .add_group(
            u32::try_from(participant_count).expect("participant count fits in u32"),
            || factory.build("participant"),
        )
        .simulate_libp2p()
        .build()
        .await?;
    timings.setup = setup.elapsed();

    let committee_setup = Instant::now();
    let collector_addr = nodes.first().unwrap().address();
    let eth_addrs: Vec<String> = nodes.iter().skip(1).map(|n| n.address()).collect();
    anyhow::ensure!(
        eth_addrs.len() >= threshold_n,
        "need at least {threshold_n} registered nodes for committee N, got {}",
        eth_addrs.len()
    );
    println!(
        "{} registered nodes, committee N={threshold_n}, collector (observer): {collector_addr}",
        eth_addrs.len(),
    );
    setup_score_sortition_environment(&bus, &eth_addrs, CHAIN_ID).await?;
    timings.committee_setup = committee_setup.elapsed();

    let e3_requested_timer = Instant::now();
    let e3_id = E3id::new("0", 1);
    let request_block = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 1;
    println!(
        "trbfv scenario: {scenario:?}, proof_aggregation={proof_aggregation_enabled}, committee={committee_size}"
    );
    bus.publish_without_context(CommitteeRequested {
        e3_id: e3_id.clone(),
        seed,
        threshold: [threshold_m, threshold_n],
        request_block,
        committee_deadline: request_block + 30,
        ticket_price: U256::from(10_000_000u64),
        chain_id: CHAIN_ID,
    })?;
    bus.publish_from_remote(
        E3Requested {
            e3_id: e3_id.clone(),
            threshold_m,
            threshold_n,
            seed,
            request_block,
            error_size,
            params_preset: bfv_preset,
            params,
        },
        0,
        Some(request_block),
        EventSource::Evm,
    )?;
    if proof_aggregation_enabled {
        // No live registry event exists here. Seed the request-time signing context so the
        // public-key aggregator can validate every synthetic NodeFold attestation.
        bus.publish_without_context(DkgFoldAttestationContextEstablished {
            schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
            e3_id: e3_id.clone(),
            context: e3_events::DkgFoldAttestationContext {
                registry: Address::ZERO,
                verifying_contract: DKG_FOLD_ATTESTATION_VERIFIER.parse()?,
            },
        })?;
    }
    sleep(Duration::from_millis(500)).await;

    let (committee, committee_scores, buffer_nodes) = determine_committee(
        &e3_id,
        seed,
        threshold_m,
        threshold_n,
        &eth_addrs,
        &collector_addr,
    )?;
    let mut finalized = CommitteeFinalized {
        e3_id: e3_id.clone(),
        committee,
        scores: committee_scores,
        chain_id: CHAIN_ID,
    };
    finalized.sort_by_address();
    println!(
        "Committee selected: {} nodes, {} buffer nodes",
        finalized.committee.len(),
        buffer_nodes.len()
    );
    let committee = finalized.committee.clone();

    wait_for_history_match(&nodes, 0, "E3Requested", pubkey_flow_timeout, |d| {
        matches!(d, InterfoldEventData::E3Requested(_))
    })
    .await?;
    let committee_finalized_timer = Instant::now();
    bus.publish_without_context(finalized)?;
    wait_for_history_match(
        &nodes,
        0,
        "CommitteeFinalized",
        pubkey_flow_timeout,
        |d| matches!(d, InterfoldEventData::CommitteeFinalized(f) if f.e3_id == e3_id),
    )
    .await?;
    timings.committee_finalization = committee_finalized_timer.elapsed();

    ///////////////////////////////////////////////////////////////////////////////////
    // Fault injection
    ///////////////////////////////////////////////////////////////////////////////////

    let mut offline_node_index = None;
    if let Fault::OfflineAfterC0 { party_id } = scenario.fault {
        let address = committee
            .get(party_id)
            .context("offline party is outside the finalized committee")?;
        let node_index = find_node_index_by_address(&nodes, address)?;
        let c0_observation_timeout = pubkey_flow_timeout.min(Duration::from_secs(dkg_window_secs));
        let published_c0 = |data: &InterfoldEventData| {
            matches!(
                data,
                InterfoldEventData::EncryptionKeyCreated(key)
                    if key.e3_id == e3_id && key.key.party_id == party_id as u64
            )
        };
        wait_for_history_match(
            &nodes,
            node_index,
            "the offline party's C0",
            c0_observation_timeout,
            published_c0,
        )
        .await?;
        // A peer must hold the key too, or the party would leave before anyone could use it.
        let witness_party_id = (0..committee.len())
            .find(|&id| id != party_id)
            .context("committee has no other party to observe C0")?;
        let witness_index = find_node_index_by_address(&nodes, &committee[witness_party_id])?;
        wait_for_history_match(
            &nodes,
            witness_index,
            "the offline party's C0 on a peer",
            c0_observation_timeout,
            published_c0,
        )
        .await?;
        nodes.disconnect_node(node_index).await?;
        offline_node_index = Some(node_index);
        println!("Disconnected committee party {party_id} at node index {node_index} after C0");
    }

    ///////////////////////////////////////////////////////////////////////////////////
    // Public key
    ///////////////////////////////////////////////////////////////////////////////////

    let mut connected_committee = Vec::new();
    for address in &committee {
        let node_index = find_node_index_by_address(&nodes, address)?;
        if Some(node_index) != offline_node_index {
            connected_committee.push(node_index);
        }
    }

    let shares_to_pubkey_timer = Instant::now();
    let observer_history = wait_for_history_match(
        &nodes,
        0,
        "PublicKeyAggregated",
        pubkey_flow_timeout,
        |d| matches!(d, InterfoldEventData::PublicKeyAggregated(k) if k.e3_id == e3_id),
    )
    .await
    .map_err(|e| anyhow::anyhow!("FAILURE in the public-key flow: {e}"))?;
    timings.shares_to_pubkey = shares_to_pubkey_timer.elapsed();
    timings.request_to_pubkey = e3_requested_timer.elapsed();
    let pubkey_event = observer_history
        .iter()
        .rev()
        .find_map(|event| match event.get_data() {
            InterfoldEventData::PublicKeyAggregated(data) if data.e3_id == e3_id => {
                Some(data.clone())
            }
            _ => None,
        })
        .context("observer history has no PublicKeyAggregated")?;
    let pubkey_bytes = pubkey_event.pubkey.clone();
    assert_eq!(
        pubkey_event.nodes.len(),
        committee_h,
        "PublicKeyAggregated must list H={committee_h} honest nodes"
    );
    let dkg_aggregator_proof = pubkey_event
        .dkg_aggregator_proof
        .clone()
        .context("PublicKeyAggregated must always carry a final DKG proof payload")?;
    assert!(
        pubkey_event
            .dkg_attestation_bundle
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty()),
        "PublicKeyAggregated must always carry a non-empty DKG attestation payload"
    );

    // The synthetic registry records the same confirmed observation as chain ingestion.
    {
        use alloy::sol_types::SolEvent;
        let proof = e3_evm::encode_zk_proof(&dkg_aggregator_proof)?;
        let observation = e3_evm::ICiphernodeRegistry::CommitteeProofPublished {
            e3Id: U256::ZERO,
            nodes: pubkey_event.committee_addresses.clone(),
            pkCommitment: pubkey_event.pk_commitment.into(),
            proof,
        }
        .encode_log_data();
        bus.publish_from_remote(
            e3_events::EvmLogObserved {
                contract: "CiphernodeRegistry".into(),
                chain_id: CHAIN_ID,
                e3_id: Some(e3_id.clone()),
                event_name: "CommitteeProofPublished".into(),
                known: true,
                signature: Some(
                    e3_evm::ICiphernodeRegistry::CommitteeProofPublished::SIGNATURE.into(),
                ),
                topics: observation
                    .topics()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                data: ArcBytes::from_bytes(&observation.data),
            },
            0,
            Some(request_block + 1),
            EventSource::Evm,
        )?;
        bus.publish_without_context(e3_events::CommitteePublished {
            e3_id: e3_id.clone(),
            nodes: pubkey_event
                .committee_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
            public_key: pubkey_bytes.clone(),
            proof: ArcBytes::from_bytes(&[]),
        })?;
        bus.flush_event_pipeline().await?;
        for node in nodes.iter() {
            node.bus().flush_event_pipeline().await?;
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////
    // Encryption and decryption
    ///////////////////////////////////////////////////////////////////////////////////

    let pubkey = PublicKey::from_bytes(&pubkey_bytes, &params_raw)?;
    let app_gen_timer = Instant::now();
    println!("Generating inputs this takes some time...");
    let (inputs, numbers) =
        e3_bfv_test_support::generate_ciphertexts(&pubkey, VOTERS, VOTES_PER_VOTER);
    timings.ciphertext_generation = app_gen_timer.elapsed();

    let running_app_timer = Instant::now();
    println!("Running application to generate outputs...");
    let outputs = e3_bfv_test_support::run_application(&inputs, &pubkey, VOTES_PER_VOTER);
    timings.fhe_application = running_app_timer.elapsed();

    let publishing_ct_timer = Instant::now();
    let ciphertexts = outputs
        .into_iter()
        .map(|ct| ArcBytes::from_bytes(&(*ct).clone().to_bytes()))
        .collect::<Vec<ArcBytes>>();
    println!("Publishing CiphertextOutputPublished...");
    bus.publish_without_context(CiphertextOutputPublished {
        ciphertext_output: ciphertexts,
        e3_id: e3_id.clone(),
        ciphertext_commitment: [0u8; 32],
    })?;

    // PlaintextAggregated is a local publication intent, so only the party that aggregates holds
    // it. A party demoted in the key phase is skipped for this one, so any connected committee
    // member can be that party.
    println!("Waiting for PlaintextAggregated");
    let (plaintext_aggregator_index, plaintext_aggregator_history) = wait_for_history_match_any(
        &nodes,
        &connected_committee,
        "PlaintextAggregated",
        plaintext_flow_timeout,
        |data| matches!(data, InterfoldEventData::PlaintextAggregated(event) if event.e3_id == e3_id),
    )
    .await
    .map_err(|e| anyhow::anyhow!("FAILURE in the plaintext flow: {e}"))?;
    timings.ciphertext_to_plaintext = publishing_ct_timer.elapsed();
    println!("PlaintextAggregated observed on node {plaintext_aggregator_index}");

    let (plaintext, decryption_aggregator_proofs) = plaintext_aggregator_history
        .iter()
        .rev()
        .find_map(|e| match e.get_data() {
            InterfoldEventData::PlaintextAggregated(PlaintextAggregated {
                decrypted_output,
                decryption_aggregator_proofs,
                ..
            }) => Some((
                decrypted_output.clone(),
                decryption_aggregator_proofs.clone(),
            )),
            _ => None,
        })
        .context("plaintext aggregator history has no PlaintextAggregated")?;
    assert_eq!(
        decryption_aggregator_proofs.len(),
        VOTES_PER_VOTER,
        "PlaintextAggregated must carry one decryption proof per tally"
    );

    let results: Vec<u64> = plaintext
        .into_iter()
        .map(|a| decode_bytes_to_vec_u64(&a.extract_bytes()).expect("error decoding bytes"))
        .map(|r| *r.first().unwrap())
        .collect();
    let plaintext_modulus = params_raw.plaintext();
    let mut expected_result = [0u64; VOTES_PER_VOTER];
    for vals in &numbers {
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

    ///////////////////////////////////////////////////////////////////////////////////
    // Audits over the finished run's histories
    ///////////////////////////////////////////////////////////////////////////////////

    // Settle in-flight deliveries so every node's history is complete. A successor can take the
    // aggregator role late, so the holders are read now, not when the key appeared.
    for node in nodes.iter() {
        node.bus().flush_event_pipeline().await?;
    }

    // Whichever parties held the aggregator role must agree on the DKG roster, and that roster
    // is the one the published key was built from.
    let pubkey_aggregators = aggregator_role_nodes(&nodes, &connected_committee, &e3_id).await?;
    let mut pubkey_role_events: Vec<InterfoldEvent> = Vec::new();
    for &node_index in &pubkey_aggregators {
        pubkey_role_events.extend(nodes.get_history(node_index).await?.iter().cloned());
    }
    let accepted_rosters: Vec<&Vec<u64>> = pubkey_role_events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::CommitmentRosterSelected(data) if data.e3_id == e3_id => {
                Some(&data.party_ids)
            }
            _ => None,
        })
        .collect();
    assert!(
        !accepted_rosters.is_empty(),
        "aggregator did not accept a DKG roster"
    );
    assert!(
        accepted_rosters
            .iter()
            .all(|roster| *roster == accepted_rosters[0]),
        "aggregator accepted conflicting DKG rosters"
    );
    let roster = accepted_rosters[0].clone();
    let selected_addresses: Vec<Address> = roster
        .iter()
        .map(|&party_id| pubkey_event.committee_addresses[party_id as usize])
        .collect();
    assert_eq!(selected_addresses, pubkey_event.honest_committee_addresses);

    if let Some(node_index) = offline_node_index {
        let offline_party_id = committee
            .iter()
            .position(|address| address == &nodes[node_index].address())
            .context("disconnected node is outside the committee")?;
        assert!(
            !roster.contains(&(offline_party_id as u64)),
            "disconnected party was selected for the DKG roster"
        );
    }

    // The aggregator can publish before a standby party's share lands; the standby party still
    // has to deal it, since it replaces a roster member that drops out.
    if proof_aggregation_enabled && offline_node_index.is_none() {
        let standby_party_id = (0..threshold_n)
            .find(|party_id| !roster.contains(&(*party_id as u64)))
            .context("DKG roster has no standby party")?;
        let standby_node_index = find_node_index_by_address(&nodes, &committee[standby_party_id])?;
        wait_for_history_match(
            &nodes,
            standby_node_index,
            "standby party C4 share",
            pubkey_flow_timeout.min(Duration::from_secs(300)),
            |data| {
                matches!(
                    data,
                    InterfoldEventData::DecryptionKeyShared(share)
                        if share.e3_id == e3_id && share.party_id == standby_party_id as u64
                )
            },
        )
        .await?;
    }

    // The runtime lets a demoted holder finish and submit the key it computed, and the chain
    // keeps the first valid submission. Every submission must therefore be the key the
    // committee goes on to use. A holder's own submission is `Local`; peers forward copies.
    let mut submissions = 0;
    for &node_index in &pubkey_aggregators {
        for event in nodes.get_history(node_index).await?.iter() {
            if let (EventSource::Local, InterfoldEventData::PublicKeyAggregated(data)) =
                (event.source(), event.get_data())
            {
                if data.e3_id == e3_id {
                    submissions += 1;
                    assert!(
                        data.pubkey == pubkey_bytes,
                        "role holder {node_index} submitted a public key that differs from the one the committee used"
                    );
                }
            }
        }
    }
    assert!(submissions > 0, "no role holder submitted the public key");

    // No node may have accused, expelled, or failed anyone, or logged an actor error. The
    // disconnected node cannot collect its own DKG shares, so it can fail locally without
    // failing the E3.
    let mut faults = Vec::new();
    for index in 1..=participant_count {
        if Some(index) == offline_node_index {
            continue;
        }
        faults.extend(collect_honest_run_faults(
            &nodes.get_history(index).await?,
            &e3_id,
            &format!("participant node {index} ({})", nodes[index].address()),
        ));
    }
    faults.extend(collect_honest_run_faults(
        &nodes.get_history(0).await?,
        &e3_id,
        "observer node 0",
    ));
    assert!(
        faults.is_empty(),
        "honest-run safeguard failures:\n{}",
        faults.join("\n")
    );

    let multithread = multithread_report.send(ToReport).await?;
    println!("{multithread}");
    timings.whole = whole_test.elapsed();

    Ok(Run {
        config: RunConfig {
            preset,
            lambda: bfv_preset.metadata().lambda,
            proof_aggregation_enabled,
            concurrent_jobs: scenario.concurrent_jobs,
            committee_n: threshold_n,
            committee_h,
            committee_t: threshold_m,
            nodes_spawned: participant_count + 1,
        },
        timings,
        e3_id,
        dkg_aggregator_proof,
        decryption_aggregator_proofs,
        pubkey_role_events,
        plaintext_aggregator_events: plaintext_aggregator_history.to_vec(),
        multithread,
    })
}
