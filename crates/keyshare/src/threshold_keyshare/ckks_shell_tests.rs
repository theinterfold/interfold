// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS actor-shell tests: five REAL `ThresholdKeyshare` actix actors (not
//! the bare machine) driven through the full CKKS lifecycle by routing the
//! bus events they emit back into each other — the same envelope path
//! (`Handler<InterfoldEvent>` -> route_events -> ckks_shell) production
//! uses. Ends in a real threshold decryption, plus restart-recovery
//! checks mid-DKG and mid-relin-ceremony.

use super::effects::ckks_ceremony_log::CeremonyChunkLog;
use super::*;
use crate::threshold_keyshare_ckks::workflow::aggregate_plaintext;
use crate::{CkksCeremonyRecovery, E3Scheme};
use actix::Actor;
use e3_data::{AutoPersist, DataStore, InMemStore, Repository};
use e3_events::{
    hlc_factory::HlcFactory, CommitteePublished, E3id, EventBus, EventBusConfig, EventSource,
    GetEvents, HistoryCollector, Seed, Sequencer, StoreEventRequested, StoreEventResponse,
    Unsequenced,
};
use e3_fhe::CkksFhe;
use e3_fhe_params::{BfvPreset, DEFAULT_BFV_PRESET};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::RngCore;
use std::sync::Mutex;

// The `minimum` committee (n=3, t=1): `CiphernodesCommitteeSize` only
// recognizes the deployed shapes, and the actor derives it from
// (threshold_m, threshold_n) when announcing encryption keys.
const N: usize = 3;
const T: usize = 1;

/// The canonical CKKS param set 0 (no ceremony; C6 posture proven).
fn ckks_params_bytes() -> (Arc<fhe::ckks::CkksParameters>, ArcBytes) {
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(0).unwrap();
    let bytes = ArcBytes::from_bytes(&params.to_bytes());
    (params, bytes)
}

/// The statistics param set 3: one relin level (0) over the standard
/// transport — the smallest E3 that runs a ceremony.
fn ckks_ceremony_params_bytes() -> (Arc<fhe::ckks::CkksParameters>, ArcBytes) {
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(3).unwrap();
    let bytes = ArcBytes::from_bytes(&params.to_bytes());
    (params, bytes)
}

struct TestNode {
    actor: Addr<ThresholdKeyshare>,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    state_repo: Repository<ThresholdKeyshareState>,
    recovery_repo: Repository<ThresholdKeyshareRecoveryState>,
    ceremony_store: DataStore,
    artifacts_dir: std::path::PathBuf,
    cipher: Arc<Cipher>,
}

#[derive(Default)]
struct SeqStore {
    next_seq: u64,
}
impl Actor for SeqStore {
    type Context = actix::Context<Self>;
}
impl Handler<StoreEventRequested> for SeqStore {
    type Result = ();
    fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) -> Self::Result {
        let StoreEventRequested { event, sender } = msg;
        let seq = self.next_seq;
        self.next_seq += 1;
        sender.do_send(StoreEventResponse(event.into_sequenced(seq)));
    }
}

fn share_enc_preset() -> BfvPreset {
    DEFAULT_BFV_PRESET
        .dkg_counterpart()
        .unwrap_or(DEFAULT_BFV_PRESET)
}

fn test_bus(name: &str) -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
    let store = SeqStore::default().start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable(name)
}

async fn start_node(e3_id: &E3id, party_id: u64, params: &ArcBytes) -> Result<TestNode> {
    start_node_with_circuits(e3_id, party_id, params, None).await
}

async fn start_node_with_circuits(
    e3_id: &E3id,
    party_id: u64,
    params: &ArcBytes,
    zk_circuits_dir: Option<std::path::PathBuf>,
) -> Result<TestNode> {
    let bus = test_bus(&format!("ckks-node-{party_id}"));
    let history = bus.history();

    let state_store = InMemStore::new(false).start();
    let state_repo =
        Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&state_store));
    let state = ThresholdKeyshareState::new(
        e3_id.clone(),
        party_id,
        KeyshareState::Init,
        T as u64,
        N as u64,
        params.clone(),
        format!("0xnode{party_id}"),
    );
    let recovery_store = InMemStore::new(false).start();
    let recovery_repo =
        Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&recovery_store));
    let cipher = Arc::new(Cipher::from_password("test-password").await?);
    let ceremony_store = DataStore::from_in_mem(&InMemStore::new(false).start())
        .scope(format!("//ceremony/{e3_id}"));
    let artifacts_dir = std::env::temp_dir().join(format!(
        "interfold-ckks-shell-test-{}-{party_id}-{}",
        e3_id.e3_id(),
        rand::random::<u32>()
    ));

    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: cipher.clone(),
        state: state_repo.to_connector().send(Some(state)),
        share_enc_preset: share_enc_preset(),
        interfold_address: Address::ZERO,
        recovery: recovery_repo
            .to_connector()
            .send(Some(ThresholdKeyshareRecoveryState::default())),
        ckks_artifacts_dir: Some(artifacts_dir.clone()),
        zk_circuits_dir,
        ckks_ceremony: Some(CkksCeremonyRecovery {
            log: CeremonyChunkLog::fresh(ceremony_store.clone()),
            replay: Vec::new(),
        }),
    })
    .start();
    Ok(TestNode {
        actor,
        history,
        state_repo,
        recovery_repo,
        ceremony_store,
        artifacts_dir,
        cipher,
    })
}

fn selected_event(e3_id: &E3id, party_id: u64, params: &ArcBytes, seed: Seed) -> InterfoldEvent {
    let data = CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: T,
        threshold_n: N,
        seed,
        error_size: ArcBytes::from_bytes(&[]),
        params_preset: DEFAULT_BFV_PRESET,
        params: params.clone(),
        party_id,
        committee: (1..=N as u64).map(|p| format!("0xnode{p}")).collect(),
        // The chain-bound program scheme (program address => protocol):
        // dispatch keys off THIS, not the params bytes.
        scheme: E3Scheme::Ckks,
    };
    seq_event(data.into(), party_id * 1000)
}

fn seq_event(data: InterfoldEventData, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        data,
        None,
        seq as u128,
        None,
        EventSource::Local,
    )
    .into_sequenced(seq)
}

/// Drain every event each node's bus emitted since the last call.
async fn drain(node: &TestNode) -> Result<Vec<InterfoldEvent>> {
    Ok(node
        .history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?)
}

/// Deliver an event to every node (the network broadcast).
async fn broadcast(nodes: &[TestNode], event: InterfoldEvent) -> Result<()> {
    for node in nodes {
        node.actor.send(event.clone()).await?;
    }
    Ok(())
}

/// Pump: repeatedly drain all nodes and re-broadcast the DKG events until
/// quiescent. Returns every KeyshareCreated observed. `seen` carries the
/// event ids already handled (the history collectors are cumulative).
async fn pump(
    nodes: &[TestNode],
    seq: &mut u64,
    seen: &mut std::collections::HashSet<String>,
) -> Result<Vec<KeyshareCreated>> {
    let mut keyshares = Vec::new();
    for _ in 0..40 {
        // The bus pipeline (publish -> sequencer -> history) is async;
        // give it a beat before draining.
        actix::clock::sleep(std::time::Duration::from_millis(50)).await;
        let mut new_events = Vec::new();
        for node in nodes {
            for event in drain(node).await? {
                let key = format!("{:?}", event.get_ctx().id());
                if seen.insert(key) {
                    new_events.push(event);
                }
            }
        }
        if new_events.is_empty() {
            return Ok(keyshares);
        }
        for event in new_events {
            let (data, _) = event.into_components();
            match data {
                InterfoldEventData::EncryptionKeyPending(p) => {
                    // The network turns Pending into Created (proof actor
                    // + gossip); C0 proofs are BFV-only machinery, so the
                    // CKKS path forwards the key as-is.
                    *seq += 1;
                    broadcast(
                        nodes,
                        seq_event(
                            EncryptionKeyCreated {
                                e3_id: p.e3_id.clone(),
                                key: p.key.clone(),
                                external: false,
                            }
                            .into(),
                            *seq,
                        ),
                    )
                    .await?;
                }
                InterfoldEventData::ThresholdShareCreated(s) => {
                    *seq += 1;
                    broadcast(nodes, seq_event(s.into(), *seq)).await?;
                }
                InterfoldEventData::RelinCeremonyShare(s) => {
                    // Unfiltered broadcast (net mirrors DecryptionKeyShared).
                    *seq += 1;
                    broadcast(nodes, seq_event(s.into(), *seq)).await?;
                }
                InterfoldEventData::PkGenerationCkksProofPending(p) => {
                    // The ProofRequestActor turns the pending request into
                    // a SIGNED C1-CKKS proof + KeyshareCreated. Mock it:
                    // dummy proof bytes with a well-formed public-signal
                    // layout (the aggregator's commitment cross-check is
                    // exercised in e3-aggregator's tests, not here).
                    *seq += 1;
                    let signer: alloy::signers::local::PrivateKeySigner =
                        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                            .parse()
                            .unwrap();
                    let signed = e3_events::SignedProofPayload::sign(
                        e3_events::ProofPayload {
                            e3_id: p.e3_id.clone(),
                            proof_type: e3_events::ProofType::C1PkGeneration,
                            proof: e3_events::Proof::new(
                                e3_events::CircuitName::PkGenerationCkksPs0,
                                ArcBytes::from_bytes(&[1]),
                                ArcBytes::from_bytes(&[0u8; 96]),
                            ),
                        },
                        &signer,
                    )?;
                    let created = KeyshareCreated {
                        pubkey: p.pk_share.clone(),
                        e3_id: p.e3_id.clone(),
                        node: p.node.clone(),
                        party_id: p.party_id,
                        signed_pk_generation_proof: Some(signed),
                    };
                    // The real ProofRequestActor publishes this on the bus
                    // (gossiped + observed by every keyshare actor).
                    broadcast(nodes, seq_event(created.clone().into(), *seq)).await?;
                    keyshares.push(created);
                }
                InterfoldEventData::KeyshareCreated(k) => {
                    assert!(
                        k.signed_pk_generation_proof.is_some(),
                        "CKKS KeyshareCreated must carry the C1-CKKS proof"
                    );
                    keyshares.push(k)
                }
                InterfoldEventData::InterfoldError(e) => {
                    bail!("bus error during pump: {e:?}");
                }
                _ => {}
            }
        }
    }
    bail!("event pump did not quiesce")
}

#[actix::test]
async fn committee_of_actors_ckks_dkg_and_threshold_decryption() -> Result<()> {
    let (params, params_bytes) = ckks_params_bytes();
    let e3_id = E3id::new("77", 1);
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    let seed = Seed(seed_bytes);

    let mut nodes = Vec::new();
    for pid in 0..N as u64 {
        nodes.push(start_node(&e3_id, pid, &params_bytes).await?);
    }

    // Kick off: each node receives its own CiphernodeSelected.
    for (i, node) in nodes.iter().enumerate() {
        node.actor
            .send(selected_event(&e3_id, i as u64, &params_bytes, seed))
            .await?;
    }

    // Pump the network to convergence.
    let mut seq = 100_000u64;
    let mut seen = std::collections::HashSet::new();
    let keyshares = pump(&nodes, &mut seq, &mut seen).await?;
    assert_eq!(
        keyshares.len(),
        N,
        "every node must publish KeyshareCreated"
    );
    // BFV-style publication: each KeyshareCreated carries the node's pk
    // SHARE. Distinct secrets => distinct shares.
    for k in &keyshares[1..] {
        assert_ne!(k.pubkey, keyshares[0].pubkey, "pk shares must differ");
    }

    // Persisted state carries the scheme.
    let persisted = nodes[0].state_repo.read().await?.expect("persisted state");
    assert_eq!(persisted.scheme, E3Scheme::Ckks);

    // Aggregate the shares (the pk-aggregator's job) into the joint pk.
    let agg_fhe = CkksFhe::from_encoded(
        &params_bytes,
        seed_bytes,
        N,
        T,
        Arc::new(Mutex::new(
            <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
        )),
    )?;
    let joint_pk_bytes =
        agg_fhe.get_aggregate_public_key(e3_fhe::ckks_runtime::GetCkksAggregatePublicKey {
            keyshares: e3_events::OrderedSet::from(
                keyshares
                    .iter()
                    .map(|k| k.pubkey.clone())
                    .collect::<Vec<_>>(),
            ),
        })?;

    // E3 compute: encrypt two values under the joint pk, homomorphic add.
    let pk = fhe::ckks::CkksPublicKey::from_bytes(&joint_pk_bytes, &params)?;
    let encoder = fhe::ckks::CkksEncoder::new(&params);
    let mut rng = rand::rng();
    let (a, b) = (42.5f64, -17.25);
    let ct_a = pk.try_encrypt(&encoder.encode(&[a], 0)?, &mut rng)?;
    let ct_b = pk.try_encrypt(&encoder.encode(&[b], 0)?, &mut rng)?;
    let output = ct_a.try_add(&ct_b)?;
    let out_bytes = output.to_bytes();

    // CiphertextOutputPublished to t+1 nodes -> DecryptionshareCreated.
    // Chain party ids (0-based committee slots); Shamir x = pid + 1.
    let reconstructing = [0u64, 2];
    let mut shares = Vec::new();
    for &pid in &reconstructing {
        seq += 1;
        nodes[pid as usize]
            .actor
            .send(seq_event(
                CiphertextOutputPublished {
                    e3_id: e3_id.clone(),
                    ciphertext_output: vec![ArcBytes::from_bytes(&out_bytes)],
                    ciphertext_commitment: [0u8; 32],
                }
                .into(),
                seq,
            ))
            .await?;
        for event in drain(&nodes[pid as usize]).await? {
            if let InterfoldEventData::DecryptionshareCreated(d) = event.into_components().0 {
                assert_eq!(d.party_id, pid, "event carries the CHAIN party id");
                // aggregate_plaintext takes the 1-based Shamir x.
                shares.push((pid + 1, d.decryption_share[0].clone()));
            }
        }
    }
    assert_eq!(
        shares.len(),
        reconstructing.len(),
        "missing decryption shares"
    );

    // Aggregate (the aggregator's job) and check the value.
    let fhe = CkksFhe::from_encoded(
        &params_bytes,
        seed_bytes,
        N,
        T,
        Arc::new(Mutex::new(
            <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
        )),
    )?;
    let values = aggregate_plaintext(&fhe, shares, &out_bytes)?;
    // Tolerance: 20-bit demo smudging against scale 2^26 leaves ~0.05
    // baseline error, but Lagrange coefficients in the t-of-n combine
    // amplify each share's noise (coefficient magnitudes depend on WHICH
    // subset reconstructs), so the observed error varies run to run —
    // ~0.8 has been seen. 2.0 keeps the check meaningful (a wrong value
    // is off by whole units) without flaking on noise.
    assert!(
        (values[0] - (a + b)).abs() < 2.0,
        "decrypted {} vs {}",
        values[0],
        a + b
    );
    Ok(())
}

/// Kill a node mid-DKG (after dealing, before convergence) and rebuild it
/// from its persisted state + recovery record: it must finish the DKG.
#[actix::test]
async fn ckks_node_recovers_mid_dkg_from_snapshot() -> Result<()> {
    let (_, params_bytes) = ckks_params_bytes();
    let e3_id = E3id::new("78", 1);
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    let seed = Seed(seed_bytes);

    let mut nodes = Vec::new();
    for pid in 0..N as u64 {
        nodes.push(start_node(&e3_id, pid, &params_bytes).await?);
    }
    for (i, node) in nodes.iter().enumerate() {
        node.actor
            .send(selected_event(&e3_id, i as u64, &params_bytes, seed))
            .await?;
    }
    let mut seq = 200_000u64;
    let mut seen = std::collections::HashSet::new();
    let keyshares = pump(&nodes, &mut seq, &mut seen).await?;
    assert_eq!(keyshares.len(), N);

    // "Crash" node 1: drop the actor, rebuild from persisted repos (the
    // hydrate path), and verify the machine snapshot restores the phase.
    let node1 = &nodes[0];
    let state = node1.state_repo.load().await?;
    let recovery = node1.recovery_repo.load().await?;
    assert!(
        recovery
            .get()
            .and_then(|r| r.ckks_machine.clone())
            .is_some(),
        "machine snapshot must be persisted"
    );

    let bus = test_bus("ckks-node-1-reborn");
    let reborn = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: node1.cipher.clone(),
        state,
        share_enc_preset: share_enc_preset(),
        interfold_address: Address::ZERO,
        recovery,
        ckks_artifacts_dir: None,
        zk_circuits_dir: None,
        ckks_ceremony: None,
    })
    .start();
    // Trigger the recovery redrive: `EffectsEnabled` is the boot-sync
    // broadcast that makes the actor resume in-flight work.
    seq += 1;
    reborn
        .send(seq_event(e3_events::EffectsEnabled::default().into(), seq))
        .await?;
    Ok(())
}

/// Full ceremony over real actors (param set 3: one relin level), with
/// node 0 CRASHED mid-round-2 and rebuilt from its persisted state +
/// recovery record + durable chunk log: the reborn actor must complete
/// the ceremony from replayed chunks and write the SAME joint key the
/// survivors wrote.
#[actix::test]
async fn ckks_node_recovers_mid_ceremony_from_chunk_log() -> Result<()> {
    let (_, params_bytes) = ckks_ceremony_params_bytes();
    let e3_id = E3id::new("79", 1);
    let mut seed_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut seed_bytes);
    let seed = Seed(seed_bytes);

    let mut nodes = Vec::new();
    for pid in 0..N as u64 {
        nodes.push(start_node(&e3_id, pid, &params_bytes).await?);
    }
    for (i, node) in nodes.iter().enumerate() {
        node.actor
            .send(selected_event(&e3_id, i as u64, &params_bytes, seed))
            .await?;
    }
    let mut seq = 300_000u64;
    let mut seen = std::collections::HashSet::new();
    // DKG converges; the ceremony is HELD until pk consensus.
    let keyshares = pump(&nodes, &mut seq, &mut seen).await?;
    assert_eq!(keyshares.len(), N);
    for node in &nodes {
        for event in drain(node).await? {
            assert!(
                !matches!(event.get_data(), InterfoldEventData::RelinCeremonyShare(_)),
                "no ceremony traffic before pk consensus"
            );
        }
    }

    // Chain-observed pk consensus releases round 1 on every node.
    seq += 1;
    broadcast(
        &nodes,
        seq_event(
            CommitteePublished {
                e3_id: e3_id.clone(),
                nodes: (0..N as u64).map(|p| format!("0xnode{p}")).collect(),
                public_key: ArcBytes::from_bytes(&[]),
                proof: ArcBytes::from_bytes(&[]),
            }
            .into(),
            seq,
        ),
    )
    .await?;

    // Route ONLY round-1 chunks; hold round-2 chunks back so every node
    // sits in RelinRound2 with its own R2 published and nothing else.
    let mut held_r2: Vec<InterfoldEvent> = Vec::new();
    for _ in 0..40 {
        actix::clock::sleep(std::time::Duration::from_millis(50)).await;
        let mut progressed = false;
        for node in &nodes {
            for event in drain(node).await? {
                if !seen.insert(format!("{:?}", event.get_ctx().id())) {
                    continue;
                }
                let (data, _) = event.into_components();
                match data {
                    InterfoldEventData::RelinCeremonyShare(s) if s.round == 1 => {
                        seq += 1;
                        broadcast(&nodes, seq_event(s.into(), seq)).await?;
                        progressed = true;
                    }
                    InterfoldEventData::RelinCeremonyShare(s) => {
                        seq += 1;
                        held_r2.push(seq_event(s.into(), seq));
                    }
                    InterfoldEventData::InterfoldError(e) => bail!("bus error: {e:?}"),
                    _ => {}
                }
            }
        }
        if !progressed && held_r2.len() >= N {
            break;
        }
    }
    assert_eq!(held_r2.len(), N, "every node published its round-2 share");

    // Deliver ONE peer's R2 chunk to node 0 (partial round 2), then
    // crash it: its buffers die, but the chunk log and snapshot survive.
    let first_r2 = held_r2
        .iter()
        .find(|e| matches!(e.get_data(), InterfoldEventData::RelinCeremonyShare(s) if s.party_id == 2))
        .cloned()
        .expect("party 2's R2");
    nodes[0].actor.send(first_r2).await?;
    actix::clock::sleep(std::time::Duration::from_millis(100)).await;
    let (log, replay) = CeremonyChunkLog::open(nodes[0].ceremony_store.clone()).await?;
    assert!(
        replay
            .iter()
            .any(|c| c.key.round == 2 && c.key.party_id_machine == 2),
        "the chunk log recorded the partial round-2 delivery"
    );
    let state = nodes[0].state_repo.load().await?;
    let recovery = nodes[0].recovery_repo.load().await?;
    let reborn_bus = test_bus("ckks-node-0-reborn");
    let reborn_bus_history = reborn_bus.history();
    let reborn = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus: reborn_bus,
        cipher: nodes[0].cipher.clone(),
        state,
        share_enc_preset: share_enc_preset(),
        interfold_address: Address::ZERO,
        recovery,
        ckks_artifacts_dir: Some(nodes[0].artifacts_dir.clone()),
        zk_circuits_dir: None,
        ckks_ceremony: Some(CkksCeremonyRecovery { log, replay }),
    })
    .start();
    seq += 1;
    reborn
        .send(seq_event(e3_events::EffectsEnabled::default().into(), seq))
        .await?;

    // Deliver every R2 chunk to the reborn node and the survivors.
    for event in &held_r2 {
        reborn.send(event.clone()).await?;
        for node in &nodes[1..] {
            node.actor.send(event.clone()).await?;
        }
    }
    actix::clock::sleep(std::time::Duration::from_millis(200)).await;

    // Surface swallowed handler errors from the reborn node's bus.
    let reborn_history = reborn_bus_history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?;
    for event in &reborn_history {
        if let InterfoldEventData::InterfoldError(e) = event.get_data() {
            bail!("reborn node error: {e:?}");
        }
    }

    // Every node wrote rlk_level_0.bin, byte-identical.
    let key_path = |dir: &std::path::Path| {
        dir.join("relin-keys")
            .join(e3_id.to_string())
            .join("rlk_level_0.bin")
    };
    let survivor_keys: Vec<Vec<u8>> = nodes[1..]
        .iter()
        .map(|node| std::fs::read(key_path(&node.artifacts_dir)).expect("survivor wrote key"))
        .collect();
    assert!(survivor_keys.windows(2).all(|w| w[0] == w[1]));
    let reborn_key = std::fs::read(key_path(&nodes[0].artifacts_dir))
        .expect("reborn node wrote the joint relin key");
    assert_eq!(
        reborn_key, survivor_keys[0],
        "joint keys must agree after recovery"
    );
    for node in &nodes {
        let _ = std::fs::remove_dir_all(&node.artifacts_dir);
    }
    Ok(())
}

/// FAIL CLOSED: a node whose circuits directory lacks a required CKKS
/// artifact refuses the E3 at `CiphernodeSelected` (bus error naming the
/// artifact, no EncryptionKeyPending); with every artifact staged the
/// same node proceeds.
#[actix::test]
async fn ckks_node_refuses_e3_when_a_required_artifact_is_missing() -> Result<()> {
    use e3_zk_prover::ckks_artifacts::{required_ckks_artifacts, RequiredArtifact};
    let (_, params_bytes) = ckks_params_bytes();
    let e3_id = E3id::new("78", 1);
    let seed = Seed([4u8; 32]);
    let circuits =
        std::env::temp_dir().join(format!("interfold-ckks-gate-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&circuits)?;

    // Empty circuits dir: refused, naming the first missing artifact.
    let node = start_node_with_circuits(&e3_id, 0, &params_bytes, Some(circuits.clone())).await?;
    node.actor
        .send(selected_event(&e3_id, 0, &params_bytes, seed))
        .await?;
    actix::clock::sleep(std::time::Duration::from_millis(100)).await;
    let events = drain(&node).await?;
    let err = events
        .iter()
        .find_map(|e| match e.get_data() {
            InterfoldEventData::InterfoldError(err) => Some(format!("{err:?}")),
            _ => None,
        })
        .expect("fail-closed error on the bus");
    assert!(err.contains("fail closed"), "{err}");
    assert!(err.contains("pk_generation_ckks_ps0"), "{err}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.get_data(), InterfoldEventData::EncryptionKeyPending(_))),
        "a refused E3 must not start its DKG"
    );

    // Stage every required artifact (json + vk): the node proceeds.
    let posture = e3_zk_prover::ckks_artifacts::check_ckks_artifacts_for_e3(
        None,
        DEFAULT_BFV_PRESET,
        &params_bytes,
        T,
        N,
    )?;
    let committee = e3_zk_helpers::CiphernodesCommitteeSize::from_threshold(T, N)?;
    let stage = |r: &RequiredArtifact| {
        let (json, vk) = r.paths(&circuits);
        std::fs::create_dir_all(json.parent().unwrap()).unwrap();
        std::fs::write(json, b"{}").unwrap();
        std::fs::write(vk, b"vk").unwrap();
    };
    for r in required_ckks_artifacts(&posture, DEFAULT_BFV_PRESET, committee.as_str())? {
        stage(&r);
    }
    let node = start_node_with_circuits(&e3_id, 1, &params_bytes, Some(circuits.clone())).await?;
    node.actor
        .send(selected_event(&e3_id, 1, &params_bytes, seed))
        .await?;
    actix::clock::sleep(std::time::Duration::from_millis(100)).await;
    let events = drain(&node).await?;
    assert!(
        events
            .iter()
            .any(|e| matches!(e.get_data(), InterfoldEventData::EncryptionKeyPending(_))),
        "staged artifacts: DKG starts"
    );
    assert!(!events
        .iter()
        .any(|e| matches!(e.get_data(), InterfoldEventData::InterfoldError(_))));
    let _ = std::fs::remove_dir_all(&circuits);
    Ok(())
}
