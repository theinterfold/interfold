// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::actors::ZkActor;
use crate::{PkCircuit, Provable, ZkBackend, ZkProver};
use e3_config::BBPath;
use e3_events::{E3RequestComplete, HistoryCollector};
use e3_slashing::AccusationManager;
use e3_zk_helpers::circuits::dkg::pk::circuit::PkCircuitData;
use std::fs;
use std::path::PathBuf;

#[path = "restart_tests.rs"]
mod restart;

#[derive(Message)]
#[rtype(result = "()")]
pub(super) struct VerificationBarrier;

macro_rules! verification_barrier {
    ($actor:ty) => {
        impl Handler<VerificationBarrier> for $actor {
            type Result = ();

            fn handle(&mut self, _: VerificationBarrier, _: &mut Self::Context) {}
        }
    };
}

verification_barrier!(ZkActor);
verification_barrier!(ProofVerificationActor);
verification_barrier!(AccusationManager);

struct VerificationHarness {
    bus: BusHandle,
    verifier: Addr<ZkActor>,
    actor: Addr<ProofVerificationActor>,
    accusations: Addr<AccusationManager>,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    party_id: u64,
}

impl VerificationHarness {
    async fn new(backend: &ZkBackend, e3_id: &E3id, signer: &PrivateKeySigner) -> Self {
        let bus = test_bus();
        let history = bus.history();
        let verifier = ZkActor::new(backend).start();
        let observer = PrivateKeySigner::random();
        let mut committee = vec![
            signer.address(),
            observer.address(),
            PrivateKeySigner::random().address(),
        ];
        committee.sort();
        let party_id = committee
            .iter()
            .position(|member| *member == signer.address())
            .unwrap() as u64;
        let actor = ProofVerificationActor::setup(
            &bus,
            verifier.clone().recipient(),
            HashMap::from([(
                e3_id.clone(),
                Committee::new(committee.iter().map(ToString::to_string).collect()),
            )]),
            HashMap::from([(
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
        );
        let accusations = AccusationManager::setup(
            &bus,
            e3_id.clone(),
            observer,
            Address::repeat_byte(9),
            committee,
            1,
            300,
            30,
            BfvPreset::InsecureThreshold512,
        );
        bus.event_bus().send(EventBusBarrier).await.unwrap();
        bus.publish_without_context(EffectsEnabled::new()).unwrap();
        bus.flush_event_pipeline().await.unwrap();
        history.send(e3_events::ResetHistory).await.unwrap();
        Self {
            bus,
            verifier,
            actor,
            accusations,
            history,
            party_id,
        }
    }

    async fn submit(
        &self,
        e3_id: &E3id,
        signer: &PrivateKeySigner,
        pk: &[u8],
        proof: &Proof,
    ) -> Arc<EncryptionKey> {
        let signed_payload = SignedProofPayload::sign(
            ProofPayload {
                e3_id: e3_id.clone(),
                proof_type: ProofType::C0PkBfv,
                proof: proof.clone(),
            },
            signer,
        )
        .unwrap();
        let key = Arc::new(
            EncryptionKey::new(self.party_id, ArcBytes::from_bytes(pk))
                .with_proof(proof.clone())
                .with_signed_payload(signed_payload),
        );
        let data = EncryptionKeyReceived {
            e3_id: e3_id.clone(),
            key: key.clone(),
        };
        let ec =
            EventContext::<Unsequenced>::from(InterfoldEventData::from(data.clone())).sequence(0);
        self.actor.send(TypedEvent::new(data, ec)).await.unwrap();
        key
    }

    async fn events(&self) -> Vec<InterfoldEventData> {
        self.verifier.send(VerificationBarrier).await.unwrap();
        self.actor.send(VerificationBarrier).await.unwrap();
        self.bus.flush_event_pipeline().await.unwrap();
        self.accusations.send(VerificationBarrier).await.unwrap();
        self.bus.flush_event_pipeline().await.unwrap();
        self.history
            .send(GetEvents::new())
            .await
            .unwrap()
            .into_iter()
            .map(|event| event.into_components().0)
            .collect()
    }

    async fn complete(&self, e3_id: &E3id) {
        self.bus
            .publish_without_context(E3RequestComplete {
                e3_id: e3_id.clone(),
            })
            .unwrap();
        self.bus.flush_event_pipeline().await.unwrap();
        self.actor.send(VerificationBarrier).await.unwrap();
    }
}

fn assert_no_blame(events: &[InterfoldEventData]) {
    assert!(
        events.iter().all(|event| !matches!(
            event,
            InterfoldEventData::SignedProofFailed(_)
                | InterfoldEventData::ProofVerificationFailed(_)
                | InterfoldEventData::ProofFailureAccusation(_)
                | InterfoldEventData::AccusationVote(_)
                | InterfoldEventData::AccusationQuorumReached(_)
        )),
        "local verification failure produced peer-failure evidence"
    );
}

#[actix::test]
async fn c0_local_verifier_failures_retry_without_peer_blame() {
    let artifacts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/bin/dkg/target");
    let Some(bb) = e3_test_helpers::find_bb().await else {
        eprintln!("skipping C0 recovery test: bb is not installed");
        return;
    };
    if !artifacts.join("pk.json").exists() || !artifacts.join("pk.vk_noir").exists() {
        eprintln!("skipping C0 recovery test: compiled C0 artifacts are unavailable");
        return;
    }
    let temp = crate::test_utils::get_tempdir().unwrap();
    let backend = ZkBackend::new(
        BBPath::Default(temp.path().join("bb")),
        temp.path().join("circuits"),
        temp.path().join("work"),
    );
    fs::copy(bb, &backend.bb_binary).unwrap();
    let preset = BfvPreset::InsecureThreshold512;
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());
    let circuit_dir = backend
        .circuits_dir
        .join(&artifacts_dir)
        .join("recursive/dkg/pk");
    fs::create_dir_all(&circuit_dir).unwrap();
    fs::copy(artifacts.join("pk.json"), circuit_dir.join("pk.json")).unwrap();
    let vk = circuit_dir.join("pk.vk");
    fs::copy(artifacts.join("pk.vk_noir"), &vk).unwrap();
    let sample = PkCircuitData::generate_sample(preset).unwrap();
    let pk = sample.public_key.to_bytes();
    let prover = ZkProver::new(&backend);
    let proof = PkCircuit
        .prove(&prover, &preset, &sample, "c0-recovery", &artifacts_dir)
        .unwrap();
    let signer = PrivateKeySigner::random();

    restart::check_c0_restart(&backend, &vk, &signer, &pk, &proof).await;

    for (index, unavailable) in [&backend.bb_binary, &vk, &backend.work_dir]
        .into_iter()
        .enumerate()
    {
        let e3_id = E3id::new((index + 1).to_string(), 31_337);
        let harness = VerificationHarness::new(&backend, &e3_id, &signer).await;
        let saved = unavailable.with_extension("saved");
        fs::rename(unavailable, &saved).unwrap();
        if unavailable == &backend.work_dir {
            fs::write(unavailable, b"not a directory").unwrap();
        }
        let key = harness.submit(&e3_id, &signer, &pk, &proof).await;
        let events = harness.events().await;
        assert_no_blame(&events);
        assert!(events.is_empty(), "unverified key was accepted");
        if unavailable == &backend.work_dir {
            fs::remove_file(unavailable).unwrap();
        }
        fs::rename(saved, unavailable).unwrap();

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let events = harness.events().await;
                assert_no_blame(&events);
                if events.iter().any(|event| matches!(event, InterfoldEventData::ProofVerificationPassed(_))) {
                    assert!(events.iter().any(|event| matches!(event,
                        InterfoldEventData::EncryptionKeyCreated(created) if created.key == key && created.external
                    )), "recovery must accept the original key");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.expect("C0 input was not retried after local verification recovered");
        harness.complete(&e3_id).await;
    }

    let other_sample = PkCircuitData::generate_sample(preset).unwrap();
    let other_pk = other_sample.public_key.to_bytes();
    let commitment = compute_dkg_pk_commitment_from_public_key_bytes(&other_pk, preset).unwrap();
    let invalid_proof = Proof::new(
        proof.circuit,
        proof.data.clone(),
        ArcBytes::from_bytes(&commitment),
    );
    let e3_id = E3id::new("4", 31_337);
    let harness = VerificationHarness::new(&backend, &e3_id, &signer).await;
    harness
        .submit(&e3_id, &signer, &other_pk, &invalid_proof)
        .await;
    let events = harness.events().await;
    assert!(events.iter().any(|event| matches!(event, InterfoldEventData::SignedProofFailed(failure) if failure.faulting_node == signer.address())));
    assert!(events.iter().any(|event| matches!(event, InterfoldEventData::ProofVerificationFailed(failure) if failure.accused_address == signer.address())));
    assert!(events.iter().any(|event| matches!(event, InterfoldEventData::ProofFailureAccusation(accusation) if accusation.accused == signer.address())));
    assert!(!events.iter().any(|event| matches!(
        event,
        InterfoldEventData::EncryptionKeyCreated(_)
            | InterfoldEventData::ProofVerificationPassed(_)
    )));
    harness.complete(&e3_id).await;

    let e3_id = E3id::new("5", 31_337);
    let harness = VerificationHarness::new(&backend, &e3_id, &signer).await;
    let saved = vk.with_extension("saved");
    fs::rename(&vk, &saved).unwrap();
    harness.submit(&e3_id, &signer, &pk, &proof).await;
    assert!(harness.events().await.is_empty());
    harness.complete(&e3_id).await;
    fs::rename(saved, &vk).unwrap();
    tokio::time::sleep(VERIFICATION_RETRY_DELAY + Duration::from_millis(100)).await;
    let events = harness.events().await;
    assert_no_blame(&events);
    assert!(
        events
            .iter()
            .all(|event| matches!(event, InterfoldEventData::E3RequestComplete(_))),
        "completed E3 resumed C0 verification"
    );
}
