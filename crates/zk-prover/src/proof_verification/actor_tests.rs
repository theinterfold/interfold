// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use actix::{Actor, Context, Handler};
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    hlc_factory::HlcFactory, E3RequestComplete, EffectsEnabled, EventBus, EventBusBarrier,
    EventBusConfig, EventPublisher, FlushEventStores, GetEvents, ProofPayload, Seed, Sequencer,
    StoreEventRequested, StoreEventResponse, Unsequenced,
};
use e3_fhe_params::build_pair_for_preset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::compute_dkg_pk_commitment_from_public_key_bytes;
use fhe::bfv::{PublicKey, SecretKey};
use fhe_traits::Serialize;
use tokio::sync::mpsc;

#[derive(Default)]
struct TestEventStore {
    next_seq: u64,
}

impl Actor for TestEventStore {
    type Context = Context<Self>;
}

impl Handler<StoreEventRequested> for TestEventStore {
    type Result = ();

    fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) {
        let StoreEventRequested { event, sender } = msg;
        let seq = self.next_seq;
        self.next_seq += 1;
        sender
            .try_send(StoreEventResponse(event.into_sequenced(seq)))
            .unwrap();
    }
}

impl Handler<FlushEventStores> for TestEventStore {
    type Result = anyhow::Result<()>;

    fn handle(&mut self, _: FlushEventStores, _: &mut Self::Context) -> Self::Result {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedVerification {
    e3_id: E3id,
    party_id: u64,
    artifacts_dir: String,
}

struct VerificationRecorder {
    sender: mpsc::UnboundedSender<ObservedVerification>,
}

impl Actor for VerificationRecorder {
    type Context = Context<Self>;
}

impl Handler<TypedEvent<ZkVerificationRequest>> for VerificationRecorder {
    type Result = ();

    fn handle(&mut self, request: TypedEvent<ZkVerificationRequest>, _: &mut Self::Context) {
        let (request, _) = request.into_components();
        let _ = self.sender.send(ObservedVerification {
            e3_id: request.e3_id,
            party_id: request.key.party_id,
            artifacts_dir: request.artifacts_dir,
        });
    }
}

fn test_bus() -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
    let store = TestEventStore::default().start();
    let sequencer =
        Sequencer::new_with_flush(&event_bus, store.clone().recipient(), store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("c0-recovery-test")
}

#[path = "recovery_tests.rs"]
mod recovery;

fn signed_c0_key(
    signer: &PrivateKeySigner,
    party_id: u64,
    e3_id: &E3id,
    preset: BfvPreset,
) -> Arc<EncryptionKey> {
    let (_, dkg_params) = build_pair_for_preset(preset).expect("build BFV test parameters");
    let mut rng = rand::rng();
    let secret_key = SecretKey::random(&dkg_params, &mut rng);
    let public_key = PublicKey::new(&secret_key, &mut rng);
    let public_key_bytes = public_key.to_bytes();
    let commitment = compute_dkg_pk_commitment_from_public_key_bytes(&public_key_bytes, preset)
        .expect("compute C0 key commitment");
    let proof = Proof::new(
        ProofType::C0PkBfv.circuit_names()[0],
        ArcBytes::from_bytes(&[1, 2, 3]),
        ArcBytes::from_bytes(&commitment),
    );
    let signed = SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C0PkBfv,
            proof: proof.clone(),
        },
        signer,
    )
    .expect("sign C0 test proof");

    Arc::new(
        EncryptionKey::new(party_id, ArcBytes::from_bytes(&public_key_bytes))
            .with_proof(proof)
            .with_signed_payload(signed),
    )
}

#[actix::test]
async fn restored_context_dispatches_c0_without_replayed_lifecycle_events() {
    let bus = test_bus();
    let e3_id = E3id::new("7", 31_337);
    let preset = BfvPreset::InsecureThreshold64;
    let signer = PrivateKeySigner::random();
    let mut committee_members = vec![
        signer.address().to_string(),
        PrivateKeySigner::random().address().to_string(),
        PrivateKeySigner::random().address().to_string(),
    ];
    committee_members.sort_by_key(|member| member.to_lowercase());
    let party_id = committee_members
        .iter()
        .position(|member| member.eq_ignore_ascii_case(&signer.address().to_string()))
        .expect("signer belongs to restored committee") as u64;

    let persisted_committees = HashMap::from([(e3_id.clone(), Committee::new(committee_members))]);
    let persisted_e3_metadata = HashMap::from([(
        e3_id.clone(),
        E3Meta {
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            params_preset: preset,
            params: ArcBytes::default(),
            error_size: ArcBytes::default(),
        },
    )]);
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let verifier = VerificationRecorder {
        sender: observed_tx,
    }
    .start();
    ProofVerificationActor::setup(
        &bus,
        verifier.recipient(),
        persisted_committees,
        persisted_e3_metadata,
    );

    // No CiphernodeSelected or CommitteeFinalized event is published: both are already
    // represented by durable snapshots and may be outside the post-snapshot replay range.
    bus.event_bus()
        .send(EventBusBarrier)
        .await
        .expect("event bus barrier");
    bus.publish_without_context(EffectsEnabled::new()).unwrap();
    bus.publish_without_context(EncryptionKeyReceived {
        e3_id: e3_id.clone(),
        key: signed_c0_key(&signer, party_id, &e3_id, preset),
    })
    .expect("publish external C0 key");

    let observed = tokio::time::timeout(std::time::Duration::from_secs(2), observed_rx.recv())
        .await
        .expect("restored C0 context did not dispatch verification before timeout")
        .expect("verification recorder stopped");
    assert_eq!(
        observed,
        ObservedVerification {
            e3_id,
            party_id,
            artifacts_dir: preset
                .artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str()),
        }
    );
}

struct UnavailableVerifier(mpsc::UnboundedSender<()>);

impl Actor for UnavailableVerifier {
    type Context = Context<Self>;
}

impl Handler<TypedEvent<ZkVerificationRequest>> for UnavailableVerifier {
    type Result = ();

    fn handle(&mut self, input: TypedEvent<ZkVerificationRequest>, _: &mut Self::Context) {
        let (request, ec) = input.into_components();
        request
            .sender
            .try_send(TypedEvent::new(
                ZkVerificationResponse {
                    e3_id: request.e3_id,
                    key: request.key,
                    outcome: ZkVerificationOutcome::InfrastructureError(
                        "verifier unavailable".into(),
                    ),
                },
                ec,
            ))
            .unwrap();
        self.0.send(()).unwrap();
    }
}

#[actix::test]
async fn c0_retries_back_off_and_stop_at_completion() {
    let bus = test_bus();
    let e3_id = E3id::new("9", 31_337);
    let signer = PrivateKeySigner::random();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let verifier = UnavailableVerifier(tx).start();
    let actor = ProofVerificationActor::setup(
        &bus,
        verifier.recipient(),
        HashMap::from([(
            e3_id.clone(),
            Committee::new(vec![signer.address().to_string()]),
        )]),
        HashMap::from([(
            e3_id.clone(),
            E3Meta {
                threshold_m: 1,
                threshold_n: 3,
                seed: Seed([0; 32]),
                params_preset: BfvPreset::InsecureThreshold64,
                params: ArcBytes::default(),
                error_size: ArcBytes::default(),
            },
        )]),
    );
    bus.event_bus().send(EventBusBarrier).await.unwrap();
    let input = EncryptionKeyReceived {
        e3_id: e3_id.clone(),
        key: signed_c0_key(&signer, 0, &e3_id, BfvPreset::InsecureThreshold64),
    };
    bus.publish_without_context(input).unwrap();
    bus.flush_event_pipeline().await.unwrap();
    assert!(
        rx.try_recv().is_err(),
        "verification ran before EffectsEnabled"
    );
    bus.publish_without_context(EffectsEnabled::new()).unwrap();
    bus.flush_event_pipeline().await.unwrap();
    rx.recv().await.unwrap();
    actor.send(recovery::VerificationBarrier).await.unwrap();
    tokio::time::pause();

    for delay in [5, 10, 20, 40, 60, 60] {
        tokio::time::advance(Duration::from_secs(delay - 1)).await;
        actor.send(recovery::VerificationBarrier).await.unwrap();
        assert!(
            rx.try_recv().is_err(),
            "C0 retried before the backoff elapsed"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("C0 did not retry when its capped backoff elapsed")
            .unwrap();
        actor.send(recovery::VerificationBarrier).await.unwrap();
    }
    bus.publish_without_context(E3RequestComplete { e3_id })
        .unwrap();
    bus.flush_event_pipeline().await.unwrap();
    tokio::time::advance(Duration::from_secs(120)).await;
    actor.send(recovery::VerificationBarrier).await.unwrap();
    assert!(rx.try_recv().is_err(), "completed E3 retried verification");
}

impl Handler<recovery::VerificationBarrier> for VerificationRecorder {
    type Result = ();

    fn handle(&mut self, _: recovery::VerificationBarrier, _: &mut Self::Context) {}
}

/// The replay after a restart can bring back the C0 input of an E3 that failed before startup,
/// and a peer can still send one later. Neither is verified; an active E3's input is.
#[actix::test]
async fn c0_inputs_of_an_e3_whose_dkg_ended_before_startup_are_not_verified() {
    use e3_data::RepositoriesFactory;
    let preset = BfvPreset::InsecureThreshold64;
    let signer = PrivateKeySigner::random();
    let (failed, active) = (E3id::new("7", 31_337), E3id::new("8", 31_337));
    let committee = Committee::new(vec![signer.address().to_string()]);
    let meta = E3Meta {
        threshold_m: 1,
        threshold_n: 3,
        seed: Seed([0; 32]),
        params_preset: preset,
        params: ArcBytes::default(),
        error_size: ArcBytes::default(),
    };
    let aggregate = e3_events::AggregateId::new(1);
    let system = e3_ciphernode_builder::EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(e3_events::AggregateConfig::new(HashMap::from([(
            aggregate,
            Duration::ZERO,
        )])));
    let mut recovery = crate::ZkActorRecovery::new(
        HashMap::from([
            (failed.clone(), committee.clone()),
            (active.clone(), committee),
        ]),
        HashMap::from([(failed.clone(), meta.clone()), (active.clone(), meta)]),
        HashMap::new(),
    );
    recovery
        .hydrate(
            &system.store().unwrap().repositories(),
            &HashMap::from([(failed.clone(), e3_events::E3Stage::Failed)]),
            &system.eventstore_reader().unwrap().seq(),
            &[aggregate],
        )
        .await
        .unwrap();
    let bus = test_bus();
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let verifier = VerificationRecorder {
        sender: observed_tx,
    }
    .start();
    let actor = recovery.setup_proof_verification(&bus, verifier.clone().recipient());
    bus.event_bus().send(EventBusBarrier).await.unwrap();

    // The replayed suffix holds an input of each E3, and effects begin after it.
    for e3_id in [&failed, &active] {
        bus.publish_without_context(EncryptionKeyReceived {
            e3_id: e3_id.clone(),
            key: signed_c0_key(&signer, 0, e3_id, preset),
        })
        .unwrap();
    }
    bus.publish_without_context(EffectsEnabled::new()).unwrap();
    bus.publish_without_context(EncryptionKeyReceived {
        e3_id: failed.clone(),
        key: signed_c0_key(&signer, 0, &failed, preset),
    })
    .unwrap();
    bus.flush_event_pipeline().await.unwrap();
    actor.send(recovery::VerificationBarrier).await.unwrap();
    verifier.send(recovery::VerificationBarrier).await.unwrap();

    let verified: Vec<_> = std::iter::from_fn(|| observed_rx.try_recv().ok())
        .map(|observed| observed.e3_id)
        .collect();
    assert_eq!(verified, [active]);
}
