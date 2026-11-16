// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use actix::{Actor, Context, Handler};
use alloy::signers::local::PrivateKeySigner;
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    hlc_factory::HlcFactory, ComputeRequestErrorKind, ComputeRequestKind, EffectsEnabled, Event,
    EventBus, EventBusBarrier, EventBusConfig, EventPublisher, GetEvents, Proof, ProofPayload,
    Sequencer, StoreEventRequested, Unsequenced, ZkError,
};
use e3_fhe_params::BfvProfile;
use e3_utils::utility_types::ArcBytes;
use std::{collections::BTreeSet, time::Duration};

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
        let seq = self.next_seq;
        self.next_seq += 1;
        let (sender, response) = msg.into_stored(seq);
        sender.do_send(response);
    }
}

fn test_bus() -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
    let store = TestEventStore::default().start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("share-recovery-test")
}

fn signed_c6(signer: &PrivateKeySigner, e3_id: &E3id, marker: u8) -> SignedProofPayload {
    let proof_type = ProofType::C6ThresholdShareDecryption;
    let proof = Proof::new(
        proof_type.circuit_names()[0],
        ArcBytes::from_bytes(&[marker, 2, 3]),
        ArcBytes::from_bytes(&[4, 5, marker]),
    );
    SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof,
        },
        signer,
    )
    .expect("sign C6 test proof")
}

#[actix::test]
async fn disabled_profile_does_not_dispatch_or_classify_a_verification_batch() {
    let e3_event_system::test_support::EventFixture { bus, history, .. } =
        e3_event_system::test_support::EventFixture::new().unwrap();
    let mut actor = ShareVerificationActor::new(&bus, HashMap::new());
    let e3_id = E3id::new("disabled-profile", 1);
    let mut expected_errors = Vec::new();
    for kind in [
        VerificationKind::ShareProofs,
        VerificationKind::DecryptionProofs,
        VerificationKind::PkGenerationProofs,
        VerificationKind::ThresholdDecryptionProofs,
    ] {
        expected_errors.push(format!(
            "Skipping {kind:?} verification for E3 {e3_id}: BFV profile sync-insecure-64 is disabled in this release"
        ));
        let dispatch = ShareVerificationDispatched {
            e3_id: e3_id.clone(),
            kind,
            share_proofs: Vec::new(),
            decryption_proofs: Vec::new(),
            pre_dishonest: BTreeSet::from([0]),
            params_profile: BfvProfile::SyncDecInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let ec = EventContext::<Unsequenced>::from(InterfoldEventData::from(dispatch.clone()))
            .sequence(0);
        actor.handle_share_verification_dispatched(TypedEvent::new(dispatch, ec));
        bus.flush_event_pipeline().await.unwrap();
        assert!(actor.pending_consistency.is_empty());
        assert!(actor.pending.is_empty());
    }
    // Each refused batch is reported once as a local fault and publishes nothing else.
    let errors: Vec<_> = history
        .send(GetEvents::<InterfoldEvent>::new())
        .await
        .unwrap()
        .into_iter()
        .map(|event| match event.into_data() {
            InterfoldEventData::InterfoldError(error) => error.message,
            other => panic!("a disabled profile published {other:?}"),
        })
        .collect();
    assert_eq!(errors, expected_errors);
}

#[actix::test]
async fn local_verifier_error_preserves_pending_work_without_accusing_parties() {
    let bus = test_bus();
    let history = bus.history();
    let e3_id = E3id::new("worker-recovery", 1);
    let correlation_id = CorrelationId::new();
    let context_data: InterfoldEventData = EffectsEnabled::new().into();
    let context = EventContext::<Unsequenced>::from(context_data).sequence(0);
    let mut actor = ShareVerificationActor::new(&bus, HashMap::new());
    actor.pending.insert(
        correlation_id,
        PendingVerification {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ShareProofs,
            ec: context.clone(),
            ecdsa_dishonest: HashSet::new(),
            pre_dishonest: BTreeSet::new(),
            dispatched_party_ids: HashSet::from([0]),
            party_addresses: HashMap::new(),
            party_proof_hashes: HashMap::new(),
            party_public_signals: HashMap::new(),
            party_proof_data: HashMap::new(),
            params_profile: BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        },
    );
    let request = ComputeRequest::zk(
        ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
            party_proofs: Vec::new(),
            params_profile: BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        }),
        correlation_id,
        e3_id,
    );

    actor.handle_compute_request_error(TypedEvent::new(
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("oom".to_owned())),
            request,
        ),
        context,
    ));

    actix::clock::sleep(Duration::from_millis(20)).await;
    assert!(actor.pending.contains_key(&correlation_id));
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await
        .expect("read history")
        .is_empty());
}

#[actix::test]
async fn restored_committee_authorizes_c6_without_replayed_finalization_event() {
    let bus = test_bus();
    let e3_id = E3id::new("0", 31_337);
    let profile = BfvProfile::SsSecure8192;
    let signers = [
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
    ];
    let committee = Committee::new(
        signers
            .iter()
            .map(|signer| signer.address().to_string())
            .collect(),
    );
    ShareVerificationActor::setup(&bus, HashMap::from([(e3_id.clone(), committee)]));

    // Register the observer and fence the EventBus before dispatching. No
    // CommitteeFinalized event is published: this models restart after that event was
    // incorporated into the durable snapshot and excluded from the replay range.
    let consistency_requested = bus.wait_for(EventType::CommitmentConsistencyCheckRequested);
    bus.event_bus()
        .send(EventBusBarrier)
        .await
        .expect("event bus barrier");

    bus.publish_without_context(ShareVerificationDispatched {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ThresholdDecryptionProofs,
        share_proofs: signers[..2]
            .iter()
            .enumerate()
            .map(|(party_id, signer)| e3_events::PartyProofsToVerify {
                sender_party_id: party_id as u64,
                signed_proofs: vec![signed_c6(signer, &e3_id, party_id as u8)],
            })
            .collect(),
        decryption_proofs: Vec::new(),
        pre_dishonest: BTreeSet::new(),
        params_profile: profile,
        committee_size: CiphernodesCommitteeSize::Minimum,
    })
    .expect("publish C6 verification dispatch");

    let event = tokio::time::timeout(Duration::from_secs(2), consistency_requested)
        .await
        .expect("restored committee did not authorize C6 before timeout")
        .expect("wait for consistency request");
    let ec = event.get_ctx().clone();
    let InterfoldEventData::CommitmentConsistencyCheckRequested(request) = event.into_data() else {
        panic!("unexpected event type")
    };
    assert_eq!(request.e3_id, e3_id);
    assert_eq!(request.party_proofs.len(), 2);
    let verification_requested = bus.wait_for(EventType::ComputeRequest);
    bus.event_bus().send(EventBusBarrier).await.unwrap();
    bus.publish(
        CommitmentConsistencyCheckComplete {
            e3_id: e3_id.clone(),
            kind: request.kind,
            correlation_id: request.correlation_id,
            inconsistent_parties: BTreeSet::new(),
        },
        ec,
    )
    .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(2), verification_requested)
        .await
        .unwrap()
        .unwrap();
    let InterfoldEventData::ComputeRequest(request) = event.into_data() else {
        panic!("expected ZK verification request");
    };
    let ComputeRequestKind::Zk(ZkRequest::VerifyShareProofs(request)) = request.request else {
        panic!("expected C6 batch verification");
    };
    assert_eq!(request.params_profile, profile);
    assert_eq!(request.party_proofs.len(), 2);
}

#[actix::test]
async fn unauthenticated_share_proofs_do_not_emit_accusations() {
    for forgery in [
        "first signature",
        "later signature",
        "wrong signer",
        "wrong E3",
        "circuit",
    ] {
        let bus = test_bus();
        let history = bus.history();
        bus.event_bus().send(EventBusBarrier).await.unwrap();
        let e3_id = E3id::new("92", 1);
        let dealer = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let third = PrivateKeySigner::random();
        let mut actor = ShareVerificationActor::new(
            &bus,
            HashMap::from([(
                e3_id.clone(),
                Committee::new(vec![
                    dealer.address().to_string(),
                    other.address().to_string(),
                    third.address().to_string(),
                ]),
            )]),
        );
        let make = |proof_type| {
            let mut proof = signed_c6(&dealer, &e3_id, 1).payload;
            proof.proof_type = proof_type;
            proof.proof.circuit = e3_zk_config::CircuitName::DkgShareDecryption;
            SignedProofPayload::sign(proof, &dealer).unwrap()
        };
        let good = e3_events::PartyShareDecryptionProofsToVerify {
            sender_party_id: 0,
            signed_sk_decryption_proof: make(ProofType::C4aSkShareDecryption),
            signed_e_sm_decryption_proofs: vec![make(ProofType::C4bESmShareDecryption)],
        };
        let mut bad = good.clone();
        match forgery {
            "first signature" => {
                bad.signed_sk_decryption_proof.signature = ArcBytes::from_bytes(&[0; 65])
            }
            "later signature" => {
                bad.signed_e_sm_decryption_proofs[0].signature = ArcBytes::from_bytes(&[0; 65])
            }
            "wrong signer" => {
                bad.signed_sk_decryption_proof =
                    SignedProofPayload::sign(bad.signed_sk_decryption_proof.payload, &other)
                        .unwrap()
            }
            "wrong E3" => {
                bad.signed_sk_decryption_proof.payload.e3_id = E3id::new("93", 1);
                bad.signed_sk_decryption_proof =
                    SignedProofPayload::sign(bad.signed_sk_decryption_proof.payload, &dealer)
                        .unwrap();
            }
            "circuit" => {
                bad.signed_sk_decryption_proof.payload.proof.circuit =
                    e3_zk_config::CircuitName::PkBfv
            }
            _ => unreachable!(),
        }
        let dispatch = |proof| ShareVerificationDispatched {
            e3_id: e3_id.clone(),
            kind: VerificationKind::DecryptionProofs,
            share_proofs: Vec::new(),
            decryption_proofs: vec![proof],
            pre_dishonest: BTreeSet::new(),
            params_profile: BfvProfile::SsInsecure64,
            committee_size: CiphernodesCommitteeSize::Minimum,
        };
        let ec = EventContext::<Unsequenced>::from(InterfoldEventData::from(dispatch(bad.clone())))
            .sequence(0);
        actor.handle_share_verification_dispatched(TypedEvent::new(dispatch(bad), ec.clone()));
        let events = history
            .send(e3_events::TakeEvents::<InterfoldEvent>::new(1))
            .await
            .unwrap();
        assert!(!events.timed_out);
        assert!(
            matches!(events.events[0].get_data(), InterfoldEventData::ShareVerificationComplete(result)
            if result.dishonest_parties == BTreeSet::from([0])),
            "{forgery} emitted fault evidence"
        );
        actor.handle_share_verification_dispatched(TypedEvent::new(dispatch(good), ec));
        assert_eq!(
            actor.pending_consistency.len(),
            1,
            "genuine bundle did not reach verification"
        );
    }
}

#[actix::test]
async fn failed_worker_payload_cannot_borrow_a_verified_signer() {
    let bus = test_bus();
    let history = bus.history();
    bus.event_bus().send(EventBusBarrier).await.unwrap();
    let e3_id = E3id::new("94", 1);
    let dealer = PrivateKeySigner::random();
    let others = [PrivateKeySigner::random(), PrivateKeySigner::random()];
    let mut actor = ShareVerificationActor::new(
        &bus,
        HashMap::from([(
            e3_id.clone(),
            Committee::new(vec![
                dealer.address().to_string(),
                others[0].address().to_string(),
                others[1].address().to_string(),
            ]),
        )]),
    );
    let good = signed_c6(&dealer, &e3_id, 1);
    let dispatch = ShareVerificationDispatched {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ThresholdDecryptionProofs,
        share_proofs: vec![e3_events::PartyProofsToVerify {
            sender_party_id: 0,
            signed_proofs: vec![good.clone()],
        }],
        decryption_proofs: Vec::new(),
        pre_dishonest: BTreeSet::new(),
        params_profile: BfvProfile::SsInsecure64,
        committee_size: CiphernodesCommitteeSize::Minimum,
    };
    let ec =
        EventContext::<Unsequenced>::from(InterfoldEventData::from(dispatch.clone())).sequence(0);
    actor.handle_share_verification_dispatched(TypedEvent::new(dispatch, ec.clone()));
    let consistency_id = *actor.pending_consistency.keys().next().unwrap();
    actor.handle_consistency_check_complete(TypedEvent::new(
        CommitmentConsistencyCheckComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ThresholdDecryptionProofs,
            correlation_id: consistency_id,
            inconsistent_parties: BTreeSet::new(),
        },
        ec.clone(),
    ));
    let correlation_id = *actor.pending.keys().next().unwrap();
    let mut bad = good;
    bad.signature = ArcBytes::from_bytes(&[0; 65]);
    actor.handle_compute_response(TypedEvent::new(
        ComputeResponse::zk(
            ZkResponse::VerifyShareProofs(e3_events::VerifyShareProofsResponse {
                party_results: vec![PartyVerificationResult {
                    sender_party_id: 0,
                    all_verified: false,
                    failed_signed_payload: Some(bad),
                    recovered_address: Some(dealer.address()),
                }],
            }),
            correlation_id,
            e3_id,
        ),
        ec,
    ));
    let events = history
        .send(e3_events::TakeEvents::<InterfoldEvent>::new(3))
        .await
        .unwrap();
    assert!(!events.timed_out);
    assert!(
        events.events.iter().all(|event| !matches!(
            event.get_data(),
            InterfoldEventData::SignedProofFailed(_)
                | InterfoldEventData::ProofVerificationFailed(_)
        )),
        "an unauthenticated worker payload borrowed the cached signer"
    );
    assert!(events.events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::ShareVerificationComplete(_)
    )));
}
