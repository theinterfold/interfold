// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use actix::{Actor, Context, Handler};
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    hlc_factory::HlcFactory, ComputeRequestErrorKind, EffectsEnabled, Event, EventBus,
    EventBusBarrier, EventBusConfig, EventPublisher, GetEvents, Proof, ProofPayload, ProofType,
    Sequencer, StoreEventRequested, StoreEventResponse, Unsequenced, ZkError,
};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::CiphernodesCommitteeSize;
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
        let StoreEventRequested { event, sender } = msg;
        let seq = self.next_seq;
        self.next_seq += 1;
        sender.do_send(StoreEventResponse(event.into_sequenced(seq)));
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
            verification_id: None,
            ec: context.clone(),
            ecdsa_dishonest: HashSet::new(),
            pre_dishonest: BTreeSet::new(),
            dispatched_party_ids: HashSet::from([0]),
            party_addresses: HashMap::new(),
            party_proof_hashes: HashMap::new(),
            party_public_signals: HashMap::new(),
            party_proof_data: HashMap::new(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
        },
    );
    let request = ComputeRequest::zk(
        ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
            party_proofs: Vec::new(),
            params_preset: BfvPreset::InsecureThreshold512,
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
        params_preset: BfvPreset::InsecureThreshold512,
        committee_size: CiphernodesCommitteeSize::Minimum,
        lbfv_context: None,
        verification_id: None,
    })
    .expect("publish C6 verification dispatch");

    let event = tokio::time::timeout(Duration::from_secs(2), consistency_requested)
        .await
        .expect("restored committee did not authorize C6 before timeout")
        .expect("wait for consistency request");
    let InterfoldEventData::CommitmentConsistencyCheckRequested(request) = event.into_data() else {
        panic!("unexpected event type")
    };
    assert_eq!(request.e3_id, e3_id);
    assert_eq!(request.party_proofs.len(), 2);
}
