// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use actix::{Actor, Context, Handler};
use alloy::signers::local::PrivateKeySigner;
use e3_events::{
    hlc_factory::HlcFactory, EventBus, EventBusBarrier, EventBusConfig, EventPublisher,
    PersistEvent, ProofPayload, Seed, Sequencer,
};
use e3_fhe_params::build_pair_for_preset;
use e3_utils::utility_types::ArcBytes;
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

impl Handler<PersistEvent> for TestEventStore {
    type Result = anyhow::Result<Option<InterfoldEvent>>;

    fn handle(&mut self, msg: PersistEvent, _: &mut Self::Context) -> Self::Result {
        let seq = self.next_seq;
        self.next_seq += 1;
        Ok(Some(msg.0.into_sequenced(seq)))
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
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("c0-recovery-test")
}

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
    let preset = BfvPreset::InsecureThreshold512;
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
