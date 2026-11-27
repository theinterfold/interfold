// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use alloy::primitives::Address;
use e3_committee_hash::{hash_committee_addresses, DkgSetupContext};
use e3_events::{
    SynchronizedDkgContext, SynchronizedDkgProofJob, SynchronizedDkgProofRequest,
    SynchronizedProofContext, SynchronizedSetupAnchors,
};
use e3_fhe_params::BfvProfile;
use e3_request::canonical_key::{
    CanonicalDkgAnchors, CanonicalPublicKey, SynchronizedDkgAuthority,
};

fn fixture() -> (ComputeEffectGate, E3id, SynchronizedDkgProofRequest) {
    let id = E3id::new("2461", 1);
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let committee: Vec<_> = (1..=3).map(Address::repeat_byte).collect();
    let context = SynchronizedProofContext {
        party_id: 1,
        setup: DkgSetupContext {
            interfold_address: Address::repeat_byte(4),
            crypto_config_id: profile.crypto_config_id(size).unwrap(),
            committee_hash: hash_committee_addresses(&committee),
        },
    };
    let signing = SynchronizedDkgContext {
        registry: Address::repeat_byte(5),
        verifying_contract: Address::repeat_byte(6),
        crypto_config_id: context.setup.crypto_config_id.0,
    };
    let binding = context
        .setup
        .hash(id.chain_id(), id.clone().try_into().unwrap());
    let key = CanonicalPublicKey {
        pk_commitment: [1; 32],
        honest_committee: vec![committee[0], committee[2]],
        committee,
        params_profile: profile,
        committee_size: size,
        interfold_address: context.setup.interfold_address,
        dkg_anchors: CanonicalDkgAnchors::Synchronized(SynchronizedDkgAuthority {
            version: 1,
            context: signing,
            setup_binding: binding.0,
            dealer_batch: [2; 32],
            party_ids: vec![0, 2],
            threshold_pk_commits: vec![[3; 32], [4; 32]],
            sk_agg_commits: vec![[5; 32], [6; 32]],
            key_bundle_commits: vec![[7; 32], [8; 32]],
        }),
    };
    let mut gate = ComputeEffectGate::new(Recorder::default().start().recipient(), HashMap::new());
    gate.local_signer = Some(key.committee[1]);
    gate.canonical_keys
        .remember_synchronized_context(id.clone(), signing)
        .unwrap();
    gate.canonical_keys
        .insert_synchronized_dkg_authority(id.clone(), key)
        .unwrap();
    let proof = |name| Proof::new(name, ArcBytes::from_bytes(&[1]), ArcBytes::default());
    let expected = SynchronizedSetupAnchors {
        binding: context
            .setup
            .binding(id.chain_id(), id.clone().try_into().unwrap()),
        recipient: 1,
        dealers: vec![0, 2],
        threshold_keys: vec![[3; 32], [4; 32]],
        dealer_batch: [2; 32],
        sk_commitment: [9; 32],
        key_bundle: [10; 32],
    };
    let request = SynchronizedDkgProofRequest {
        params_profile: profile,
        committee_size: size,
        context,
        job: SynchronizedDkgProofJob::Recipient {
            c0: proof(CircuitName::PkBfv),
            own_c2: proof(CircuitName::SkShareComputation),
            c4: proof(CircuitName::DkgShareDecryption),
            dealers: vec![proof(CircuitName::NodeFold); 2],
            expected,
        },
    };
    (gate, id, request)
}

fn work(
    id: &E3id,
    join: SynchronizedDkgProofRequest,
    correlation: CorrelationId,
) -> InterfoldEvent {
    outcome_event(ComputeRequest::zk(
        ZkRequest::SynchronizedDkg(Box::new(join)),
        correlation,
        id.clone(),
    ))
}

#[actix::test]
async fn key_published_before_dispatch_only_releases_the_confirmed_outside_h_join() {
    let (mut gate, id, join) = fixture();
    // Authority is projected before fan-out. A missing C0 cannot be (re)proved while the
    // stage notification is still queued at this gate.
    assert!(!gate.forward(outcome_event(ComputeRequest::zk(
        ZkRequest::PkBfv(PkBfvProofRequest::new(
            ArcBytes::default(),
            join.params_profile,
            join.committee_size,
        )),
        CorrelationId::new(),
        id.clone(),
    ))));
    gate.record_stage(id.clone(), E3Stage::KeyPublished);
    gate.cancel(&id);
    let mut changed = join.clone();
    if let SynchronizedDkgProofJob::Recipient { expected, .. } = &mut changed.job {
        expected.dealer_batch[0] ^= 1;
    }
    assert!(!gate.forward(work(&id, changed, CorrelationId::new())));
    let mut wrong_owner = join.clone();
    wrong_owner.context.party_id = 2;
    assert!(!gate.forward(work(&id, wrong_owner, CorrelationId::new())));
    let mut wrong_keys = join.clone();
    if let SynchronizedDkgProofJob::Recipient { expected, .. } = &mut wrong_keys.job {
        expected.threshold_keys.swap(0, 1);
    }
    assert!(!gate.forward(work(&id, wrong_keys, CorrelationId::new())));
    assert!(
        !gate.forward(work(&id, join.clone(), CorrelationId::new()).with_source(EventSource::Net))
    );
    gate.local_signer = Some(Address::repeat_byte(1));
    assert!(!gate.forward(work(&id, join.clone(), CorrelationId::new())));
    gate.local_signer = Some(Address::repeat_byte(2));
    assert!(
        gate.forward(work(&id, join, CorrelationId::new())),
        "late recipient was discarded"
    );
}

#[actix::test]
async fn key_published_while_recipient_is_running_preserves_it_until_retirement() {
    let (mut gate, id, join) = fixture();
    let authority = std::mem::take(&mut gate.canonical_keys);
    let key = authority.get(&id).unwrap();
    gate.canonical_keys
        .remember_synchronized_selection(
            id.clone(),
            e3_request::canonical_key::SynchronizedDkgSelection {
                params_profile: key.params_profile,
                committee_size: key.committee_size,
                interfold_address: key.interfold_address,
                committee: key.committee,
            },
        )
        .unwrap();
    let c0_id = CorrelationId::new();
    assert!(gate.forward(outcome_event(ComputeRequest::zk(
        ZkRequest::PkBfv(PkBfvProofRequest::new(
            ArcBytes::default(),
            join.params_profile,
            join.committee_size,
        )),
        c0_id,
        id.clone(),
    ))));
    let c0 = gate.running.start(&id, c0_id);
    let correlation = CorrelationId::new();
    assert!(gate.forward(work(&id, join.clone(), correlation)));
    let job = gate.running.start(&id, correlation);
    let mut other = join.clone();
    if let SynchronizedDkgProofJob::Recipient { expected, .. } = &mut other.job {
        expected.dealer_batch[31] ^= 1;
    }
    let other_id = CorrelationId::new();
    assert!(gate.forward(work(&id, other, other_id)));
    let losing_job = gate.running.start(&id, other_id);
    let mut foreign = join.clone();
    foreign.context.party_id = 2;
    if let SynchronizedDkgProofJob::Recipient { expected, .. } = &mut foreign.job {
        expected.recipient = 2;
        expected.dealers = vec![0, 1];
    }
    let foreign_id = CorrelationId::new();
    assert!(gate.forward(work(&id, foreign, foreign_id)));
    let foreign_job = gate.running.start(&id, foreign_id);
    gate.record_stage(id.clone(), E3Stage::KeyPublished);
    gate.cancel(&id);
    assert!(
        *c0.cancellation.borrow(),
        "publication kept a synchronized leaf job running as if it were SS"
    );
    assert!(*foreign_job.cancellation.borrow());
    assert!(
        !*job.cancellation.borrow(),
        "publication cancelled the correlated recipient join"
    );
    // The stage callback can precede the row/proof logs. Keep this existing run; do not
    // forward another attempt until the authority is available.
    assert!(!gate.forward(work(&id, join.clone(), CorrelationId::new())));
    let context = authority.synchronized_context(&id).unwrap();
    gate.canonical_keys = authority;
    // The request-time context can be the last input to the shared projection, too.
    gate.handle(
        outcome_event(e3_events::SynchronizedDkgContextEstablished {
            schema_version: e3_events::SYNCHRONIZED_DKG_CONTEXT_SCHEMA_VERSION,
            e3_id: id.clone(),
            context,
        })
        .with_source(EventSource::Evm),
        &mut Context::new(),
    );
    assert!(
        *losing_job.cancellation.borrow(),
        "the last authority input did not cancel the losing join"
    );
    assert!(!*job.cancellation.borrow());
    gate.record_stage(id.clone(), E3Stage::CiphertextReady);
    gate.cancel(&id);
    assert!(!*job.cancellation.borrow());
    gate.record_stage(id.clone(), E3Stage::Complete);
    gate.cancel(&id);
    assert!(*job.cancellation.borrow());
    assert!(!gate.forward(work(&id, join, CorrelationId::new())));
}

#[actix::test]
async fn only_a_local_worker_response_can_satisfy_a_reopened_recipient_join() {
    let (mut gate, id, join) = fixture();
    let old = CorrelationId::new();
    gate.queue(work(&id, join.clone(), old));
    let SynchronizedDkgProofJob::Recipient { expected, .. } = &join.job else {
        unreachable!()
    };
    let proof = Proof::new(
        CircuitName::NodesFold,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::default(),
    );
    let result = ComputeResponse::zk(
        e3_events::ZkResponse::SynchronizedDkg(
            e3_events::SynchronizedDkgProofResponse::Recipient {
                proof,
                setup: expected.clone(),
            },
        ),
        old,
        id.clone(),
    );
    gate.on_outcome(&outcome_event(result).with_source(EventSource::Net));
    assert!(gate.forward(work(&id, join, CorrelationId::new())));
}
