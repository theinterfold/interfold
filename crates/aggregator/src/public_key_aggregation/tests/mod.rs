// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::primitives::Address;
use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repository};
use e3_events::EventConstructorWithTimestamp;
use e3_events::{
    CircuitName, ComputeRequestErrorKind, EffectsEnabled, GetEvents, HistoryCollector,
    ProofPayload, ProofType, Seed, TakeEvents, Unsequenced, ZkError,
};
use e3_test_helpers::get_common_setup;
use std::collections::{BTreeSet, HashMap};

fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(0)
}

fn test_state<T: PersistableData>(initial_state: T) -> Persistable<T> {
    let repo = Repository::<T>::new(DataStore::from_in_mem(&InMemStore::new(false).start()));
    repo.to_connector().send(Some(initial_state))
}

fn dummy_proof(circuit: CircuitName) -> Proof {
    Proof::new(
        circuit,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&[2]),
    )
}

fn generating_c5_state(correlation_id: CorrelationId) -> PublicKeyAggregatorState {
    PublicKeyAggregatorState::GeneratingC5Proof {
        public_key: ArcBytes::from_bytes(&[1, 2, 3]),
        keyshare_bytes: Vec::new(),
        nodes: OrderedSet::new(),
        party_nodes: HashMap::new(),
        dkg_node_proofs: HashMap::new(),
        dkg_fold_attestations: HashMap::new(),
        honest_party_ids: BTreeSet::new(),
        dishonest_parties: BTreeSet::new(),
        circuit_committee_n: 3,
        circuit_committee_h: 3,
        dkg_aggregation_correlation: Some(correlation_id),
        dkg_aggregated_proof: None,
        c5_proof_pending: Some(dummy_proof(CircuitName::PkAggregation)),
        last_ec: None,
        nodes_fold_accumulator: None,
        nodes_fold_completed_slots: 0,
        nodes_fold_step_correlation: None,
    }
}

fn complete_state() -> PublicKeyAggregatorState {
    PublicKeyAggregatorState::Complete {
        public_key: ArcBytes::from_bytes(&[1, 2, 3]),
        keyshares: OrderedSet::new(),
        nodes: OrderedSet::new(),
        committee_addresses: Vec::new(),
        honest_committee_addresses: Vec::new(),
    }
}

async fn build_public_key_aggregator(
    initial_state: PublicKeyAggregatorState,
) -> Result<(
    PublicKeyAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    build_public_key_aggregator_with_committee(initial_state, CiphernodesCommitteeSize::Minimum)
        .await
}

async fn build_public_key_aggregator_with_committee(
    initial_state: PublicKeyAggregatorState,
    committee_size: CiphernodesCommitteeSize,
) -> Result<(
    PublicKeyAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe,
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator: true,
            initial_stage: E3Stage::None,
            effects_enabled: true,
        },
        test_state(initial_state),
    );

    Ok((aggregator, history, e3_id))
}

fn c1_proof_with_pk_commitment(e3_id: &E3id, pk_commitment: [u8; 32]) -> SignedProofPayload {
    let mut signals = vec![0u8; 96];
    signals[32..64].copy_from_slice(&pk_commitment);
    SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C1PkGeneration,
            proof: Proof::new(
                CircuitName::PkGeneration,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&signals),
            ),
        },
        signature: ArcBytes::from_bytes(&[0u8; 65]),
    }
}

fn verifying_c1_non_square_state(
    fhe: &Fhe,
    e3_id: &E3id,
) -> Result<(PublicKeyAggregatorState, usize, usize, usize)> {
    use fhe::bfv::SecretKey;
    use fhe::mbfv::PublicKeyShare;
    use fhe_traits::Serialize;

    let committee = CiphernodesCommitteeSize::Micro.values();
    let threshold_n = committee.n;
    let threshold_m = committee.threshold;
    let circuit_h = committee.h;
    assert_ne!(
        threshold_n, circuit_h,
        "test requires a non-square committee (N != H)"
    );

    let mut submission_order = Vec::with_capacity(threshold_n);
    let mut c1_proofs = Vec::with_capacity(threshold_n);
    let mut canonical_party_nodes = HashMap::with_capacity(threshold_n);
    let mut rng = rand::rng();

    for party_id in 0..threshold_n as u64 {
        let node = format!("0x{:040x}", party_id + 1);
        canonical_party_nodes.insert(party_id, node.clone());
        if party_id < circuit_h as u64 {
            let sk = SecretKey::random(&fhe.params, &mut rng);
            let pk_share = PublicKeyShare::new(&sk, fhe.crp.clone(), &mut rng)?;
            let ks_bytes = ArcBytes::from_bytes(&pk_share.to_bytes());
            let commitment = e3_zk_helpers::compute_pk_commitment_from_keyshare_bytes(
                &ks_bytes,
                &fhe.params,
                &fhe.crp,
            )?;
            submission_order.push((party_id, node, ks_bytes));
            c1_proofs.push(Some(c1_proof_with_pk_commitment(e3_id, commitment)));
        } else {
            submission_order.push((party_id, node, ArcBytes::from_bytes(&[party_id as u8])));
            c1_proofs.push(None);
        }
    }

    Ok((
        PublicKeyAggregatorState::VerifyingC1 {
            submission_order,
            threshold_m,
            circuit_committee_n: threshold_n,
            circuit_committee_h: circuit_h,
            c1_proofs,
            no_proof_parties: vec![],
            canonical_party_nodes,
        },
        threshold_n,
        threshold_m,
        circuit_h,
    ))
}

async fn next_event(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<InterfoldEvent> {
    let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(!result.timed_out, "timed out waiting for an event");
    Ok(result.events.pop().expect("expected one event"))
}

#[actix::test]
async fn restart_redrives_c1_verification() -> Result<()> {
    let e3_id = E3id::new("42", 1);
    let keyshare = ArcBytes::from_bytes(&[1, 2, 3]);
    let state = PublicKeyAggregatorState::VerifyingC1 {
        submission_order: vec![(0, Address::ZERO.to_string(), keyshare)],
        threshold_m: 0,
        circuit_committee_n: 1,
        circuit_committee_h: 1,
        c1_proofs: vec![Some(c1_proof_with_pk_commitment(&e3_id, [7; 32]))],
        no_proof_parties: Vec::new(),
        canonical_party_nodes: HashMap::from([(0, Address::ZERO.to_string())]),
    };
    let (mut aggregator, history, _) = build_public_key_aggregator(state).await?;

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.e3_id == e3_id && data.kind == VerificationKind::PkGenerationProofs
    ));
    Ok(())
}

fn micro_aggregator(
    bus: BusHandle,
    fhe: Arc<Fhe>,
    e3_id: &E3id,
    initial_is_aggregator: bool,
    state: PublicKeyAggregatorState,
) -> (PublicKeyAggregator, Repository<PublicKeyAggregatorState>) {
    let repository = Repository::new(DataStore::from_in_mem(&InMemStore::new(false).start()));
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe,
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Micro,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator,
            initial_stage: E3Stage::None,
            effects_enabled: true,
        },
        repository.send(Some(state)),
    );
    (aggregator, repository)
}

fn c1_verified(
    e3_id: &E3id,
    dishonest_parties: BTreeSet<u64>,
) -> TypedEvent<ShareVerificationComplete> {
    let verified = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::PkGenerationProofs,
        dishonest_parties,
    };
    TypedEvent::new(verified.clone(), test_ctx(verified))
}

/// Wait until the history holds a C5 proof request for `e3_id`.
async fn c5_proof_requested(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    e3_id: &E3id,
) -> Result<bool> {
    for _ in 0..100 {
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        if events.iter().any(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::PkAggregationProofPending(data) if &data.e3_id == e3_id
            )
        }) {
            return Ok(true);
        }
        actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    }
    Ok(false)
}

#[actix::test]
async fn demoted_aggregator_finishes_the_c1_verification_it_dispatched() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, circuit_h) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let (mut aggregator, repository) = micro_aggregator(bus, fhe, &e3_id, true, state);
    aggregator.continue_c1_verification(test_ctx(EffectsEnabled::new()))?;

    // A failover moves aggregation to another party while C1 verification runs.
    let aggregator = aggregator.start();
    let demotion = AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    };
    aggregator
        .send(TypedEvent::new(demotion.clone(), test_ctx(demotion)))
        .await?;
    aggregator
        .send(c1_verified(
            &e3_id,
            (circuit_h as u64..threshold_n as u64).collect(),
        ))
        .await?;

    assert!(matches!(
        repository.read().await?,
        Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
    ));
    assert!(c5_proof_requested(&history, &e3_id).await?);
    Ok(())
}

#[actix::test]
async fn a_late_c1_failure_after_key_publication_does_not_fail_the_e3() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, _) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let (mut aggregator, repository) = micro_aggregator(bus, fhe, &e3_id, true, state);
    aggregator.continue_c1_verification(test_ctx(EffectsEnabled::new()))?;
    let aggregator = aggregator.start();

    // A failover demotes this node, and its successor publishes the key.
    let demotion = AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    };
    aggregator
        .send(TypedEvent::new(demotion.clone(), test_ctx(demotion)))
        .await?;
    let published = e3_events::E3StageChanged {
        e3_id: e3_id.clone(),
        previous_stage: E3Stage::CommitteeFinalized,
        new_stage: E3Stage::KeyPublished,
    };
    aggregator
        .send(
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                published.into(),
                None,
                1,
                None,
                e3_events::EventSource::Evm,
            )
            .into_sequenced(1),
        )
        .await?;
    // Its own C1 check then fails every dealer.
    aggregator
        .send(c1_verified(&e3_id, (0..threshold_n as u64).collect()))
        .await?;

    actix::clock::sleep(std::time::Duration::from_millis(50)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(!events
        .iter()
        .any(|event| matches!(event.get_data(), InterfoldEventData::E3Failed(_))));
    assert!(matches!(
        repository.read().await?,
        Some(PublicKeyAggregatorState::VerifyingC1 { .. })
    ));
    Ok(())
}

#[actix::test]
async fn a_c1_failure_after_another_node_published_the_key_does_not_fail_the_e3() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, _) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let (mut aggregator, _repository) = micro_aggregator(bus, fhe, &e3_id, true, state);
    aggregator.continue_c1_verification(test_ctx(EffectsEnabled::new()))?;
    // A demoted predecessor finished first and published the key.
    aggregator.observe_stage(&E3Stage::KeyPublished);

    aggregator
        .handle_c1_verification_complete(c1_verified(&e3_id, (0..threshold_n as u64).collect()))?;

    actix::clock::sleep(std::time::Duration::from_millis(50)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(!events
        .iter()
        .any(|event| matches!(event.get_data(), InterfoldEventData::E3Failed(_))));
    Ok(())
}

#[actix::test]
async fn a_demoted_aggregator_stops_its_work_once_a_key_is_published() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let mut state = generating_c5_state(CorrelationId::new());
    if let PublicKeyAggregatorState::GeneratingC5Proof {
        c5_proof_pending, ..
    } = &mut state
    {
        *c5_proof_pending = None;
    }
    let (mut aggregator, _repository) = micro_aggregator(bus, fhe, &e3_id, false, state);
    aggregator.observe_stage(&E3Stage::KeyPublished);

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    actix::clock::sleep(std::time::Duration::from_millis(50)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::PkAggregationProofPending(_)
    )));
    Ok(())
}

#[actix::test]
async fn standby_ignores_c1_verification_that_it_did_not_dispatch() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, circuit_h) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let (aggregator, repository) = micro_aggregator(bus, fhe, &e3_id, false, state);
    let aggregator = aggregator.start();

    aggregator
        .send(c1_verified(
            &e3_id,
            (circuit_h as u64..threshold_n as u64).collect(),
        ))
        .await?;

    assert!(
        matches!(
            repository.read().await?,
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ),
        "a standby applied a C1 verification that it did not dispatch"
    );
    Ok(())
}

#[actix::test]
async fn demoted_aggregator_resumes_its_key_proof_after_restart() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let mut state = generating_c5_state(CorrelationId::new());
    if let PublicKeyAggregatorState::GeneratingC5Proof {
        c5_proof_pending, ..
    } = &mut state
    {
        *c5_proof_pending = None;
    }
    // The persisted state proves that this node computed the key before a failover demoted it.
    let (mut aggregator, _repository) = micro_aggregator(bus, fhe, &e3_id, false, state);

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    assert!(c5_proof_requested(&history, &e3_id).await?);
    Ok(())
}

#[actix::test]
async fn standby_persists_and_resumes_public_key_work() -> Result<()> {
    let e3_id = E3id::new("42", 1);
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let nodes = (0..committee.n as u64)
        .map(|party_id| (party_id, format!("0x{:040x}", party_id + 1)))
        .collect::<HashMap<_, _>>();
    let state = PublicKeyAggregatorState::init(
        committee.n,
        committee.threshold,
        Seed([0; 32]),
        nodes.clone(),
    );
    let (mut aggregator, history, _) = build_public_key_aggregator(state).await?;
    aggregator.is_aggregator = false;
    let ec = test_ctx(EffectsEnabled::new());
    for (party_id, node) in nodes {
        aggregator.add_keyshare(
            ArcBytes::from_bytes(&[party_id as u8]),
            node,
            party_id,
            Some(c1_proof_with_pk_commitment(&e3_id, [7; 32])),
            &ec,
        )?;
    }
    aggregator.accept_dkg_roster(
        CommitmentRosterSelected {
            e3_id: e3_id.clone(),
            party_ids: vec![0, 1],
        },
        ec.clone(),
    )?;
    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::VerifyingC1 { .. })
    ));
    let ready = next_event(&history).await?;
    assert!(matches!(
        ready.get_data(),
        InterfoldEventData::AggregationInputsReady(data)
            if data.e3_id == e3_id && data.phase == AggregationPhase::PublicKey
    ));
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::ShareVerificationDispatched(_)
    )));

    aggregator.is_aggregator = true;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.e3_id == e3_id && data.kind == VerificationKind::PkGenerationProofs
    ));
    Ok(())
}

#[actix::test]
async fn collecting_aggregator_accepts_a_roster_replacement_before_c1() -> Result<()> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let state = PublicKeyAggregatorState::init(
        committee.n,
        committee.threshold,
        Seed([0; 32]),
        (0..committee.n as u64)
            .map(|party_id| (party_id, format!("0x{:040x}", party_id + 1)))
            .collect(),
    );
    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(state).await?;
    let ec = test_ctx(EffectsEnabled::new());

    aggregator.accept_dkg_roster(
        CommitmentRosterSelected {
            e3_id: e3_id.clone(),
            party_ids: vec![1, 2],
        },
        ec.clone(),
    )?;
    aggregator.accept_dkg_roster(
        CommitmentRosterSelected {
            e3_id,
            party_ids: vec![0, 1],
        },
        ec,
    )?;

    assert_eq!(
        aggregator.recovery.try_get()?.selected_roster,
        Some(BTreeSet::from([0, 1]))
    );
    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::Collecting { .. })
    ));
    Ok(())
}

#[actix::test]
async fn expelling_a_selected_roster_member_fails_the_dkg_immediately() -> Result<()> {
    let selected_node = Address::repeat_byte(0x11);
    let e3_id = E3id::new("42", 1);
    for removal in [
        InterfoldEventData::from(CommitteeMemberExpelled {
            e3_id: e3_id.clone(),
            node: selected_node,
            reason: [0; 32],
            active_count_after: 2,
            party_id: None,
        }),
        InterfoldEventData::from(CommitteeMemberExcluded {
            e3_id: e3_id.clone(),
            node: selected_node,
            proof_type: ProofType::C1PkGeneration,
            party_id: None,
        }),
    ] {
        let committee_addresses = vec![
            selected_node,
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x33),
        ];
        let state = PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            committee_addresses
                .iter()
                .enumerate()
                .map(|(party_id, node)| (party_id as u64, node.to_string()))
                .collect(),
        );
        let (mut aggregator, history, _) = build_public_key_aggregator(state).await?;
        aggregator
            .recovery
            .try_mutate_without_context(|mut recovery| {
                recovery.selected_roster = Some(BTreeSet::from([0, 1]));
                Ok(recovery)
            })?;
        let bus = aggregator.bus.clone();
        let actor = aggregator.start();
        // A local candidate and another E3's publication do not end this E3's DKG.
        for event in [
            InterfoldEventData::from(PublicKeyAggregated {
                e3_id: e3_id.clone(),
                pubkey: ArcBytes::from_bytes(&[1]),
                nodes: OrderedSet::new(),
                committee_addresses: committee_addresses.clone(),
                honest_committee_addresses: committee_addresses[..2].to_vec(),
                pk_commitment: [0; 32],
                dkg_aggregator_proof: None,
                dkg_attestation_bundle: None,
            }),
            InterfoldEventData::from(e3_events::CommitteePublished {
                e3_id: E3id::new("43", 1),
                nodes: Vec::new(),
                public_key: ArcBytes::from_bytes(&[1]),
                proof: ArcBytes::from_bytes(&[]),
            }),
            InterfoldEventData::from(e3_events::E3StageChanged {
                e3_id: E3id::new("43", 1),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage: E3Stage::KeyPublished,
            }),
            removal,
        ] {
            actor
                .send(bus.event_from(event, None)?.into_sequenced(0))
                .await?;
        }
        let event = next_event(&history).await?;
        assert!(matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(E3Failed {
                e3_id: failed_e3,
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::InsufficientCommitteeMembers,
            }) if failed_e3 == e3_id
        ));
    }

    Ok(())
}

#[actix::test]
async fn standby_retains_dkg_fold_for_failover() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let party_id = 2;
    let mut initial_state = generating_c5_state(CorrelationId::new());
    let PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        honest_party_ids,
        ..
    } = &mut initial_state
    else {
        unreachable!();
    };
    party_nodes.insert(party_id, Address::repeat_byte(0x22).to_string());
    honest_party_ids.insert(party_id);

    let state_store = InMemStore::new(false).start();
    let state_repository = Repository::new(DataStore::from_in_mem(&state_store));
    let state = state_repository.send(Some(initial_state));
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe,
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator: false,
            initial_stage: E3Stage::None,
            effects_enabled: true,
        },
        state,
    )
    .start();

    let fold = DKGRecursiveAggregationComplete {
        e3_id,
        party_id,
        aggregated_proof: None,
        fold_attestation: None,
    };
    aggregator
        .send(TypedEvent::new(fold.clone(), test_ctx(fold)))
        .await?;

    let persisted = state_repository
        .read()
        .await?
        .expect("persisted public-key aggregator state");
    let PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_node_proofs, ..
    } = persisted
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert_eq!(dkg_node_proofs.get(&party_id), Some(&None));
    Ok(())
}

/// A C5 state whose node proofs are all absent, so the C5 proof alone completes the key.
fn c5_state_without_node_proofs() -> PublicKeyAggregatorState {
    let mut state = generating_c5_state(CorrelationId::new());
    if let PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        honest_party_ids,
        dkg_node_proofs,
        c5_proof_pending,
        last_ec,
        dkg_aggregation_correlation,
        ..
    } = &mut state
    {
        *party_nodes = (0..3)
            .map(|party| (party, format!("0x{:040x}", party + 1)))
            .collect();
        *honest_party_ids = BTreeSet::from([0, 2]);
        *dkg_node_proofs = HashMap::from([(0, None), (2, None)]);
        *dkg_aggregation_correlation = None;
        *last_ec = Some(test_ctx(EffectsEnabled::new()));
        *c5_proof_pending = None;
    }
    state
}

/// A failover demotes the aggregator while it proves C5. Its C5 proof still arrives, and the node
/// publishes the key: the work that it started is not lost.
#[actix::test]
async fn a_demoted_aggregator_publishes_the_key_from_its_c5_proof() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_public_key_aggregator(c5_state_without_node_proofs()).await?;
    aggregator.mark_started_as_aggregator();
    let actor = aggregator.start();
    let demotion = AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    };
    actor
        .send(TypedEvent::new(demotion.clone(), test_ctx(demotion)))
        .await?;

    let mut signals = vec![0; 3 * 32];
    signals[64..].copy_from_slice(&[7; 32]);
    let signed = PkAggregationProofSigned {
        e3_id: e3_id.clone(),
        signed_proof: SignedProofPayload {
            payload: ProofPayload {
                e3_id: e3_id.clone(),
                proof_type: ProofType::C5PkAggregation,
                proof: Proof::new(
                    CircuitName::PkAggregation,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&signals),
                ),
            },
            signature: ArcBytes::from_bytes(&[0u8; 65]),
        },
    };
    actor
        .send(TypedEvent::new(signed.clone(), test_ctx(signed)))
        .await?;

    for _ in 0..100 {
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        if events
            .iter()
            .any(|event| matches!(event.get_data(), InterfoldEventData::PublicKeyAggregated(_)))
        {
            return Ok(());
        }
        actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the demoted aggregator did not publish the key");
}

/// A demoted aggregator that finished the key restarts while the registry writer still publishes
/// the key, and the key is on chain: the node sends its saved publication again.
#[actix::test]
async fn a_demoted_aggregator_sends_its_saved_key_publication_again_after_a_restart() -> Result<()>
{
    let (mut aggregator, history, e3_id) = build_public_key_aggregator(complete_state()).await?;
    let publication = PublicKeyAggregated {
        e3_id: e3_id.clone(),
        pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
        nodes: OrderedSet::new(),
        committee_addresses: Vec::new(),
        honest_committee_addresses: Vec::new(),
        pk_commitment: [7; 32],
        dkg_aggregator_proof: None,
        dkg_attestation_bundle: None,
    };
    aggregator
        .recovery
        .try_mutate_without_context(|mut recovery| {
            recovery.pending_publication = Some(publication.clone());
            Ok(recovery)
        })?;
    aggregator.is_aggregator = false;
    aggregator.observe_stage(&E3Stage::KeyPublished);

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.get_data(),
        InterfoldEventData::PublicKeyAggregated(sent) if sent.pk_commitment == [7; 32]
    ));
    Ok(())
}

/// Once every node assembled the whole key from the chain's chunks, the saved key publication is
/// cleared, and a restart does not send it again. Without that, the restart sends it.
#[actix::test]
async fn a_key_on_chain_clears_the_saved_key_publication() -> Result<()> {
    for on_chain in [false, true] {
        let (mut aggregator, history, e3_id) =
            build_public_key_aggregator(complete_state()).await?;
        aggregator
            .recovery
            .try_mutate_without_context(|mut recovery| {
                recovery.pending_publication = Some(PublicKeyAggregated {
                    e3_id: e3_id.clone(),
                    pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
                    nodes: OrderedSet::new(),
                    committee_addresses: Vec::new(),
                    honest_committee_addresses: Vec::new(),
                    pk_commitment: [7; 32],
                    dkg_aggregator_proof: None,
                    dkg_attestation_bundle: None,
                });
                Ok(recovery)
            })?;
        let bus = aggregator.bus.clone();
        let actor = aggregator.start();
        let published = InterfoldEventData::from(e3_events::CommitteePublished {
            e3_id: e3_id.clone(),
            nodes: Vec::new(),
            public_key: ArcBytes::from_bytes(&[1, 2, 3]),
            proof: ArcBytes::from_bytes(&[]),
        });
        let events = on_chain
            .then_some(published)
            .into_iter()
            .chain([InterfoldEventData::from(EffectsEnabled::new())]);
        for event in events {
            actor
                .send(bus.event_from(event, None)?.into_sequenced(0))
                .await?;
        }
        actix::clock::sleep(std::time::Duration::from_millis(100)).await;
        let sent_again = history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .iter()
            .any(|event| matches!(event.get_data(), InterfoldEventData::PublicKeyAggregated(_)));
        assert_eq!(sent_again, !on_chain, "key on chain: {on_chain}");
    }
    Ok(())
}

#[actix::test]
async fn mock_publication_carries_registry_roster() -> Result<()> {
    let mut state = generating_c5_state(CorrelationId::new());
    let PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        honest_party_ids,
        dkg_node_proofs,
        c5_proof_pending,
        last_ec,
        dkg_aggregation_correlation,
        ..
    } = &mut state
    else {
        unreachable!()
    };
    *party_nodes = (0..3)
        .map(|party| (party, format!("0x{:040x}", party + 1)))
        .collect();
    *honest_party_ids = BTreeSet::from([0, 2]);
    *dkg_node_proofs = HashMap::from([(0, None), (2, None)]);
    *dkg_aggregation_correlation = None;
    *last_ec = Some(test_ctx(EffectsEnabled::new()));
    let commitment = [7; 32];
    let mut signals = vec![0; 3 * 32];
    signals[64..].copy_from_slice(&commitment);
    *c5_proof_pending = Some(Proof::new(
        CircuitName::PkAggregation,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&signals),
    ));
    let (mut aggregator, history, _) = build_public_key_aggregator(state).await?;
    aggregator.try_publish_complete()?;
    let event = next_event(&history).await?;
    let InterfoldEventData::PublicKeyAggregated(result) = event.get_data() else {
        panic!("expected key publication");
    };
    let proof = result.dkg_aggregator_proof.as_ref().unwrap();
    let fields: Vec<_> = proof.public_signals.chunks_exact(32).collect();
    assert_eq!(fields.len(), 12, "registry requires 6 + 3H fields");
    assert_eq!(fields[2], &[0; 32]);
    assert_eq!(
        fields[3],
        &alloy::primitives::U256::from(2).to_be_bytes::<32>()
    );
    assert_eq!(fields[11], &commitment);
    assert_eq!(
        result.honest_committee_addresses,
        vec![result.committee_addresses[0], result.committee_addresses[2]]
    );
    Ok(())
}

mod attestations;
mod failures;

/// A failed E3's aggregation does not resume after a restart: the stage change that ends it comes
/// before `EffectsEnabled`, and the actor stops.
#[actix::test]
async fn a_failure_before_effects_resume_stops_public_key_aggregation() -> Result<()> {
    let (aggregator, history, e3_id) =
        build_public_key_aggregator(generating_c5_state(CorrelationId::new())).await?;
    let aggregator = aggregator.start();
    let event = |data: InterfoldEventData, seq: u64| {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            seq.into(),
            None,
            e3_events::EventSource::Local,
        )
        .into_sequenced(seq)
    };
    let failed = e3_events::E3StageChanged {
        e3_id: e3_id.clone(),
        previous_stage: E3Stage::CommitteeFinalized,
        new_stage: E3Stage::Failed,
    };
    aggregator.send(event(failed.into(), 1)).await?;
    let _ = aggregator
        .send(event(EffectsEnabled::new().into(), 2))
        .await;
    actix::clock::sleep(std::time::Duration::from_millis(100)).await;

    assert!(!aggregator.connected());
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events.iter().all(|event| !matches!(
        event.get_data(),
        InterfoldEventData::AggregationInputsReady(_)
            | InterfoldEventData::PkAggregationProofPending(_)
            | InterfoldEventData::ComputeRequest(_)
            | InterfoldEventData::PublicKeyAggregated(_)
    )));
    Ok(())
}
