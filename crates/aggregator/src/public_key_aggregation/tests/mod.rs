// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::LBFV_PUBLICATION_SCHEMA_VERSION;
use crate::{LbfvContributionRepositoryFactory, PublicKeyRepositoryFactory};
use alloy::primitives::{Address, B256};
use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repositories, Repository};
use e3_events::{
    CircuitName, CommitteeMemberExpelled, ComputeRequestErrorKind, EffectsEnabled, GetEvents,
    HistoryCollector, LbfvKeyShareDocument, LbfvKeyShareDocumentFetchFailureClass,
    LbfvKeyShareDocumentRole, ProofPayload, ProofType, Seed, TakeEvents, Unsequenced, ZkError,
};
use e3_test_helpers::get_common_setup;
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn lbfv_publication(e3_id: E3id) -> LbfvPublicKeyAggregated {
    LbfvPublicKeyAggregated {
        pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
        e3_id,
        nodes: OrderedSet::from_iter(["node".to_owned()]),
        committee_addresses: vec![Address::repeat_byte(1)],
        honest_committee_addresses: vec![Address::repeat_byte(1)],
        pk_commitment: [7; 32],
        dkg_aggregator_v2_proof: dummy_proof(CircuitName::DkgAggregatorV2),
        dkg_attestation_bundle: Some(ArcBytes::from_bytes(&[6])),
    }
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
            lbfv_collection: None,
            repositories: e3_data::Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: true,
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

#[actix::test]
async fn secure_16384_restart_redrives_publication_intent() -> Result<()> {
    let e3_id = E3id::new("42", 1);
    let publication = lbfv_publication(e3_id.clone());
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: None,
            repositories: Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: Some(test_state(LbfvPublicKeyPublicationStateV1 {
                schema_version: LBFV_PUBLICATION_SCHEMA_VERSION,
                e3_id: e3_id.clone(),
                pending: Some(publication.clone()),
            })),
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(complete_state()),
    );

    let mut aggregator = aggregator;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    assert!(matches!(
        next_event(&history).await?.into_data(),
        InterfoldEventData::LbfvPublicKeyAggregated(event) if event == publication
    ));
    Ok(())
}

#[actix::test]
async fn secure_16384_restart_redrives_terminal_aggregation_failure() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::fixture;

    let fixture = fixture();
    let e3_id = fixture.state.e3_id.clone();
    let mut aggregation =
        LbfvAggregationStateV1::new(e3_id.clone(), fixture.state.proof_domain, vec![0, 1])?;
    aggregation.fail("worker failed")?;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let mut aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: None,
            repositories: Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: Some(test_state(aggregation)),
            lbfv_publication: None,
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(generating_c5_state(CorrelationId::new())),
    );

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    assert!(matches!(
        next_event(&history).await?.into_data(),
        InterfoldEventData::E3Failed(event)
            if event.e3_id == e3_id
                && event.failed_at_stage == E3Stage::CommitteeFinalized
                && event.reason == FailureReason::DKGInvalidShares
    ));
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert_eq!(events.len(), 1);
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
    aggregator.publish_inputs_ready(ec)?;

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

mod attestations;
mod failures;

#[actix::test]
async fn secure_16384_never_dispatches_standalone_c1_verification() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};

    let fixture = fixture();
    let (_, _, manifest) = bundle(&fixture, 0);
    let mut collection = fixture.state.clone();
    collection.admit_manifest(&manifest)?;
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .write_sync(&collection)
        .await?;
    let collection = repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let mut aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: fixture.state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(collection),
            repositories,
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            fixture
                .state
                .committee
                .iter()
                .enumerate()
                .map(|(party_id, address)| (party_id as u64, address.to_string()))
                .collect(),
        )),
    );

    aggregator.dispatch_c1_verification(&[], &[], test_ctx(EffectsEnabled::new()))?;

    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(!events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::ShareVerificationDispatched(dispatch)
            if dispatch.kind == VerificationKind::PkGenerationProofs
    )));
    Ok(())
}

#[actix::test]
async fn secure_16384_publishes_inputs_ready_only_after_collection_settles() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{complete_party, fixture};

    let fixture = fixture();
    let pending_collection = fixture.state.clone();
    let mut settled_collection = pending_collection.clone();
    for party_id in 0..3 {
        complete_party(&mut settled_collection, &fixture, party_id);
    }
    let submissions = fixture
        .state
        .committee
        .iter()
        .enumerate()
        .map(|(party_id, address)| {
            (
                party_id as u64,
                address.to_string(),
                ArcBytes::from_bytes(&[party_id as u8]),
            )
        })
        .collect::<Vec<_>>();
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let mut aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: fixture.state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(test_state(pending_collection)),
            repositories: Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: true,
        },
        test_state(PublicKeyAggregatorState::VerifyingC1 {
            c1_proofs: vec![None; submissions.len()],
            submission_order: submissions,
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            no_proof_parties: Vec::new(),
            canonical_party_nodes: fixture
                .state
                .committee
                .iter()
                .enumerate()
                .map(|(party_id, address)| (party_id as u64, address.to_string()))
                .collect(),
        }),
    );
    let ec = test_ctx(EffectsEnabled::new());

    aggregator.publish_inputs_ready(ec.clone())?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    aggregator.replace_lbfv_collection(settled_collection);
    aggregator.publish_inputs_ready(ec)?;
    assert!(matches!(
        next_event(&history).await?.into_data(),
        InterfoldEventData::AggregationInputsReady(data)
            if data.e3_id == fixture.state.e3_id
                && data.phase == AggregationPhase::PublicKey
    ));
    Ok(())
}

#[actix::test]
async fn restart_validates_documents_durable_lbfv_bundles() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};

    let fixture = fixture();
    let (public_key, rlk, manifest) = bundle(&fixture, 0);
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&fixture.state.e3_id)
        .write_sync(&fixture.state)
        .await?;
    let (state, _) = repositories
        .persist_publickey_lbfv_manifest(&fixture.state, &manifest)
        .await?;
    let (state, _) = repositories
        .persist_publickey_lbfv_document(&state, &public_key)
        .await?;
    let (state, _) = repositories
        .persist_publickey_lbfv_document(&state, &rlk)
        .await?;
    assert_eq!(
        state.parties[&0].status,
        crate::LbfvPartyContributionStatusV1::DocumentsDurable
    );
    let loaded = repositories
        .publickey_lbfv_collection(&state.e3_id)
        .load()
        .await?;
    let LbfvKeyShareDocument::PublicKeyV1(public_key_document) = public_key.document else {
        unreachable!();
    };
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let actor = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories: repositories.clone(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: false,
        },
        test_state(PublicKeyAggregatorState::VerifyingC1 {
            submission_order: vec![(
                0,
                state.committee[0].to_string(),
                ArcBytes::from_bytes(&[0]),
            )],
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            c1_proofs: vec![Some(public_key_document.signed_c1_proof)],
            no_proof_parties: Vec::new(),
            canonical_party_nodes: state
                .committee
                .iter()
                .enumerate()
                .map(|(party_id, address)| (party_id as u64, address.to_string()))
                .collect(),
        }),
    )
    .start();
    let ec = test_ctx(EffectsEnabled::new());
    actor
        .send(
            e3_events::InterfoldEvent::<e3_events::Unsequenced>::new_with_timestamp(
                EffectsEnabled::new().into(),
                Some(ec.clone()),
                ec.ts(),
                ec.block(),
                e3_events::EventSource::Local,
            )
            .into_sequenced(ec.seq()),
        )
        .await?;
    actor
        .send(TypedEvent::new(
            AggregatorChanged {
                e3_id: state.e3_id.clone(),
                is_aggregator: false,
            },
            ec,
        ))
        .await?;

    assert_eq!(
        repositories
            .publickey_lbfv_collection(&state.e3_id)
            .read()
            .await?
            .expect("l-BFV collection")
            .parties[&0]
            .status,
        crate::LbfvPartyContributionStatusV1::InvalidData
    );
    Ok(())
}

#[actix::test]
async fn restart_redrives_due_lbfv_fetches() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};

    let fixture = fixture();
    let (_, _, manifest) = bundle(&fixture, 0);
    let mut state = fixture.state.clone();
    state.admit_manifest(&manifest)?;
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&state.e3_id)
        .write_sync(&state)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&state.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories,
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: true,
        },
        test_state(PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            HashMap::new(),
        )),
    );

    aggregator.publish_due_lbfv_fetches(test_ctx(EffectsEnabled::new()))?;

    let first = next_event(&history).await?.into_data();
    let second = next_event(&history).await?.into_data();
    assert!(matches!(
        first,
        InterfoldEventData::LbfvKeyShareDocumentFetchRequested(_)
    ));
    assert!(matches!(
        second,
        InterfoldEventData::LbfvKeyShareDocumentFetchRequested(_)
    ));
    Ok(())
}

#[actix::test]
async fn lbfv_retry_timer_dispatches_without_another_event() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{bundle, failure, fixture};

    let fixture = fixture();
    let (_, _, manifest) = bundle(&fixture, 0);
    let mut state = fixture.state.clone();
    state.admit_manifest(&manifest)?;
    let retry_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(1);
    for role in [
        LbfvKeyShareDocumentRole::PublicKey,
        LbfvKeyShareDocumentRole::RelinearizationKey,
    ] {
        let unavailable = failure(
            &state,
            0,
            role,
            1,
            LbfvKeyShareDocumentFetchFailureClass::Unavailable,
            Some(retry_at),
        );
        state.record_fetch_failure(&unavailable)?;
    }
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&state.e3_id)
        .write_sync(&state)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&state.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let actor = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories,
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: false,
        },
        test_state(PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            HashMap::new(),
        )),
    )
    .start();
    let ec = test_ctx(EffectsEnabled::new());
    actor
        .send(
            e3_events::InterfoldEvent::<e3_events::Unsequenced>::new_with_timestamp(
                EffectsEnabled::new().into(),
                Some(ec.clone()),
                ec.ts(),
                ec.block(),
                e3_events::EventSource::Local,
            )
            .into_sequenced(ec.seq()),
        )
        .await?;

    actix::clock::sleep(Duration::from_millis(1_200)).await;

    for _ in 0..2 {
        assert!(matches!(
            next_event(&history).await?.into_data(),
            InterfoldEventData::LbfvKeyShareDocumentFetchRequested(request)
                if request.request().attempt == 2
        ));
    }
    Ok(())
}

#[actix::test]
async fn lbfv_expulsion_durably_invalidates_an_in_flight_dispatch() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{complete_party, fixture};

    let fixture = fixture();
    let mut collection = fixture.state.clone();
    for party_id in 0..3 {
        complete_party(&mut collection, &fixture, party_id);
    }
    collection.mark_ready(vec![0, 1, 2])?;
    collection.mark_verification_dispatched()?;
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .write_sync(&collection)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let submissions = fixture
        .state
        .committee
        .iter()
        .enumerate()
        .map(|(party_id, address)| {
            (
                party_id as u64,
                address.to_string(),
                ArcBytes::from_bytes(&[party_id as u8]),
            )
        })
        .collect::<Vec<_>>();
    let actor = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: collection.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories: repositories.clone(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: false,
        },
        test_state(PublicKeyAggregatorState::VerifyingC1 {
            c1_proofs: vec![None; submissions.len()],
            submission_order: submissions,
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            no_proof_parties: Vec::new(),
            canonical_party_nodes: fixture
                .state
                .committee
                .iter()
                .enumerate()
                .map(|(party_id, address)| (party_id as u64, address.to_string()))
                .collect(),
        }),
    )
    .start();
    let ec = test_ctx(EffectsEnabled::new());
    actor
        .send(
            e3_events::InterfoldEvent::<e3_events::Unsequenced>::new_with_timestamp(
                CommitteeMemberExpelled {
                    e3_id: collection.e3_id.clone(),
                    node: collection.committee[1],
                    reason: [7; 32],
                    active_count_after: 2,
                    party_id: None,
                }
                .into(),
                Some(ec.clone()),
                ec.ts(),
                ec.block(),
                e3_events::EventSource::Local,
            )
            .into_sequenced(ec.seq()),
        )
        .await?;
    actor
        .send(TypedEvent::new(
            AggregatorChanged {
                e3_id: collection.e3_id.clone(),
                is_aggregator: false,
            },
            ec,
        ))
        .await?;

    let persisted = repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .read()
        .await?
        .expect("l-BFV collection");
    assert_eq!(
        persisted.parties[&1].status,
        crate::LbfvPartyContributionStatusV1::Excluded
    );
    assert!(matches!(
        persisted.verification,
        crate::LbfvContributionVerificationStateV1::Collecting
    ));
    Ok(())
}

#[actix::test]
async fn lbfv_stale_verification_completion_is_ignored() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{complete_party, fixture};

    let fixture = fixture();
    let mut collection = fixture.state.clone();
    for party_id in 0..3 {
        complete_party(&mut collection, &fixture, party_id);
    }
    collection.mark_ready(vec![0, 1, 2])?;
    collection.mark_verification_dispatched()?;
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .write_sync(&collection)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .load()
        .await?;
    let submissions = collection
        .committee
        .iter()
        .enumerate()
        .map(|(party_id, address)| {
            (
                party_id as u64,
                address.to_string(),
                ArcBytes::from_bytes(&[party_id as u8]),
            )
        })
        .collect::<Vec<_>>();
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let actor = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: collection.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories: repositories.clone(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(PublicKeyAggregatorState::VerifyingC1 {
            c1_proofs: vec![None; submissions.len()],
            submission_order: submissions,
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            no_proof_parties: Vec::new(),
            canonical_party_nodes: collection
                .committee
                .iter()
                .enumerate()
                .map(|(party_id, address)| (party_id as u64, address.to_string()))
                .collect(),
        }),
    )
    .start();
    let completion = ShareVerificationComplete {
        e3_id: collection.e3_id.clone(),
        kind: VerificationKind::LbfvGenerationProofs,
        verification_id: Some(B256::repeat_byte(0xff)),
        dishonest_parties: BTreeSet::new(),
    };
    let ec = test_ctx(completion.clone());
    actor.send(TypedEvent::new(completion, ec.clone())).await?;
    actor
        .send(TypedEvent::new(
            AggregatorChanged {
                e3_id: collection.e3_id.clone(),
                is_aggregator: true,
            },
            ec,
        ))
        .await?;

    assert!(matches!(
        repositories
            .publickey_lbfv_collection(&collection.e3_id)
            .read()
            .await?
            .expect("l-BFV collection")
            .verification,
        crate::LbfvContributionVerificationStateV1::Dispatched { .. }
    ));
    Ok(())
}

#[actix::test]
async fn sealed_sidecar_recovery_applies_the_exact_accepted_set() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{
        accepted_commitments, complete_party, fixture,
    };
    use fhe::{bfv::SecretKey, mbfv::PublicKeyShare};
    use fhe_traits::Serialize;

    let fixture = fixture();
    let mut collection = fixture.state.clone();
    for party_id in 0..3 {
        complete_party(&mut collection, &fixture, party_id);
    }
    collection.mark_ready(vec![0, 1, 2])?;
    collection.mark_verification_dispatched()?;
    collection.seal(vec![accepted_commitments(0), accepted_commitments(2)])?;
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .write_sync(&collection)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&collection.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let mut random = rand::rng();
    let mut submissions = Vec::new();
    let mut c1_proofs = Vec::new();
    let mut canonical_party_nodes = HashMap::new();
    for (party_id, address) in fixture.state.committee.iter().enumerate() {
        let secret = SecretKey::random(&fhe.params, &mut random);
        let share = PublicKeyShare::new(&secret, fhe.crp.clone(), &mut random)?;
        let bytes = ArcBytes::from_bytes(&share.to_bytes());
        submissions.push((party_id as u64, address.to_string(), bytes));
        c1_proofs.push(None);
        canonical_party_nodes.insert(party_id as u64, address.to_string());
    }
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe,
            bus,
            e3_id: collection.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories: repositories.clone(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: true,
            effects_enabled: false,
        },
        test_state(PublicKeyAggregatorState::VerifyingC1 {
            submission_order: submissions,
            threshold_m: 1,
            circuit_committee_n: 3,
            circuit_committee_h: 2,
            c1_proofs,
            no_proof_parties: Vec::new(),
            canonical_party_nodes,
        }),
    )
    .start();
    let ec = test_ctx(EffectsEnabled::new());
    aggregator
        .send(
            e3_events::InterfoldEvent::<e3_events::Unsequenced>::new_with_timestamp(
                EffectsEnabled::new().into(),
                Some(ec.clone()),
                ec.ts(),
                ec.block(),
                e3_events::EventSource::Local,
            )
            .into_sequenced(ec.seq()),
        )
        .await?;
    aggregator
        .send(TypedEvent::new(
            AggregatorChanged {
                e3_id: collection.e3_id.clone(),
                is_aggregator: true,
            },
            ec,
        ))
        .await?;

    assert!(matches!(
        repositories.publickey(&collection.e3_id).read().await?,
        Some(PublicKeyAggregatorState::GeneratingC5Proof { honest_party_ids, .. })
            if honest_party_ids == BTreeSet::from([0, 2])
    ));
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events.iter().any(|event| matches!(
        event.get_data(),
        InterfoldEventData::PkAggregationProofPending(_)
    )));
    Ok(())
}

#[actix::test]
async fn concurrent_document_roles_do_not_overwrite_sidecar_updates() -> Result<()> {
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};

    let fixture = fixture();
    let (public_key, rlk, manifest) = bundle(&fixture, 0);
    let repositories = Repositories::in_mem();
    repositories
        .publickey_lbfv_collection(&fixture.state.e3_id)
        .write_sync(&fixture.state)
        .await?;
    let loaded = repositories
        .publickey_lbfv_collection(&fixture.state.e3_id)
        .load()
        .await?;
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let actor = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: fixture.state.e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: Some(loaded),
            repositories: repositories.clone(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: false,
            effects_enabled: false,
        },
        test_state(PublicKeyAggregatorState::init(
            3,
            1,
            Seed([0; 32]),
            HashMap::new(),
        )),
    )
    .start();
    let ec = test_ctx(EffectsEnabled::new());
    actor
        .send(TypedEvent::new(
            e3_events::LbfvKeyShareManifestPublished { manifest },
            ec.clone(),
        ))
        .await?;
    let (pk_result, rlk_result) = futures::join!(
        actor.send(TypedEvent::new(public_key.clone(), ec.clone())),
        actor.send(TypedEvent::new(rlk.clone(), ec.clone()))
    );
    pk_result?;
    rlk_result?;
    actor
        .send(TypedEvent::new(
            AggregatorChanged {
                e3_id: fixture.state.e3_id.clone(),
                is_aggregator: false,
            },
            ec,
        ))
        .await?;

    let state = repositories
        .publickey_lbfv_collection(&fixture.state.e3_id)
        .read()
        .await?
        .expect("collection sidecar");
    assert!(state.parties[&0]
        .public_key_fetch
        .as_ref()
        .is_some_and(|fetch| fetch.artifact_durable));
    assert!(state.parties[&0]
        .relinearization_key_fetch
        .as_ref()
        .is_some_and(|fetch| fetch.artifact_durable));
    assert_eq!(
        state.parties[&0].status,
        crate::LbfvPartyContributionStatusV1::DocumentsDurable
    );
    assert!(
        repositories
            .publickey_lbfv_document(&fixture.state.e3_id, &public_key.content_hash)
            .has()
            .await
    );
    assert!(
        repositories
            .publickey_lbfv_document(&fixture.state.e3_id, &rlk.content_hash)
            .has()
            .await
    );
    Ok(())
}
