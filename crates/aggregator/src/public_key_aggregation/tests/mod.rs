// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::primitives::Address;
use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repository};
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
mod node_proof_deadline;
