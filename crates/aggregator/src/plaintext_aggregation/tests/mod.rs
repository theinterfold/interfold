// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::signers::local::PrivateKeySigner;
use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repository};
use e3_events::{
    CircuitName, Committee, ComputeRequestErrorKind, ComputeRequestKind, EffectsEnabled, GetEvents,
    HistoryCollector, ProofPayload, ProofType, Seed, TakeEvents, Unsequenced, ZkError,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, DEFAULT_BFV_PRESET};
use e3_sortition::{
    AggregatorFailoverState, CiphernodeSelector, CiphernodeSelectorState, NodeStateStore,
    SortitionBackend, SortitionParams,
};
use e3_test_helpers::get_common_setup;
use std::collections::{BTreeMap, BTreeSet, HashMap};

fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(0)
}

fn c6_completion(
    aggregator: &ThresholdPlaintextAggregator,
    dishonest_parties: BTreeSet<u64>,
) -> TypedEvent<ShareVerificationComplete> {
    let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) = aggregator.state.get() else {
        panic!("expected a C6 batch")
    };
    let request = aggregator.c6_verification_request(batch.c6_proofs);
    let result = ShareVerificationComplete {
        e3_id: aggregator.e3_id.clone(),
        kind: VerificationKind::ThresholdDecryptionProofs,
        dishonest_parties,
    };
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        result.clone().into(),
        Some(test_ctx(request)),
        1,
        None,
        e3_events::EventSource::Local,
    )
    .into_sequenced(1);
    event.to_typed_event(result)
}

fn test_persistable<T: PersistableData>(value: T) -> Persistable<T> {
    let repo = Repository::<T>::new(DataStore::from_in_mem(&InMemStore::new(false).start()));
    repo.to_connector().send(Some(value))
}

fn test_params() -> ArcBytes {
    ArcBytes::from_bytes(&encode_bfv_params(
        &BfvParamSet::from(DEFAULT_BFV_PRESET).build_arc(),
    ))
}

fn dummy_proof(circuit: CircuitName) -> Proof {
    Proof::new(
        circuit,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&[2]),
    )
}

fn dummy_signed_c6_proof(e3_id: &E3id) -> SignedProofPayload {
    SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C6ThresholdShareDecryption,
            proof: dummy_proof(CircuitName::ThresholdShareDecryption),
        },
        signature: ArcBytes::from_bytes(&[0; 65]),
    }
}

#[test]
fn decryption_sender_must_own_an_honest_party_slot() {
    let first = Address::repeat_byte(0x11);
    let second = Address::repeat_byte(0x22);
    let committee = [first, second];
    let honest = [first];

    assert!(node_owns_committee_party_slot(
        &committee,
        &honest,
        &first.to_string(),
        0
    ));
    assert!(!node_owns_committee_party_slot(
        &committee,
        &honest,
        &first.to_string(),
        1
    ));
    assert!(!node_owns_committee_party_slot(
        &committee,
        &honest,
        &second.to_string(),
        1
    ));
    assert!(!node_owns_committee_party_slot(
        &committee,
        &honest,
        &first.to_string(),
        2
    ));
}

fn computing_state() -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::Computing(Computing {
        threshold_m: 1,
        threshold_n: 2,
        shares: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
        ciphertext_output: vec![ArcBytes::from_bytes(&[8])],
        params: test_params(),
    })
}

fn verifying_c6_state() -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
        threshold_m: 1,
        threshold_n: 2,
        shares: BTreeMap::from([
            (0, vec![ArcBytes::from_bytes(&[7])]),
            (1, vec![ArcBytes::from_bytes(&[8])]),
        ]),
        c6_proofs: BTreeMap::new(),
        ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
        params: test_params(),
        seed: Seed([0u8; 32]),
        rejected_parties: BTreeSet::new(),
        queued_shares: BTreeMap::new(),
    })
}

fn generating_c7_state() -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
        threshold_m: 1,
        threshold_n: 2,
        shares: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
        plaintext: vec![ArcBytes::from_bytes(&[9])],
    })
}

fn collecting_state() -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::Collecting(Collecting {
        threshold_m: 1,
        threshold_n: 2,
        shares: BTreeMap::new(),
        c6_proofs: BTreeMap::new(),
        seed: Seed([0u8; 32]),
        ciphertext_output: test_ciphertexts()[..1].to_vec(),
        params: test_params(),
        rejected_parties: BTreeSet::new(),
    })
}

fn start_sortition(bus: &BusHandle) -> Addr<Sortition> {
    let selector = CiphernodeSelector::new(
        bus,
        test_persistable(CiphernodeSelectorState::default()),
        test_persistable(AggregatorFailoverState::default()),
        "node-1",
    )
    .start();

    Sortition::new(SortitionParams {
        admission: test_persistable(e3_sortition::AdmissionState::default()),
        bus: bus.clone(),
        backends: test_persistable(HashMap::<u64, SortitionBackend>::new()),
        node_state: test_persistable(HashMap::<u64, NodeStateStore>::new()),
        bond_owners: test_persistable(e3_sortition::BondOwnerState::default()),
        recovery: test_persistable(e3_sortition::SortitionRecoveryState::default()),
        finalized_committees: test_persistable(HashMap::<E3id, Committee>::new()),
        ciphernode_selector: selector,
        address: "node-1".to_string(),
        submitted_e3s: Default::default(),
    })
    .start()
}

fn test_committee_address() -> Address {
    test_signer(0).address()
}

fn test_signer(party: u64) -> PrivateKeySigner {
    PrivateKeySigner::from_slice(&[party as u8 + 1; 32]).unwrap()
}

fn test_ciphertexts() -> Vec<ArcBytes> {
    use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheEncoder, FheEncrypter, Serialize};
    use rand::SeedableRng;
    use std::sync::LazyLock;
    static CIPHERTEXTS: LazyLock<Vec<ArcBytes>> = LazyLock::new(|| {
        let (params, _) =
            e3_fhe_params::build_pair_for_preset(BfvPreset::InsecureThreshold512).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let key = PublicKey::new(&SecretKey::random(&params, &mut rng), &mut rng);
        [1u64, 2]
            .into_iter()
            .map(|value| {
                let plaintext = Plaintext::try_encode(&[value], Encoding::poly(), &params).unwrap();
                ArcBytes::from_bytes(&key.try_encrypt(&plaintext, &mut rng).unwrap().to_bytes())
            })
            .collect()
    });
    CIPHERTEXTS.clone()
}

async fn build_plaintext_aggregator(
    initial_state: ThresholdPlaintextAggregatorState,
    proof_aggregation_enabled: bool,
) -> Result<(
    ThresholdPlaintextAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    build_plaintext_aggregator_with_role(initial_state, proof_aggregation_enabled, true).await
}

async fn build_plaintext_aggregator_with_role(
    initial_state: ThresholdPlaintextAggregatorState,
    proof_aggregation_enabled: bool,
    initial_is_aggregator: bool,
) -> Result<(
    ThresholdPlaintextAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let aggregator = ThresholdPlaintextAggregator::new(
        ThresholdPlaintextAggregatorParams {
            bus: bus.clone(),
            sortition: start_sortition(&bus),
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
            proof_aggregation_enabled,
            initial_is_aggregator,
            effects_enabled: true,
            committee_addresses: (0..3).map(|party| test_signer(party).address()).collect(),
            honest_committee_addresses: (0..2).map(|party| test_signer(party).address()).collect(),
            recovery: test_persistable(ThresholdPlaintextAggregatorRecoveryState::default()),
        },
        test_persistable(initial_state),
    );

    Ok((aggregator, history, e3_id))
}

async fn next_event(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<InterfoldEvent> {
    let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(!result.timed_out, "timed out waiting for an event");
    Ok(result.events.pop().expect("expected one event"))
}

#[actix::test]
async fn restart_redrives_threshold_decryption() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(computing_state(), false).await?;

    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ComputeRequest(data)
            if data.e3_id == e3_id
                && matches!(
                    data.request,
                    ComputeRequestKind::TrBFV(
                        TrBFVRequest::CalculateThresholdDecryption(_)
                    )
                )
    ));
    Ok(())
}

#[actix::test]
async fn standby_persists_and_resumes_plaintext_work() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator_with_role(collecting_state(), true, false).await?;
    let ec = test_ctx(EffectsEnabled::new());
    for party in 0..2 {
        let (shares, proofs) =
            threshold::share_with_matching_commitment(&e3_id, party, &test_ciphertexts()[..1]);
        aggregator.add_share(party, shares, proofs, &ec)?;
    }
    aggregator.publish_inputs_ready(ec)?;

    assert!(matches!(
        aggregator.state.get(),
        Some(ThresholdPlaintextAggregatorState::VerifyingC6(_))
    ));
    let ready = next_event(&history).await?;
    assert!(matches!(
        ready.get_data(),
        InterfoldEventData::AggregationInputsReady(data)
            if data.e3_id == e3_id && data.phase == AggregationPhase::Plaintext
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
            if data.e3_id == e3_id
                && data.kind == VerificationKind::ThresholdDecryptionProofs
    ));
    Ok(())
}

#[actix::test]
async fn decryption_share_after_collection_closed_is_ignored() -> Result<()> {
    let (mut aggregator, _history, e3_id) =
        build_plaintext_aggregator(computing_state(), false).await?;

    aggregator.add_share(
        0,
        vec![ArcBytes::from_bytes(&[7])],
        vec![dummy_signed_c6_proof(&e3_id)],
        &test_ctx(EffectsEnabled::new()),
    )?;

    assert!(matches!(
        aggregator.state.get(),
        Some(ThresholdPlaintextAggregatorState::Computing(_))
    ));
    Ok(())
}

mod completion;
mod failures;
mod share_admission;
mod threshold;
