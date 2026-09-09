// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
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
        ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
        params: test_params(),
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
        bus: bus.clone(),
        backends: test_persistable(HashMap::<u64, SortitionBackend>::new()),
        node_state: test_persistable(HashMap::<u64, NodeStateStore>::new()),
        recovery: test_persistable(e3_sortition::SortitionRecoveryState::default()),
        finalized_committees: test_persistable(HashMap::<E3id, Committee>::new()),
        ciphernode_selector: selector,
        address: "node-1".to_string(),
    })
    .start()
}

fn test_committee_address() -> Address {
    "0x0000000000000000000000000000000000000001"
        .parse()
        .expect("test address")
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
            committee_addresses: vec![test_committee_address()],
            honest_committee_addresses: vec![test_committee_address()],
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
    aggregator.add_share(
        0,
        vec![ArcBytes::from_bytes(&[7])],
        vec![dummy_signed_c6_proof(&e3_id)],
        &ec,
    )?;
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

mod completion;
mod failures;

/// A decryption share that arrives after collection closed must be ignored, not raised as an
/// error.
///
/// This is the decryption-phase twin of the DKG-side `add_keyshare` defect. Peers re-announce
/// their in-flight document pointers whenever a node (re)subscribes to the gossip topic, so a
/// restart anywhere in the committee re-delivers every decryption share to aggregators that have
/// already moved to `VerifyingC6`. Without a state guard `TryInto<Collecting>` fails and the
/// duplicate surfaces as `InterfoldError("PlaintextState was expected to be Collecting but it
/// was not.")` on a node doing nothing wrong.
#[actix::test]
async fn a_decryption_share_after_collection_closed_is_ignored_not_an_error() -> Result<()> {
    // Start already past collection, which is what a late re-announce finds.
    let state = ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
        threshold_m: 1,
        threshold_n: 2,
        shares: BTreeMap::new(),
        c6_proofs: BTreeMap::new(),
        ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
        params: test_params(),
    });
    let (mut aggregator, _history, _e3_id) = build_plaintext_aggregator(state, false).await?;
    let ec = test_ctx(EffectsEnabled::new());

    let result = aggregator.add_share(
        0,
        vec![ArcBytes::from_bytes(&[1])],
        vec![SignedProofPayload {
            payload: ProofPayload {
                e3_id: E3id::new("42", 1),
                proof_type: ProofType::C6ThresholdShareDecryption,
                proof: Proof::new(
                    CircuitName::ThresholdShareDecryption,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&[0u8; 32]),
                ),
            },
            signature: ArcBytes::from_bytes(&[0u8; 65]),
        }],
        &ec,
    );

    assert!(
        result.is_ok(),
        "a re-announced decryption share must be ignored after collection closed, not raised \
         as an error: {result:?}"
    );
    assert!(
        matches!(
            aggregator.state.get(),
            Some(ThresholdPlaintextAggregatorState::VerifyingC6(_))
        ),
        "the late share must not disturb the state"
    );
    Ok(())
}
