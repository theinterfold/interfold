// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use e3_data::{AutoPersist, DataStore, InMemStore, PersistableData, Repository};
use e3_events::{
    CircuitName, Committee, ComputeRequestErrorKind, HistoryCollector, Seed, TakeEvents,
    Unsequenced, ZkError,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, DEFAULT_BFV_PRESET};
use e3_sortition::{
    CiphernodeSelector, CiphernodeSelectorState, NodeStateStore, SortitionBackend, SortitionParams,
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
    collecting_state_with_deadline(u64::MAX)
}

fn collecting_state_with_deadline(deadline_unix_ms: u64) -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::Collecting(Collecting {
        threshold_m: 1,
        threshold_n: 2,
        shares: BTreeMap::new(),
        c6_proofs: BTreeMap::new(),
        seed: Seed([0u8; 32]),
        ciphertext_output: vec![ArcBytes::from_bytes(&[9])],
        params: test_params(),
        deadline_unix_ms,
        timeout_context: test_ctx(E3Failed {
            e3_id: E3id::new("42", 1),
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::None,
        }),
    })
}

#[test]
fn collection_timeout_uses_only_remaining_absolute_budget() {
    assert_eq!(
        remaining_collection_timeout(1_500, 1_000),
        Duration::from_millis(500)
    );
    assert_eq!(remaining_collection_timeout(999, 1_000), Duration::ZERO);
}

fn start_sortition(bus: &BusHandle) -> Addr<Sortition> {
    let selector = CiphernodeSelector::new(
        bus,
        test_persistable(CiphernodeSelectorState::default()),
        "node-1",
    )
    .start();

    Sortition::new(SortitionParams {
        bus: bus.clone(),
        backends: test_persistable(HashMap::<u64, SortitionBackend>::new()),
        node_state: test_persistable(HashMap::<u64, NodeStateStore>::new()),
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
            committee_addresses: vec![test_committee_address()],
            honest_committee_addresses: vec![test_committee_address()],
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

mod completion;
mod failures;
