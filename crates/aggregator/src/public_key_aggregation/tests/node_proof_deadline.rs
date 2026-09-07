// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded wait for honest-party NodeDkgFold proofs.

use super::*;

/// `GeneratingC5Proof` with C5 already signed and `present` of `honest` node proofs delivered.
fn awaiting_node_proofs(honest: &[u64], present: &[u64]) -> PublicKeyAggregatorState {
    let mut dkg_node_proofs = HashMap::new();
    for id in present {
        dkg_node_proofs.insert(*id, Some(dummy_proof(CircuitName::NodeFold)));
    }
    PublicKeyAggregatorState::GeneratingC5Proof {
        public_key: ArcBytes::from_bytes(&[1, 2, 3]),
        keyshare_bytes: Vec::new(),
        nodes: OrderedSet::new(),
        party_nodes: HashMap::new(),
        dkg_node_proofs,
        dkg_fold_attestations: HashMap::new(),
        honest_party_ids: honest.iter().copied().collect::<BTreeSet<u64>>(),
        dishonest_parties: BTreeSet::new(),
        circuit_committee_n: 3,
        circuit_committee_h: honest.len(),
        dkg_aggregation_correlation: None,
        dkg_aggregated_proof: None,
        c5_proof_pending: Some(dummy_proof(CircuitName::PkAggregation)),
        last_ec: None,
        nodes_fold_accumulator: None,
        nodes_fold_completed_slots: 0,
        nodes_fold_step_correlation: None,
    }
}

/// Round 14: cn3 could not finish its node fold (13/14 inner proofs), and the aggregator waited
/// for it through three 10-minute standby budgets before giving up at the canonical deadline.
/// The missing party must be identifiable so the wait can be bounded and attributed.
#[actix::test]
async fn missing_node_proof_parties_names_only_the_absent_honest_parties() -> Result<()> {
    let (aggregator, _history, _e3_id) =
        build_public_key_aggregator(awaiting_node_proofs(&[0, 1, 2], &[0, 2])).await?;
    assert_eq!(aggregator.missing_node_proof_parties(), vec![1]);
    Ok(())
}

#[actix::test]
async fn nothing_is_missing_once_every_honest_proof_arrived() -> Result<()> {
    let (aggregator, _history, _e3_id) =
        build_public_key_aggregator(awaiting_node_proofs(&[0, 1, 2], &[0, 1, 2])).await?;
    assert!(aggregator.missing_node_proof_parties().is_empty());
    Ok(())
}

/// A dishonest party is not waited on: only the capped honest set gates the fold.
#[actix::test]
async fn dishonest_parties_are_not_waited_for() -> Result<()> {
    let (aggregator, _history, _e3_id) =
        build_public_key_aggregator(awaiting_node_proofs(&[0, 2], &[0, 2])).await?;
    assert!(aggregator.missing_node_proof_parties().is_empty());
    Ok(())
}

/// Once the final DKG aggregation proof exists the collection is over, so an expiring timer
/// must not fail an E3 that already succeeded.
#[actix::test]
async fn nothing_is_missing_after_the_aggregated_proof_exists() -> Result<()> {
    let mut state = awaiting_node_proofs(&[0, 1, 2], &[0]);
    if let PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_aggregated_proof,
        ..
    } = &mut state
    {
        *dkg_aggregated_proof = Some(dummy_proof(CircuitName::NodesFold));
    }
    let (aggregator, _history, _e3_id) = build_public_key_aggregator(state).await?;
    assert!(aggregator.missing_node_proof_parties().is_empty());
    Ok(())
}

/// Before C5 exists the aggregator is not yet in the node-proof wait.
#[actix::test]
async fn a_non_collecting_state_reports_nothing_missing() -> Result<()> {
    let (aggregator, _history, _e3_id) = build_public_key_aggregator(complete_state()).await?;
    assert!(aggregator.missing_node_proof_parties().is_empty());
    Ok(())
}

/// Budget expiry with a proof still missing must fail the E3 explicitly rather than hang.
/// Excluding the late party is impossible here: C5 is already signed over this exact honest
/// set, so the only bounded outcome is an attributable failure.
#[actix::test]
async fn expiring_the_budget_fails_the_e3_with_dkg_timeout() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_public_key_aggregator(awaiting_node_proofs(&[0, 1, 2], &[0, 2])).await?;

    aggregator.fail_on_missing_node_proofs(
        &test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGTimeout,
        }),
        std::time::Duration::from_secs(1800),
    );

    let failed = next_event(&history).await?;
    let InterfoldEventData::E3Failed(data) = failed.get_data() else {
        panic!("an expired node-proof budget must publish E3Failed, got {failed:?}");
    };
    assert_eq!(data.e3_id, e3_id);
    assert_eq!(data.reason, FailureReason::DKGTimeout);
    assert_eq!(data.failed_at_stage, E3Stage::CommitteeFinalized);
    Ok(())
}

/// The timer can fire after the last proof landed (cancel races delivery). That must be inert.
#[actix::test]
async fn expiring_the_budget_is_inert_once_every_proof_arrived() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_public_key_aggregator(awaiting_node_proofs(&[0, 1, 2], &[0, 1, 2])).await?;

    aggregator.fail_on_missing_node_proofs(
        &test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGTimeout,
        }),
        std::time::Duration::from_secs(1800),
    );

    // Nothing was published, so nothing to take. `TakeEvents` reports the timeout instead of
    // hanging, which is exactly the assertion: a late timer publishes no event at all.
    let result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(
        result.timed_out && result.events.is_empty(),
        "a late timer must not fail an E3 whose proofs all arrived, got {:?}",
        result.events
    );
    Ok(())
}
