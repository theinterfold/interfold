// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn dkg_aggregation_compute_error_preserves_pending_work() -> Result<()> {
    let correlation_id = CorrelationId::new();
    let (mut aggregator, history, e3_id) =
        build_public_key_aggregator(generating_c5_state(correlation_id)).await?;

    let request = ComputeRequest::zk(
        ZkRequest::DkgAggregation(DkgAggregationRequest {
            node_fold_proofs: vec![dummy_proof(CircuitName::PkAggregation)],
            nodes_fold_proof: None,
            c5_proof: dummy_proof(CircuitName::PkAggregation),
            party_ids: vec![0],
            committee_addresses: vec!["0x0000000000000000000000000000000000000001"
                .parse()
                .expect("test address")],
            params_preset: BfvPreset::InsecureThreshold,
            committee_size: CiphernodesCommitteeSize::Minimum,
        }),
        correlation_id,
        e3_id.clone(),
    );

    aggregator.handle_compute_request_error(TypedEvent::new(
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("boom".to_string())),
            request,
        ),
        test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        }),
    ))?;

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_aggregation_correlation,
        c5_proof_pending,
        ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert_eq!(dkg_aggregation_correlation, Some(correlation_id));
    assert!(c5_proof_pending.is_some());

    Ok(())
}

#[actix::test]
async fn mixed_test_modes_preserve_work_without_failing_the_round() -> Result<()> {
    let correlation_id = CorrelationId::new();
    let mut initial_state = generating_c5_state(correlation_id);
    let PublicKeyAggregatorState::GeneratingC5Proof {
        ref mut dkg_aggregation_correlation,
        ref mut dkg_node_proofs,
        ref mut honest_party_ids,
        ..
    } = initial_state
    else {
        unreachable!();
    };
    *dkg_aggregation_correlation = None;
    honest_party_ids.extend([0, 1]);
    dkg_node_proofs.insert(0, Some(dummy_proof(CircuitName::PkAggregation)));
    dkg_node_proofs.insert(1, None);

    let (mut aggregator, history, e3_id) = build_public_key_aggregator(initial_state).await?;
    let ec = test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::None,
        reason: FailureReason::None,
    });

    aggregator.try_dispatch_dkg_aggregation(&ec)?;

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_aggregation_correlation,
        c5_proof_pending,
        ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert!(dkg_aggregation_correlation.is_none());
    assert!(c5_proof_pending.is_some());

    Ok(())
}
