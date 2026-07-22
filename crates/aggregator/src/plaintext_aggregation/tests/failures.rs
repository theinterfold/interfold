// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn decryption_collection_timeout_fails_round_while_collecting() -> Result<()> {
    let (aggregator, history, _) = build_plaintext_aggregator(collecting_state(), true).await?;
    let addr = aggregator.start();

    addr.send(DecryptionCollectionTimeout).await?;

    let event = next_event(&history).await?;
    assert!(
        matches!(
            event.into_data(),
            InterfoldEventData::E3Failed(data)
                if data.reason == FailureReason::DecryptionTimeout
        ),
        "expected E3Failed with DecryptionTimeout when collection window elapses"
    );
    Ok(())
}

#[actix::test]
async fn expired_persisted_collection_deadline_fails_without_a_new_share() -> Result<()> {
    let (aggregator, history, _) =
        build_plaintext_aggregator(collecting_state_with_deadline(0), true).await?;
    let _addr = aggregator.start();

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.reason == FailureReason::DecryptionTimeout
    ));
    Ok(())
}

#[actix::test]
async fn threshold_decryption_compute_error_emits_e3_failed() -> Result<()> {
    let correlation_id = CorrelationId::new();
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(computing_state(), true).await?;
    aggregator.pending.threshold_decryption_correlation = Some(correlation_id);

    let request = ComputeRequest::trbfv(
        TrBFVRequest::CalculateThresholdDecryption(CalculateThresholdDecryptionRequest {
            ciphertexts: vec![ArcBytes::from_bytes(&[8])],
            trbfv_config: TrBFVConfig::new(test_params(), 2, 1),
            d_share_polys: vec![(0, vec![ArcBytes::from_bytes(&[7])])],
        }),
        correlation_id,
        e3_id.clone(),
    );

    aggregator.handle_compute_request_error(TypedEvent::new(
        ComputeRequestError::new(
            ComputeRequestErrorKind::TrBFV(e3_trbfv::TrBFVError::CalculateThresholdDecryption(
                "boom".into(),
            )),
            request,
        ),
        test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        }),
    ))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CiphertextReady
                && data.reason == FailureReason::DecryptionInvalidShares
    ));
    assert!(aggregator
        .pending
        .threshold_decryption_correlation
        .is_none());

    Ok(())
}

#[actix::test]
async fn insufficient_honest_c6_shares_emit_e3_failed() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(verifying_c6_state(), true).await?;

    aggregator.handle_c6_verification_complete(TypedEvent::new(
        ShareVerificationComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ThresholdDecryptionProofs,
            dishonest_parties: BTreeSet::from([1]),
        },
        test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::None,
            reason: FailureReason::None,
        }),
    ))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CiphertextReady
                && data.reason == FailureReason::DecryptionInvalidShares
    ));

    Ok(())
}

#[actix::test]
async fn decryption_aggregation_compute_error_emits_e3_failed() -> Result<()> {
    let correlation_id = CorrelationId::new();
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(generating_c7_state(), true).await?;
    aggregator.pending.c7_proofs_pending = Some(vec![dummy_proof(CircuitName::PkAggregation)]);
    aggregator.pending.honest_c6_proofs_for_agg = Some(vec![(
        0,
        vec![dummy_proof(CircuitName::ThresholdShareDecryption)],
    )]);
    aggregator.pending.decryption_aggregation_correlation = Some(correlation_id);
    aggregator.pending.last_ec = Some(test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::None,
        reason: FailureReason::None,
    }));

    let request = ComputeRequest::zk(
        ZkRequest::DecryptionAggregation(DecryptionAggregationRequest {
            c6_total_slots: 1,
            jobs: Vec::new(),
            committee_addresses: vec![test_committee_address()],
            params_preset: BfvPreset::InsecureThreshold512,
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

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CiphertextReady
                && data.reason == FailureReason::DecryptionInvalidShares
    ));
    assert!(aggregator
        .pending
        .decryption_aggregation_correlation
        .is_none());
    assert!(aggregator.pending.c7_proofs_pending.is_none());

    Ok(())
}
