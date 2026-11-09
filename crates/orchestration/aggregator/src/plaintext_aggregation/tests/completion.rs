// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::recovery::{batch_c7_proofs, signed_c7_result};
use super::*;
use e3_events::{
    DecryptionAggregationResponse, DkgAggregationResponse, PkAggregationProofResponse,
};

#[actix::test]
async fn missing_c6_inner_proofs_emit_e3_failed() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(generating_c7_state(), true).await?;
    aggregator.pending.c7_proofs_pending = Some(vec![dummy_proof(CircuitName::PkAggregation)]);
    aggregator.pending.honest_c6_proofs_for_agg = Some(vec![
        (0, vec![]),
        (1, vec![dummy_proof(CircuitName::ThresholdShareDecryption)]),
    ]);

    let ec = test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::None,
        reason: FailureReason::None,
    });
    aggregator.dispatch_decryption_aggregation(&ec)?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CiphertextReady
                && data.reason == FailureReason::DecryptionInvalidShares
    ));
    assert!(aggregator.pending.honest_c6_proofs_for_agg.is_none());
    assert!(aggregator
        .pending
        .decryption_aggregation_correlation
        .is_none());
    assert!(aggregator.pending.c7_proofs_pending.is_none());
    assert!(aggregator.pending.decryption_aggregator_proofs.is_none());

    Ok(())
}

#[actix::test]
async fn mock_plaintext_publication_carries_the_canonical_domain() -> Result<()> {
    let (mut aggregator, history, e3_id) =
        build_plaintext_aggregator(generating_c7_state(), false).await?;
    let c7_proof = dummy_proof(CircuitName::DecryptedSharesAggregation);
    aggregator.pending.c7_proofs_pending = Some(vec![c7_proof.clone()]);
    let ciphertexts = test_ciphertexts();
    let (_, signed) = share_with_matching_commitment(&e3_id, 0, &ciphertexts[..1]);
    aggregator.pending.honest_c6_proofs_for_agg = Some(vec![(
        0,
        signed
            .into_iter()
            .map(|proof| proof.payload.proof)
            .collect(),
    )]);
    let ec = test_ctx(EffectsEnabled::new());
    aggregator.pending.last_ec = Some(ec.clone());

    aggregator.maybe_start_decryption_aggregation(&ec)?;
    aggregator.try_publish_complete()?;
    let event = next_event(&history).await?;
    let InterfoldEventData::PlaintextAggregated(result) = event.get_data() else {
        panic!("expected plaintext publication");
    };
    let proof = &result.decryption_aggregator_proofs[0];
    assert_eq!(proof.circuit, CircuitName::DecryptionAggregator);
    assert_eq!(proof.data, c7_proof.data);
    let domain = e3_committee_hash::decryption_domain_limbs(
        e3_id.chain_id(),
        e3_id.try_into()?,
        test_decryption_domain(),
        alloy::primitives::keccak256(&ciphertexts[0][..]),
    );
    assert_eq!(
        &proof.public_signals[128..160],
        &alloy::primitives::U256::from(domain.hi).to_be_bytes::<32>()
    );
    assert_eq!(
        &proof.public_signals[160..192],
        &alloy::primitives::U256::from(domain.lo).to_be_bytes::<32>()
    );
    Ok(())
}

/// An aggregator in `GeneratingC7Proof` for two tallies, holding the verified C6 proofs of
/// parties 0 and 1 (threshold 1). Also returns the C7 proofs that bind to that batch.
async fn aggregator_awaiting_c7(
    proof_aggregation_enabled: bool,
) -> Result<(
    ThresholdPlaintextAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
    Vec<Proof>,
)> {
    let id = E3id::new("42", 1);
    let ciphertexts = test_ciphertexts();
    let (shares, c6): (Vec<_>, Vec<_>) = [0, 1]
        .into_iter()
        .map(|party| {
            let (shares, proofs) = share_with_matching_commitment(&id, party, &ciphertexts);
            let proofs = proofs
                .into_iter()
                .map(|proof| proof.payload.proof)
                .collect();
            ((party, shares), (party, proofs))
        })
        .unzip();
    let state = ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
        threshold_m: 1,
        threshold_n: 2,
        shares,
        plaintext: vec![ArcBytes::from_bytes(&0u64.to_le_bytes()); ciphertexts.len()],
    });
    let (mut aggregator, history, _) =
        build_plaintext_aggregator(state, proof_aggregation_enabled).await?;
    aggregator.pending.honest_c6_proofs_for_agg = Some(c6);
    Ok((
        aggregator,
        history,
        id,
        batch_c7_proofs(&[0, 1], ciphertexts.len()),
    ))
}

fn deliver_c7_result(aggregator: &mut ThresholdPlaintextAggregator, c7: &[Proof]) -> Result<()> {
    aggregator.handle_aggregation_proof_signed(TypedEvent::new(
        signed_c7_result(&aggregator.e3_id, c7),
        test_ctx(EffectsEnabled::new()),
    ))
}

fn deliver_zk_response(
    aggregator: &mut ThresholdPlaintextAggregator,
    correlation_id: CorrelationId,
    response: ZkResponse,
) -> Result<()> {
    let e3_id = aggregator.e3_id.clone();
    aggregator.handle_compute_response(TypedEvent::new(
        ComputeResponse::zk(response, correlation_id, e3_id),
        test_ctx(EffectsEnabled::new()),
    ))
}

fn decryption_aggregation_requests(
    events: &[InterfoldEventData],
) -> Vec<&DecryptionAggregationRequest> {
    events
        .iter()
        .filter_map(|event| match event {
            InterfoldEventData::ComputeRequest(ComputeRequest {
                request: ComputeRequestKind::Zk(ZkRequest::DecryptionAggregation(request)),
                ..
            }) => Some(request),
            _ => None,
        })
        .collect()
}

fn plaintext_publications(events: &[InterfoldEventData]) -> Vec<&PlaintextAggregated> {
    events
        .iter()
        .filter_map(|event| match event {
            InterfoldEventData::PlaintextAggregated(data) => Some(data),
            _ => None,
        })
        .collect()
}

fn final_proofs(count: usize) -> Vec<Proof> {
    (0..count as u8)
        .map(|index| {
            Proof::new(
                CircuitName::DecryptionAggregator,
                ArcBytes::from_bytes(&[index]),
                ArcBytes::from_bytes(&[2]),
            )
        })
        .collect()
}

/// The plaintext is published only after the C7 result and the final DecryptionAggregation both
/// arrived, once, with one final proof per tally. Late key-phase proofs, or answers to another
/// request, are not that result.
#[actix::test]
async fn recursive_aggregation_publishes_the_plaintext_once_after_the_final_proofs() -> Result<()> {
    let (mut aggregator, history, _, c7) = aggregator_awaiting_c7(true).await?;

    // A repeated C7 result does not start a second final aggregation.
    deliver_c7_result(&mut aggregator, &c7)?;
    deliver_c7_result(&mut aggregator, &c7)?;
    let events = published(&aggregator, &history).await?;
    let [request] = &decryption_aggregation_requests(&events)[..] else {
        panic!("the C7 result must start exactly one final aggregation");
    };
    assert_eq!(request.jobs.len(), c7.len());
    assert!(plaintext_publications(&events).is_empty());
    let correlation = aggregator
        .pending
        .decryption_aggregation_correlation
        .expect("the final aggregation is in flight");

    let proofs = final_proofs(c7.len());
    for response in [
        ZkResponse::PkAggregation(PkAggregationProofResponse {
            proof: dummy_proof(CircuitName::PkAggregation),
        }),
        ZkResponse::DkgAggregation(DkgAggregationResponse {
            proof: dummy_proof(CircuitName::PkAggregation),
        }),
        ZkResponse::DecryptionAggregation(DecryptionAggregationResponse {
            proofs: proofs.clone(),
        }),
    ] {
        deliver_zk_response(&mut aggregator, CorrelationId::new(), response)?;
    }
    assert!(plaintext_publications(&published(&aggregator, &history).await?).is_empty());

    for _ in 0..2 {
        deliver_zk_response(
            &mut aggregator,
            correlation,
            ZkResponse::DecryptionAggregation(DecryptionAggregationResponse {
                proofs: proofs.clone(),
            }),
        )?;
    }
    let events = published(&aggregator, &history).await?;
    let [published_plaintext] = &plaintext_publications(&events)[..] else {
        panic!("the final proofs must publish the plaintext exactly once");
    };
    assert_eq!(published_plaintext.decryption_aggregator_proofs, proofs);
    assert_eq!(published_plaintext.decrypted_output.len(), c7.len());
    assert!(matches!(
        aggregator.state.get(),
        Some(ThresholdPlaintextAggregatorState::Complete(_))
    ));
    Ok(())
}

#[actix::test]
async fn a_final_aggregation_with_the_wrong_proof_count_fails_the_round() -> Result<()> {
    let (mut aggregator, history, e3_id, c7) = aggregator_awaiting_c7(true).await?;
    deliver_c7_result(&mut aggregator, &c7)?;
    let correlation = aggregator
        .pending
        .decryption_aggregation_correlation
        .expect("the final aggregation is in flight");

    deliver_zk_response(
        &mut aggregator,
        correlation,
        ZkResponse::DecryptionAggregation(DecryptionAggregationResponse {
            proofs: final_proofs(c7.len() - 1),
        }),
    )?;

    let events = published(&aggregator, &history).await?;
    assert!(plaintext_publications(&events).is_empty());
    assert!(events.iter().any(|event| matches!(event,
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id && data.reason == FailureReason::DecryptionInvalidShares)));
    Ok(())
}

/// Without recursive proof aggregation the C7 result completes the round, and no second compute
/// request runs.
#[actix::test]
async fn without_recursive_aggregation_the_c7_result_publishes_the_plaintext_once() -> Result<()> {
    let (mut aggregator, history, _, c7) = aggregator_awaiting_c7(false).await?;

    deliver_c7_result(&mut aggregator, &c7)?;
    deliver_c7_result(&mut aggregator, &c7)?;

    let events = published(&aggregator, &history).await?;
    assert!(decryption_aggregation_requests(&events).is_empty());
    let [published_plaintext] = &plaintext_publications(&events)[..] else {
        panic!("the C7 result must publish the plaintext exactly once");
    };
    assert_eq!(
        published_plaintext.decryption_aggregator_proofs.len(),
        c7.len()
    );
    Ok(())
}
