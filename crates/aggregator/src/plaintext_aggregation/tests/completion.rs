// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

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
