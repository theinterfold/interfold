// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn late_c5_proof_is_ignored_after_completion() -> Result<()> {
    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(complete_state()).await?;
    let signed_proof = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C5PkAggregation,
            proof: dummy_proof(CircuitName::PkAggregation),
        },
        signature: ArcBytes::from_bytes(&[0u8; 65]),
    };
    let event = PkAggregationProofSigned {
        e3_id: e3_id.clone(),
        signed_proof,
    };

    aggregator
        .handle_pk_aggregation_proof_signed(TypedEvent::new(event.clone(), test_ctx(event)))?;

    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::Complete { .. })
    ));
    Ok(())
}

#[actix::test]
async fn replayed_c1_artifacts_are_ignored_after_completion() -> Result<()> {
    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(complete_state()).await?;
    let verification = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::PkGenerationProofs,
        dishonest_parties: BTreeSet::new(),
    };

    aggregator.handle_c1_verification_complete(TypedEvent::new(
        verification.clone(),
        test_ctx(verification),
    ))?;
    aggregator.add_keyshare(
        ArcBytes::from_bytes(&[4, 5, 6]),
        "0x0000000000000000000000000000000000000001".to_string(),
        0,
        None,
        &test_ctx(KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[4, 5, 6]),
            e3_id,
            node: "0x0000000000000000000000000000000000000001".to_string(),
            party_id: 0,
            signed_pk_generation_proof: None,
        }),
    )?;

    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::Complete { .. })
    ));
    Ok(())
}

#[actix::test]
async fn honest_dkg_fold_without_attestation_is_not_buffered() -> Result<()> {
    let correlation_id = CorrelationId::new();
    let mut initial_state = generating_c5_state(correlation_id);
    let PublicKeyAggregatorState::GeneratingC5Proof {
        ref mut party_nodes,
        ref mut honest_party_ids,
        ..
    } = initial_state
    else {
        unreachable!();
    };
    honest_party_ids.insert(2);
    party_nodes.insert(2, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string());

    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(initial_state).await?;
    let ec = test_ctx(DKGRecursiveAggregationComplete {
        e3_id: e3_id.clone(),
        party_id: 2,
        aggregated_proof: Some(dummy_proof(CircuitName::NodeFold)),
        fold_attestation: None,
    });

    aggregator.handle_dkg_recursive_aggregation_complete(TypedEvent::new(
        DKGRecursiveAggregationComplete {
            e3_id: e3_id.clone(),
            party_id: 2,
            aggregated_proof: Some(dummy_proof(CircuitName::NodeFold)),
            fold_attestation: None,
        },
        ec,
    ))?;

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_node_proofs, ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert!(!dkg_node_proofs.contains_key(&2));

    Ok(())
}

#[actix::test]
async fn pk_aggregation_proof_pending_carries_canonical_committee_dims() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (initial_state, threshold_n, threshold_m, circuit_h) =
        verifying_c1_non_square_state(&fhe, &e3_id)?;
    let mut aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Some(fhe),
            ckks: None,
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Micro,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(initial_state),
    );

    let dishonest: BTreeSet<u64> = (circuit_h as u64..threshold_n as u64).collect();
    aggregator.handle_c1_verification_complete(TypedEvent::new(
        ShareVerificationComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::PkGenerationProofs,
            dishonest_parties: dishonest,
        },
        test_ctx(ShareVerificationComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::PkGenerationProofs,
            dishonest_parties: BTreeSet::new(),
        }),
    ))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::PkAggregationProofPending(data)
            if data.e3_id == e3_id
                && data.proof_request.committee_n == threshold_n
                && data.proof_request.committee_h == circuit_h
                && data.proof_request.committee_threshold == threshold_m
                && data.proof_request.keyshare_bytes.len() == circuit_h
    ));

    Ok(())
}

#[actix::test]
async fn early_exclusion_keeps_full_committee_for_final_proof_binding() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (mut state, threshold_n, _threshold_m, circuit_h) =
        verifying_c1_non_square_state(&fhe, &e3_id)?;
    let PublicKeyAggregatorState::VerifyingC1 {
        submission_order,
        c1_proofs,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    submission_order.truncate(circuit_h);
    c1_proofs.truncate(circuit_h);

    let mut aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Some(fhe),
            ckks: None,
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Micro,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(state),
    );

    let verification = ShareVerificationComplete {
        e3_id,
        kind: VerificationKind::PkGenerationProofs,
        dishonest_parties: BTreeSet::new(),
    };
    aggregator.handle_c1_verification_complete(TypedEvent::new(
        verification.clone(),
        test_ctx(verification),
    ))?;

    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        honest_party_ids,
        ..
    }) = aggregator.state.get()
    else {
        panic!("expected GeneratingC5Proof state");
    };
    assert_eq!(party_nodes.len(), threshold_n);
    assert_eq!(honest_party_ids.len(), circuit_h);
    Ok(())
}
