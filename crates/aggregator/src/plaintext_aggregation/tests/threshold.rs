// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_zk_helpers::{
    circuits::commitments::compute_threshold_decryption_share_commitment,
    circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS,
    threshold::share_decryption::{Bits, Bounds},
    Computation,
};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::Serialize;

// These actor tests inject a local verification result. The share and its commitment
// are real, but the proof bytes do not exercise the ZK verifier.
pub(super) fn share_with_matching_commitment(
    e3_id: &E3id,
    party: u64,
    ciphertexts: &[ArcBytes],
) -> (Vec<ArcBytes>, Vec<SignedProofPayload>) {
    let preset = BfvPreset::InsecureThreshold512;
    let (params, _) = e3_fhe_params::build_pair_for_preset(preset).unwrap();
    let poly = Poly::<PowerBasis>::zero(params.context_at_level(0).unwrap());
    let crt = e3_polynomial::CrtPolynomial::from_fhe_polynomial(&poly);
    let bits = Bits::compute(preset, &Bounds::compute(preset, &()).unwrap()).unwrap();
    let commitment = compute_threshold_decryption_share_commitment(
        &crt,
        bits.d_native_bit,
        MAX_MSG_NON_ZERO_COEFFS,
    );
    let (_, bytes) = commitment.to_bytes_be();
    let proofs = ciphertexts
        .iter()
        .map(|ciphertext| {
            let mut signals = [0u8; 192];
            signals[192 - bytes.len()..].copy_from_slice(&bytes);
            signals[64..96].copy_from_slice(
                &e3_bfv_client::compute_ct_commitment_with_params(ciphertext, &params).unwrap(),
            );
            let mut proof = dummy_signed_c6_proof(e3_id).payload;
            proof.proof.public_signals = ArcBytes::from_bytes(&signals);
            SignedProofPayload::sign(proof, &test_signer(party)).unwrap()
        })
        .collect();
    (
        vec![ArcBytes::from_bytes(&poly.to_bytes()); ciphertexts.len()],
        proofs,
    )
}

async fn small_aggregator() -> Result<(
    ThresholdPlaintextAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
)> {
    let state = ThresholdPlaintextAggregatorState::init(
        9,
        19,
        Seed([0; 32]),
        test_ciphertexts()[..1].to_vec(),
        test_params(),
    );
    let (mut aggregator, history, e3_id) = build_plaintext_aggregator(state, true).await?;
    aggregator.committee_size = CiphernodesCommitteeSize::Small;
    aggregator.committee_addresses = (0..19).map(|party| test_signer(party).address()).collect();
    aggregator.honest_committee_addresses = aggregator.committee_addresses[5..].to_vec();
    Ok((aggregator, history, e3_id))
}

fn collect(
    aggregator: &mut ThresholdPlaintextAggregator,
    parties: impl Iterator<Item = u64>,
) -> Result<()> {
    let ec = test_ctx(EffectsEnabled::new());
    for party in parties {
        let (share, proofs) =
            share_with_matching_commitment(&aggregator.e3_id, party, &test_ciphertexts()[..1]);
        aggregator.add_share(party, share, proofs, &ec)?;
    }
    Ok(())
}

#[actix::test]
async fn small_decrypts_with_ten_verified_shares_not_all_fourteen() -> Result<()> {
    for missing in 0..=5 {
        let (mut aggregator, history, _) = small_aggregator().await?;
        collect(&mut aggregator, 5..19 - missing)?;
        if missing == 5 {
            assert!(matches!(
                aggregator.state.get(),
                Some(ThresholdPlaintextAggregatorState::Collecting(_))
            ));
            continue;
        }
        let outcome = c6_completion(&aggregator, BTreeSet::new());
        aggregator.handle_c6_verification_complete(outcome)?;
        let event = next_event(&history).await?;
        assert!(matches!(
            event.get_data(),
            InterfoldEventData::ComputeRequest(_)
        ));
        let Some(ThresholdPlaintextAggregatorState::Computing(state)) = aggregator.state.get()
        else {
            panic!()
        };
        assert_eq!(state.shares.len(), 10);
        assert_eq!(state.shares.first().unwrap().0, 5);
        assert_eq!(aggregator.recovery.try_get()?.honest_c6_proofs.len(), 10);
    }
    Ok(())
}

#[actix::test]
async fn bad_first_share_uses_early_or_late_backup_without_failing_round() -> Result<()> {
    for backup_arrives_early in [false, true] {
        for invalid_proof in [false, true] {
            let (mut aggregator, history, _) = small_aggregator().await?;
            collect(&mut aggregator, 5..15)?;
            if !invalid_proof {
                // Check the second validation boundary with a corrupted saved share.
                aggregator
                    .state
                    .try_mutate(&test_ctx(EffectsEnabled::new()), |mut state| {
                        if let ThresholdPlaintextAggregatorState::VerifyingC6(batch) = &mut state {
                            batch.shares.insert(5, vec![ArcBytes::from_bytes(&[0])]);
                        }
                        Ok(state)
                    })?;
            }
            if backup_arrives_early {
                collect(&mut aggregator, 15..16)?;
            }
            let old_result = c6_completion(
                &aggregator,
                if invalid_proof {
                    BTreeSet::from([5])
                } else {
                    BTreeSet::new()
                },
            );
            aggregator.handle_c6_verification_complete(old_result.clone())?;
            if !backup_arrives_early {
                assert!(matches!(
                    aggregator.state.get(),
                    Some(ThresholdPlaintextAggregatorState::Collecting(_))
                ));
                collect(&mut aggregator, 15..16)?;
            }
            let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) =
                aggregator.state.get()
            else {
                panic!()
            };
            assert_eq!(
                batch.shares.keys().copied().collect::<Vec<_>>(),
                (6..16).collect::<Vec<_>>()
            );
            // A duplicate result for the previous batch must not authorize the replacement.
            aggregator.handle_c6_verification_complete(old_result)?;
            assert!(matches!(
                aggregator.state.get(),
                Some(ThresholdPlaintextAggregatorState::VerifyingC6(_))
            ));
            let replacement_result = c6_completion(&aggregator, BTreeSet::new());
            aggregator.handle_c6_verification_complete(replacement_result)?;
            assert!(matches!(
                aggregator.state.get(),
                Some(ThresholdPlaintextAggregatorState::Computing(_))
            ));
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            assert!(!events
                .iter()
                .any(|event| matches!(event.get_data(), InterfoldEventData::E3Failed(_))));
        }
    }
    Ok(())
}

#[actix::test]
async fn replayed_results_survive_restart_and_wait_for_effects_and_promotion() -> Result<()> {
    let (mut aggregator, history, _) = small_aggregator().await?;
    collect(&mut aggregator, 5..16)?;
    aggregator.effects_enabled = false;
    aggregator.is_aggregator = false;
    let rejected = c6_completion(&aggregator, BTreeSet::from([5]));
    aggregator.handle_c6_verification_complete(rejected)?;
    // Snapshot both stores, as restart hydration does, and discard process-local work.
    let state = bincode::deserialize(&bincode::serialize(&aggregator.state.try_get()?)?)?;
    let recovery = bincode::deserialize(&bincode::serialize(&aggregator.recovery.try_get()?)?)?;
    aggregator.state = test_persistable(state);
    aggregator.recovery = test_persistable(recovery);
    aggregator.pending = PendingDecryptionWork::default();
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    aggregator.effects_enabled = true;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    aggregator.is_aggregator = true;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    deliver_resume(&mut aggregator, &history).await?;
    let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) = aggregator.state.get() else {
        panic!()
    };
    assert_eq!(
        batch.shares.keys().copied().collect::<Vec<_>>(),
        (6..16).collect::<Vec<_>>()
    );
    let completion = c6_completion(&aggregator, BTreeSet::new());
    aggregator.effects_enabled = false;
    aggregator.handle_c6_verification_complete(completion)?;
    aggregator.effects_enabled = true;
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    deliver_resume(&mut aggregator, &history).await?;
    assert!(matches!(
        aggregator.state.get(),
        Some(ThresholdPlaintextAggregatorState::Computing(_))
    ));
    Ok(())
}

#[actix::test]
async fn a_network_verdict_cannot_authorize_decryption() -> Result<()> {
    let (mut aggregator, history, _) = small_aggregator().await?;
    collect(&mut aggregator, 5..15)?;
    let (payload, ec) = c6_completion(&aggregator, BTreeSet::new()).into_components();
    aggregator.handle_c6_verification_complete(TypedEvent::new(
        payload,
        ec.with_source(e3_events::EventSource::Net),
    ))?;
    assert!(aggregator.recovery.try_get()?.c6_outcomes.is_empty());
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}

#[actix::test]
async fn cached_verdict_persists_under_the_current_resume_event() -> Result<()> {
    use e3_events::{Insert, InsertBatch, StoreKeys, WithAggregateId};
    let (mut aggregator, history, _) = small_aggregator().await?;
    collect(&mut aggregator, 5..15)?;
    aggregator.effects_enabled = false;
    let outcome = c6_completion(&aggregator, BTreeSet::new());
    let aggregate = outcome.get_ctx().aggregate_id();
    aggregator.handle_c6_verification_complete(outcome)?;

    let store = InMemStore::new(false).start();
    let data = DataStore::from_in_mem(&store);
    let state_repo = Repository::new(data.scope("state"));
    let recovery_repo = Repository::new(data.scope("recovery"));
    state_repo.write_sync(&aggregator.state.try_get()?).await?;
    recovery_repo
        .write_sync(&aggregator.recovery.try_get()?)
        .await?;
    aggregator.state = state_repo.load().await?;
    aggregator.recovery = recovery_repo.load().await?;
    // Simulate a later committed snapshot. Writes under the old verdict must be rejected.
    store
        .send(InsertBatch::new(vec![Insert::new(
            StoreKeys::aggregate_seq(aggregate).into_bytes(),
            10u64.to_le_bytes().to_vec(),
        )]))
        .await??;
    aggregator.effects_enabled = true;
    // EffectsEnabled belongs to aggregate zero, not this chain. Resume through a new E3 event.
    aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
    let resumed = next_event(&history).await?;
    let InterfoldEventData::PlaintextVerificationResumed(payload) = resumed.into_data() else {
        panic!()
    };
    assert_eq!(
        InterfoldEventData::from(payload.clone()).get_aggregate_id(),
        aggregate
    );
    let resume_context =
        EventContext::<Unsequenced>::from(InterfoldEventData::from(payload.clone())).sequence(20);
    aggregator.handle_c6_resume(TypedEvent::new(payload, resume_context))?;
    assert!(matches!(
        state_repo.read().await?,
        Some(ThresholdPlaintextAggregatorState::Computing(_))
    ));
    assert_eq!(
        recovery_repo.read().await?.unwrap().honest_c6_proofs.len(),
        10
    );
    Ok(())
}

#[actix::test]
async fn a_bad_share_for_the_second_ciphertext_does_not_reserve_a_slot() -> Result<()> {
    let (mut aggregator, _history, _) = small_aggregator().await?;
    let ec = test_ctx(EffectsEnabled::new());
    let mut collecting = match aggregator.state.try_get()? {
        ThresholdPlaintextAggregatorState::Collecting(state) => state,
        _ => panic!(),
    };
    collecting.ciphertext_output = test_ciphertexts();
    aggregator.state = test_persistable(ThresholdPlaintextAggregatorState::Collecting(collecting));
    for party in 5..16 {
        let (shares, proofs) =
            share_with_matching_commitment(&aggregator.e3_id, party, &test_ciphertexts());
        let second = if party == 5 {
            ArcBytes::from_bytes(&[0])
        } else {
            shares[0].clone()
        };
        aggregator.add_share(party, vec![shares[0].clone(), second], proofs, &ec)?;
    }
    let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) = aggregator.state.get() else {
        panic!()
    };
    assert!(!batch.shares.contains_key(&5));
    assert!(batch.shares.contains_key(&15));
    let replacement = c6_completion(&aggregator, BTreeSet::new());
    aggregator.handle_c6_verification_complete(replacement)?;
    assert!(matches!(
        aggregator.state.get(),
        Some(ThresholdPlaintextAggregatorState::Computing(_))
    ));
    Ok(())
}

async fn deliver_resume(
    aggregator: &mut ThresholdPlaintextAggregator,
    history: &Addr<HistoryCollector<InterfoldEvent>>,
) -> Result<()> {
    loop {
        let event = next_event(history).await?;
        if let InterfoldEventData::PlaintextVerificationResumed(payload) = event.get_data() {
            return aggregator.handle_c6_resume(event.to_typed_event(payload.clone()));
        }
    }
}
