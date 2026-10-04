// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use e3_crypto::SensitiveBytes;
use e3_events::{
    CircuitName, ComputeRequestErrorKind, ComputeRequestKind, DkgShareDecryptionProofRequest,
    E3Failed, E3Stage, EncryptionKey, Event, EventConstructorWithTimestamp, FailureReason,
    GetEvents, HistoryCollector, PkGenerationProofRequest, ShareComputationProofRequest,
    ThresholdShare, ThresholdSharePending, Unsequenced, ZkError,
};
use e3_fhe_params::BfvPreset;
use e3_test_helpers::get_common_setup;
use e3_trbfv::{shares::BfvEncryptedShares, TrBFVError, TrBFVFailure};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(0)
}

async fn assert_no_events(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<()> {
    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}

#[actix::test]
async fn c0_compute_error_preserves_pending_work_without_failing_the_round() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("44", 1);
    let correlation_id = CorrelationId::new();

    actor.pending.insert(
        correlation_id,
        PendingProofRequest {
            e3_id: e3_id.clone(),
            key: Arc::new(EncryptionKey::new(7, ArcBytes::from_bytes(&[1]))),
        },
    );

    actor.handle_compute_request_error(TypedEvent::new(
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("boom".to_string())),
            ComputeRequest::zk(
                ZkRequest::PkBfv(PkBfvProofRequest::new(
                    ArcBytes::from_bytes(&[1]),
                    e3_fhe_params::BfvPreset::InsecureThreshold512,
                    e3_zk_helpers::CiphernodesCommitteeSize::Minimum,
                )),
                correlation_id,
                e3_id.clone(),
            ),
        ),
        test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGInvalidShares,
        }),
    ));

    assert_no_events(&history).await?;
    assert!(actor.pending.contains_key(&correlation_id));

    Ok(())
}

#[actix::test]
async fn c0_signing_error_preserves_work_without_failing_the_round() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("not-a-uint256", 1);
    let correlation_id = CorrelationId::new();
    actor.pending.insert(
        correlation_id,
        PendingProofRequest {
            e3_id: e3_id.clone(),
            key: Arc::new(EncryptionKey::new(7, ArcBytes::from_bytes(&[1]))),
        },
    );

    actor.handle_pk_bfv_response(
        &correlation_id,
        Proof::new(
            CircuitName::PkBfv,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&[2]),
        ),
        &test_ctx(E3Failed {
            e3_id,
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGInvalidShares,
        }),
    );

    assert_no_events(&history).await?;
    assert!(actor.pending.contains_key(&correlation_id));

    Ok(())
}

/// An incorrectly typed worker failure must still correlate to the pending request without being
/// converted into evidence of invalid committee data.
#[actix::test]
async fn c0_trbfv_compute_error_preserves_pending_work() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("46", 1);
    let correlation_id = CorrelationId::new();

    actor.pending.insert(
        correlation_id,
        PendingProofRequest {
            e3_id: e3_id.clone(),
            key: Arc::new(EncryptionKey::new(7, ArcBytes::from_bytes(&[1]))),
        },
    );

    actor.handle_compute_request_error(TypedEvent::new(
        ComputeRequestError::new(
            ComputeRequestErrorKind::TrBFV(TrBFVError::GenPkShareAndSkSss(
                TrBFVFailure::from_error(&anyhow::anyhow!("pool died")),
            )),
            ComputeRequest::zk(
                ZkRequest::PkBfv(PkBfvProofRequest::new(
                    ArcBytes::from_bytes(&[1]),
                    e3_fhe_params::BfvPreset::InsecureThreshold512,
                    e3_zk_helpers::CiphernodesCommitteeSize::Minimum,
                )),
                correlation_id,
                e3_id.clone(),
            ),
        ),
        test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGInvalidShares,
        }),
    ));

    assert_no_events(&history).await?;
    assert!(actor.pending.contains_key(&correlation_id));

    Ok(())
}

#[actix::test]
async fn own_c0_reaches_the_node_fold_before_encryption_key_created() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("47", 1);
    let correlation_id = CorrelationId::new();
    actor.pending.insert(
        correlation_id,
        PendingProofRequest {
            e3_id: e3_id.clone(),
            key: Arc::new(EncryptionKey::new(7, ArcBytes::from_bytes(&[1]))),
        },
    );
    let proof = Proof::new(
        CircuitName::PkBfv,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&[2]),
    );
    let ec = test_ctx(E3Failed {
        e3_id,
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGInvalidShares,
    });

    // No ThresholdSharePending has arrived, so no seq layout exists yet.
    actor.handle_pk_bfv_response(&correlation_id, proof.clone(), &ec);

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let c0 = events.iter().position(|event| {
        matches!(event.get_data(), InterfoldEventData::DKGInnerProofReady(ready)
            if ready.seq == 0 && ready.proof == proof)
    });
    let key = events.iter().position(|event| {
        matches!(
            event.get_data(),
            InterfoldEventData::EncryptionKeyCreated(_)
        )
    });
    // EncryptionKeyCreated can end key collection, so C0 must be logged before it.
    assert!(matches!((c0, key), (Some(c0), Some(key)) if c0 < key));
    Ok(())
}

fn threshold_share_pending(e3_id: E3id, marker: u8) -> ThresholdSharePending {
    let sensitive = || SensitiveBytes::from_encrypted(&[]);
    let share_request = || ShareComputationProofRequest {
        secret_raw: sensitive(),
        secret_sss_raw: sensitive(),
        dkg_input_type: DkgInputType::SecretKey,
        params_preset: BfvPreset::InsecureThreshold512,
        committee_size: CiphernodesCommitteeSize::Minimum,
    };

    ThresholdSharePending {
        e3_id,
        full_share: Arc::new(ThresholdShare {
            party_id: 0,
            pk_share: ArcBytes::from_bytes(&[marker]),
            sk_sss: BfvEncryptedShares::default(),
            esi_sss: vec![],
        }),
        proof_request: PkGenerationProofRequest {
            pk0_share: ArcBytes::from_bytes(&[marker]),
            sk: sensitive(),
            eek: sensitive(),
            e_sm: sensitive(),
            params_preset: BfvPreset::InsecureThreshold512,
            committee_size: CiphernodesCommitteeSize::Minimum,
        },
        sk_share_computation_request: share_request(),
        e_sm_share_computation_request: share_request(),
        sk_share_encryption_requests: vec![],
        e_sm_share_encryption_requests: vec![],
        recipient_party_ids: vec![0],
    }
}

fn recovered_threshold_proofs(e3_id: E3id, count: usize) -> HashMap<E3id, BTreeMap<usize, Proof>> {
    let proofs = (1..=count)
        .map(|seq| {
            let circuit = match seq {
                1 => CircuitName::PkGeneration,
                2 => CircuitName::SkShareComputation,
                3 => CircuitName::ESmShareComputation,
                _ => CircuitName::ShareEncryption,
            };
            (
                seq,
                Proof::new(
                    circuit,
                    ArcBytes::from_bytes(&[seq as u8]),
                    ArcBytes::from_bytes(&[seq as u8 + 10]),
                ),
            )
        })
        .collect();
    HashMap::from([(e3_id, proofs)])
}

#[actix::test]
async fn restart_reuses_complete_persisted_threshold_proofs() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let e3_id = E3id::new("45", 1);
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true)
        .with_recovered_inner_proofs(recovered_threshold_proofs(e3_id.clone(), 3));
    let event = threshold_share_pending(e3_id.clone(), 0x11);

    actor.handle_threshold_share_pending(TypedEvent::new(event.clone(), test_ctx(event)));

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events
        .iter()
        .all(|event| !matches!(event.get_data(), InterfoldEventData::ComputeRequest(_))));
    assert!(actor.pending_threshold.is_empty());
    assert!(actor.threshold_correlation.is_empty());
    assert!(actor.completed_threshold.contains(&e3_id));
    Ok(())
}

#[actix::test]
async fn restart_dispatches_only_missing_threshold_proofs() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let e3_id = E3id::new("partially-recovered-threshold", 1);
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true)
        .with_recovered_inner_proofs(recovered_threshold_proofs(e3_id.clone(), 2));
    let event = threshold_share_pending(e3_id.clone(), 0x11);

    actor.handle_threshold_share_pending(TypedEvent::new(event.clone(), test_ctx(event)));

    actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let requests = events
        .iter()
        .filter(|event| matches!(event.get_data(), InterfoldEventData::ComputeRequest(_)))
        .count();
    assert_eq!(requests, 1);
    assert_eq!(actor.pending_threshold[&e3_id].total_received(), 2);
    assert_eq!(actor.threshold_correlation.len(), 1);
    Ok(())
}

#[actix::test]
async fn replayed_threshold_work_invalidates_old_correlations() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), false);
    let e3_id = E3id::new("duplicate-threshold", 1);
    let ec = test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGInvalidShares,
    });

    actor.handle_threshold_share_pending(TypedEvent::new(
        threshold_share_pending(e3_id.clone(), 0x11),
        ec.clone(),
    ));
    let first_correlations = actor
        .threshold_correlation
        .keys()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(first_correlations.len(), 3);

    actor.handle_threshold_share_pending(TypedEvent::new(
        threshold_share_pending(e3_id.clone(), 0x22),
        ec.clone(),
    ));

    assert_eq!(actor.threshold_correlation.len(), 3);
    assert!(first_correlations
        .iter()
        .all(|correlation| !actor.threshold_correlation.contains_key(correlation)));
    assert_eq!(
        &actor.pending_threshold[&e3_id].full_share.pk_share,
        &ArcBytes::from_bytes(&[0x22])
    );

    actor.handle_threshold_proof_response(
        &first_correlations[0],
        Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&[1]),
            ArcBytes::from_bytes(&[2]),
        ),
        &ec,
    );
    assert_eq!(actor.pending_threshold[&e3_id].total_received(), 0);
    Ok(())
}

#[actix::test]
async fn c4_dispatch_before_the_seq_layout_is_held_until_threshold_share_pending() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("held-c4", 1);
    let request = |dkg_input_type| DkgShareDecryptionProofRequest {
        sk_bfv: SensitiveBytes::from_encrypted(&[]),
        honest_ciphertexts_raw: vec![],
        num_honest_parties: 0,
        num_moduli: 0,
        own_plaintext_idx: None,
        own_share_raw: None,
        dkg_input_type,
        params_preset: BfvPreset::InsecureThreshold512,
        committee_size: CiphernodesCommitteeSize::Minimum,
    };
    let c4 = DecryptionShareProofsPending {
        e3_id: e3_id.clone(),
        party_id: 0,
        node: "0x00".into(),
        sk_request: request(DkgInputType::SecretKey),
        esm_requests: vec![request(DkgInputType::SmudgingNoise)],
    };
    let layout = threshold_share_pending(e3_id, 0x11);

    actor.handle_decryption_share_proofs_pending(TypedEvent::new(c4.clone(), test_ctx(c4)));
    assert!(actor.decryption_correlation.is_empty());
    actor.handle_threshold_share_pending(TypedEvent::new(layout.clone(), test_ctx(layout)));

    // With no share encryptions C0-C3 take seqs 0-3, so C4a and C4b take 4 and 5.
    let mut seqs: Vec<_> = actor
        .decryption_correlation
        .values()
        .map(|(_, _, seq)| *seq)
        .collect();
    seqs.sort_unstable();
    assert_eq!(seqs, vec![4, 5]);
    Ok(())
}

/// Canonical key authority for `id` and a C6 request whose public inputs match it.
fn c6_fixture(
    id: &E3id,
) -> Result<(
    e3_request::canonical_key::CanonicalPublicKeys,
    e3_events::ShareDecryptionProofPending,
)> {
    use alloy::primitives::Address;
    use e3_bfv_client::{client::generate_public_key, compute_pk_commitment};
    use e3_events::{ShareDecryptionProofPending, ThresholdShareDecryptionProofRequest};
    use e3_fhe_params::{BfvParamSet, BfvPreset};
    use e3_request::canonical_key::{CanonicalPublicKey, CanonicalPublicKeys};
    let params = BfvParamSet::from(BfvPreset::InsecureThreshold512);
    let pk = generate_public_key(
        params.degree,
        params.plaintext_modulus,
        params.moduli.to_vec(),
    )?;
    let key = CanonicalPublicKey {
        pk_commitment: compute_pk_commitment(
            pk.clone(),
            params.degree,
            params.plaintext_modulus,
            params.moduli.to_vec(),
        )?,
        committee: vec![
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            Address::repeat_byte(3),
        ],
        honest_committee: vec![Address::repeat_byte(1), Address::repeat_byte(3)],
        params_preset: BfvPreset::InsecureThreshold512,
        committee_size: CiphernodesCommitteeSize::Minimum,
        interfold_address: Address::repeat_byte(9),
        sk_agg_commits: vec![],
        esm_agg_commits: vec![],
    };
    let keys = CanonicalPublicKeys::default();
    keys.insert(id.clone(), key.clone())?;
    keys.remember_key(id, ArcBytes::from_bytes(&pk))?;
    let pending = ShareDecryptionProofPending {
        e3_id: id.clone(),
        party_id: 0,
        node: Address::repeat_byte(1).to_string(),
        decryption_share: vec![ArcBytes::from_bytes(&[4])],
        proof_request: ThresholdShareDecryptionProofRequest {
            ciphertext_bytes: vec![ArcBytes::from_bytes(&[5])],
            aggregated_pk_bytes: ArcBytes::from_bytes(&pk),
            sk_poly_sum: e3_crypto::SensitiveBytes::from_encrypted(&[2]),
            es_poly_sum: vec![e3_crypto::SensitiveBytes::from_encrypted(&[3])],
            d_share_bytes: vec![ArcBytes::from_bytes(&[4])],
            decryption_domain: key.domain(Address::ZERO),
            params_preset: key.params_preset,
            committee_size: key.committee_size,
        },
        redelivery: 0,
    };
    Ok((keys, pending))
}

#[actix::test]
async fn a_redelivered_c6_request_asks_for_the_proof_again() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let id = E3id::new("84", 1);
    let (keys, pending) = c6_fixture(&id)?;
    actor.canonical_keys = keys;
    let request = |redelivery| {
        let pending = e3_events::ShareDecryptionProofPending {
            redelivery,
            ..pending.clone()
        };
        TypedEvent::new(pending.clone(), test_ctx(pending))
    };
    let c6_request_ids = || async {
        actix::clock::sleep(std::time::Duration::from_millis(20)).await;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        anyhow::Ok(
            events
                .iter()
                .filter_map(|event| match event.get_data() {
                    InterfoldEventData::ComputeRequest(data)
                        if matches!(
                            data.request,
                            ComputeRequestKind::Zk(ZkRequest::ThresholdShareDecryption(_))
                        ) =>
                    {
                        Some(data.correlation_id)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
        )
    };

    let signed_redeliveries = || async {
        actix::clock::sleep(std::time::Duration::from_millis(20)).await;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        anyhow::Ok(
            events
                .iter()
                .filter_map(|event| match event.get_data() {
                    InterfoldEventData::DecryptionShareProofSigned(data) => Some(data.redelivery),
                    _ => None,
                })
                .collect::<Vec<_>>(),
        )
    };

    actor.handle_share_decryption_proof_pending(request(0));
    // A copy of the same request is a duplicate.
    actor.handle_share_decryption_proof_pending(request(0));
    assert_eq!(c6_request_ids().await?.len(), 1);

    // The keyshare redelivers its request with a fresh value, and a value replayed from before a
    // restart can come first. Each new value requests the proof again under a new ID; a copy of
    // the latest one is a duplicate.
    for redelivery in [6, 6, 1] {
        actor.handle_share_decryption_proof_pending(request(redelivery));
    }
    let ids = c6_request_ids().await?;
    assert_eq!(ids.len(), 3);
    assert_eq!(
        ids.iter().collect::<std::collections::HashSet<_>>().len(),
        3
    );

    // The answer to the latest request completes the proof, and the late answers to the earlier
    // ones are no orphans.
    let proof = Proof::new(
        CircuitName::ThresholdShareDecryption,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&[2]),
    );
    for id in [ids[2], ids[0], ids[1]] {
        actor.handle_share_decryption_proof_response(&id, vec![proof.clone()]);
    }
    assert_eq!(signed_redeliveries().await?, vec![1]);
    assert!(actor.share_decryption_correlation.is_empty());

    // A redelivery after completion means the keyshare missed the completion. Its answer is a
    // completion of its own, which EventBus deduplication passes.
    actor.handle_share_decryption_proof_pending(request(9));
    let ids = c6_request_ids().await?;
    assert_eq!(ids.len(), 4);
    actor.handle_share_decryption_proof_response(&ids[3], vec![proof]);
    assert_eq!(signed_redeliveries().await?, vec![1, 9]);
    assert!(errors
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}

#[actix::test]
async fn a_c6_request_after_the_e3_ended_is_ignored() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let id = E3id::new("84", 1);
    let (keys, pending) = c6_fixture(&id)?;
    actor.canonical_keys = keys;
    let actor = actor.start();
    let event = |data: InterfoldEventData, seq: u64| {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            seq.into(),
            None,
            e3_events::EventSource::Local,
        )
        .into_sequenced(seq)
    };

    actor
        .send(event(
            e3_events::E3RequestComplete { e3_id: id.clone() }.into(),
            1,
        ))
        .await?;
    // A redelivery that the keyshare published before it saw the end arrives late.
    actor
        .send(event(
            e3_events::ShareDecryptionProofPending {
                redelivery: 7,
                ..pending
            }
            .into(),
            2,
        ))
        .await?;

    assert_no_events(&history).await
}

#[test]
fn finished_e3s_forget_the_oldest_beyond_the_bound() {
    let mut finished = FinishedE3s::default();
    for index in 0..=MAX_FINISHED_E3S {
        finished.insert(E3id::new(index.to_string(), 1));
    }
    finished.insert(E3id::new("1", 1));
    assert!(!finished.contains(&E3id::new("0", 1)));
    assert!(finished.contains(&E3id::new("1", 1)));
    assert!(finished.contains(&E3id::new(MAX_FINISHED_E3S.to_string(), 1)));
}

#[actix::test]
async fn replayed_c6_intent_is_repaired_before_deduplication() -> Result<()> {
    use e3_ciphernode_builder::EventSystem;
    use e3_data::RepositoriesFactory;
    use e3_events::{
        AggregateConfig, AggregateId, EventConstructorWithTimestamp, EvmEventConfig,
        EvmEventConfigChain, HistoricalEvmEventsReceived, HistoricalNetSyncEventsReceived,
        NetReady, RequestRouterCheckpoint,
    };
    use e3_sync::SyncRepositoryFactory;
    use std::time::Duration;
    let id = E3id::new("83", 1);
    let (keys, pending) = c6_fixture(&id)?;
    let aggregate = AggregateId::new(1);
    let stored = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            aggregate,
            Duration::ZERO,
        )])));
    let old_bus = stored.handle()?.enable("retained-c6");
    old_bus.publish_without_context(pending.clone())?;
    old_bus.flush_event_pipeline().await?;
    let aggregate_config = AggregateConfig::new(HashMap::from([(aggregate, Duration::ZERO)]));
    let resumed = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(aggregate_config.clone());
    let bus = resumed.handle()?.enable("resumed-c6");
    let history = bus.history();
    let _actor = ProofRequestActor::setup_with_recovery(
        &bus,
        PrivateKeySigner::random(),
        false,
        HashMap::new(),
        keys.clone(),
    );
    let repositories = resumed.store()?.repositories();
    repositories
        .schema_version()
        .write_sync(&e3_sync::SCHEMA_VERSION)
        .await?;
    repositories
        .request_router_checkpoint()
        .write_sync(&RequestRouterCheckpoint::default())
        .await?;
    let evm_config = EvmEventConfig::from_config(std::collections::BTreeMap::from([(
        1,
        EvmEventConfigChain::new(0),
    )]));
    let evm_started = bus.wait_for(EventType::HistoricalEvmSyncStart);
    let net_started = bus.wait_for(EventType::HistoricalNetSyncStart);
    let history_sources = async {
        let event = evm_started.await?;
        let InterfoldEventData::HistoricalEvmSyncStart(start) = event.get_data() else {
            anyhow::bail!("expected EVM history request");
        };
        start
            .sender
            .as_ref()
            .unwrap()
            .send(HistoricalEvmEventsReceived::new(vec![], 1))
            .await?;
        net_started.await?;
        bus.publish_without_context(HistoricalNetSyncEventsReceived::new(vec![]))?;
        anyhow::Ok(())
    };
    let net_ready = async {
        Ok(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            NetReady::new().into(),
            None,
            1,
            None,
            e3_events::EventSource::Local,
        )
        .into_sequenced(1))
    };
    let reader = stored.eventstore_reader()?.seq();
    actix::clock::timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            e3_sync::sync_with_net_ready(
                &bus,
                &evm_config,
                &repositories,
                &aggregate_config,
                &reader,
                net_ready,
            ),
            history_sources,
        )
    })
    .await??;
    let mut corrected = pending.clone();
    keys.repair_request(&id, &mut corrected.proof_request)?;
    bus.publish_without_context(corrected.clone())?;
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let requests: Vec<_> = events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::ComputeRequest(data) => match &data.request {
                e3_events::ComputeRequestKind::Zk(ZkRequest::ThresholdShareDecryption(request)) => {
                    Some(request)
                }
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        requests.len(),
        1,
        "canonical replay and recovery must share one proof job"
    );
    assert_eq!(requests[0], &corrected.proof_request);
    Ok(())
}
