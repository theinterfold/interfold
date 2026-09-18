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
    CircuitName, ComputeRequestErrorKind, EncryptionKey, Event, HistoryCollector,
    PkGenerationProofRequest, ShareComputationProofRequest, TakeEvents, ThresholdShare,
    ThresholdSharePending, Unsequenced, ZkError,
};
use e3_fhe_params::BfvPreset;
use e3_test_helpers::get_common_setup;
use e3_trbfv::{shares::BfvEncryptedShares, TrBFVError, TrBFVFailure};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

fn test_ctx(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(0)
}

async fn next_event(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<InterfoldEvent> {
    let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(!result.timed_out, "timed out waiting for an event");
    Ok(result.events.pop().expect("expected one event"))
}

#[actix::test]
async fn c0_compute_error_emits_e3_failed() -> Result<()> {
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

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGInvalidShares
    ));
    assert!(actor.pending.is_empty());

    Ok(())
}

#[actix::test]
async fn decryption_failure_helper_emits_e3_failed() -> Result<()> {
    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("45", 1);

    actor.fail_decryption_round(
        e3_id.clone(),
        &test_ctx(E3Failed {
            e3_id: e3_id.clone(),
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::DecryptionInvalidShares,
        }),
        "test decryption failure",
    );

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

/// A worker failure must fail the round whatever kind the worker reported. A `TrBFV` error was
/// previously discarded before the correlation lookup, so the round waited for a proof that no
/// longer had a pending computation.
#[actix::test]
async fn c0_trbfv_compute_error_also_emits_e3_failed() -> Result<()> {
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

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGInvalidShares
    ));
    assert!(
        actor.pending.is_empty(),
        "a failed computation must clear its pending entry"
    );

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
