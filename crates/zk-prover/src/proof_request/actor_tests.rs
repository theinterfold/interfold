// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use e3_events::{
    ComputeRequestErrorKind, EncryptionKey, Event, HistoryCollector, TakeEvents, Unsequenced,
    ZkError,
};
use e3_test_helpers::get_common_setup;
use e3_trbfv::{TrBFVError, TrBFVFailure};
use e3_utils::utility_types::ArcBytes;

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
