// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::actors::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
use actix::{Actor, Addr, Handler};
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository, ShutdownStore};
use e3_events::{
    hlc_factory::HlcFactory, BusHandle, CircuitName, ComputeRequestKind, E3Stage, E3id,
    EffectsEnabled, EventBus, EventBusConfig, EventSource, FailureReason, GetEvents,
    HistoryCollector, InterfoldEvent, InterfoldEventData, Proof, ProofPayload, Seed, Sequencer,
    StoreEventRequested, StoreEventResponse, TakeEvents, Unsequenced,
};
use e3_fhe_params::{BfvPreset, DEFAULT_BFV_PRESET};
use e3_trbfv::{
    gen_lbfv_key_shares::{EncryptedRlkWitness, GenLbfvKeySharesRequest, GenLbfvKeySharesResponse},
    lbfv_operation::LbfvOperationId,
    TrBFVRequest,
};
use std::sync::Arc;

#[derive(Default)]
struct TestEventStore {
    next_seq: u64,
}

impl Actor for TestEventStore {
    type Context = actix::Context<Self>;
}

impl Handler<StoreEventRequested> for TestEventStore {
    type Result = ();

    fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) -> Self::Result {
        let StoreEventRequested { event, sender } = msg;
        let seq = self.next_seq;
        self.next_seq += 1;
        sender.do_send(StoreEventResponse(event.into_sequenced(seq)));
    }
}

fn test_bus() -> (BusHandle, Addr<HistoryCollector<InterfoldEvent>>) {
    let event_bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
    let store = TestEventStore::default().start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    let bus = BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("test-keyshare");
    let history = bus.history();
    (bus, history)
}

fn test_state(
    e3_id: &E3id,
    keyshare_state: KeyshareState,
) -> (
    Persistable<ThresholdKeyshareState>,
    Repository<ThresholdKeyshareState>,
) {
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let state = ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        keyshare_state,
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    );
    (repo.send(Some(state)), repo)
}

fn test_recovery() -> Persistable<ThresholdKeyshareRecoveryState> {
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&store));
    repo.send(Some(ThresholdKeyshareRecoveryState::default()))
}

fn test_lbfv_generation() -> Persistable<LbfvGenerationStateV1> {
    let store = InMemStore::new(false).start();
    let repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&store));
    repo.send(None)
}

fn test_signer() -> PrivateKeySigner {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse()
        .unwrap()
}

fn secure_selection(e3_id: &E3id) -> CiphernodeSelected {
    CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: 1,
        threshold_n: 3,
        seed: Seed([0; 32]),
        error_size: ArcBytes::from_bytes(&[1]),
        params_preset: BfvPreset::SecureThreshold16384,
        params: ArcBytes::from_bytes(b"secure-16384-params"),
        party_id: 0,
        committee: vec![
            test_signer().address().to_string(),
            Address::repeat_byte(0xfe).to_string(),
            Address::repeat_byte(0xff).to_string(),
        ],
    }
}

fn ready_state() -> ReadyForDecryption {
    ReadyForDecryption {
        pk_share: ArcBytes::from_bytes(&[1]),
        sk_poly_sum: SensitiveBytes::from_encrypted(&[2]),
        es_poly_sum: vec![SensitiveBytes::from_encrypted(&[3])],
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}

async fn start_actor_with_state(
    keyshare_state: KeyshareState,
) -> Result<(
    Addr<ThresholdKeyshare>,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
    Repository<ThresholdKeyshareState>,
)> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let (state, repo) = test_state(&e3_id, keyshare_state);
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        recovery: test_recovery(),
        lbfv_generation: test_lbfv_generation(),
        signer: test_signer(),
    })
    .start();

    Ok((actor, history, e3_id, repo))
}

async fn start_actor() -> Result<(
    Addr<ThresholdKeyshare>,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
    Repository<ThresholdKeyshareState>,
)> {
    start_actor_with_state(KeyshareState::Init).await
}

async fn next_event(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<InterfoldEvent> {
    let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(!result.timed_out, "timed out waiting for an event");
    Ok(result.events.pop().expect("expected one event"))
}

async fn next_events(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    count: usize,
) -> Result<Vec<InterfoldEvent>> {
    let result = history
        .send(TakeEvents::<InterfoldEvent>::new(count))
        .await?;
    assert!(!result.timed_out, "timed out waiting for events");
    assert_eq!(result.events.len(), count, "expected {count} events");
    Ok(result.events)
}

#[actix::test]
async fn encryption_key_collection_failure_preserves_telemetry_and_emits_e3_failed() -> Result<()> {
    let (actor, history, e3_id, repo) = start_actor().await?;
    let failure = EncryptionKeyCollectionFailed {
        e3_id,
        reason: "missing encryption keys".to_string(),
        missing_parties: vec![2, 3],
    };

    actor.send(failure.clone()).await?;

    let mut events = next_events(&history, 2).await?;
    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::EncryptionKeyCollectionFailed(data) if data == failure
    ));

    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGTimeout
    ));
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Failed {
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGTimeout,
        }
    ));

    Ok(())
}

#[actix::test]
async fn terminal_failure_stops_after_a_sidecar_cleanup_write_rejection() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let (state, state_repo) = test_state(&e3_id, KeyshareState::Init);
    let lbfv_store = InMemStore::new(false).start();
    let lbfv_repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&lbfv_store));
    let mut lbfv_state = LbfvGenerationStateV1::from_selection(
        &secure_selection(&e3_id),
        Address::repeat_byte(0x11),
        test_signer().address(),
        4,
    )?;
    let mut request = GenLbfvKeySharesRequest {
        operation_id: LbfvOperationId([0; 32]),
        session_id: lbfv_state.context.proof_session_id.0,
        party_id: lbfv_state.context.party_id,
        secret_key_bytes: SensitiveBytes::from_encrypted(&[4]),
        generation_seed: SensitiveBytes::from_encrypted(&[5]),
        params_preset: BfvPreset::SecureThreshold16384,
        ciphertext_level: 0,
        key_level: 0,
    };
    request.operation_id = request.expected_operation_id();
    lbfv_state.record_generation_request(request)?;
    let lbfv_generation = lbfv_repo.send(Some(lbfv_state));
    lbfv_store.send(ShutdownStore).await??;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::SecureDkg16384,
        interfold_address: Address::repeat_byte(0x11),
        recovery: test_recovery(),
        lbfv_generation,
        signer: test_signer(),
    })
    .start();
    let failure = EncryptionKeyCollectionFailed {
        e3_id: e3_id.clone(),
        reason: "missing encryption keys".to_string(),
        missing_parties: vec![2],
    };

    actor.send(failure).await?;

    let events = next_events(&history, 2).await?;
    assert!(matches!(
        events[1].get_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id && data.reason == FailureReason::DKGTimeout
    ));
    assert!(matches!(
        state_repo
            .read()
            .await?
            .expect("persisted keyshare state")
            .state,
        KeyshareState::Failed {
            reason: FailureReason::DKGTimeout,
            ..
        }
    ));
    assert!(actor.send(Die).await.is_err());
    Ok(())
}

#[actix::test]
async fn threshold_share_collection_failure_preserves_telemetry_and_emits_e3_failed() -> Result<()>
{
    let (actor, history, e3_id, repo) = start_actor().await?;
    let failure = ThresholdShareCollectionFailed {
        e3_id,
        reason: "missing threshold shares".to_string(),
        missing_parties: vec![4, 5],
    };

    actor.send(failure.clone()).await?;

    let mut events = next_events(&history, 2).await?;
    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ThresholdShareCollectionFailed(data) if data == failure
    ));

    let event = events.remove(0);
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGTimeout
    ));
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Failed {
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DKGTimeout,
        }
    ));

    Ok(())
}

#[actix::test]
async fn decryption_key_shared_collection_failure_emits_e3_failed() -> Result<()> {
    let (actor, history, e3_id, repo) = start_actor().await?;
    let failure = DecryptionKeySharedCollectionFailed {
        e3_id,
        reason: "missing decryption key shares".to_string(),
        missing_parties: vec![6, 7],
    };

    actor.send(failure.clone()).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == failure.e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DecryptionTimeout
    ));
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Failed {
            failed_at_stage: E3Stage::CommitteeFinalized,
            reason: FailureReason::DecryptionTimeout,
        }
    ));

    Ok(())
}

#[actix::test]
async fn restart_redrives_a_persisted_terminal_failure() -> Result<()> {
    let failed_at_stage = E3Stage::CommitteeFinalized;
    let reason = FailureReason::DKGTimeout;
    let (actor, history, e3_id, _) = start_actor_with_state(KeyshareState::Failed {
        failed_at_stage: failed_at_stage.clone(),
        reason: reason.clone(),
    })
    .await?;
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == failed_at_stage
                && data.reason == reason
    ));

    Ok(())
}

#[actix::test]
async fn restart_repairs_a_torn_lbfv_terminal_failure() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let failed_at_stage = E3Stage::CommitteeFinalized;
    let reason = FailureReason::DKGInvalidShares;
    let (state, _) = test_state(
        &e3_id,
        KeyshareState::Failed {
            failed_at_stage: failed_at_stage.clone(),
            reason: reason.clone(),
        },
    );
    let lbfv_store = InMemStore::new(false).start();
    let lbfv_repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&lbfv_store));
    let mut lbfv_state = LbfvGenerationStateV1::from_selection(
        &secure_selection(&e3_id),
        Address::repeat_byte(0x11),
        test_signer().address(),
        4,
    )?;
    let mut request = GenLbfvKeySharesRequest {
        operation_id: LbfvOperationId([0; 32]),
        session_id: lbfv_state.context.proof_session_id.0,
        party_id: lbfv_state.context.party_id,
        secret_key_bytes: SensitiveBytes::from_encrypted(&[4]),
        generation_seed: SensitiveBytes::from_encrypted(&[5]),
        params_preset: BfvPreset::SecureThreshold16384,
        ciphertext_level: 0,
        key_level: 0,
    };
    request.operation_id = request.expected_operation_id();
    lbfv_state.record_generation_request(request.clone())?;
    lbfv_state.record_generation_response(GenLbfvKeySharesResponse {
        operation_id: request.operation_id,
        public_key_share_bytes: ArcBytes::from_bytes(b"public-key-share"),
        rlk_share_bytes: ArcBytes::from_bytes(b"relinearization-key-share"),
        witness: EncryptedRlkWitness {
            r_bytes: SensitiveBytes::from_encrypted(&[6]),
            errors_d0_bytes: (0..5)
                .map(|row| SensitiveBytes::from_encrypted(&[row]))
                .collect(),
            errors_d2_bytes: (5..10)
                .map(|row| SensitiveBytes::from_encrypted(&[row]))
                .collect(),
        },
    })?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::SecureDkg16384,
        interfold_address: Address::repeat_byte(0x11),
        recovery: test_recovery(),
        lbfv_generation: lbfv_repo.send(Some(lbfv_state)),
        signer: test_signer(),
    })
    .start();
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::E3Failed(data)
            if data.e3_id == e3_id
                && data.failed_at_stage == failed_at_stage
                && data.reason == reason
    ));
    let repaired = lbfv_repo.read().await?.expect("persisted l-BFV state");
    assert!(repaired.failure.is_some());
    assert!(repaired.generation_request.is_none());
    assert!(repaired.generation_response.is_none());
    Ok(())
}

#[actix::test]
async fn restart_redrives_a_decryption_share_compute_request() -> Result<()> {
    let decrypting = Decrypting {
        pk_share: ArcBytes::from_bytes(&[1]),
        sk_poly_sum: SensitiveBytes::from_encrypted(&[2]),
        es_poly_sum: vec![SensitiveBytes::from_encrypted(&[3])],
        ciphertext_output: vec![ArcBytes::from_bytes(&[4])],
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    };
    let (actor, history, e3_id, _) =
        start_actor_with_state(KeyshareState::Decrypting(decrypting)).await?;
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ComputeRequest(data)
            if data.e3_id == e3_id
                && matches!(
                    data.request,
                    ComputeRequestKind::TrBFV(TrBFVRequest::CalculateDecryptionShare(_))
                )
    ));

    Ok(())
}

#[actix::test]
async fn restart_skips_dkg_work_after_public_key_context_is_persisted() -> Result<()> {
    let e3_id = E3id::new("42", 1);
    let ready = ReadyForDecryption {
        pk_share: ArcBytes::from_bytes(&[1]),
        sk_poly_sum: SensitiveBytes::from_encrypted(&[2]),
        es_poly_sum: vec![SensitiveBytes::from_encrypted(&[3])],
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    };
    let (bus, history) = test_bus();
    let (mut state, _) = test_state(&e3_id, KeyshareState::ReadyForDecryption(ready));
    state.try_mutate_without_context(|mut state| {
        state.keyshare_published = true;
        state.aggregated_pk = Some(ArcBytes::from_bytes(&[4]));
        state.decryption_domain = Some(e3_committee_hash::DecryptionDomainContext {
            interfold_address: Address::ZERO,
            committee_hash: [5; 32].into(),
            committee_public_key: [6; 32].into(),
        });
        Ok(state)
    })?;
    let recovery_store = InMemStore::new(false).start();
    let recovery_repo =
        Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&recovery_store));
    let recovery = recovery_repo.send(Some(ThresholdKeyshareRecoveryState {
        keyshare_publish_authorized: true,
        ..Default::default()
    }));
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        recovery,
        lbfv_generation: test_lbfv_generation(),
        signer: test_signer(),
    })
    .start();
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;
    actix::clock::sleep(std::time::Duration::from_millis(25)).await;

    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events.is_empty(), "restart replayed superseded DKG work");
    Ok(())
}

#[actix::test]
async fn restart_redrives_the_durable_lbfv_generation_request() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let (state, _) = test_state(&e3_id, KeyshareState::ReadyForDecryption(ready_state()));
    let lbfv_store = InMemStore::new(false).start();
    let lbfv_repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&lbfv_store));
    let mut lbfv_state = LbfvGenerationStateV1::from_selection(
        &secure_selection(&e3_id),
        Address::repeat_byte(0x11),
        test_signer().address(),
        4,
    )?;
    let mut request = GenLbfvKeySharesRequest {
        operation_id: LbfvOperationId([0; 32]),
        session_id: lbfv_state.context.proof_session_id.0,
        party_id: lbfv_state.context.party_id,
        secret_key_bytes: SensitiveBytes::from_encrypted(&[4]),
        generation_seed: SensitiveBytes::from_encrypted(&[5]),
        params_preset: BfvPreset::SecureThreshold16384,
        ciphertext_level: 0,
        key_level: 0,
    };
    request.operation_id = request.expected_operation_id();
    lbfv_state.record_generation_request(request.clone())?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::SecureDkg16384,
        interfold_address: Address::repeat_byte(0x11),
        recovery: test_recovery(),
        lbfv_generation: lbfv_repo.send(Some(lbfv_state)),
        signer: test_signer(),
    })
    .start();
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ComputeRequest(data)
            if matches!(
                &data.request,
                ComputeRequestKind::TrBFV(TrBFVRequest::GenLbfvKeyShares(redriven))
                    if redriven == &request
            )
    ));
    Ok(())
}

#[actix::test]
async fn restart_redrives_all_missing_lbfv_row_requests() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let (state, _) = test_state(&e3_id, KeyshareState::ReadyForDecryption(ready_state()));
    let lbfv_store = InMemStore::new(false).start();
    let lbfv_repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&lbfv_store));
    let mut lbfv_state = LbfvGenerationStateV1::from_selection(
        &secure_selection(&e3_id),
        Address::repeat_byte(0x11),
        test_signer().address(),
        4,
    )?;
    let mut request = GenLbfvKeySharesRequest {
        operation_id: LbfvOperationId([0; 32]),
        session_id: lbfv_state.context.proof_session_id.0,
        party_id: lbfv_state.context.party_id,
        secret_key_bytes: SensitiveBytes::from_encrypted(&[4]),
        generation_seed: SensitiveBytes::from_encrypted(&[5]),
        params_preset: BfvPreset::SecureThreshold16384,
        ciphertext_level: 0,
        key_level: 0,
    };
    request.operation_id = request.expected_operation_id();
    lbfv_state.record_generation_request(request.clone())?;
    lbfv_state.record_generation_response(GenLbfvKeySharesResponse {
        operation_id: request.operation_id,
        public_key_share_bytes: ArcBytes::from_bytes(b"public-key-share"),
        rlk_share_bytes: ArcBytes::from_bytes(b"relinearization-key-share"),
        witness: EncryptedRlkWitness {
            r_bytes: SensitiveBytes::from_encrypted(&[6]),
            errors_d0_bytes: (0..5)
                .map(|row| SensitiveBytes::from_encrypted(&[row]))
                .collect(),
            errors_d2_bytes: (5..10)
                .map(|row| SensitiveBytes::from_encrypted(&[row]))
                .collect(),
        },
    })?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::SecureDkg16384,
        interfold_address: Address::repeat_byte(0x11),
        recovery: test_recovery(),
        lbfv_generation: lbfv_repo.send(Some(lbfv_state)),
        signer: test_signer(),
    })
    .start();
    let effects_enabled = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(effects_enabled).await?;

    let events = next_events(&history, 10).await?;
    let mut pk_rows = BTreeSet::new();
    let mut rlk_rows = BTreeSet::new();
    for event in events {
        let InterfoldEventData::ComputeRequest(data) = event.into_data() else {
            panic!("expected an l-BFV proof request");
        };
        let ComputeRequestKind::Zk(request) = data.request else {
            panic!("expected an l-BFV ZK request");
        };
        match request {
            ZkRequest::LbfvPkGeneration(request) => {
                request.validate_operation_id()?;
                pk_rows.insert(request.row_index);
            }
            ZkRequest::RlkGeneration(request) => {
                request.validate_operation_id()?;
                rlk_rows.insert(request.row_index);
            }
            _ => panic!("expected an l-BFV generation proof request"),
        }
    }
    assert_eq!(pk_rows, BTreeSet::from([0, 1, 2, 3, 4]));
    assert_eq!(rlk_rows, BTreeSet::from([0, 1, 2, 3, 4]));
    Ok(())
}

#[actix::test]
async fn secure_keyshare_publication_waits_for_the_lbfv_bundle() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("42", 1);
    let mut ready = ready_state();
    ready.signed_pk_generation_proof = Some(SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C1PkGeneration,
            proof: Proof::new(
                CircuitName::PkGeneration,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&[]),
            ),
        },
        &test_signer(),
    )?);
    let (state, state_repo) = test_state(&e3_id, KeyshareState::ReadyForDecryption(ready));
    let recovery_store = InMemStore::new(false).start();
    let recovery_repo =
        Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&recovery_store));
    let lbfv_store = InMemStore::new(false).start();
    let lbfv_repo = Repository::<LbfvGenerationStateV1>::new(DataStore::from_in_mem(&lbfv_store));
    let lbfv_state = LbfvGenerationStateV1::from_selection(
        &secure_selection(&e3_id),
        Address::repeat_byte(0x11),
        test_signer().address(),
        4,
    )?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::SecureDkg16384,
        interfold_address: Address::repeat_byte(0x11),
        recovery: recovery_repo.send(Some(ThresholdKeyshareRecoveryState::default())),
        lbfv_generation: lbfv_repo.send(Some(lbfv_state)),
        signer: test_signer(),
    });
    let trigger = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.publish_keyshare_created(trigger.get_ctx().clone())?;
    actix::clock::sleep(std::time::Duration::from_millis(25)).await;

    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    assert!(
        !state_repo
            .read()
            .await?
            .expect("persisted keyshare state")
            .keyshare_published
    );
    assert!(
        recovery_repo
            .read()
            .await?
            .expect("persisted recovery state")
            .keyshare_publish_authorized
    );
    Ok(())
}
