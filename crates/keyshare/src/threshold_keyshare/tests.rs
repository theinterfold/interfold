// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::actors::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
use actix::{Actor, Addr, Handler};
use alloy::primitives::Address;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository};
use e3_events::{
    hlc_factory::HlcFactory, BusHandle, ComputeRequestKind, ComputeResponse, CorrelationId,
    E3Stage, E3id, EffectsEnabled, EventBus, EventBusConfig, EventSource, FailureReason, GetEvents,
    HistoryCollector, InterfoldEvent, InterfoldEventData, Seed, Sequencer, StoreEventRequested,
    StoreEventResponse, TakeEvents, Unsequenced,
};
use e3_fhe_params::DEFAULT_BFV_PRESET;
use std::sync::Arc;
use std::time::Duration;

use actix::clock::sleep;
use anyhow::bail;

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

/// After a restart in `ReadyForDecryption` with no peer `DecryptionKeyShared` yet persisted,
/// recovery used to skip the collector (it only rebuilt one when there were shares to
/// replay). The first peer share then hit the "no collector (sole honest party)" branch in
/// `route_events` and was dropped, and with no collector there was no decryption timeout
/// either — the node sat in `ReadyForDecryption` forever. The collector must exist whenever
/// peer shares are expected. Here the DKG start is long past, so the rebuilt collector's
/// DKG-relative timeout fires at once and the observable proof is the failure it emits.
#[actix::test]
async fn restart_ready_for_decryption_without_shares_rebuilds_the_collector() -> Result<()> {
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
    let e3_id = E3id::new("42", 1);
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let mut state = ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        KeyshareState::ReadyForDecryption(ready),
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    );
    // Two honest peers owe us a share; the DKG started long ago so the timeout is due.
    state.honest_parties = Some([0, 1, 2].into_iter().collect());
    state.dkg_started_at_unix_secs = Some(1);
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state: repo.send(Some(state)),
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        recovery: test_recovery(),
    })
    .start();

    actor
        .send(
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                EffectsEnabled::new().into(),
                None,
                1,
                None,
                EventSource::Local,
            )
            .into_sequenced(1),
        )
        .await?;

    // The collector's timeout is the only thing that can produce this after a restart with
    // zero persisted shares. Before the fix there was no collector, hence no timeout, hence
    // nothing on the bus — this call would time out.
    let event = next_event(&history).await?;
    assert!(
        matches!(
            event.get_data(),
            InterfoldEventData::E3Failed(data)
                if data.e3_id == e3_id && data.reason == FailureReason::DecryptionTimeout
        ),
        "the rebuilt collector must own the decryption timeout after a restart; got {:?}",
        event.event_type()
    );
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Failed {
            reason: FailureReason::DecryptionTimeout,
            ..
        }
    ));
    Ok(())
}

/// A restart inside the DKG window drives `CalculateDecryptionKey` twice: the event-store
/// replay re-forwards the original `ComputeRequest`, and the re-driven
/// `ShareVerificationComplete` publishes a second one with a fresh correlation id, so the
/// effect gate cannot dedup them. The first response moves the actor to
/// `ReadyForDecryption` and clears the pending C4 inputs; the second used to hit "No pending
/// share decryption data" and surface as an `InterfoldError` on an otherwise healthy node
/// (Round 10, cn4). A response that arrives after the key is derived must be a no-op.
#[actix::test]
async fn a_second_calculate_decryption_key_response_is_ignored_not_an_error() -> Result<()> {
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
    let e3_id = E3id::new("43", 1);
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let state = ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        KeyshareState::ReadyForDecryption(ready),
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    );
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state: repo.send(Some(state)),
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        recovery: test_recovery(),
    })
    .start();

    // The late/duplicate response, exactly what the second compute produces.
    let response = ComputeResponse::trbfv(
        e3_trbfv::TrBFVResponse::CalculateDecryptionKey(
            e3_trbfv::calculate_decryption_key::CalculateDecryptionKeyResponse {
                sk_poly_sum: SensitiveBytes::from_encrypted(&[9]),
                es_poly_sum: vec![SensitiveBytes::from_encrypted(&[9])],
            },
        ),
        CorrelationId::new(),
        e3_id.clone(),
    );
    actor
        .send(
            InterfoldEvent::<Unsequenced>::new_with_timestamp(
                response.into(),
                None,
                1,
                None,
                EventSource::Local,
            )
            .into_sequenced(1),
        )
        .await?;
    sleep(Duration::from_millis(100)).await;

    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let errors: Vec<_> = events
        .iter()
        .filter(|event| matches!(event.get_data(), InterfoldEventData::InterfoldError(_)))
        .collect();
    assert!(
        errors.is_empty(),
        "a duplicate CalculateDecryptionKey response must be ignored, got {errors:?}"
    );
    // And the derived key was not overwritten by the stray response.
    let persisted = repo.read().await?.expect("persisted keyshare state");
    let KeyshareState::ReadyForDecryption(after) = persisted.state else {
        bail!("state must remain ReadyForDecryption");
    };
    assert_eq!(after.pk_share, ArcBytes::from_bytes(&[1]));
    Ok(())
}

/// After a restart mid-DKG, recovery rebuilds the share collector from persisted peer shares
/// before it redrives this node's own share generation. Peer shares are already on the wire,
/// so the collector completes while the local state is still `GeneratingThresholdShare`. The
/// collector cancels its timeout on completion and never re-emits, so the message must be
/// held rather than rejected — otherwise the DKG stalls with no timer left to fail it.
#[actix::test]
async fn all_shares_collected_before_own_generation_is_held_not_dropped() -> Result<()> {
    let generating = GeneratingThresholdShareData {
        pk_share: None,
        sk_sss: None,
        esi_sss: None,
        e_sm_raw: None,
        sk_bfv: SensitiveBytes::from_encrypted(&[1]),
        pk_bfv: ArcBytes::from_bytes(&[2]),
        collected_encryption_keys: Vec::new(),
        ciphernode_selected: None,
        proof_request_data: None,
    };
    let (actor, history, _e3_id, repo) =
        start_actor_with_state(KeyshareState::GeneratingThresholdShare(generating)).await?;

    let ctx = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1)
    .get_ctx()
    .clone();
    let collected = TypedEvent::new(
        AllThresholdSharesCollected::new(HashMap::new(), HashMap::new()),
        ctx,
    );

    actor.send(collected).await?;

    // Before the fix this produced an `InterfoldError("Invalid state")` on the bus and the
    // shares were gone for good. Now nothing is published: the message is parked.
    let result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(
        result.timed_out || result.events.is_empty(),
        "AllThresholdSharesCollected in GeneratingThresholdShare must be held, not turned \
         into an error event; got {:?}",
        result.events
    );

    // The state was not disturbed by the early arrival.
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::GeneratingThresholdShare(_)
    ));

    Ok(())
}

/// The live case: a node restarted mid-DKG is still collecting encryption keys while its
/// peers — who already hold its key — finish and send their threshold shares. The collector
/// completes two states early. Observed on a 5-node swarm: `kill -9` during DKG left the node
/// permanently stalled with `InterfoldError("Invalid state")` and no timer to fail the E3.
#[actix::test]
async fn all_shares_collected_while_collecting_encryption_keys_is_held_not_dropped() -> Result<()> {
    let e3_id = E3id::new("1234", 1);
    let collecting = CollectingEncryptionKeysData {
        sk_bfv: SensitiveBytes::from_encrypted(&[1]),
        pk_bfv: ArcBytes::from_bytes(&[2]),
        ciphernode_selected: CiphernodeSelected {
            e3_id: e3_id.clone(),
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0u8; 32]),
            error_size: ArcBytes::from_bytes(&[0]),
            params_preset: DEFAULT_BFV_PRESET,
            params: ArcBytes::from_bytes(b"params"),
            party_id: 0,
            committee: Vec::new(),
        },
    };
    let (actor, history, _e3_id, repo) =
        start_actor_with_state(KeyshareState::CollectingEncryptionKeys(collecting)).await?;

    let ctx = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1)
    .get_ctx()
    .clone();
    actor
        .send(TypedEvent::new(
            AllThresholdSharesCollected::new(HashMap::new(), HashMap::new()),
            ctx,
        ))
        .await?;

    let result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(
        result.timed_out || result.events.is_empty(),
        "AllThresholdSharesCollected in CollectingEncryptionKeys must be held, not turned \
         into an error event; got {:?}",
        result.events
    );
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::CollectingEncryptionKeys(_)
    ));

    Ok(())
}
