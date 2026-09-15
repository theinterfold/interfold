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
    hlc_factory::HlcFactory, AggregatorChanged, BusHandle, CircuitName, ComputeRequestKind,
    DecryptionKeyShared, DkgCoordination, DkgCoordinationKind, DkgDealer, E3Stage, E3id,
    EffectsEnabled, EncryptionKey, EncryptionKeyCreated, Event, EventBus, EventBusConfig,
    EventSource, FailureReason, GetEvents, HistoryCollector, InterfoldEvent, InterfoldEventData,
    Proof, ProofPayload, ProofType, Sequencer, SignedProofPayload, StoreEventRequested,
    StoreEventResponse, TakeEvents, Unsequenced, VerificationKind,
};
use e3_fhe_params::DEFAULT_BFV_PRESET;
use std::collections::BTreeSet;
use std::sync::Arc;

#[actix::test]
async fn selection_waits_for_frozen_timing_and_rejects_expired_dkg() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("43", 1);
    let (mut state, repo) = test_state(&e3_id, KeyshareState::Init);
    state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs = None;
        state.dkg_window_secs = None;
        Ok(state)
    })?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let read_calls = Arc::clone(&calls);
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery: test_recovery(),
        dkg_timing_reader: Arc::new(move |_| {
            read_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok((
                    crate::domain::timeout_policy::now_unix_secs().saturating_sub(1),
                    3_600,
                ))
            })
        }),
    })
    .start();
    let selection = CiphernodeSelected {
        e3_id: e3_id.clone(),
        ..CiphernodeSelected::default()
    };
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        selection.into(),
        None,
        1,
        None,
        EventSource::Evm,
    )
    .into_sequenced(1);
    actor.send(event).await?;

    actix::clock::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if matches!(
                repo.read().await?.expect("persisted keyshare state").state,
                KeyshareState::Failed { .. }
            ) {
                break Ok::<(), anyhow::Error>(());
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await??;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let event = next_event(&history).await?;
    assert!(matches!(event.get_data(), InterfoldEventData::E3Failed(_)));
    Ok(())
}

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
    let mut state = ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        keyshare_state,
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    );
    state.dkg_deadline_unix_secs =
        Some(crate::domain::timeout_policy::now_unix_secs().saturating_add(7_200));
    state.dkg_window_secs = Some(7_200);
    (repo.send(Some(state)), repo)
}

fn test_recovery() -> Persistable<ThresholdKeyshareRecoveryState> {
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&store));
    repo.send(Some(ThresholdKeyshareRecoveryState::default()))
}

fn test_ec(seq: u64) -> EventContext<Sequenced> {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        seq.into(),
        None,
        EventSource::Local,
    )
    .into_sequenced(seq)
    .get_ctx()
    .clone()
}

fn aggregating_decryption_key_for_roster_test() -> AggregatingDecryptionKey {
    AggregatingDecryptionKey {
        pk_share: ArcBytes::from_bytes(&[1]),
        sk_bfv: SensitiveBytes::from_encrypted(&[2]),
        own_sk_share_raw: SensitiveBytes::from_encrypted(&[3]),
        own_esi_shares_raw: vec![SensitiveBytes::from_encrypted(&[4])],
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    }
}

fn ready_message(party_id: u64, dealer_ids: &[u64], e3_id: &E3id) -> DkgCoordination {
    DkgCoordination {
        e3_id: e3_id.clone(),
        interfold_address: Address::ZERO,
        party_id,
        kind: DkgCoordinationKind::Ready,
        dealers: dealer_ids
            .iter()
            .map(|&dealer_id| DkgDealer {
                party_id: dealer_id,
                contribution_hash: [dealer_id as u8; 32],
            })
            .collect(),
        signature: ArcBytes::from_bytes(&[]),
    }
}

#[actix::test]
async fn only_the_active_aggregator_proposes_a_ready_roster() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("47", 1);
    let store = InMemStore::new(false).start();
    let state_repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let state = state_repo.send(Some(ThresholdKeyshareState::new(
        e3_id.clone(),
        2,
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    )));
    let mut recovery = test_recovery();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery
            .ready_by_party
            .insert(0, ready_message(0, &[0, 1], &e3_id));
        recovery
            .ready_by_party
            .insert(1, ready_message(1, &[0, 1], &e3_id));
        Ok(recovery)
    })?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.propose_dkg_roster(test_ec(1))?;
    assert!(actor.recovery.try_get()?.dkg_roster.is_none());

    actor.handle_aggregator_changed(
        AggregatorChanged {
            e3_id: e3_id.clone(),
            active_party_id: Some(2),
            is_aggregator: true,
        },
        test_ec(2),
    )?;

    let roster = next_events(&history, 2)
        .await?
        .into_iter()
        .find_map(|event| match event.into_data() {
            InterfoldEventData::DkgCoordination(roster) => Some(roster),
            _ => None,
        })
        .expect("expected DKG roster proposal");
    assert_eq!(
        roster
            .dealers
            .iter()
            .map(|dealer| dealer.party_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let recovery = actor.recovery.try_get()?;
    assert!(recovery.dkg_roster.is_none());
    assert_eq!(recovery.active_aggregator_party_id, Some(2));
    assert!(recovery.is_aggregator);
    Ok(())
}

#[actix::test]
async fn roster_from_non_active_party_is_ignored() -> Result<()> {
    let (bus, _history) = test_bus();
    let e3_id = E3id::new("48", 1);
    let signers = [
        alloy::signers::local::PrivateKeySigner::random(),
        alloy::signers::local::PrivateKeySigner::random(),
        alloy::signers::local::PrivateKeySigner::random(),
    ];
    let committee = signers
        .iter()
        .map(|signer| signer.address().to_string())
        .collect();
    let legitimate_dealers = vec![
        DkgDealer {
            party_id: 0,
            contribution_hash: [0; 32],
        },
        DkgDealer {
            party_id: 1,
            contribution_hash: [1; 32],
        },
    ];
    let own_ready = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        0,
        DkgCoordinationKind::Ready,
        legitimate_dealers,
        &signers[0],
    )?;
    let forged_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Roster,
        vec![
            DkgDealer {
                party_id: 0,
                contribution_hash: [9; 32],
            },
            DkgDealer {
                party_id: 1,
                contribution_hash: [9; 32],
            },
        ],
        &signers[2],
    )?;

    let store = InMemStore::new(false).start();
    let state_repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let state = state_repo.send(Some(ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    )));
    let mut recovery = test_recovery();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(
            CiphernodeSelected {
                e3_id: e3_id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                party_id: 0,
                committee,
                ..Default::default()
            },
            test_ec(1),
        ));
        recovery.dkg_ready = Some(own_ready);
        recovery.active_aggregator_party_id = Some(0);
        recovery.is_aggregator = true;
        Ok(recovery)
    })?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: signers[0].clone(),
        effects_enabled: false,
        recovery,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.record_dkg_coordination(forged_roster, test_ec(2))?;

    assert!(actor.recovery.try_get()?.dkg_roster.is_none());
    Ok(())
}

#[actix::test]
async fn conflicting_roster_after_acceptance_is_ignored() -> Result<()> {
    let (bus, _history) = test_bus();
    let e3_id = E3id::new("49", 1);
    let signers = [
        alloy::signers::local::PrivateKeySigner::random(),
        alloy::signers::local::PrivateKeySigner::random(),
        alloy::signers::local::PrivateKeySigner::random(),
    ];
    let committee = signers
        .iter()
        .map(|signer| signer.address().to_string())
        .collect();
    let dealer = |party_id| DkgDealer {
        party_id,
        contribution_hash: [party_id as u8; 32],
    };
    let own_ready = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        0,
        DkgCoordinationKind::Ready,
        vec![dealer(0), dealer(1), dealer(2)],
        &signers[0],
    )?;
    let first_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        0,
        DkgCoordinationKind::Roster,
        vec![dealer(0), dealer(1)],
        &signers[0],
    )?;
    let conflicting_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        1,
        DkgCoordinationKind::Roster,
        vec![dealer(0), dealer(2)],
        &signers[1],
    )?;

    let store = InMemStore::new(false).start();
    let state_repo = Repository::<ThresholdKeyshareState>::new(DataStore::from_in_mem(&store));
    let state = state_repo.send(Some(ThresholdKeyshareState::new(
        e3_id.clone(),
        0,
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
        1,
        3,
        ArcBytes::from_bytes(b"params"),
        Address::ZERO.to_string(),
    )));
    let mut recovery = test_recovery();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(
            CiphernodeSelected {
                e3_id: e3_id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                party_id: 0,
                committee,
                ..Default::default()
            },
            test_ec(1),
        ));
        recovery.dkg_ready = Some(own_ready);
        recovery.active_aggregator_party_id = Some(0);
        recovery.is_aggregator = true;
        Ok(recovery)
    })?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: signers[0].clone(),
        effects_enabled: false,
        recovery,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.record_dkg_coordination(first_roster, test_ec(2))?;
    actor.handle_aggregator_changed(
        AggregatorChanged {
            e3_id: e3_id.clone(),
            active_party_id: Some(1),
            is_aggregator: false,
        },
        test_ec(3),
    )?;
    actor.record_dkg_coordination(conflicting_roster, test_ec(4))?;

    let accepted = actor
        .recovery
        .try_get()?
        .dkg_roster
        .expect("first roster should remain accepted");
    assert_eq!(
        accepted
            .dealers
            .iter()
            .map(|entry| entry.party_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    Ok(())
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
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery: test_recovery(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
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
async fn a_replayed_decryption_share_response_does_not_fault_after_the_state_advances() -> Result<()>
{
    let generating = GeneratingDecryptionProof {
        pk_share: ArcBytes::from_bytes(&[1]),
        decryption_share: vec![ArcBytes::from_bytes(&[2])],
        signed_pk_generation_proof: None,
        signed_sk_share_computation_proof: None,
        signed_e_sm_share_computation_proof: None,
        signed_sk_share_encryption_proofs: Vec::new(),
        signed_e_sm_share_encryption_proofs: Vec::new(),
    };
    let (actor, history, e3_id, repo) =
        start_actor_with_state(KeyshareState::GeneratingDecryptionProof(generating)).await?;
    let ec = InterfoldEvent::<Unsequenced>::new_with_timestamp(
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
            ComputeResponse::trbfv(
                TrBFVResponse::CalculateDecryptionShare(CalculateDecryptionShareResponse {
                    d_share_poly: vec![ArcBytes::from_bytes(&[3])],
                }),
                CorrelationId::new(),
                e3_id,
            ),
            ec,
        ))
        .await?;

    let events = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(events
        .events
        .iter()
        .all(|event| !matches!(event.get_data(), InterfoldEventData::InterfoldError(_))));
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::GeneratingDecryptionProof(_)
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
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
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
async fn restart_rebuilds_c4_collector_before_peer_share_arrives() -> Result<()> {
    let e3_id = E3id::new("44", 1);
    let (bus, history) = test_bus();
    let (mut state, _) = test_state(
        &e3_id,
        KeyshareState::ReadyForDecryption(ready_for_c4_test()),
    );
    state.try_mutate_without_context(|mut state| {
        state.honest_parties = Some(BTreeSet::from([0, 1]));
        Ok(state)
    })?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery: test_recovery(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
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

    actor.send(peer_c4_event(&e3_id, 2)).await?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.kind == VerificationKind::DecryptionProofs
    ));
    Ok(())
}

#[actix::test]
async fn duplicate_c4_after_collection_does_not_start_another_collector() -> Result<()> {
    let e3_id = E3id::new("45", 1);
    let (bus, history) = test_bus();
    let (mut state, _) = test_state(
        &e3_id,
        KeyshareState::ReadyForDecryption(ready_for_c4_test()),
    );
    state.try_mutate_without_context(|mut state| {
        state.honest_parties = Some(BTreeSet::from([0, 1]));
        Ok(state)
    })?;
    let duplicate = peer_c4_event(&e3_id, 2);
    let mut recovery = test_recovery();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery.decryption_key_shares.insert(
            1,
            TypedEvent::new(
                match duplicate.get_data() {
                    InterfoldEventData::DecryptionKeyShared(data) => data.clone(),
                    _ => unreachable!(),
                },
                duplicate.get_ctx().clone(),
            ),
        );
        Ok(recovery)
    })?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery,
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    })
    .start();
    actor.send(duplicate).await?;
    actix::clock::sleep(std::time::Duration::from_millis(25)).await;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events.is_empty(), "duplicate C4 restarted collection");
    Ok(())
}

#[actix::test]
async fn recovery_keeps_the_first_c0_and_c4_from_each_party() -> Result<()> {
    let e3_id = E3id::new("46", 1);
    let (bus, _) = test_bus();
    let (state, _) = test_state(&e3_id, KeyshareState::Init);
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery: test_recovery(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });
    let first_c4_event = peer_c4_event(&e3_id, 1);
    let ec = first_c4_event.get_ctx().clone();
    let first_c0 = EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(&[1]))),
        external: true,
    };
    let later_c0 = EncryptionKeyCreated {
        key: Arc::new(EncryptionKey::new(1, ArcBytes::from_bytes(&[2]))),
        ..first_c0.clone()
    };
    actor.record_encryption_key(&TypedEvent::new(first_c0.clone(), ec.clone()))?;
    actor.record_encryption_key(&TypedEvent::new(later_c0, ec.clone()))?;

    let InterfoldEventData::DecryptionKeyShared(first_c4) = first_c4_event.get_data() else {
        unreachable!();
    };
    let mut later_c4 = first_c4.clone();
    later_c4.signed_sk_decryption_proof.signature = ArcBytes::from_bytes(&[9]);
    actor.record_decryption_key_share(&TypedEvent::new(first_c4.clone(), ec.clone()))?;
    actor.record_decryption_key_share(&TypedEvent::new(later_c4, ec))?;

    let recovery = actor.recovery.try_get()?;
    assert_eq!(recovery.encryption_keys.get(&1).unwrap().key, first_c0.key);
    assert_eq!(
        recovery
            .decryption_key_shares
            .get(&1)
            .unwrap()
            .clone()
            .into_inner(),
        first_c4.clone()
    );
    Ok(())
}

fn ready_for_c4_test() -> ReadyForDecryption {
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

fn peer_c4_event(e3_id: &E3id, seq: u64) -> InterfoldEvent {
    let proof = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C4aSkShareDecryption,
            proof: Proof::new(
                CircuitName::DkgShareDecryption,
                ArcBytes::from_bytes(&[]),
                ArcBytes::from_bytes(&[]),
            ),
        },
        signature: ArcBytes::from_bytes(&[]),
    };
    let mut esm_proof = proof.clone();
    esm_proof.payload.proof_type = ProofType::C4bESmShareDecryption;
    let share = DecryptionKeyShared {
        e3_id: e3_id.clone(),
        party_id: 1,
        node: Address::ZERO.to_string(),
        signed_sk_decryption_proof: proof,
        signed_e_sm_decryption_proofs: vec![esm_proof],
        external: true,
    };
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        share.into(),
        None,
        seq.into(),
        None,
        EventSource::Net,
    )
    .into_sequenced(seq)
}
