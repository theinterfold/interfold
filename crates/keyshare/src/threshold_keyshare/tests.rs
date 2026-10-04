// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::actors::decryption_key_shared_collector::DecryptionKeySharedCollectionFailed;
use crate::actors::threshold_share_collector::{
    ThresholdShareCollectionCutoff, ThresholdShareCollectionTimeout,
};
use actix::{Actor, Addr, Handler};
use alloy::primitives::Address;
use anyhow::Result;
use e3_crypto::Cipher;
use e3_data::{AutoPersist, DataStore, InMemStore, Persistable, Repository, StoreConnector};
use e3_events::{
    hlc_factory::HlcFactory, AggregatorChanged, BusHandle, CircuitName, CommitteeMemberExcluded,
    CommitteeMemberExpelled, ComputeRequest, ComputeRequestError, ComputeRequestErrorKind,
    ComputeRequestKind, DecryptionKeyShared, DkgCoordination, DkgCoordinationKind, DkgDealer,
    DkgProofSigned, E3Stage, E3id, EffectsEnabled, EncryptionKey, EncryptionKeyCreated, Event,
    EventBus, EventBusConfig, EventSource, EventType, FailureReason, Get, GetEvents,
    HistoryCollector, Insert, InterfoldEvent, InterfoldEventData, OrderedSet,
    PkGenerationProofSigned, Proof, ProofPayload, ProofType, PublicKeyAggregated, Remove,
    Sequencer, SignedProofPayload, StoreEventRequested, StoreEventResponse, TakeEvents, TestEvent,
    Unsequenced, VerificationKind,
};
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset, DEFAULT_BFV_PRESET};
use e3_trbfv::{
    gen_esi_sss::GenEsiSssRequest, TrBFVConfig, TrBFVError, TrBFVFailure, TrBFVRequest,
};
use std::collections::BTreeSet;
use std::sync::Arc;

#[actix::test]
async fn late_selection_does_not_fail_the_shared_e3() -> Result<()> {
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
        recovery_payloads: test_recovery_payloads(),
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
        while calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Init
    ));
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        events
            .iter()
            .all(|event| !matches!(event.get_data(), InterfoldEventData::E3Failed(_))),
        "one late node must not fail the shared E3"
    );
    Ok(())
}

#[actix::test]
async fn peer_keys_that_arrive_before_selection_count_toward_collection() -> Result<()> {
    let e3_id = E3id::new("early-keys", 1);
    let (actor, repo) = start_actor_before_selection(&e3_id, 7_200).await?;

    // Parties 1 and 2 publish their keys before this node, party 0, handles its selection.
    actor
        .send(keyshare_event(peer_key(&e3_id, 1), 1, EventSource::Net))
        .await?;
    actor
        .send(keyshare_event(peer_key(&e3_id, 2), 2, EventSource::Net))
        .await?;
    actor
        .send(keyshare_event(selection(&e3_id), 3, EventSource::Evm))
        .await?;
    wait_for_keyshare_state(&repo, |state| {
        matches!(state, KeyshareState::CollectingEncryptionKeys(_))
    })
    .await?;
    actor
        .send(keyshare_event(peer_key(&e3_id, 0), 4, EventSource::Local))
        .await?;

    // The collector holds all three keys, so the DKG continues before the 10% cutoff.
    let KeyshareState::GeneratingThresholdShare(data) = wait_for_keyshare_state(&repo, |state| {
        matches!(state, KeyshareState::GeneratingThresholdShare(_))
    })
    .await?
    else {
        unreachable!("the wait returns only a matching state");
    };
    let mut parties = data
        .collected_encryption_keys
        .iter()
        .map(|key| key.party_id)
        .collect::<Vec<_>>();
    parties.sort_unstable();
    assert_eq!(parties, vec![0, 1, 2]);
    Ok(())
}

#[actix::test]
async fn a_recorded_key_from_an_expelled_party_does_not_count_toward_h() -> Result<()> {
    let e3_id = E3id::new("early-expelled-key", 1);
    // With a 30 s window, the encryption-key cutoff (10%) comes 3 s after selection.
    let (actor, repo) = start_actor_before_selection(&e3_id, 30).await?;

    // In production this node's key follows its selection. Here it is recorded first, so selection
    // queues every key to the new collector before the collector schedules its cutoff. No test step
    // races the cutoff.
    actor
        .send(keyshare_event(peer_key(&e3_id, 0), 1, EventSource::Local))
        .await?;
    actor
        .send(keyshare_event(peer_key(&e3_id, 1), 2, EventSource::Net))
        .await?;
    actor
        .send(keyshare_event(expulsion_of(&e3_id, 1), 3, EventSource::Evm))
        .await?;
    actor
        .send(keyshare_event(selection(&e3_id), 4, EventSource::Evm))
        .await?;

    // The collector continues with keys 0 and 1 at the cutoff. The keyshare removes party 1's key,
    // and one key is below H = 2, so the DKG fails instead of generating shares.
    let state = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::Failed { .. } | KeyshareState::GeneratingThresholdShare(_)
        )
    })
    .await?;
    assert!(
        matches!(
            state,
            KeyshareState::Failed {
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            }
        ),
        "expected the DKG to fail with one usable key, got {state:?}"
    );
    Ok(())
}

#[actix::test]
async fn a_live_key_after_the_cutoff_does_not_reach_a_waiting_collector() -> Result<()> {
    let e3_id = E3id::new("late-live-key", 1);
    // The 10% cutoff of this 2,000 s window passed 800 s ago.
    let (mut actor, _, recovery_repo, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        1_000,
        2_000,
        &[],
    )
    .await?;
    let (parent, parent_repo, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    let parent = parent.start();
    // A collector whose timer has not fired yet. Its relative timer can fire up to a second after
    // the absolute cutoff. It holds keys 0 and 2, so key 1 would complete it.
    let collector = EncryptionKeyCollector::setup(
        parent.clone(),
        3,
        2,
        0,
        e3_id.clone(),
        Some(std::time::Duration::from_secs(3_600)),
    );
    for party_id in [0, 2] {
        collector
            .send(TypedEvent::new(
                peer_key(&e3_id, party_id),
                test_ec(party_id + 1),
            ))
            .await?;
    }
    actor.encryption_key_collector = Some(collector);

    // The late key is an expected input, not an error: it is recorded, but it reaches no
    // collector.
    actor
        .handle_encryption_key_created(TypedEvent::new(peer_key(&e3_id, 1), test_ec(4)), parent)?;

    assert!(recovery_repo
        .read()
        .await?
        .expect("recovery state")
        .encryption_keys
        .contains_key(&1));
    actix::clock::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        matches!(
            parent_repo.read().await?.expect("keyshare state").state,
            KeyshareState::CollectingEncryptionKeys(_)
        ),
        "the late key must not complete the collection"
    );
    Ok(())
}

#[actix::test]
async fn a_share_after_the_dkg_deadline_is_recorded_but_reaches_no_collector() -> Result<()> {
    let e3_id = E3id::new("late-share", 1);
    let (mut actor, _, recovery_repo, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    actor.state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs =
            Some(crate::domain::timeout_policy::now_unix_secs().saturating_sub(10));
        Ok(state)
    })?;
    let (parent, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;

    actor.handle_threshold_share_created(
        TypedEvent::new(peer_share(&e3_id, 2), test_ec(2)),
        parent.start(),
    )?;

    assert!(recovery_repo
        .read()
        .await?
        .expect("recovery state")
        .threshold_share_refs
        .contains_key(&2));
    assert!(actor.decryption_key_collector.is_none());
    Ok(())
}

#[actix::test]
async fn a_collector_takes_its_timing_from_the_reading_that_admitted_its_input() -> Result<()> {
    let e3_id = E3id::new("one-clock-reading", 1);
    let (parent, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    let parent = parent.start();
    let now = crate::domain::timeout_policy::now_unix_secs();

    // The canonical DKG deadline is reached at `now`. A share admitted one second earlier still
    // gets a collector.
    let (mut actor, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    actor.state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs = Some(now);
        Ok(state)
    })?;
    actor.ensure_collector(parent.clone(), &test_ec(1), now - 1)?;
    assert!(actor.decryption_key_collector.is_some());

    // The encryption-key cutoff, 10% into a 1,000 s window, is reached at `now`. A key admitted
    // one second earlier still gets a collector.
    let (mut actor, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    actor.state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs = Some(now + 900);
        state.dkg_window_secs = Some(1_000);
        Ok(state)
    })?;
    actor.ensure_encryption_key_collector(parent, &test_ec(1), now - 1)?;
    assert!(actor.encryption_key_collector.is_some());
    Ok(())
}

#[actix::test]
async fn an_own_dkg_proof_after_share_aggregation_is_ignored() -> Result<()> {
    let e3_id = E3id::new("late-own-proof", 1);
    let (mut actor, repo, _, _) = build_actor(
        &e3_id,
        KeyshareState::ReadyForDecryption(ready_for_c4_test()),
        7_200,
        7_200,
        &[],
    )
    .await?;

    actor.handle_share_computation_proof_signed(TypedEvent::new(
        DkgProofSigned {
            e3_id: e3_id.clone(),
            party_id: 0,
            signed_proof: c2_proof(&e3_id, ProofType::C2aSkShareComputation, 0),
        },
        test_ec(1),
    ))?;

    assert!(matches!(
        repo.read().await?.expect("keyshare state").state,
        KeyshareState::ReadyForDecryption(_)
    ));
    Ok(())
}

#[actix::test]
async fn a_restart_after_the_key_cutoff_continues_with_h_recorded_keys() -> Result<()> {
    let e3_id = E3id::new("overdue-keys", 1);
    // The 10% cutoff of this 2,000 s window passed 800 s ago. The deadline is 1,000 s away.
    let (mut actor, repo, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        1_000,
        2_000,
        &[],
    )
    .await?;
    for party_id in [0, 1] {
        actor.record_encryption_key(&TypedEvent::new(
            peer_key(&e3_id, party_id),
            test_ec(party_id + 1),
        ))?;
    }
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;

    // This node's key and one peer key reach H = 2, so the DKG continues without party 2.
    let state = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::GeneratingThresholdShare(_) | KeyshareState::Failed { .. }
        )
    })
    .await?;
    let KeyshareState::GeneratingThresholdShare(data) = state else {
        panic!("expected the DKG to continue after the overdue cutoff, got {state:?}");
    };
    let parties = data
        .collected_encryption_keys
        .iter()
        .map(|key| key.party_id)
        .collect::<Vec<_>>();
    assert_eq!(parties, vec![0, 1]);
    Ok(())
}

#[actix::test]
async fn a_restart_after_the_key_cutoff_without_this_nodes_key_fails_the_dkg() -> Result<()> {
    let e3_id = E3id::new("overdue-without-own-key", 1);
    let (mut actor, repo, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        1_000,
        2_000,
        &[],
    )
    .await?;
    for party_id in [1, 2] {
        actor.record_encryption_key(&TypedEvent::new(
            peer_key(&e3_id, party_id),
            test_ec(party_id),
        ))?;
    }
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;

    // Two peer keys reach H = 2, but share generation also needs this node's key.
    let state = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::GeneratingThresholdShare(_) | KeyshareState::Failed { .. }
        )
    })
    .await?;
    assert!(
        matches!(
            state,
            KeyshareState::Failed {
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            }
        ),
        "expected the overdue cutoff to fail the DKG, got {state:?}"
    );
    Ok(())
}

#[actix::test]
async fn a_restart_during_key_collection_replays_saved_threshold_shares() -> Result<()> {
    let e3_id = E3id::new("saved-shares", 1);
    let (mut actor, _, recovery_repo, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    // Parties 1 and 2 sent their shares before this node collected every encryption key.
    for party_id in [1, 2] {
        actor.record_threshold_share(&TypedEvent::new(
            peer_share(&e3_id, party_id),
            test_ec(party_id),
        ))?;
    }
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;

    // The new collector gets both saved shares and records the complete batch.
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids.is_some()
    })
    .await?;
    assert_eq!(
        recovery.collected_threshold_share_ids,
        Some(BTreeSet::from([1, 2]))
    );
    Ok(())
}

#[actix::test]
async fn a_rebuilt_share_collector_does_not_wait_for_an_expelled_party() -> Result<()> {
    let e3_id = E3id::new("expelled-share", 1);
    // The 75% threshold-share cutoff of this 7,200 s window is 5,400 s away.
    let (mut actor, _, recovery_repo, _) = build_actor(
        &e3_id,
        KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
            pk_share: None,
            sk_sss: None,
            esi_sss: None,
            e_sm_raw: None,
            sk_bfv: SensitiveBytes::from_encrypted(&[1]),
            pk_bfv: ArcBytes::from_bytes(&[2]),
            collected_encryption_keys: [0, 1, 2]
                .map(|party_id| peer_key(&e3_id, party_id).key)
                .to_vec(),
            ciphernode_selected: Some(CiphernodeSelected {
                e3_id: e3_id.clone(),
                party_id: 0,
                threshold_m: 1,
                threshold_n: 3,
                ..Default::default()
            }),
            proof_request_data: None,
        }),
        7_200,
        7_200,
        &[1],
    )
    .await?;
    // Party 1's share was saved before its expulsion.
    for party_id in [1, 2] {
        actor.record_threshold_share(&TypedEvent::new(
            peer_share(&e3_id, party_id),
            test_ec(party_id),
        ))?;
    }
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;

    // The rebuilt collector learns that party 1 is expelled, so party 2's share completes the batch
    // before the cutoff and party 1's share does not count.
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids.is_some()
    })
    .await?;
    assert_eq!(
        recovery.collected_threshold_share_ids,
        Some(BTreeSet::from([2]))
    );
    Ok(())
}

/// The expulsion of `party_id` from the chain, with the party ID that sortition adds.
fn expulsion_of(e3_id: &E3id, party_id: u64) -> CommitteeMemberExpelled {
    CommitteeMemberExpelled {
        e3_id: e3_id.clone(),
        node: Address::ZERO,
        reason: [0; 32],
        active_count_after: 2,
        party_id: Some(party_id),
    }
}

#[actix::test]
async fn a_key_collector_created_after_an_expulsion_does_not_wait_for_that_party() -> Result<()> {
    let e3_id = E3id::new("expelled-before-key-collector", 1);
    // The encryption-key cutoff (10% of 7,200 s) is 720 s after selection.
    let (actor, repo) = start_actor_before_selection(&e3_id, 7_200).await?;
    actor
        .send(keyshare_event(peer_key(&e3_id, 0), 1, EventSource::Local))
        .await?;
    actor
        .send(keyshare_event(peer_key(&e3_id, 2), 2, EventSource::Net))
        .await?;
    actor
        .send(keyshare_event(expulsion_of(&e3_id, 1), 3, EventSource::Evm))
        .await?;
    actor
        .send(keyshare_event(selection(&e3_id), 4, EventSource::Evm))
        .await?;

    // The new collector knows that party 1 is expelled, so keys 0 and 2 complete the collection
    // long before the cutoff.
    let KeyshareState::GeneratingThresholdShare(data) = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::GeneratingThresholdShare(_) | KeyshareState::Failed { .. }
        )
    })
    .await?
    else {
        panic!("expected the DKG to continue without party 1");
    };
    let mut parties = data
        .collected_encryption_keys
        .iter()
        .map(|key| key.party_id)
        .collect::<Vec<_>>();
    parties.sort_unstable();
    assert_eq!(parties, vec![0, 2]);
    Ok(())
}

#[actix::test]
async fn a_share_collector_created_after_an_expulsion_does_not_wait_for_that_party() -> Result<()> {
    let e3_id = E3id::new("expelled-before-share-collector", 1);
    // The threshold-share cutoff (75% of 7,200 s) is 5,400 s after selection.
    let (actor, repo, recovery_repo) =
        start_actor_before_selection_with_recovery(&e3_id, 7_200).await?;
    actor
        .send(keyshare_event(expulsion_of(&e3_id, 1), 1, EventSource::Evm))
        .await?;
    actor
        .send(keyshare_event(selection(&e3_id), 2, EventSource::Evm))
        .await?;
    wait_for_keyshare_state(&repo, |state| {
        matches!(state, KeyshareState::CollectingEncryptionKeys(_))
    })
    .await?;
    actor
        .send(keyshare_event(peer_share(&e3_id, 2), 3, EventSource::Net))
        .await?;

    // Selection created the share collector after party 1's expulsion. Party 2's share is the last
    // one that the collector waits for.
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids.is_some()
    })
    .await?;
    assert_eq!(
        recovery.collected_threshold_share_ids,
        Some(BTreeSet::from([2]))
    );
    Ok(())
}

#[actix::test]
async fn a_restarted_key_collector_does_not_wait_for_an_expelled_party() -> Result<()> {
    let e3_id = E3id::new("expelled-key-restart", 1);
    // The encryption-key cutoff (10% of the 7,200 s window) is 720 s away.
    let (mut actor, repo, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[1],
    )
    .await?;
    for party_id in [0, 2] {
        actor.record_encryption_key(&TypedEvent::new(
            peer_key(&e3_id, party_id),
            test_ec(party_id + 1),
        ))?;
    }
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;

    // The recovered collector knows that party 1 is expelled, so the recorded keys 0 and 2
    // complete the collection before the cutoff.
    let KeyshareState::GeneratingThresholdShare(data) = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::GeneratingThresholdShare(_) | KeyshareState::Failed { .. }
        )
    })
    .await?
    else {
        panic!("expected the DKG to continue without party 1");
    };
    let parties = data
        .collected_encryption_keys
        .iter()
        .map(|key| key.party_id)
        .collect::<Vec<_>>();
    assert_eq!(parties, vec![0, 2]);
    Ok(())
}

#[actix::test]
async fn a_new_collector_stays_reachable_when_its_seeding_fails() -> Result<()> {
    let e3_id = E3id::new("seed-overflow", 1);
    // More recorded expulsions than a new collector's mailbox holds, so seeding fails part of the
    // way through.
    let expelled: Vec<u64> = (1..=(e3_utils::MAILBOX_LIMIT as u64 + 44)).collect();
    let (mut actor, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &expelled,
    )
    .await?;
    let (parent, _, _, _) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[],
    )
    .await?;
    let parent = parent.start();

    let now = crate::domain::timeout_policy::now_unix_secs();
    assert!(actor
        .ensure_collector(parent.clone(), &test_ec(1), now)
        .is_err());
    assert!(
        actor.decryption_key_collector.is_some(),
        "the started share collector must stay reachable"
    );
    assert!(actor
        .ensure_encryption_key_collector(parent, &test_ec(2), now)
        .is_err());
    assert!(
        actor.encryption_key_collector.is_some(),
        "the started key collector must stay reachable"
    );
    Ok(())
}

#[actix::test]
async fn an_expulsion_that_leaves_fewer_than_h_keys_fails_the_dkg() -> Result<()> {
    let e3_id = E3id::new("expelled-after-collection", 1);
    let (actor, repo, _, history) = build_actor(
        &e3_id,
        collecting_encryption_keys_state(&e3_id),
        7_200,
        7_200,
        &[1],
    )
    .await?;
    let actor = actor.start();

    // The collector completed with H = 2 keys before party 1's expulsion reached it.
    let keys = [0, 1]
        .map(|party_id| peer_key(&e3_id, party_id).key)
        .to_vec();
    actor
        .send(TypedEvent::new(
            AllEncryptionKeysCollected { keys },
            test_ec(1),
        ))
        .await?;

    let state = wait_for_keyshare_state(&repo, |state| {
        matches!(
            state,
            KeyshareState::GeneratingThresholdShare(_) | KeyshareState::Failed { .. }
        )
    })
    .await?;
    assert!(
        matches!(
            state,
            KeyshareState::Failed {
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout,
            }
        ),
        "expected the DKG to fail with one usable key, got {state:?}"
    );
    let failure = next_event(&history).await?;
    assert!(
        matches!(
            failure.get_data(),
            InterfoldEventData::EncryptionKeyCollectionFailed(data)
                if data.missing_parties == vec![2]
        ),
        "expected party 2 to be reported missing, got {failure:?}"
    );
    Ok(())
}

/// A store that stops when it starts, so it refuses every snapshot write, as a store whose
/// mailbox rejects writes does.
struct StoppedStore;

impl Actor for StoppedStore {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.stop();
    }
}

impl Handler<Get> for StoppedStore {
    type Result = Option<Vec<u8>>;
    fn handle(&mut self, _: Get, _: &mut Self::Context) -> Self::Result {
        None
    }
}

impl Handler<Insert> for StoppedStore {
    type Result = ();
    fn handle(&mut self, _: Insert, _: &mut Self::Context) {}
}

impl Handler<Remove> for StoppedStore {
    type Result = ();
    fn handle(&mut self, _: Remove, _: &mut Self::Context) {}
}

/// Hold `value` in a persistable whose writes all fail.
async fn unwritable<T>(value: T) -> Persistable<T>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + Clone + Send + Sync + 'static,
{
    let store = StoppedStore.start();
    actix::clock::sleep(std::time::Duration::from_millis(10)).await;
    let connector = StoreConnector::new(
        b"unwritable",
        &store.clone().recipient(),
        &store.clone().recipient(),
        &store.recipient(),
    );
    Persistable::new(Some(value), connector)
}

/// Start a keyshare in `keyshare_state` whose state and recovery writes all fail, and return the
/// bus history.
async fn start_unwritable_actor(
    e3_id: &E3id,
    keyshare_state: KeyshareState,
) -> Result<(
    Addr<ThresholdKeyshare>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let (bus, history) = test_bus();
    let (state, _) = test_state(e3_id, keyshare_state);
    let state = unwritable(state.try_get()?).await;
    let recovery = unwritable(ThresholdKeyshareRecoveryState::default()).await;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: false,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    })
    .start();
    Ok((actor, history))
}

/// Wait for `count` events and return the messages of those that are `InterfoldError`s.
async fn error_messages(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    count: usize,
) -> Result<Vec<String>> {
    Ok(next_events(history, count)
        .await?
        .into_iter()
        .filter_map(|event| match event.into_data() {
            InterfoldEventData::InterfoldError(error) => Some(error.message),
            _ => None,
        })
        .collect())
}

#[actix::test]
async fn the_event_router_reports_failed_state_writes() -> Result<()> {
    let e3_id = E3id::new("unwritable", 1);
    let own_proof = c2_proof(&e3_id, ProofType::C2aSkShareComputation, 0);
    let events: Vec<InterfoldEventData> = vec![
        PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&[1]),
            e3_id: e3_id.clone(),
            nodes: OrderedSet::new(),
            committee_addresses: Vec::new(),
            honest_committee_addresses: Vec::new(),
            pk_commitment: [1; 32],
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        }
        .into(),
        peer_share(&e3_id, 2).into(),
        PkGenerationProofSigned {
            e3_id: e3_id.clone(),
            party_id: 0,
            signed_proof: own_proof.clone(),
        }
        .into(),
        DkgProofSigned {
            e3_id: e3_id.clone(),
            party_id: 0,
            signed_proof: own_proof,
        }
        .into(),
        expulsion_of(&e3_id, 1).into(),
        CommitteeMemberExcluded {
            e3_id: e3_id.clone(),
            node: Address::ZERO,
            proof_type: ProofType::C2aSkShareComputation,
            party_id: Some(2),
        }
        .into(),
    ];

    // One keyshare per event: the bus drops a repeated error with the same payload.
    for data in events {
        let (actor, history) = start_unwritable_actor(
            &e3_id,
            KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
        )
        .await?;
        let event_type = data.event_type();
        actor
            .send(keyshare_event(data, 1, EventSource::Net))
            .await?;

        let errors = error_messages(&history, 1).await?;
        assert_eq!(
            errors.len(),
            1,
            "{event_type}: the failed write is reported"
        );
        assert!(
            errors[0].contains("rejected snapshot write"),
            "{event_type}: {}",
            errors[0]
        );
    }
    Ok(())
}

#[actix::test]
async fn the_event_router_reports_a_failed_encryption_key_write() -> Result<()> {
    let e3_id = E3id::new("unwritable-key", 1);
    let (actor, history) = start_unwritable_actor(&e3_id, KeyshareState::Init).await?;

    actor
        .send(keyshare_event(peer_key(&e3_id, 1), 1, EventSource::Net))
        .await?;

    let errors = error_messages(&history, 1).await?;
    assert_eq!(
        errors.len(),
        1,
        "the failed key write is reported: {errors:?}"
    );
    assert!(errors[0].contains("rejected snapshot write"));
    Ok(())
}

/// Build a keyshare in `keyshare_state` with insecure BFV parameters, as restart recovery hydrates
/// it. The DKG deadline is `deadline_in_secs` from now, at the end of a `dkg_window_secs` window.
/// The caller records inputs, starts the actor and sends `EffectsEnabled`.
async fn build_actor(
    e3_id: &E3id,
    keyshare_state: KeyshareState,
    deadline_in_secs: u64,
    dkg_window_secs: u64,
    expelled_parties: &[u64],
) -> Result<(
    ThresholdKeyshare,
    Repository<ThresholdKeyshareState>,
    Repository<ThresholdKeyshareRecoveryState>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let (bus, history) = test_bus();
    let (mut state, repo) = test_state(e3_id, keyshare_state);
    state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs =
            Some(crate::domain::timeout_policy::now_unix_secs().saturating_add(deadline_in_secs));
        state.dkg_window_secs = Some(dkg_window_secs);
        state.params = insecure_threshold_params();
        state.expelled_parties.extend(expelled_parties);
        Ok(state)
    })?;
    let (recovery, recovery_repo) = test_recovery_with_repo();
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: false,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });
    Ok((actor, repo, recovery_repo, history))
}

fn insecure_threshold_params() -> ArcBytes {
    ArcBytes::from_bytes(&encode_bfv_params(
        &BfvParamSet::from(BfvPreset::InsecureThreshold512).build_arc(),
    ))
}

/// Start a keyshare in `Init` that has not yet read its DKG timing, as before its own selection.
async fn start_actor_before_selection(
    e3_id: &E3id,
    dkg_window_secs: u64,
) -> Result<(Addr<ThresholdKeyshare>, Repository<ThresholdKeyshareState>)> {
    let (actor, repo, _) =
        start_actor_before_selection_with_recovery(e3_id, dkg_window_secs).await?;
    Ok((actor, repo))
}

/// `start_actor_before_selection`, which also returns the recovery repository.
async fn start_actor_before_selection_with_recovery(
    e3_id: &E3id,
    dkg_window_secs: u64,
) -> Result<(
    Addr<ThresholdKeyshare>,
    Repository<ThresholdKeyshareState>,
    Repository<ThresholdKeyshareRecoveryState>,
)> {
    let (bus, _) = test_bus();
    let (mut state, repo) = test_state(e3_id, KeyshareState::Init);
    state.try_mutate_without_context(|mut state| {
        state.dkg_deadline_unix_secs = None;
        state.dkg_window_secs = None;
        state.params = insecure_threshold_params();
        Ok(state)
    })?;
    let (recovery, recovery_repo) = test_recovery_with_repo();
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(move |_| {
            Box::pin(async move {
                Ok((
                    crate::domain::timeout_policy::now_unix_secs().saturating_add(dkg_window_secs),
                    dkg_window_secs,
                ))
            })
        }),
    })
    .start();
    Ok((actor, repo, recovery_repo))
}

fn keyshare_event(
    data: impl Into<InterfoldEventData>,
    seq: u64,
    source: EventSource,
) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(data.into(), None, seq.into(), None, source)
        .into_sequenced(seq)
}

fn selection(e3_id: &E3id) -> CiphernodeSelected {
    CiphernodeSelected {
        e3_id: e3_id.clone(),
        ..CiphernodeSelected::default()
    }
}

fn peer_key(e3_id: &E3id, party_id: u64) -> EncryptionKeyCreated {
    EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(
            party_id,
            ArcBytes::from_bytes(&[party_id as u8]),
        )),
        external: party_id != 0,
    }
}

fn peer_share(e3_id: &E3id, party_id: u64) -> ThresholdShareCreated {
    ThresholdShareCreated {
        e3_id: e3_id.clone(),
        share: Arc::new(ThresholdShare {
            party_id,
            pk_share: ArcBytes::from_bytes(&[party_id as u8]),
            sk_sss: Default::default(),
            esi_sss: Vec::new(),
        }),
        target_party_id: 0,
        external: true,
        signed_c2a_proof: None,
        signed_c2b_proof: None,
        signed_c3a_proofs: Vec::new(),
        signed_c3b_proofs: Vec::new(),
    }
}

async fn wait_for_keyshare_state(
    repo: &Repository<ThresholdKeyshareState>,
    matches_state: impl Fn(&KeyshareState) -> bool,
) -> Result<KeyshareState> {
    Ok(wait_for_record(repo, |state| matches_state(&state.state))
        .await?
        .state)
}

async fn wait_for_record<T>(repo: &Repository<T>, matches_record: impl Fn(&T) -> bool) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize,
{
    actix::clock::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(record) = repo.read().await? {
                if matches_record(&record) {
                    return Ok(record);
                }
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?
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
    test_recovery_with_repo().0
}

fn test_recovery_with_repo() -> (
    Persistable<ThresholdKeyshareRecoveryState>,
    Repository<ThresholdKeyshareRecoveryState>,
) {
    let store = InMemStore::new(false).start();
    let repo = Repository::<ThresholdKeyshareRecoveryState>::new(DataStore::from_in_mem(&store));
    (
        repo.send(Some(ThresholdKeyshareRecoveryState::default())),
        repo,
    )
}

fn test_recovery_payloads() -> ThresholdKeyshareRecoveryPayloads {
    let store = InMemStore::new(false).start();
    ThresholdKeyshareRecoveryPayloads::new(DataStore::from_in_mem(&store))
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

fn collecting_encryption_keys_state(e3_id: &E3id) -> KeyshareState {
    KeyshareState::CollectingEncryptionKeys(CollectingEncryptionKeysData {
        sk_bfv: SensitiveBytes::from_encrypted(&[1]),
        pk_bfv: ArcBytes::from_bytes(&[2]),
        ciphernode_selected: CiphernodeSelected {
            e3_id: e3_id.clone(),
            party_id: 0,
            threshold_m: 1,
            threshold_n: 3,
            ..Default::default()
        },
    })
}

fn gen_pk_response(cipher: &Cipher, e3_id: &E3id, seq: u64) -> Result<TypedEvent<ComputeResponse>> {
    Ok(TypedEvent::new(
        ComputeResponse::trbfv(
            TrBFVResponse::GenPkShareAndSkSss(GenPkShareAndSkSssResponse {
                pk_share: ArcBytes::from_bytes(&[3]),
                sk_sss: e3_trbfv::shares::Encrypted::new(SharedSecret::new(Vec::new()), cipher)?,
                pk0_share_raw: ArcBytes::from_bytes(&[4]),
                sk_raw: SensitiveBytes::new([5], cipher)?,
                eek_raw: SensitiveBytes::new([6], cipher)?,
                e_sm_raw: SensitiveBytes::new([7], cipher)?,
            }),
            CorrelationId::new(),
            e3_id.clone(),
        ),
        test_ec(seq),
    ))
}

fn gen_esi_response(e3_id: &E3id, seq: u64) -> TypedEvent<ComputeResponse> {
    TypedEvent::new(
        ComputeResponse::trbfv(
            TrBFVResponse::GenEsiSss(GenEsiSssResponse {
                esi_sss: Vec::new(),
            }),
            CorrelationId::new(),
            e3_id.clone(),
        ),
        test_ec(seq),
    )
}

#[actix::test]
async fn replayed_dkg_outputs_wait_for_their_prerequisites() -> Result<()> {
    let (bus, _) = test_bus();
    let e3_id = E3id::new("replay-order", 1);
    let cipher = Arc::new(Cipher::from_password("test-password").await?);
    let (state, _) = test_state(&e3_id, collecting_encryption_keys_state(&e3_id));
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: cipher.clone(),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: false,
        recovery: test_recovery(),
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    let pk_response = gen_pk_response(&cipher, &e3_id, 2)?;
    let esi_response = gen_esi_response(&e3_id, 3);
    actor.handle_gen_pk_share_and_sk_sss_response(pk_response.clone())?;
    actor.handle_gen_esi_sss_response(esi_response.clone())?;
    let (mut repeated_pk, repeated_pk_ec) = pk_response.clone().into_components();
    repeated_pk.correlation_id = CorrelationId::new();
    actor.handle_gen_pk_share_and_sk_sss_response(TypedEvent::new(repeated_pk, repeated_pk_ec))?;
    let (mut repeated_esi, repeated_esi_ec) = esi_response.clone().into_components();
    repeated_esi.correlation_id = CorrelationId::new();
    actor.handle_gen_esi_sss_response(TypedEvent::new(repeated_esi, repeated_esi_ec))?;

    assert_eq!(actor.pending.gen_pk_response, Some(pk_response));
    assert_eq!(actor.pending.gen_esi_response, Some(esi_response));
    assert!(matches!(
        actor.state.try_get()?.state,
        KeyshareState::CollectingEncryptionKeys(_)
    ));
    Ok(())
}

#[actix::test]
async fn recovered_encryption_keys_reuse_the_replayed_key_output() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("replay-output", 1);
    let cipher = Arc::new(Cipher::from_password("test-password").await?);
    let (state, _) = test_state(&e3_id, collecting_encryption_keys_state(&e3_id));
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: cipher.clone(),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: false,
        recovery: test_recovery(),
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.handle_gen_pk_share_and_sk_sss_response(gen_pk_response(&cipher, &e3_id, 2)?)?;
    actor.handle_all_encryption_keys_collected(TypedEvent::new(
        AllEncryptionKeysCollected {
            keys: [0, 1]
                .map(|party_id| peer_key(&e3_id, party_id).key)
                .to_vec(),
        },
        test_ec(1),
    ))?;

    let state = actor.state.try_get()?;
    let KeyshareState::GeneratingThresholdShare(data) = state.state else {
        panic!("expected threshold-share generation state");
    };
    assert_eq!(data.pk_share, Some(ArcBytes::from_bytes(&[3])));
    assert!(actor.pending.gen_pk_response.is_none());

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::ComputeRequest(ComputeRequest {
            request: ComputeRequestKind::TrBFV(TrBFVRequest::GenEsiSss(_)),
            ..
        })
    ));
    Ok(())
}

#[actix::test]
async fn early_threshold_share_batch_is_verified_after_own_shares_exist() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("early-batch", 1);
    let cipher = Arc::new(Cipher::from_password("test-password").await?);
    let (threshold_params, params) =
        e3_fhe_params::build_pair_for_preset(BfvPreset::InsecureThreshold512)?;
    let l = threshold_params.moduli().len();
    let mut rng = rand::rng();
    let sk = fhe::bfv::SecretKey::random(&params, &mut rng);
    let pk_bfv = ArcBytes::from_bytes(&fhe::bfv::PublicKey::new(&sk, &mut rng).to_bytes());
    let secret = SharedSecret::new(vec![ndarray::Array2::from_elem((3, params.degree()), 1); l]);
    // The same 32-byte field is the C0 output and the C3 recipient-key input.
    let proof = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C3aSkShareEncryption,
            proof: Proof::new(
                CircuitName::PkBfv,
                ArcBytes::from_bytes(&[]),
                ArcBytes::from_bytes(&[7; 32]),
            ),
        },
        signature: ArcBytes::from_bytes(&[]),
    };
    let keys = [0, 1].map(|party| Arc::new(EncryptionKey::new(party, pk_bfv.clone())));
    let (state, _) = test_state(
        &e3_id,
        KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
            pk_share: Some(ArcBytes::from_bytes(&[3])),
            sk_sss: Some(e3_trbfv::shares::Encrypted::new(secret.clone(), &cipher)?),
            esi_sss: None,
            e_sm_raw: Some(SensitiveBytes::new([7], &cipher)?),
            sk_bfv: SensitiveBytes::from_encrypted(&[1]),
            pk_bfv: pk_bfv.clone(),
            collected_encryption_keys: keys.to_vec(),
            ciphernode_selected: None,
            proof_request_data: Some(ProofRequestData {
                pk0_share_raw: ArcBytes::from_bytes(&[4]),
                sk_raw: SensitiveBytes::new([5], &cipher)?,
                eek_raw: SensitiveBytes::new([6], &cipher)?,
            }),
        }),
    );
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: cipher.clone(),
        state,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer: alloy::signers::local::PrivateKeySigner::random(),
        effects_enabled: true,
        recovery: test_recovery(),
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });
    let own_c0 = EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(0, pk_bfv).with_signed_payload(proof.clone())),
        external: false,
    };
    actor.record_encryption_key(&TypedEvent::new(own_c0, test_ec(1)))?;
    let proofs = ReceivedShareProofs {
        signed_c2a_proof: Some(proof.clone()),
        signed_c2b_proof: Some(proof.clone()),
        signed_c3a_proofs: vec![proof.clone(); l],
        signed_c3b_proofs: vec![proof; l],
    };
    let peer = ThresholdShareCreated {
        e3_id: e3_id.clone(),
        share: Arc::new(ThresholdShare {
            party_id: 1,
            pk_share: ArcBytes::from_bytes(&[8]),
            sk_sss: Default::default(),
            esi_sss: vec![Default::default()],
        }),
        target_party_id: 0,
        external: true,
        signed_c2a_proof: proofs.signed_c2a_proof.clone(),
        signed_c2b_proof: proofs.signed_c2b_proof.clone(),
        signed_c3a_proofs: proofs.signed_c3a_proofs.clone(),
        signed_c3b_proofs: proofs.signed_c3b_proofs.clone(),
    };
    actor.record_threshold_share(&TypedEvent::new(peer.clone(), test_ec(2)))?;

    // The peer batch completes while own shares are still being generated.
    let batch = TypedEvent::new(
        AllThresholdSharesCollected::new(
            HashMap::from([(1, peer.share)]),
            HashMap::from([(1, proofs)]),
        ),
        test_ec(3),
    );
    assert!(actor.record_collected_threshold_shares(&batch)?);
    actor.handle_all_threshold_shares_collected(batch)?;
    actor.handle_gen_esi_sss_response(TypedEvent::new(
        ComputeResponse::trbfv(
            TrBFVResponse::GenEsiSss(GenEsiSssResponse {
                esi_sss: vec![e3_trbfv::shares::Encrypted::new(secret, &cipher)?],
            }),
            CorrelationId::new(),
            e3_id,
        ),
        test_ec(4),
    ))?;

    let events = next_events(&history, 2).await?;
    assert!(events.into_iter().any(|event| matches!(
        event.into_data(),
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.kind == VerificationKind::ShareProofs
    )));
    Ok(())
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

#[actix::test]
async fn replayed_signed_c3_proof_is_stored_once() -> Result<()> {
    let (bus, _) = test_bus();
    let e3_id = E3id::new("42", 1);
    let (state, _) = test_state(
        &e3_id,
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
    );
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let signed_proof = SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C3aSkShareEncryption,
            proof: Proof::new(
                CircuitName::ShareEncryption,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&[2]),
            ),
        },
        &signer,
    )?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer,
        effects_enabled: true,
        recovery: test_recovery(),
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });
    let event = DkgProofSigned {
        e3_id,
        party_id: 0,
        signed_proof,
    };

    actor.handle_share_computation_proof_signed(TypedEvent::new(event.clone(), test_ec(1)))?;
    actor.handle_share_computation_proof_signed(TypedEvent::new(event, test_ec(2)))?;

    let state = actor.state.try_get()?;
    let KeyshareState::AggregatingDecryptionKey(state) = state.state else {
        panic!("expected AggregatingDecryptionKey");
    };
    assert_eq!(state.signed_sk_share_encryption_proofs.len(), 1);
    Ok(())
}

/// Dealers whose contribution hash is their party ID in every byte.
fn dealers(ids: &[u64]) -> Vec<DkgDealer> {
    ids.iter()
        .map(|&party_id| DkgDealer {
            party_id,
            contribution_hash: [party_id as u8; 32],
        })
        .collect()
}

fn ready_message(party_id: u64, dealer_ids: &[u64], e3_id: &E3id) -> DkgCoordination {
    DkgCoordination {
        e3_id: e3_id.clone(),
        interfold_address: Address::ZERO,
        party_id,
        kind: DkgCoordinationKind::Ready,
        dealers: dealers(dealer_ids),
        signature: ArcBytes::from_bytes(&[]),
    }
}

/// A keyshare for party 0 in `AggregatingDecryptionKey(current)`, in a committee of the three
/// `signers`. It signs as party 0. `setup` edits the recovery state.
async fn committee_actor(
    e3_id: &E3id,
    signers: &[alloy::signers::local::PrivateKeySigner; 3],
    current: AggregatingDecryptionKey,
    cipher: Arc<Cipher>,
    setup: impl FnOnce(&mut ThresholdKeyshareRecoveryState),
) -> Result<CommitteeActor> {
    let (bus, history) = test_bus();
    let (state, _) = test_state(e3_id, KeyshareState::AggregatingDecryptionKey(current));
    let (mut recovery, recovery_repo) = test_recovery_with_repo();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(
            CiphernodeSelected {
                e3_id: e3_id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                party_id: 0,
                committee: signers
                    .iter()
                    .map(|signer| signer.address().to_string())
                    .collect(),
                ..Default::default()
            },
            test_ec(1),
        ));
        setup(&mut recovery);
        Ok(recovery)
    })?;
    let actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus: bus.clone(),
        cipher,
        state,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer: signers[0].clone(),
        effects_enabled: false,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });
    Ok(CommitteeActor {
        actor,
        bus,
        history,
        recovery_repo,
    })
}

struct CommitteeActor {
    actor: ThresholdKeyshare,
    bus: BusHandle,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    recovery_repo: Repository<ThresholdKeyshareRecoveryState>,
}

fn three_signers() -> [alloy::signers::local::PrivateKeySigner; 3] {
    std::array::from_fn(|_| alloy::signers::local::PrivateKeySigner::random())
}

/// A C2 proof of `proof_type` by `party_id`. Dealer identity hashes the statement, not the
/// signature, so the proof is not signed.
fn c2_proof(e3_id: &E3id, proof_type: ProofType, party_id: u64) -> SignedProofPayload {
    let circuit = match proof_type {
        ProofType::C2aSkShareComputation => CircuitName::SkShareComputation,
        _ => CircuitName::ESmShareComputation,
    };
    SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof: Proof::new(
                circuit,
                ArcBytes::from_bytes(&[party_id as u8]),
                ArcBytes::from_bytes(&[party_id as u8, 1]),
            ),
        },
        signature: ArcBytes::from_bytes(&[]),
    }
}

/// A completed C2/C3 verification with no dishonest party.
fn share_proofs_verified(e3_id: &E3id) -> TypedEvent<ShareVerificationComplete> {
    TypedEvent::new(
        ShareVerificationComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ShareProofs,
            dishonest_parties: BTreeSet::new(),
        },
        test_ec(1),
    )
}

/// A keyshare for party 0 in share aggregation, with its own shares and C0 proof, whose share
/// batch held only dealer 1. Dealer 1 is expelled and dealer 2's share is recorded, so the batch
/// can grow to `{2}`. `verified` says whether the first batch's verdict is already recorded.
/// Peers 1 and 2 have sent their shares. `setup` sets the saved C2/C3 batch.
async fn committee_with_two_shares(
    e3_id: &E3id,
    setup: impl FnOnce(&mut ThresholdKeyshareRecoveryState),
) -> Result<CommitteeActor> {
    let signers = three_signers();
    let cipher = Arc::new(Cipher::from_password("test-password").await?);
    // One row per own share: each peer needs one C3a and one C3b proof and one ESI share.
    let rows = bincode::serialize(&vec![vec![1u64]])?;
    let current = AggregatingDecryptionKey {
        own_sk_share_raw: SensitiveBytes::new(rows.clone(), &cipher)?,
        own_esi_shares_raw: vec![SensitiveBytes::new(rows, &cipher)?],
        ..aggregating_decryption_key_for_roster_test()
    };
    // C0 output and C3 recipient-key input share one 32-byte field.
    let proof = SignedProofPayload {
        payload: ProofPayload {
            e3_id: e3_id.clone(),
            proof_type: ProofType::C3aSkShareEncryption,
            proof: Proof::new(
                CircuitName::PkBfv,
                ArcBytes::from_bytes(&[]),
                ArcBytes::from_bytes(&[7; 32]),
            ),
        },
        signature: ArcBytes::from_bytes(&[]),
    };
    let mut committee = committee_actor(e3_id, &signers, current, cipher, setup).await?;
    let actor = &mut committee.actor;
    actor.record_encryption_key(&TypedEvent::new(
        EncryptionKeyCreated {
            e3_id: e3_id.clone(),
            key: Arc::new(
                EncryptionKey::new(0, ArcBytes::from_bytes(&[0]))
                    .with_signed_payload(proof.clone()),
            ),
            external: false,
        },
        test_ec(1),
    ))?;
    for party_id in [1, 2] {
        actor.record_threshold_share(&TypedEvent::new(
            ThresholdShareCreated {
                share: Arc::new(ThresholdShare {
                    party_id,
                    pk_share: ArcBytes::from_bytes(&[party_id as u8]),
                    sk_sss: Default::default(),
                    esi_sss: vec![Default::default()],
                }),
                signed_c2a_proof: Some(proof.clone()),
                signed_c2b_proof: Some(proof.clone()),
                signed_c3a_proofs: vec![proof.clone()],
                signed_c3b_proofs: vec![proof.clone()],
                ..peer_share(e3_id, party_id)
            },
            test_ec(party_id + 1),
        ))?;
    }
    Ok(committee)
}

async fn batch_with_an_expelled_dealer(e3_id: &E3id, verified: bool) -> Result<CommitteeActor> {
    let mut committee = committee_with_two_shares(e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([1]));
        if verified {
            recovery.share_verification_complete = Some(share_proofs_verified(e3_id));
        }
    })
    .await?;
    committee
        .actor
        .handle_committee_member_expelled(expulsion_of(e3_id, 1), test_ec(4))?;
    Ok(committee)
}

/// The context of the C2/C3 dispatch that the actor sent for `dealers`.
async fn share_dispatch_of(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    dealers: &[u64],
) -> Result<EventContext<Sequenced>> {
    Ok(share_dispatch_event_of(history, dealers)
        .await?
        .get_ctx()
        .clone())
}

/// The C2/C3 dispatch that the actor sent for `dealers`, as the event log holds it.
async fn share_dispatch_event_of(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    dealers: &[u64],
) -> Result<InterfoldEvent> {
    actix::clock::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            let dispatch = events.iter().find(|event| {
                matches!(
                    event.get_data(),
                    InterfoldEventData::ShareVerificationDispatched(dispatch)
                        if dispatch.kind == VerificationKind::ShareProofs
                            && dispatch
                                .share_proofs
                                .iter()
                                .map(|proofs| proofs.sender_party_id)
                                .eq(dealers.iter().copied())
                )
            });
            if let Some(dispatch) = dispatch {
                return Ok(dispatch.clone());
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?
}

/// Reports how many C2/C3 results a running actor keeps for a later dispatch.
#[derive(Message)]
#[rtype(result = "usize")]
struct KeptShareVerdicts;

impl Handler<KeptShareVerdicts> for ThresholdKeyshare {
    type Result = usize;
    fn handle(&mut self, _: KeptShareVerdicts, _: &mut Self::Context) -> usize {
        self.pending.parked_share_verdicts.len()
    }
}

async fn wait_for_kept_share_verdicts(actor: &Addr<ThresholdKeyshare>, count: usize) -> Result<()> {
    actix::clock::timeout(std::time::Duration::from_secs(10), async {
        while actor.send(KeptShareVerdicts).await? != count {
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    })
    .await?
}

#[actix::test]
async fn a_share_batch_grows_past_a_dealer_that_was_expelled() -> Result<()> {
    let e3_id = E3id::new("batch-past-expelled", 1);
    let CommitteeActor {
        mut actor, history, ..
    } = batch_with_an_expelled_dealer(&e3_id, true).await?;

    actor.dispatch_expanded_threshold_share_batch(test_ec(5))?;

    assert_eq!(
        actor.recovery.try_get()?.collected_threshold_share_ids,
        Some(BTreeSet::from([2]))
    );
    let dispatched = next_event(&history).await?;
    let InterfoldEventData::ShareVerificationDispatched(dispatched) = dispatched.into_data() else {
        panic!("expected the grown batch to be verified");
    };
    assert_eq!(
        dispatched
            .share_proofs
            .iter()
            .map(|party| party.sender_party_id)
            .collect::<Vec<_>>(),
        vec![2]
    );
    Ok(())
}

#[actix::test]
async fn a_grown_batch_completes_when_its_verdict_equals_the_first() -> Result<()> {
    let e3_id = E3id::new("grown-batch-verdict", 1);
    let CommitteeActor {
        actor,
        bus,
        history,
        recovery_repo,
    } = batch_with_an_expelled_dealer(&e3_id, false).await?;
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    // Each verdict comes from its own dispatch, as in production; the payloads are equal.
    let verdict = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ShareProofs,
        dishonest_parties: BTreeSet::new(),
    };
    let dispatch_before_restart = |batch: &str| {
        keyshare_event(TestEvent::new(batch, 1), 10, EventSource::Local)
            .get_ctx()
            .clone()
    };

    // The verdict for `{1}` arrives after dealer 1's expulsion, so the batch grows to `{2}`.
    bus.publish(verdict.clone(), dispatch_before_restart("first batch"))?;
    wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids == Some(BTreeSet::from([2]))
            && recovery.share_verification_complete.is_none()
    })
    .await?;

    // `{1}` was also sent before the restart with another payload. Its verdict counts dealer 2,
    // which only the grown batch holds, so it is kept.
    bus.publish(
        verdict.clone(),
        dispatch_before_restart("first batch, sent again"),
    )?;
    wait_for_kept_share_verdicts(&actor, 1).await?;
    let recovery = recovery_repo.read().await?.expect("saved recovery state");
    assert!(recovery.share_verification_complete.is_none());
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::new()));

    // The grown batch's verdict is equal to the first one and must still be delivered.
    bus.publish(verdict, share_dispatch_of(&history, &[2]).await?)?;
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_verification_complete.is_some()
    })
    .await?;
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([2])));
    Ok(())
}

#[actix::test]
async fn a_verdict_of_an_earlier_batch_does_not_complete_a_grown_batch() -> Result<()> {
    let e3_id = E3id::new("earlier-batch-verdict", 1);
    let CommitteeActor {
        mut actor,
        bus,
        history,
        recovery_repo,
    } = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
    })
    .await?;
    actor.verify_recorded_threshold_shares(test_ec(4))?;
    let first_dispatch = share_dispatch_of(&history, &[2]).await?;
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    let verdict = |dishonest_parties: BTreeSet<u64>| ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ShareProofs,
        dishonest_parties,
    };

    // `{2}` is verified, and the batch grows to `{1, 2}`.
    bus.publish(verdict(BTreeSet::new()), first_dispatch.clone())?;
    wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids == Some(BTreeSet::from([1, 2]))
            && recovery.share_verification_complete.is_none()
    })
    .await?;

    // Another verdict of the first dispatch does not count dealer 1 as verified.
    bus.publish(verdict(BTreeSet::from([2])), first_dispatch)?;
    wait_for_kept_share_verdicts(&actor, 1).await?;
    let recovery = recovery_repo.read().await?.expect("saved recovery state");
    assert!(recovery.share_verification_complete.is_none());
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([2])));

    bus.publish(
        verdict(BTreeSet::new()),
        share_dispatch_of(&history, &[1, 2]).await?,
    )?;
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_verification_complete.is_some()
    })
    .await?;
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([1, 2])));
    Ok(())
}

#[actix::test]
async fn a_kept_verdict_applies_when_restart_sends_its_batch_again() -> Result<()> {
    let e3_id = E3id::new("kept-share-verdict", 1);
    let verdict = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ShareProofs,
        dishonest_parties: BTreeSet::new(),
    };
    // Before the restart, the batch grew past expelled dealer 1 to `{2}` and was sent.
    let before = batch_with_an_expelled_dealer(&e3_id, false).await?;
    let first_actor = before.actor.start();
    before.bus.subscribe(
        EventType::ShareVerificationComplete,
        first_actor.recipient(),
    );
    let first_dispatch = keyshare_event(TestEvent::new("first batch", 1), 10, EventSource::Local)
        .get_ctx()
        .clone();
    before.bus.publish(verdict.clone(), first_dispatch)?;
    let grown_dispatch = share_dispatch_of(&before.history, &[2]).await?;

    // After the restart, replay delivers the grown batch's verdict before the batch is sent again.
    let after = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        recovery.verified_dealer_ids = Some(BTreeSet::new());
    })
    .await?;
    let CommitteeActor {
        mut actor,
        bus,
        recovery_repo,
        ..
    } = after;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    bus.publish(verdict, grown_dispatch)?;
    wait_for_kept_share_verdicts(&actor, 1).await?;

    // The batch is sent again with the same payload, which applies the kept verdict.
    actor
        .send(keyshare_event(EffectsEnabled::new(), 3, EventSource::Local))
        .await?;
    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_verification_complete.is_some()
    })
    .await?;
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([2])));
    Ok(())
}

/// The recovery state keeps the C2/C3 dispatch IDs of the current batch. After a restart, replay
/// therefore applies the result of a dispatch sent before the restart where it applied before,
/// without waiting for `EffectsEnabled` to send the batch again.
#[actix::test]
async fn a_restart_applies_the_result_of_a_dispatch_sent_before_it() -> Result<()> {
    let e3_id = E3id::new("persisted-share-dispatch", 1);
    let verdict = ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ShareProofs,
        dishonest_parties: BTreeSet::new(),
    };
    // Before the restart, the batch grew past expelled dealer 1 to `{2}` and was sent.
    let before = batch_with_an_expelled_dealer(&e3_id, false).await?;
    let first_actor = before.actor.start();
    before.bus.subscribe(
        EventType::ShareVerificationComplete,
        first_actor.recipient(),
    );
    let first_dispatch = keyshare_event(TestEvent::new("first batch", 1), 10, EventSource::Local)
        .get_ctx()
        .clone();
    before.bus.publish(verdict.clone(), first_dispatch)?;
    let grown_dispatch = share_dispatch_of(&before.history, &[2]).await?;
    let persisted = wait_for_record(&before.recovery_repo, |recovery| {
        recovery.share_dispatch_ids.contains(&grown_dispatch.id())
    })
    .await?;

    // After the restart, replay delivers the grown batch's verdict before the batch is sent again.
    let after = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        recovery.verified_dealer_ids = Some(BTreeSet::new());
        recovery.share_dispatch_ids = persisted.share_dispatch_ids.clone();
    })
    .await?;
    let CommitteeActor {
        mut actor,
        bus,
        recovery_repo,
        ..
    } = after;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    bus.publish(verdict, grown_dispatch)?;

    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_verification_complete.is_some()
    })
    .await?;
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([2])));
    assert_eq!(actor.send(KeptShareVerdicts).await?, 0);
    Ok(())
}

/// A dispatch ID can be missing from the saved state: `EffectsEnabled` sends a recorded batch
/// again without a logged cause, and the node can stop before that write is saved. Replay delivers
/// the logged dispatch before its result, so the actor records the ID again, and the result applies
/// where it applied before the restart instead of waiting for the next `EffectsEnabled`.
#[actix::test]
async fn replay_records_a_logged_dispatch_that_the_saved_state_lacks() -> Result<()> {
    let e3_id = E3id::new("logged-share-dispatch", 1);
    // The batch grew past expelled dealer 1 to `{2}`, and `{2}` has no result yet.
    let saved_batch = |recovery: &mut ThresholdKeyshareRecoveryState| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        recovery.verified_dealer_ids = Some(BTreeSet::new());
    };
    let CommitteeActor {
        mut actor, history, ..
    } = committee_with_two_shares(&e3_id, saved_batch).await?;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 5, EventSource::Local))
        .await?;
    let (dispatch, dispatch_ec) = share_dispatch_event_of(&history, &[2])
        .await?
        .into_components();

    // After the restart, the saved state has the batch but not the ID of that dispatch.
    let CommitteeActor {
        mut actor,
        bus,
        recovery_repo,
        ..
    } = committee_with_two_shares(&e3_id, saved_batch).await?;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    actor
        .send(keyshare_event(dispatch, 6, EventSource::Local))
        .await?;
    bus.publish(
        ShareVerificationComplete {
            e3_id: e3_id.clone(),
            kind: VerificationKind::ShareProofs,
            dishonest_parties: BTreeSet::new(),
        },
        dispatch_ec.clone(),
    )?;

    let recovery = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_verification_complete.is_some()
    })
    .await?;
    assert_eq!(recovery.verified_dealer_ids, Some(BTreeSet::from([2])));
    assert!(recovery.share_dispatch_ids.contains(&dispatch_ec.id()));
    assert_eq!(actor.send(KeptShareVerdicts).await?, 0);
    Ok(())
}

/// A batch that `EffectsEnabled` sends again is saved with the last saved context, which the store
/// can refuse as stale. When the logged dispatch reaches the actor, the actor saves its recovery
/// state again at the dispatch's own position, also though it already holds the ID, so a later
/// snapshot cut keeps the ID.
#[actix::test]
async fn a_logged_dispatch_is_saved_at_its_own_position() -> Result<()> {
    let e3_id = E3id::new("dispatch-position", 1);
    let CommitteeActor {
        mut actor,
        history,
        recovery_repo,
        ..
    } = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        recovery.verified_dealer_ids = Some(BTreeSet::new());
    })
    .await?;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let actor = actor.start();
    actor
        .send(keyshare_event(EffectsEnabled::new(), 5, EventSource::Local))
        .await?;
    let (dispatch, dispatch_ec) = share_dispatch_event_of(&history, &[2])
        .await?
        .into_components();
    let resent = wait_for_record(&recovery_repo, |recovery| {
        recovery.share_dispatch_ids.contains(&dispatch_ec.id())
    })
    .await?;
    assert_ne!(resent.last_ec.map(|ec| ec.id()), Some(dispatch_ec.id()));

    actor
        .send(keyshare_event(dispatch, 6, EventSource::Local))
        .await?;

    wait_for_record(&recovery_repo, |recovery| {
        recovery
            .last_ec
            .as_ref()
            .is_some_and(|ec| ec.id() == dispatch_ec.id())
            && recovery.share_dispatch_ids.contains(&dispatch_ec.id())
    })
    .await?;
    Ok(())
}

/// A logged dispatch of an earlier batch does not verify a grown batch, so the actor does not
/// record its ID, and another result of it is kept instead of completing the grown batch.
#[actix::test]
async fn a_logged_dispatch_of_an_earlier_batch_is_not_recorded_for_a_grown_batch() -> Result<()> {
    let e3_id = E3id::new("earlier-logged-dispatch", 1);
    let CommitteeActor {
        mut actor,
        bus,
        history,
        recovery_repo,
    } = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
    })
    .await?;
    actor.verify_recorded_threshold_shares(test_ec(4))?;
    let (first_dispatch, first_ec) = share_dispatch_event_of(&history, &[2])
        .await?
        .into_components();
    let actor = actor.start();
    bus.subscribe(
        EventType::ShareVerificationComplete,
        actor.clone().recipient(),
    );
    let verdict = |dishonest_parties: BTreeSet<u64>| ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::ShareProofs,
        dishonest_parties,
    };

    // `{2}` is verified, and the batch grows to `{1, 2}`.
    bus.publish(verdict(BTreeSet::new()), first_ec.clone())?;
    wait_for_record(&recovery_repo, |recovery| {
        recovery.collected_threshold_share_ids == Some(BTreeSet::from([1, 2]))
            && recovery.share_verification_complete.is_none()
    })
    .await?;

    // The first dispatch arrives again, then another result of it.
    actor
        .send(keyshare_event(first_dispatch, 6, EventSource::Local))
        .await?;
    bus.publish(verdict(BTreeSet::from([2])), first_ec.clone())?;
    wait_for_kept_share_verdicts(&actor, 1).await?;
    let recovery = recovery_repo.read().await?.expect("saved recovery state");
    assert!(!recovery.share_dispatch_ids.contains(&first_ec.id()));
    assert!(recovery.share_verification_complete.is_none());
    Ok(())
}

/// A verified batch stays verified when the collector reports its live dealers again together
/// with an expelled dealer: an expelled dealer is not growth, so the result is not cleared and the
/// same batch is not sent for verification again.
#[actix::test]
async fn an_expelled_dealer_does_not_restart_a_verified_batch() -> Result<()> {
    let e3_id = E3id::new("expelled-is-not-growth", 1);
    let CommitteeActor { mut actor, .. } = committee_with_two_shares(&e3_id, |recovery| {
        recovery.collected_threshold_share_ids = Some(BTreeSet::from([2]));
        recovery.verified_dealer_ids = Some(BTreeSet::from([2]));
        recovery.share_verification_complete = Some(share_proofs_verified(&e3_id));
    })
    .await?;
    actor.handle_committee_member_expelled(expulsion_of(&e3_id, 1), test_ec(4))?;
    let shares = [1u64, 2].map(|party_id| {
        (
            party_id,
            Arc::new(ThresholdShare {
                party_id,
                pk_share: ArcBytes::from_bytes(&[party_id as u8]),
                sk_sss: Default::default(),
                esi_sss: vec![Default::default()],
            }),
        )
    });
    let replacement = AllThresholdSharesCollected::new(
        std::collections::HashMap::from(shares),
        Default::default(),
    );

    assert!(!actor.record_collected_threshold_shares(&TypedEvent::new(replacement, test_ec(5)))?);
    let recovery = actor.recovery.try_get()?;
    assert_eq!(
        recovery.collected_threshold_share_ids,
        Some(BTreeSet::from([2]))
    );
    assert!(recovery.share_verification_complete.is_some());
    Ok(())
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
        recovery_payloads: test_recovery_payloads(),
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
async fn roster_from_future_aggregator_is_held_until_promotion() -> Result<()> {
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
    let deferred_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Roster,
        vec![
            DkgDealer {
                party_id: 0,
                contribution_hash: [0; 32],
            },
            DkgDealer {
                party_id: 1,
                contribution_hash: [1; 32],
            },
        ],
        &signers[2],
    )?;
    let proposer_ready = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Ready,
        vec![
            DkgDealer {
                party_id: 0,
                contribution_hash: [0; 32],
            },
            DkgDealer {
                party_id: 1,
                contribution_hash: [1; 32],
            },
            DkgDealer {
                party_id: 2,
                contribution_hash: [2; 32],
            },
        ],
        &signers[2],
    )?;
    let conflicting_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Roster,
        vec![
            DkgDealer {
                party_id: 0,
                contribution_hash: [0; 32],
            },
            DkgDealer {
                party_id: 2,
                contribution_hash: [2; 32],
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
        recovery.ready_by_party.insert(2, proposer_ready);
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
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.record_dkg_coordination(deferred_roster.clone(), test_ec(2))?;

    let recovery = actor.recovery.try_get()?;
    assert!(recovery.dkg_roster.is_none());
    assert_eq!(recovery.pending_rosters.get(&2), Some(&deferred_roster));

    actor.record_dkg_coordination(conflicting_roster, test_ec(3))?;
    assert_eq!(
        actor.recovery.try_get()?.pending_rosters.get(&2),
        Some(&deferred_roster)
    );

    actor.handle_aggregator_changed(
        AggregatorChanged {
            e3_id: e3_id.clone(),
            active_party_id: Some(2),
            is_aggregator: false,
        },
        test_ec(4),
    )?;

    let recovery = actor.recovery.try_get()?;
    assert_eq!(recovery.dkg_roster, Some(deferred_roster));
    assert!(recovery.pending_rosters.is_empty());
    assert_eq!(
        actor.state.try_get()?.honest_parties,
        Some(BTreeSet::from([0, 1]))
    );
    Ok(())
}

#[actix::test]
async fn held_roster_starts_failover_without_every_peer_ready_report() -> Result<()> {
    let (bus, history) = test_bus();
    let e3_id = E3id::new("44", 1);
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
        vec![dealer(0), dealer(1)],
        &signers[0],
    )?;
    let proposer_ready = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Ready,
        vec![dealer(0), dealer(1), dealer(2)],
        &signers[2],
    )?;
    let held_roster = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        2,
        DkgCoordinationKind::Roster,
        vec![dealer(0), dealer(1)],
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
        recovery.dkg_ready = Some(own_ready.clone());
        recovery.ready_by_party.insert(0, own_ready);
        recovery.ready_by_party.insert(2, proposer_ready);
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
        effects_enabled: true,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.record_dkg_coordination(held_roster.clone(), test_ec(2))?;

    let event = next_event(&history).await?;
    assert!(matches!(
        event.into_data(),
        InterfoldEventData::AggregationInputsReady(AggregationInputsReady {
            phase: AggregationPhase::DkgRoster,
            ..
        })
    ));
    let recovery = actor.recovery.try_get()?;
    assert!(recovery.dkg_roster.is_none());
    assert_eq!(recovery.pending_rosters.get(&2), Some(&held_roster));
    Ok(())
}

#[actix::test]
async fn lower_ranked_roster_replaces_an_accepted_roster_before_c4() -> Result<()> {
    let (bus, _history) = test_bus();
    let e3_id = E3id::new("45", 1);
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
    let all_dealers = vec![dealer(0), dealer(1), dealer(2)];
    let ready = |party_id: usize| {
        DkgCoordination::sign(
            e3_id.clone(),
            Address::ZERO,
            party_id as u64,
            DkgCoordinationKind::Ready,
            all_dealers.clone(),
            &signers[party_id],
        )
    };
    let higher = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        1,
        DkgCoordinationKind::Roster,
        vec![dealer(0), dealer(2)],
        &signers[1],
    )?;
    let lower = DkgCoordination::sign(
        e3_id.clone(),
        Address::ZERO,
        0,
        DkgCoordinationKind::Roster,
        vec![dealer(1), dealer(2)],
        &signers[0],
    )?;

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
    let own_ready = ready(2)?;
    let mut recovery = test_recovery();
    recovery.try_mutate_without_context(|mut recovery| {
        recovery.ciphernode_selected = Some(TypedEvent::new(
            CiphernodeSelected {
                e3_id: e3_id.clone(),
                threshold_m: 1,
                threshold_n: 3,
                party_id: 2,
                committee,
                ..Default::default()
            },
            test_ec(1),
        ));
        recovery.dkg_ready = Some(own_ready.clone());
        recovery.ready_by_party.insert(1, ready(1)?);
        recovery.ready_by_party.insert(2, own_ready);
        recovery.active_aggregator_party_id = Some(1);
        Ok(recovery)
    })?;
    let mut actor = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus,
        cipher: Arc::new(Cipher::from_password("test-password").await?),
        state,
        share_enc_preset: DEFAULT_BFV_PRESET,
        interfold_address: Address::ZERO,
        signer: signers[2].clone(),
        effects_enabled: false,
        recovery,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    });

    actor.record_dkg_coordination(lower.clone(), test_ec(2))?;
    assert!(actor.recovery.try_get()?.dkg_roster.is_none());
    assert_eq!(
        actor.recovery.try_get()?.pending_rosters.get(&0).cloned(),
        Some(lower.clone())
    );

    actor.record_dkg_coordination(higher, test_ec(3))?;
    assert_eq!(
        actor
            .recovery
            .try_get()?
            .dkg_roster
            .as_ref()
            .map(|r| r.party_id),
        Some(1)
    );

    actor.record_dkg_coordination(ready(0)?, test_ec(4))?;
    assert_eq!(actor.recovery.try_get()?.dkg_roster, Some(lower));
    assert_eq!(
        actor.state.try_get()?.honest_parties,
        Some(BTreeSet::from([1, 2]))
    );
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
        recovery.dkg_ready = Some(own_ready.clone());
        recovery.ready_by_party.insert(0, own_ready);
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
        recovery_payloads: test_recovery_payloads(),
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
        recovery_payloads: test_recovery_payloads(),
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

#[actix::test]
async fn local_trbfv_error_does_not_fail_the_shared_e3() -> Result<()> {
    let (actor, history, e3_id, repo) = start_actor().await?;
    let error = ComputeRequestError::new(
        ComputeRequestErrorKind::TrBFV(TrBFVError::GenEsiSss(TrBFVFailure::from(
            "local worker failure",
        ))),
        ComputeRequest::trbfv(
            TrBFVRequest::GenEsiSss(GenEsiSssRequest {
                trbfv_config: TrBFVConfig::new(ArcBytes::from_bytes(b"params"), 3, 1),
                e_sm_raw: SensitiveBytes::from_encrypted(&[1]),
            }),
            CorrelationId::new(),
            e3_id,
        ),
    );
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        error.into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1);

    actor.send(event).await?;
    actix::clock::sleep(std::time::Duration::from_millis(25)).await;

    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .iter()
        .all(|event| !matches!(event.get_data(), InterfoldEventData::E3Failed(_))));
    assert!(matches!(
        repo.read().await?.expect("persisted keyshare state").state,
        KeyshareState::Init
    ));
    Ok(())
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
    let (actor, history, e3_id, repo) =
        start_actor_with_state(KeyshareState::ReadyForDecryption(ready_for_c4_test())).await?;
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

async fn assert_no_collector_failure(
    bus: &BusHandle,
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    barrier: u64,
) -> Result<()> {
    let marker = TestEvent::new("collector failure barrier", barrier);
    bus.publish_without_context(marker.clone())?;
    actix::clock::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
            if events.iter().any(|event| {
                matches!(event.get_data(), InterfoldEventData::TestEvent(data) if *data == marker)
            }) {
                assert!(events.iter().all(|event| !matches!(
                    event.get_data(),
                    InterfoldEventData::E3Failed(_)
                        | InterfoldEventData::EncryptionKeyCollectionFailed(_)
                        | InterfoldEventData::ThresholdShareCollectionFailed(_)
                )), "a superseded collection must not publish a failure");
                return Ok(());
            }
            actix::clock::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?
}

async fn stale_threshold_share_deadline_preserves_decryption(decrypting: bool) -> Result<()> {
    let e3_id = E3id::new("stale-share-deadline", 1);
    let CommitteeActor {
        mut actor,
        bus,
        history,
        recovery_repo,
    } = committee_with_two_shares(&e3_id, |_| {}).await?;
    let (mut state, repo) = test_state(&e3_id, actor.state.try_get()?.state);
    state.try_mutate_without_context(|mut state| {
        state.params = insecure_threshold_params();
        state.honest_parties = Some(BTreeSet::from([0, 1]));
        Ok(state)
    })?;
    actor.state = state;

    // Supply the C4 witness intent and the compute response at the crypto boundary. Collection,
    // phase transitions, failure delivery, and snapshot recovery use the production actor paths.
    let current: AggregatingDecryptionKey = actor.state.try_get()?.try_into()?;
    let sk_request = DkgShareDecryptionProofRequest {
        sk_bfv: current.sk_bfv,
        honest_ciphertexts_raw: vec![ArcBytes::from_bytes(&[1])],
        num_honest_parties: 2,
        num_moduli: 1,
        own_plaintext_idx: Some(0),
        own_share_raw: Some(current.own_sk_share_raw),
        dkg_input_type: e3_zk_helpers::computation::DkgInputType::SecretKey,
        params_preset: BfvPreset::InsecureDkg512,
        committee_size: actor.state.try_get()?.committee_size()?,
    };
    let esm_request = DkgShareDecryptionProofRequest {
        dkg_input_type: e3_zk_helpers::computation::DkgInputType::SmudgingNoise,
        own_share_raw: Some(current.own_esi_shares_raw[0].clone()),
        ..sk_request.clone()
    };
    actor.pending.share_decryption_data = Some((sk_request, vec![esm_request]));
    let share = actor
        .recovery_payloads
        .share(1)
        .expect("recorded peer share")
        .clone();
    let cipher = actor.cipher.clone();
    let signer = actor.signer.clone();
    let mut collector = None;
    let parent = ThresholdKeyshare::create(|ctx| {
        collector = Some(
            actor
                .ensure_collector(
                    ctx.address(),
                    &test_ec(4),
                    crate::domain::timeout_policy::now_unix_secs(),
                )
                .expect("share collector"),
        );
        actor
    });
    let collector = collector.expect("share collector");
    collector.send(share).await?;
    collector.send(ThresholdShareCollectionCutoff).await?;
    share_dispatch_of(&history, &[1]).await?;
    assert!(
        collector.connected(),
        "the soft cutoff keeps the deadline active"
    );

    parent
        .send(TypedEvent::new(
            ComputeResponse::trbfv(
                TrBFVResponse::CalculateDecryptionKey(CalculateDecryptionKeyResponse {
                    sk_poly_sum: SensitiveBytes::from_encrypted(&[2]),
                    es_poly_sum: vec![SensitiveBytes::from_encrypted(&[3])],
                }),
                CorrelationId::new(),
                e3_id.clone(),
            ),
            test_ec(5),
        ))
        .await?;
    wait_for_keyshare_state(&repo, |state| {
        matches!(state, KeyshareState::ReadyForDecryption(_))
    })
    .await?;
    if decrypting {
        parent
            .send(TypedEvent::new(
                CiphertextOutputPublished {
                    e3_id: e3_id.clone(),
                    ciphertext_output: vec![ArcBytes::from_bytes(&[4])],
                    ciphertext_commitment: [0; 32],
                },
                test_ec(6),
            ))
            .await?;
        wait_for_keyshare_state(&repo, |state| matches!(state, KeyshareState::Decrypting(_)))
            .await?;
    }
    let expected = repo.read().await?.expect("decryption state");
    assert!(recovery_repo
        .read()
        .await?
        .expect("recovery state")
        .threshold_share_refs
        .is_empty());

    collector
        .send(ExpelPartyFromShareCollection {
            party_id: 1,
            ec: test_ec(7),
        })
        .await?;
    collector.send(ThresholdShareCollectionTimeout).await?;
    // This mailbox barrier follows the collector's failure message to the parent.
    parent
        .send(keyshare_event(
            TestEvent::new("parent barrier", 1),
            8,
            EventSource::Local,
        ))
        .await?;
    assert_eq!(
        repo.read().await?.expect("persisted decryption state"),
        expected
    );
    assert_no_collector_failure(&bus, &history, 1).await?;

    parent.send(Die).await?;
    let recovered = ThresholdKeyshare::new(ThresholdKeyshareParams {
        bus: bus.clone(),
        cipher,
        state: repo.load().await?,
        share_enc_preset: BfvPreset::InsecureDkg512,
        interfold_address: Address::ZERO,
        signer,
        effects_enabled: false,
        recovery: recovery_repo.load().await?,
        recovery_payloads: test_recovery_payloads(),
        dkg_timing_reader: Arc::new(|_| Box::pin(async { Ok((8_200, 7_200)) })),
    })
    .start();
    recovered
        .send(keyshare_event(EffectsEnabled::new(), 9, EventSource::Local))
        .await?;
    deliver_collector_failure(
        &recovered,
        DkgTimeoutPhase::ThresholdShareCollection,
        &e3_id,
    )
    .await?;
    assert_eq!(
        repo.read().await?.expect("restored decryption state"),
        expected
    );
    assert_no_collector_failure(&bus, &history, 2).await?;
    recovered.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn stale_threshold_share_deadline_preserves_ready_state_after_restart() -> Result<()> {
    stale_threshold_share_deadline_preserves_decryption(false).await
}

#[actix::test]
async fn stale_threshold_share_deadline_preserves_decrypting_state_after_restart() -> Result<()> {
    stale_threshold_share_deadline_preserves_decryption(true).await
}

fn generating_threshold_share_state(e3_id: &E3id) -> KeyshareState {
    let KeyshareState::CollectingEncryptionKeys(current) = collecting_encryption_keys_state(e3_id)
    else {
        unreachable!();
    };
    KeyshareState::GeneratingThresholdShare(GeneratingThresholdShareData {
        pk_share: None,
        sk_sss: None,
        esi_sss: None,
        e_sm_raw: None,
        sk_bfv: current.sk_bfv,
        pk_bfv: current.pk_bfv,
        collected_encryption_keys: Vec::new(),
        ciphernode_selected: Some(current.ciphernode_selected),
        proof_request_data: None,
    })
}

#[actix::test]
async fn unfinished_threshold_collection_fails_at_the_canonical_deadline() -> Result<()> {
    let e3_id = E3id::new("unfinished-dkg", 1);
    for phase in [
        KeyshareState::Init,
        collecting_encryption_keys_state(&e3_id),
        generating_threshold_share_state(&e3_id),
        KeyshareState::AggregatingDecryptionKey(aggregating_decryption_key_for_roster_test()),
    ] {
        let (mut actor, repo, _, history) = build_actor(&e3_id, phase, 7_200, 7_200, &[]).await?;
        let bus = actor.bus.clone();
        let mut collector = None;
        let parent = ThresholdKeyshare::create(|ctx| {
            collector = Some(
                actor
                    .ensure_collector(
                        ctx.address(),
                        &test_ec(1),
                        crate::domain::timeout_policy::now_unix_secs(),
                    )
                    .expect("share collector"),
            );
            actor
        });
        let collector = collector.expect("share collector");
        collector.send(ThresholdShareCollectionCutoff).await?;
        parent
            .send(keyshare_event(
                TestEvent::new("parent barrier", 1),
                2,
                EventSource::Local,
            ))
            .await?;
        assert_no_collector_failure(&bus, &history, 1).await?;
        history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;

        collector.send(ThresholdShareCollectionTimeout).await?;
        let events = next_events(&history, 2).await?;
        assert!(events.iter().any(|event| matches!(event.get_data(),
            InterfoldEventData::ThresholdShareCollectionFailed(data) if data.e3_id == e3_id
        )));
        assert!(events.iter().any(|event| matches!(event.get_data(),
            InterfoldEventData::E3Failed(data) if data.e3_id == e3_id
                && data.failed_at_stage == E3Stage::CommitteeFinalized
                && data.reason == FailureReason::DKGTimeout
        )));
        assert!(matches!(
            repo.read().await?.expect("persisted failure").state,
            KeyshareState::Failed {
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGTimeout
            }
        ));
        parent.send(Die).await?;
    }
    Ok(())
}

async fn deliver_collector_failure(
    actor: &Addr<ThresholdKeyshare>,
    phase: DkgTimeoutPhase,
    e3_id: &E3id,
) -> Result<()> {
    match phase {
        DkgTimeoutPhase::EncryptionKeyCollection => {
            actor
                .send(EncryptionKeyCollectionFailed {
                    e3_id: e3_id.clone(),
                    reason: "missing encryption keys".into(),
                    missing_parties: vec![1],
                })
                .await?
        }
        DkgTimeoutPhase::ThresholdShareCollection => {
            actor
                .send(ThresholdShareCollectionFailed {
                    e3_id: e3_id.clone(),
                    reason: "missing threshold shares".into(),
                    missing_parties: vec![1],
                })
                .await?
        }
        DkgTimeoutPhase::DecryptionKeySharedCollection => {
            actor
                .send(DecryptionKeySharedCollectionFailed {
                    e3_id: e3_id.clone(),
                    reason: "missing decryption key shares".into(),
                    missing_parties: vec![1],
                })
                .await?
        }
    }
    Ok(())
}

#[actix::test]
async fn collector_failures_ignore_another_e3() -> Result<()> {
    let e3_id = E3id::new("current-collection", 1);
    for (phase, state) in [
        (
            DkgTimeoutPhase::EncryptionKeyCollection,
            collecting_encryption_keys_state(&e3_id),
        ),
        (
            DkgTimeoutPhase::ThresholdShareCollection,
            generating_threshold_share_state(&e3_id),
        ),
        (
            DkgTimeoutPhase::DecryptionKeySharedCollection,
            KeyshareState::ReadyForDecryption(ready_for_c4_test()),
        ),
    ] {
        let (actor, repo, _, history) = build_actor(&e3_id, state, 7_200, 7_200, &[]).await?;
        let bus = actor.bus.clone();
        let expected = actor.state.try_get()?;
        let actor = actor.start();
        for other_e3 in [
            E3id::new("other-collection", 1),
            E3id::new("current-collection", 2),
        ] {
            deliver_collector_failure(&actor, phase, &other_e3).await?;
        }
        assert_eq!(repo.read().await?.expect("unchanged collection"), expected);
        assert_no_collector_failure(&bus, &history, 1).await?;
        history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        deliver_collector_failure(&actor, phase, &e3_id).await?;
        let count = if phase == DkgTimeoutPhase::DecryptionKeySharedCollection {
            1
        } else {
            2
        };
        let events = next_events(&history, count).await?;
        assert!(events.iter().any(|event| matches!(event.get_data(),
            InterfoldEventData::E3Failed(data) if data.e3_id == e3_id
        )));
        actor.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn collector_failures_ignore_superseded_phases() -> Result<()> {
    let e3_id = E3id::new("superseded-collection", 1);
    let ready = ready_for_c4_test();
    let decrypting = KeyshareState::Decrypting(Decrypting {
        pk_share: ready.pk_share,
        sk_poly_sum: ready.sk_poly_sum,
        es_poly_sum: ready.es_poly_sum,
        ciphertext_output: vec![ArcBytes::from_bytes(&[4])],
        signed_pk_generation_proof: ready.signed_pk_generation_proof,
        signed_sk_share_computation_proof: ready.signed_sk_share_computation_proof,
        signed_e_sm_share_computation_proof: ready.signed_e_sm_share_computation_proof,
        signed_sk_share_encryption_proofs: ready.signed_sk_share_encryption_proofs,
        signed_e_sm_share_encryption_proofs: ready.signed_e_sm_share_encryption_proofs,
    });
    for phase in [
        DkgTimeoutPhase::EncryptionKeyCollection,
        DkgTimeoutPhase::ThresholdShareCollection,
        DkgTimeoutPhase::DecryptionKeySharedCollection,
    ] {
        let first_superseding = match phase {
            DkgTimeoutPhase::EncryptionKeyCollection => generating_threshold_share_state(&e3_id),
            DkgTimeoutPhase::ThresholdShareCollection
            | DkgTimeoutPhase::DecryptionKeySharedCollection => {
                KeyshareState::ReadyForDecryption(ready_for_c4_test())
            }
        };
        for (state, published, authorized, verified, public_key) in [
            (
                first_superseding,
                phase == DkgTimeoutPhase::DecryptionKeySharedCollection,
                false,
                false,
                false,
            ),
            (
                KeyshareState::ReadyForDecryption(ready_for_c4_test()),
                false,
                true,
                false,
                false,
            ),
            (
                KeyshareState::ReadyForDecryption(ready_for_c4_test()),
                false,
                false,
                true,
                false,
            ),
            (decrypting.clone(), false, false, false, false),
            (KeyshareState::Completed, false, false, false, false),
            (
                KeyshareState::Failed {
                    failed_at_stage: E3Stage::CiphertextReady,
                    reason: FailureReason::DecryptionTimeout,
                },
                false,
                false,
                false,
                false,
            ),
            (
                match phase {
                    DkgTimeoutPhase::EncryptionKeyCollection => {
                        collecting_encryption_keys_state(&e3_id)
                    }
                    DkgTimeoutPhase::ThresholdShareCollection => {
                        KeyshareState::AggregatingDecryptionKey(
                            aggregating_decryption_key_for_roster_test(),
                        )
                    }
                    DkgTimeoutPhase::DecryptionKeySharedCollection => {
                        KeyshareState::ReadyForDecryption(ready_for_c4_test())
                    }
                },
                false,
                false,
                false,
                true,
            ),
        ] {
            let (mut actor, repo, _, history) =
                build_actor(&e3_id, state, 7_200, 7_200, &[]).await?;
            actor.state.try_mutate_without_context(|mut state| {
                state.keyshare_published = published;
                Ok(state)
            })?;
            actor.recovery.try_mutate_without_context(|mut recovery| {
                recovery.keyshare_publish_authorized = authorized;
                if verified {
                    recovery.decryption_verification_complete = Some(TypedEvent::new(
                        ShareVerificationComplete {
                            e3_id: e3_id.clone(),
                            kind: VerificationKind::DecryptionProofs,
                            dishonest_parties: BTreeSet::new(),
                        },
                        test_ec(1),
                    ));
                }
                Ok(recovery)
            })?;
            let bus = actor.bus.clone();
            let actor = actor.start();
            if public_key {
                actor
                    .send(keyshare_event(
                        PublicKeyAggregated {
                            e3_id: e3_id.clone(),
                            pubkey: ArcBytes::from_bytes(&[7]),
                            pk_commitment: [8; 32],
                            nodes: OrderedSet::from(vec![Address::ZERO.to_string()]),
                            committee_addresses: vec![Address::ZERO],
                            honest_committee_addresses: vec![Address::ZERO],
                            dkg_aggregator_proof: None,
                            dkg_attestation_bundle: None,
                        },
                        2,
                        EventSource::Evm,
                    ))
                    .await?;
            }
            let expected = repo.read().await?.expect("current state");
            deliver_collector_failure(&actor, phase, &e3_id).await?;
            assert_eq!(
                repo.read().await?.expect("unchanged state"),
                expected,
                "phase {phase:?}"
            );
            assert_no_collector_failure(&bus, &history, 1).await?;
            actor.send(Die).await?;
        }
    }
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
        recovery_payloads: test_recovery_payloads(),
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
        recovery_payloads: test_recovery_payloads(),
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
        recovery_payloads: test_recovery_payloads(),
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
        recovery_payloads: test_recovery_payloads(),
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
