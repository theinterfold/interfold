// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use e3_events::{
    ComputeRequestErrorKind, DkgShareDecryptionProofRequest, EncryptionKey, Event,
    HistoryCollector, TakeEvents, Unsequenced, ZkError,
};
use e3_test_helpers::get_common_setup;
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

/// `c4_base_seq` is derived from `ThresholdSharePending`'s layout. On a restart inside the
/// DKG window the keyshare recovery re-publishes both pending events and the C4 one can be
/// handled first; dispatching then would give C4a/C4b seq 0/1 and collide with C0/C1 in the
/// node fold buffer, so the real C4 slots stay empty and the fold never completes (Round 11,
/// cn3 stuck at 12/14). The C4 dispatch must be held and replayed once the layout is known.
#[actix::test]
async fn c4_dispatch_before_the_seq_layout_is_held_and_replayed_with_the_right_seqs() -> Result<()>
{
    use e3_crypto::SensitiveBytes;
    use e3_fhe_params::BfvPreset;
    use e3_zk_helpers::{computation::DkgInputType, CiphernodesCommitteeSize};

    let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("46", 1);
    let req = || DkgShareDecryptionProofRequest {
        sk_bfv: SensitiveBytes::from_encrypted(&[]),
        honest_ciphertexts_raw: vec![],
        num_honest_parties: 0,
        num_moduli: 0,
        own_plaintext_idx: 0,
        own_share_raw: SensitiveBytes::from_encrypted(&[]),
        dkg_input_type: DkgInputType::SecretKey,
        params_preset: BfvPreset::default(),
        committee_size: CiphernodesCommitteeSize::Minimum,
    };
    let pending = DecryptionShareProofsPending {
        e3_id: e3_id.clone(),
        party_id: 1,
        node: "0x00".into(),
        sk_request: req(),
        esm_requests: vec![req()],
    };

    // C4 arrives first: nothing may be dispatched yet.
    actor.handle_decryption_share_proofs_pending(TypedEvent::new(
        pending.clone(),
        test_ctx(pending.clone()),
    ));
    assert!(
        actor.decryption_correlation.is_empty(),
        "C4 must not be dispatched before the seq layout is known"
    );
    assert!(actor.held_decryption_pending.contains_key(&e3_id));

    // The layout lands: 4 + 4 sk-enc + 4 esm-enc + 2 = 14, so C4a=12, C4b=13.
    actor.node_agg_meta.insert(
        e3_id.clone(),
        NodeAggregationMeta {
            party_id: 1,
            total_expected: NodeAggregationMeta::total_expected_for(4, 4),
            pending_c0: None,
            c0_emitted: false,
        },
    );
    let held = actor
        .held_decryption_pending
        .remove(&e3_id)
        .expect("held C4 dispatch");
    actor.handle_decryption_share_proofs_pending(held);

    let mut seqs: Vec<usize> = actor
        .decryption_correlation
        .values()
        .filter(|(eid, _, _)| *eid == e3_id)
        .map(|(_, _, seq)| *seq)
        .collect();
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        vec![12, 13],
        "C4a/C4b must land in the C4 slots, not on top of C0/C1"
    );
    assert!(actor.held_decryption_pending.is_empty());
    Ok(())
}

/// After a restart the effect gate replays the pre-crash C4 `ComputeRequest` (old correlation
/// id) and drops the re-driven one as a semantic duplicate. The response therefore arrives
/// under an id this process never registered. Before the fix it fell through to the
/// threshold handler and was silently lost — the fold sat at 12/14 forever (Round 12). It must
/// be matched by kind to the pending dispatch.
#[actix::test]
async fn an_orphaned_c4_response_is_adopted_by_kind() -> Result<()> {
    use e3_zk_helpers::computation::DkgInputType;

    let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
    let mut actor = ProofRequestActor::new(&bus, PrivateKeySigner::random(), true);
    let e3_id = E3id::new("47", 1);
    let sk_corr = CorrelationId::new();
    let esm0_corr = CorrelationId::new();
    let esm1_corr = CorrelationId::new();
    actor
        .decryption_correlation
        .insert(sk_corr, (e3_id.clone(), DecryptionProofKind::SecretKey, 12));
    actor.decryption_correlation.insert(
        esm1_corr,
        (
            e3_id.clone(),
            DecryptionProofKind::SmudgingNoise { esi_idx: 1 },
            14,
        ),
    );
    actor.decryption_correlation.insert(
        esm0_corr,
        (
            e3_id.clone(),
            DecryptionProofKind::SmudgingNoise { esi_idx: 0 },
            13,
        ),
    );
    // A different E3 must never be matched.
    actor.decryption_correlation.insert(
        CorrelationId::new(),
        (E3id::new("99", 1), DecryptionProofKind::SecretKey, 12),
    );

    assert_eq!(
        actor.adopt_orphaned_c4_response(&e3_id, DkgInputType::SecretKey),
        Some(sk_corr)
    );
    // Lowest outstanding esi_idx first — canonical dispatch order.
    assert_eq!(
        actor.adopt_orphaned_c4_response(&e3_id, DkgInputType::SmudgingNoise),
        Some(esm0_corr)
    );
    actor.decryption_correlation.remove(&esm0_corr);
    assert_eq!(
        actor.adopt_orphaned_c4_response(&e3_id, DkgInputType::SmudgingNoise),
        Some(esm1_corr)
    );
    assert_eq!(
        actor.adopt_orphaned_c4_response(&E3id::new("48", 1), DkgInputType::SecretKey),
        None
    );
    Ok(())
}
/// Round 14, cn3: after a restart inside the DKG window every inner proof except C0 is
/// regenerated (their `*Pending` triggers are replayed). C0 is generated exactly once, before
/// the aggregate snapshot cursor, so the fresh `ProofRequestActor` never sees
/// `EncryptionKeyPending` again and the node fold sticks at 13/14 forever. The own C0 is now
/// persisted the moment it is signed, and `ThresholdSharePending` re-seeds `seq: 0` from that
/// record when nothing has been emitted in this process.
#[actix::test]
async fn own_c0_is_reseeded_from_the_durable_record_after_restart() -> Result<()> {
    use e3_data::{DataStore, InMemStore, RepositoriesFactory};
    use e3_events::CircuitName;

    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let e3_id = E3id::new("47", 1);

    // "Pre-crash": the record the first process wrote when it signed C0.
    let c0 = Proof::new(
        CircuitName::PkBfv,
        ArcBytes::from_bytes(&[0xC0u8; 8]),
        ArcBytes::from_bytes(&[0x51u8; 4]),
    );
    store
        .repositories()
        .own_c0(&e3_id)
        .write_sync(&OwnC0Record {
            party_id: 1,
            proof: c0.clone(),
        })
        .await?;

    // "Post-restart": a fresh actor, store attached, NO C0 in memory. ThresholdSharePending
    // has just set the layout (this is what its handler does before calling the re-seed).
    let mut actor =
        ProofRequestActor::new(&bus, PrivateKeySigner::random(), true).with_store(store);
    actor.node_agg_meta.insert(
        e3_id.clone(),
        NodeAggregationMeta {
            party_id: 1,
            total_expected: 14,
            pending_c0: None,
            c0_emitted: false,
        },
    );
    let ec = test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGTimeout,
    });
    actor.reseed_own_c0_from_store(e3_id.clone(), 1, ec);
    assert!(
        actor.node_agg_meta[&e3_id].c0_emitted,
        "the re-seed must be recorded so a later C0 response cannot double-emit seq 0"
    );

    // The read is async — drain the bus until seq 0 lands.
    let mut c0_ready = None;
    for _ in 0..80 {
        let mut result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        match result.events.pop() {
            Some(evt) => {
                if let InterfoldEventData::DKGInnerProofReady(d) = evt.into_data() {
                    if d.seq == 0 {
                        c0_ready = Some(d);
                        break;
                    }
                }
            }
            None => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
        }
    }
    let c0_ready =
        c0_ready.expect("DKGInnerProofReady seq=0 must be re-seeded from the own-C0 record");
    assert_eq!(c0_ready.e3_id, e3_id);
    assert_eq!(c0_ready.party_id, 1);
    assert_eq!(c0_ready.proof, c0);
    Ok(())
}

/// Without a record (a node that was never in this E3, or a pre-fix store) the re-seed must
/// be a no-op that still marks `c0_emitted`, so the live C0 path is unaffected.
#[actix::test]
async fn reseed_without_a_record_emits_nothing() -> Result<()> {
    use e3_data::{DataStore, InMemStore};

    let (bus, _rng, _seed, _params, _crp, _errors, history) = get_common_setup(None)?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let e3_id = E3id::new("48", 1);
    let mut actor =
        ProofRequestActor::new(&bus, PrivateKeySigner::random(), true).with_store(store);
    actor.node_agg_meta.insert(
        e3_id.clone(),
        NodeAggregationMeta {
            party_id: 1,
            total_expected: 14,
            pending_c0: None,
            c0_emitted: false,
        },
    );
    let ec = test_ctx(E3Failed {
        e3_id: e3_id.clone(),
        failed_at_stage: E3Stage::CommitteeFinalized,
        reason: FailureReason::DKGTimeout,
    });
    actor.reseed_own_c0_from_store(e3_id.clone(), 1, ec);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let result = history.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
    assert!(
        !result
            .events
            .iter()
            .any(|e| matches!(e.get_data(), InterfoldEventData::DKGInnerProofReady(_))),
        "no record => nothing re-seeded"
    );
    Ok(())
}
