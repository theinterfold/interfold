// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{
    ext::{AggregatorRoleExtension, ThresholdPlaintextAggregatorExtension},
    TrBfvPlaintextRepositoryFactory,
};
use e3_data::{InMemEventLog, InMemSequenceIndex, RepositoriesFactory, Snapshot};
use e3_events::{
    CiphertextOutputPublished, EventSource, EventStore, EventStoreQueryBy, EventStoreRouter, SeqAgg,
};
use e3_keyshare::canonical_key::{CanonicalPublicKey, CanonicalPublicKeys};
use e3_request::{
    ContextRepositoryFactory, E3Context, E3ContextParams, E3Extension, E3Meta, META_KEY,
};
use e3_sync::SyncRepositoryFactory;
use std::{sync::Arc, time::Duration};

async fn replay_suffix(
    bus: &BusHandle,
    store: &DataStore,
    reader: &Recipient<EventStoreQueryBy<SeqAgg>>,
    cursor: u64,
    recipient: &Recipient<InterfoldEvent>,
    history: &Addr<HistoryCollector<InterfoldEvent>>,
) -> Result<()> {
    use e3_events::{
        AggregateConfig, AggregateId, EventType, EvmEventConfig, EvmEventConfigChain,
        HistoricalEvmEventsReceived, HistoricalNetSyncEventsReceived, NetReady,
        RequestRouterCheckpoint,
    };
    let aggregate = AggregateId::new(1);
    let repositories = store.repositories();
    repositories
        .schema_version()
        .write_sync(&e3_sync::SCHEMA_VERSION)
        .await?;
    repositories
        .aggregate_seq(aggregate)
        .write_sync(&cursor)
        .await?;
    repositories
        .request_router_checkpoint()
        .write_sync(&RequestRouterCheckpoint {
            contexts: vec![E3id::new("42", 1)],
            replay_cursors: HashMap::from([(aggregate, cursor)]),
            ..Default::default()
        })
        .await?;
    bus.subscribe(EventType::All, recipient.clone());
    let evm = bus.wait_for(EventType::HistoricalEvmSyncStart);
    let net = bus.wait_for(EventType::HistoricalNetSyncStart);
    let evm_config =
        EvmEventConfig::from_config(BTreeMap::from([(1, EvmEventConfigChain::new(0))]));
    let config = AggregateConfig::new(HashMap::from([(aggregate, Duration::ZERO)]));
    futures::try_join!(
        e3_sync::sync_with_net_ready(
            bus,
            &evm_config,
            &repositories,
            &config,
            reader,
            std::future::ready(Ok(event(NetReady::new(), EventSource::Local, 0)))
        ),
        async {
            let InterfoldEventData::HistoricalEvmSyncStart(start) = evm.await?.into_data() else {
                unreachable!()
            };
            start
                .sender
                .unwrap()
                .try_send(HistoricalEvmEventsReceived::new(vec![], 1))?;
            net.await?;
            bus.flush_event_pipeline().await?;
            assert!(
                !history
                    .send(GetEvents::<InterfoldEvent>::new())
                    .await?
                    .iter()
                    .any(|event| match event.get_data() {
                        InterfoldEventData::ShareVerificationDispatched(_)
                        | InterfoldEventData::PlaintextAggregated(_) => true,
                        InterfoldEventData::ComputeRequest(request) => !matches!(
                            request.request,
                            ComputeRequestKind::Zk(ZkRequest::DecryptedSharesAggregation(_))
                        ),
                        _ => false,
                    }),
                "plaintext effects ran before replay completed"
            );
            bus.publish_without_context(HistoricalNetSyncEventsReceived::new(vec![]))?;
            Ok::<_, anyhow::Error>(())
        }
    )?;
    Ok(())
}

fn canonical_key() -> CanonicalPublicKey {
    CanonicalPublicKey {
        pk_commitment: [7; 32],
        committee: (0..3).map(|party| test_signer(party).address()).collect(),
        honest_committee: (0..2).map(|party| test_signer(party).address()).collect(),
        params_preset: BfvPreset::InsecureThreshold64,
        committee_size: CiphernodesCommitteeSize::Minimum,
        interfold_address: test_decryption_domain().interfold_address,
        sk_agg_commits: vec![],
        esm_agg_commits: vec![],
    }
}

fn event(data: impl Into<InterfoldEventData>, source: EventSource, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(data.into(), None, seq as u128, None, source)
        .into_sequenced(seq)
}

fn ciphertext_event(id: &E3id) -> InterfoldEvent {
    event(
        CiphertextOutputPublished {
            e3_id: id.clone(),
            ciphertext_output: test_ciphertexts(),
            ciphertext_commitment: [0; 32],
        },
        EventSource::Local,
        1,
    )
}

fn share_event(id: &E3id, party: u64, wrong_domain: bool, seq: u64) -> InterfoldEvent {
    let (shares, mut proofs) = share_with_matching_commitment(id, party, &test_ciphertexts());
    if wrong_domain {
        let proof = proofs.last_mut().unwrap();
        let mut signals = proof.payload.proof.public_signals.to_vec();
        signals[127] ^= 1;
        proof.payload.proof.public_signals = ArcBytes::from_bytes(&signals);
        *proof = SignedProofPayload::sign(proof.payload.clone(), &test_signer(party)).unwrap();
    }
    event(
        DecryptionshareCreated {
            e3_id: id.clone(),
            node: test_signer(party).address().to_string(),
            party_id: party,
            decryption_share: shares,
            signed_decryption_proofs: proofs,
        },
        EventSource::Net,
        seq,
    )
}

fn history_reader(events: &[InterfoldEvent]) -> Result<Recipient<EventStoreQueryBy<SeqAgg>>> {
    let mut store = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
    for event in events {
        store.store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            event.get_data().clone(),
            None,
            event.ts(),
            None,
            event.source(),
        ))?;
    }
    let global = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
    Ok(
        EventStoreRouter::new(HashMap::from([(0, global.start()), (1, store.start())]))
            .start()
            .recipient(),
    )
}

fn plaintext_repositories(store: &DataStore, id: &E3id) -> e3_data::Repositories {
    DataStore::from(&store.repositories().context(id)).repositories()
}

async fn context(store: &DataStore, id: &E3id) -> Result<E3Context> {
    let mut context = E3Context::from_params(E3ContextParams {
        repository: store.repositories().context(id),
        e3_id: id.clone(),
        extensions: Arc::new(vec![]),
    });
    // The installed plaintext extension declares this recipient, so the router defers its events.
    context.recipients.insert("plaintext".to_owned(), None);
    context.set_dependency(
        META_KEY,
        E3Meta {
            threshold_m: 1,
            threshold_n: 3,
            seed: Seed([0; 32]),
            params_preset: BfvPreset::InsecureThreshold64,
            params: ArcBytes::from_bytes(&encode_bfv_params(
                &BfvParamSet::from(BfvPreset::InsecureThreshold64).build_arc(),
            )),
            error_size: ArcBytes::from_bytes(&[]),
        },
    );
    context.set_event_recipient(
        "threshold_keyshare",
        Some(
            HistoryCollector::<InterfoldEvent>::new()
                .start()
                .recipient(),
        ),
    );
    let snapshot = context.snapshot()?;
    AggregatorRoleExtension::create(HashMap::from([(id.clone(), true)]))
        .hydrate(&mut context, &snapshot)
        .await?;
    Ok(context)
}

fn initial_state() -> ThresholdPlaintextAggregatorState {
    ThresholdPlaintextAggregatorState::init(1, 3, Seed([0; 32]), test_ciphertexts(), test_params())
}

async fn await_verifying(store: &DataStore, id: &E3id) -> Result<VerifyingC6> {
    for _ in 0..200 {
        if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(state)) =
            plaintext_repositories(store, id)
                .trbfv_plaintext(id)
                .read()
                .await?
        {
            return Ok(state);
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    panic!("corrected canonical shares did not reach C6 verification")
}

#[actix::test]
async fn canonical_domain_gates_live_and_replayed_shares() -> Result<()> {
    for replay in [false, true] {
        let (bus, _, _, _, _, _, history) =
            get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
        let id = E3id::new("42", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let ciphertext = ciphertext_event(&id);
        let keys = CanonicalPublicKeys::default();
        keys.insert(id.clone(), canonical_key())?;
        let extension = ThresholdPlaintextAggregatorExtension::create(
            &bus,
            &start_sortition(&bus),
            true,
            keys,
            history_reader(std::slice::from_ref(&ciphertext))?,
        );
        let mut ctx = context(&store, &id).await?;
        if replay {
            plaintext_repositories(&store, &id)
                .trbfv_plaintext(&id)
                .write_sync(&initial_state())
                .await?;
            plaintext_repositories(&store, &id)
                .trbfv_plaintext_recovery(&id)
                .write_sync(&crate::new_threshold_plaintext_recovery(
                    ciphertext.get_ctx().clone(),
                ))
                .await?;
            let mut snapshot = ctx.snapshot()?;
            snapshot.recipients.push("plaintext".into());
            extension.hydrate(&mut ctx, &snapshot).await?;
        } else {
            extension.on_event(&mut ctx, &ciphertext);
        }
        let recipient = ctx.get_event_recipient("plaintext").unwrap();
        if replay {
            let reader = history_reader(&[
                ciphertext,
                share_event(&id, 0, true, 2),
                share_event(&id, 0, false, 3),
                share_event(&id, 1, false, 4),
            ])?;
            replay_suffix(&bus, &store, &reader, 1, recipient, &history).await?;
        } else {
            recipient.send(share_event(&id, 0, true, 2)).await?;
            recipient.send(share_event(&id, 0, false, 3)).await?;
            recipient.send(share_event(&id, 1, false, 4)).await?;
        }
        let state = await_verifying(&store, &id).await?;
        let (_, canonical) = share_with_matching_commitment(&id, 0, &test_ciphertexts());
        assert_eq!(
            state.c6_proofs[&0], canonical,
            "wrong-domain bundle reserved a party slot (replay={replay})"
        );
        assert!(state.rejected_parties.is_empty());
        bus.flush_event_pipeline().await?;
        assert!(history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .iter()
            .any(|event| matches!(
                event.get_data(),
                InterfoldEventData::AggregationInputsReady(_)
            )));
    }
    Ok(())
}

#[actix::test]
async fn hydration_rebuilds_noncanonical_c6_work_in_every_phase() -> Result<()> {
    for phase in 0..5 {
        for wrong_domain in [true, false] {
            let (bus, _, _, _, _, _, history) =
                get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
            let id = E3id::new("42", 1);
            let store = DataStore::from_in_mem(&InMemStore::new(false).start());
            let ciphertext = ciphertext_event(&id);
            let events = [
                ciphertext.clone(),
                share_event(&id, 0, wrong_domain, 2),
                share_event(&id, 1, false, 3),
            ];
            let mut collecting: Collecting = initial_state().try_into()?;
            for event in &events[1..] {
                let InterfoldEventData::DecryptionshareCreated(data) = event.get_data() else {
                    unreachable!()
                };
                collecting
                    .shares
                    .insert(data.party_id, data.decryption_share.clone());
                collecting
                    .c6_proofs
                    .insert(data.party_id, data.signed_decryption_proofs.clone());
            }
            let shares = collecting.shares.clone().into_iter().collect::<Vec<_>>();
            let recovery = ThresholdPlaintextAggregatorRecoveryState {
                honest_c6_proofs: if phase >= 2 {
                    collecting
                        .c6_proofs
                        .iter()
                        .map(|(party, proofs)| {
                            (
                                *party,
                                proofs
                                    .iter()
                                    .map(|proof| proof.payload.proof.clone())
                                    .collect(),
                            )
                        })
                        .collect()
                } else {
                    vec![]
                },
                c7_proofs: (phase >= 3).then(|| batch_c7_proofs(&[0, 1], 2)),
                decryption_aggregator_proofs: (phase == 4)
                    .then(|| vec![dummy_proof(CircuitName::DecryptionAggregator); 2]),
                c6_outcomes: BTreeMap::from([([9; 32], BTreeSet::new())]),
                last_ec: Some(events[2].get_ctx().clone()),
                ..Default::default()
            };
            if phase == 0 {
                collecting.shares.remove(&1);
                collecting.c6_proofs.remove(&1);
            }
            let state = match phase {
                0 => ThresholdPlaintextAggregatorState::Collecting(collecting),
                1 => ThresholdPlaintextAggregatorState::VerifyingC6(VerifyingC6 {
                    threshold_m: 1,
                    threshold_n: 3,
                    shares: collecting.shares,
                    c6_proofs: collecting.c6_proofs,
                    seed: collecting.seed,
                    ciphertext_output: collecting.ciphertext_output,
                    params: collecting.params,
                    rejected_parties: BTreeSet::new(),
                    queued_shares: BTreeMap::new(),
                }),
                2 => ThresholdPlaintextAggregatorState::Computing(Computing {
                    threshold_m: 1,
                    threshold_n: 3,
                    shares,
                    ciphertext_output: test_ciphertexts(),
                    params: test_params(),
                }),
                3 => ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
                    threshold_m: 1,
                    threshold_n: 3,
                    shares,
                    plaintext: vec![ArcBytes::from_bytes(&0u64.to_le_bytes()); 2],
                }),
                _ => ThresholdPlaintextAggregatorState::Complete(Complete {
                    shares,
                    decrypted: vec![ArcBytes::from_bytes(&0u64.to_le_bytes()); 2],
                }),
            };
            plaintext_repositories(&store, &id)
                .trbfv_plaintext(&id)
                .write_sync(&state)
                .await?;
            plaintext_repositories(&store, &id)
                .trbfv_plaintext_recovery(&id)
                .write_sync(&recovery)
                .await?;
            let keys = CanonicalPublicKeys::default();
            keys.insert(id.clone(), canonical_key())?;
            let extension = ThresholdPlaintextAggregatorExtension::create(
                &bus,
                &start_sortition(&bus),
                true,
                keys,
                history_reader(&events)?,
            );
            let mut ctx = context(&store, &id).await?;
            let mut snapshot = ctx.snapshot()?;
            snapshot.recipients.push("plaintext".into());
            extension.hydrate(&mut ctx, &snapshot).await?;
            let restored = plaintext_repositories(&store, &id)
                .trbfv_plaintext(&id)
                .read()
                .await?
                .unwrap();
            if !wrong_domain {
                assert_eq!(
                    bincode::serialize(&restored)?,
                    bincode::serialize(&state)?,
                    "canonical phase {phase} changed"
                );
                continue;
            }
            let ThresholdPlaintextAggregatorState::Collecting(restored) = restored else {
                panic!("phase {phase} retained noncanonical C6 work");
            };
            assert_eq!(
                restored.shares.keys().copied().collect::<Vec<_>>(),
                [1],
                "phase {phase} kept an invalid share or lost a canonical share"
            );
            assert!(restored.rejected_parties.is_empty());
            let recovery = plaintext_repositories(&store, &id)
                .trbfv_plaintext_recovery(&id)
                .read()
                .await?
                .unwrap();
            assert!(recovery.honest_c6_proofs.is_empty());
            assert!(recovery.c6_outcomes.is_empty());
            assert!(recovery.c7_proofs.is_none());
            assert!(recovery.decryption_aggregator_proofs.is_none());
            let recipient = ctx.get_event_recipient("plaintext").unwrap();
            let mut replay = events.to_vec();
            replay.extend([share_event(&id, 0, true, 4), share_event(&id, 0, false, 5)]);
            replay_suffix(
                &bus,
                &store,
                &history_reader(&replay)?,
                3,
                recipient,
                &history,
            )
            .await?;
            let corrected = await_verifying(&store, &id).await?;
            let (_, canonical) = share_with_matching_commitment(&id, 0, &test_ciphertexts());
            assert_eq!(corrected.c6_proofs[&0], canonical);
            bus.flush_event_pipeline().await?;
            assert!(
                history.send(GetEvents::<InterfoldEvent>::new()).await?.iter().any(|event|
                    matches!(event.get_data(), InterfoldEventData::ShareVerificationDispatched(data) if data.share_proofs.len() == 2)),
                "phase {phase} did not rebuild verification"
            );
            bus.flush_event_pipeline().await?;
            assert!(
                !history
                    .send(GetEvents::<InterfoldEvent>::new())
                    .await?
                    .iter()
                    .any(|event| matches!(
                        event.get_data(),
                        InterfoldEventData::PlaintextAggregated(_)
                    )),
                "phase {phase} republished retained plaintext"
            );
        }
    }
    Ok(())
}

fn recovery_key() -> CanonicalPublicKey {
    let mut key = canonical_key();
    key.committee.sort();
    key.honest_committee = vec![key.committee[0], key.committee[2]];
    key.sk_agg_commits = vec![[0; 32]; 2];
    key.esm_agg_commits = vec![[0; 32]; 2];
    key
}

fn confirmed_event(data: impl Into<InterfoldEventData>, seq: u64) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        data.into(),
        None,
        seq as u128,
        Some(seq),
        EventSource::Evm,
    )
    .into_sequenced(seq)
}

fn authority_event(id: &E3id, key: &CanonicalPublicKey, seq: u64) -> InterfoldEvent {
    use alloy::{
        primitives::{Bytes, B256, U256},
        sol_types::{SolEvent, SolValue},
    };
    let mut inputs = vec![B256::ZERO; 12];
    inputs[3] = B256::from(U256::from(2).to_be_bytes::<32>());
    inputs[11] = key.pk_commitment.into();
    let log = e3_evm::ICiphernodeRegistry::CommitteeProofPublished {
        e3Id: id.clone().try_into().unwrap(),
        nodes: key.committee.clone(),
        pkCommitment: key.pk_commitment.into(),
        proof: Bytes::from((Bytes::new(), inputs).abi_encode_params()),
    }
    .encode_log_data();
    confirmed_event(
        e3_events::EvmLogObserved {
            contract: "CiphernodeRegistry".into(),
            chain_id: id.chain_id(),
            e3_id: Some(id.clone()),
            event_name: "CommitteeProofPublished".into(),
            signature: None,
            known: true,
            topics: log.topics().iter().map(ToString::to_string).collect(),
            data: ArcBytes::from_bytes(&log.data),
        },
        seq,
    )
}

fn recovery_share(id: &E3id, key: &CanonicalPublicKey, party: u64, seq: u64) -> InterfoldEvent {
    let signer = (0..3)
        .map(test_signer)
        .find(|signer| signer.address() == key.committee[party as usize])
        .unwrap();
    let (shares, mut proofs) = share_with_matching_commitment(id, 0, &test_ciphertexts());
    for (proof, ciphertext) in proofs.iter_mut().zip(test_ciphertexts()) {
        let domain = e3_committee_hash::decryption_domain_limbs(
            id.chain_id(),
            id.clone().try_into().unwrap(),
            key.domain(key.interfold_address),
            alloy::primitives::keccak256(&ciphertext[..]),
        );
        let mut signals = proof.payload.proof.public_signals.to_vec();
        signals[112..128].copy_from_slice(&domain.hi.to_be_bytes());
        signals[144..160].copy_from_slice(&domain.lo.to_be_bytes());
        proof.payload.proof.public_signals = ArcBytes::from_bytes(&signals);
        *proof = SignedProofPayload::sign(proof.payload.clone(), &signer).unwrap();
    }
    event(
        DecryptionshareCreated {
            e3_id: id.clone(),
            node: signer.address().to_string(),
            party_id: party,
            decryption_share: shares,
            signed_decryption_proofs: proofs,
        },
        EventSource::Net,
        seq,
    )
}

#[actix::test]
async fn restart_recovers_ciphertext_deferred_until_key_authority() -> Result<()> {
    for authority_before_hydration in [false, true] {
        deferred_plaintext_restart(false, authority_before_hydration, false, false).await?;
    }
    Ok(())
}

#[actix::test]
async fn startup_keeps_plaintext_snapshot_dormant_until_chain_authority() -> Result<()> {
    deferred_plaintext_restart(true, false, false, false).await
}

/// A restored plaintext aggregation that waits for chain authority does not resume when its E3
/// failed: the Failed stage change that startup sends before effects ends it.
#[actix::test]
async fn a_deferred_plaintext_snapshot_of_a_failed_e3_does_not_resume() -> Result<()> {
    deferred_plaintext_restart(true, false, false, true).await
}

async fn deferred_plaintext_restart(
    existing_snapshot: bool,
    authority_before_hydration: bool,
    sustained_traffic: bool,
    failed_before_effects: bool,
) -> Result<()> {
    let (bus, _, _, _, _, _, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let id = E3id::new("42", 1);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let keys = CanonicalPublicKeys::default();
    let key = recovery_key();
    let request = confirmed_event(
        e3_events::E3Requested {
            e3_id: id.clone(),
            threshold_m: 1,
            threshold_n: 3,
            params_preset: key.params_preset,
            ..Default::default()
        },
        1,
    );
    let ciphertext = event(ciphertext_event(&id).into_data(), EventSource::Local, 2);
    let mut events = vec![
        request.clone(),
        ciphertext.clone(),
        recovery_share(&id, &key, 0, 3),
        recovery_share(&id, &key, 2, 4),
        confirmed_event(
            e3_events::E3StageChanged {
                e3_id: id.clone(),
                previous_stage: E3Stage::KeyPublished,
                new_stage: E3Stage::CiphertextReady,
            },
            5,
        ),
    ];
    if sustained_traffic {
        for seq in 6..1286 {
            events.push(event(
                DecryptionshareCreated {
                    e3_id: id.clone(),
                    party_id: 99,
                    node: format!("unrecognized-{seq}"),
                    decryption_share: vec![ArcBytes::from_bytes(&vec![seq as u8; 16 * 1024])],
                    signed_decryption_proofs: vec![],
                },
                EventSource::Net,
                seq,
            ));
        }
        events.push(recovery_share(&id, &key, 2, 1286));
    }
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reader = CountingHistoryReader {
        dest: history_reader(&events)?,
        reads: reads.clone(),
    }
    .start()
    .recipient();
    let mut ctx = context(&store, &id).await?;
    if !existing_snapshot {
        let extension = ThresholdPlaintextAggregatorExtension::create(
            &bus,
            &start_sortition(&bus),
            true,
            keys.clone(),
            reader.clone(),
        );
        let mut buffer = e3_request::EventBuffer::default();
        for event in &events[1..] {
            extension.on_event(&mut ctx, event);
            ctx.forward_message(event, &mut buffer);
        }
        assert!(ctx.get_event_recipient("plaintext").is_none());
        assert_eq!(
            buffer
                .take(&id, "plaintext")
                .iter()
                .filter(|event| matches!(
                    event.get_data(),
                    InterfoldEventData::DecryptionshareCreated(_)
                ))
                .count(),
            2
        );
    }
    let mut snapshot = ctx.snapshot()?;
    let mut saved: Collecting = initial_state().try_into()?;
    if existing_snapshot {
        // This exclusion is present only in the snapshot. Recovery must retain it.
        saved.rejected_parties.insert(1);
        let retained = if sustained_traffic {
            vec![events[2].clone()]
        } else {
            vec![events[2].clone(), share_event(&id, 2, true, 5)]
        };
        for event in &retained {
            let InterfoldEventData::DecryptionshareCreated(data) = event.get_data() else {
                unreachable!()
            };
            saved
                .shares
                .insert(data.party_id, data.decryption_share.clone());
            saved
                .c6_proofs
                .insert(data.party_id, data.signed_decryption_proofs.clone());
        }
        plaintext_repositories(&store, &id)
            .trbfv_plaintext(&id)
            .write_sync(&ThresholdPlaintextAggregatorState::Collecting(
                saved.clone(),
            ))
            .await?;
        plaintext_repositories(&store, &id)
            .trbfv_plaintext_recovery(&id)
            .write_sync(&crate::new_threshold_plaintext_recovery(
                events[3].get_ctx().clone(),
            ))
            .await?;
        snapshot.recipients.push("plaintext".into());
    }
    store
        .repositories()
        .context(&id)
        .write_sync(&snapshot)
        .await?;
    drop(ctx);

    let projection = e3_evm::canonical_key::CanonicalKeyProjection::new(
        keys.clone(),
        HashMap::from([(1, key.interfold_address)]),
    )
    .start();
    projection.send(request).await?;
    let authority = authority_event(&id, &key, if sustained_traffic { 1287 } else { 6 });
    if authority_before_hydration {
        projection.send(authority.clone()).await?;
    }
    let extension = ThresholdPlaintextAggregatorExtension::create(
        &bus,
        &start_sortition(&bus),
        true,
        keys.clone(),
        reader.clone(),
    );
    let snapshot = store.repositories().context(&id).read().await?.unwrap();
    ctx = context(&store, &id).await?;
    extension.hydrate(&mut ctx, &snapshot).await?;
    let recipient = ctx
        .get_event_recipient("plaintext")
        .expect("startup must retain a plaintext recipient")
        .clone();
    if existing_snapshot {
        let dormant = plaintext_repositories(&store, &id)
            .trbfv_plaintext(&id)
            .read()
            .await?
            .unwrap();
        assert_eq!(
            bincode::serialize(&dormant)?,
            bincode::serialize(&ThresholdPlaintextAggregatorState::Collecting(saved))?,
            "startup replaced the dormant snapshot"
        );
    }
    if failed_before_effects {
        // Startup tells a restored recipient of a failed E3 about the failure before effects.
        let failed = e3_events::E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Failed,
        };
        recipient.send(event(failed, EventSource::Local, 6)).await?;
        let _ = recipient
            .send(event(
                e3_events::EffectsEnabled::new(),
                EventSource::Local,
                7,
            ))
            .await;
        projection.send(authority.clone()).await?;
        extension.on_event(&mut ctx, &authority);
        let _ = recipient.send(authority).await;
        for _ in 0..200 {
            if !recipient.connected() {
                break;
            }
            actix::clock::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !recipient.connected(),
            "the deferred aggregation of a failed E3 kept running"
        );
        let stored = plaintext_repositories(&store, &id)
            .trbfv_plaintext(&id)
            .read()
            .await?
            .unwrap();
        assert!(
            matches!(stored, ThresholdPlaintextAggregatorState::Collecting(_)),
            "the aggregation of a failed E3 resumed"
        );
        let recorded = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert!(!recorded.iter().any(|event| matches!(
            event.get_data(),
            InterfoldEventData::ShareVerificationDispatched(_)
                | InterfoldEventData::ComputeRequest(_)
                | InterfoldEventData::PlaintextAggregated(_)
        )));
        return Ok(());
    }
    replay_suffix(&bus, &store, &reader, 5, &recipient, &history).await?;
    let reads_before_authority = reads.load(std::sync::atomic::Ordering::SeqCst);
    if !authority_before_hydration {
        assert!(keys.get(&id).is_none());
        projection.send(authority.clone()).await?;
        assert_eq!(keys.get(&id), Some(key.clone()));
        extension.on_event(&mut ctx, &authority);
        recipient.send(authority).await?;
    }
    let restored = await_verifying(&store, &id).await?;
    if sustained_traffic {
        assert!(
            reads.load(std::sync::atomic::Ordering::SeqCst) >= reads_before_authority + 2,
            "deferred input must be read from durable history in bounded pages"
        );
    }
    assert_eq!(restored.ciphertext_output, test_ciphertexts());
    assert_eq!(restored.shares.keys().copied().collect::<Vec<_>>(), [0, 2]);
    assert_eq!(
        restored.rejected_parties.contains(&1),
        existing_snapshot,
        "recovery discarded the saved exclusion"
    );
    let recorded = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        recorded
            .iter()
            .filter(|event| matches!(
                event.get_data(),
                InterfoldEventData::CiphertextOutputPublished(_)
                    | InterfoldEventData::DecryptionshareCreated(_)
            ))
            .all(
                |replayed| events.iter().any(|original| replayed.id() == original.id()
                    && replayed.source() == original.source()
                    && replayed.ts() == original.ts())
            ),
        "recovery required a new ciphertext or share publication"
    );
    assert!(
        recorded.iter().any(|event| matches!(event.get_data(),
        InterfoldEventData::ShareVerificationDispatched(data) if data.share_proofs.len() == 2)),
        "recovered shares did not resume verification"
    );
    Ok(())
}

#[actix::test]
async fn deferred_plaintext_reloads_sustained_traffic_from_history() -> Result<()> {
    deferred_plaintext_restart(true, false, true, false).await
}

struct CountingHistoryReader {
    dest: Recipient<EventStoreQueryBy<SeqAgg>>,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl Actor for CountingHistoryReader {
    type Context = Context<Self>;
}
impl Handler<EventStoreQueryBy<SeqAgg>> for CountingHistoryReader {
    type Result = actix::ResponseFuture<()>;
    fn handle(&mut self, msg: EventStoreQueryBy<SeqAgg>, _: &mut Context<Self>) -> Self::Result {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dest = self.dest.clone();
        Box::pin(async move {
            dest.send(msg).await.unwrap();
        })
    }
}

fn batch_c7_proofs(parties: &[u64], ciphertexts: usize) -> Vec<Proof> {
    use alloy::primitives::U256;
    use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
    let id = E3id::new("42", 1);
    let (_, c6) = share_with_matching_commitment(&id, parties[0], &test_ciphertexts());
    (0..ciphertexts)
        .map(|index| {
            let mut fields = Vec::new();
            for _ in parties {
                fields.extend_from_slice(&c6[index].payload.proof.public_signals[160..192]);
            }
            for party in parties {
                fields.extend_from_slice(&U256::from(party + 1).to_be_bytes::<32>());
            }
            fields.resize((2 * parties.len() + MAX_MSG_NON_ZERO_COEFFS) * 32, 0);
            Proof::new(
                CircuitName::DecryptedSharesAggregation,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&fields),
            )
        })
        .collect()
}

async fn wait_for_event(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
    matches: impl Fn(&InterfoldEventData) -> bool,
) -> Result<InterfoldEvent> {
    for _ in 0..300 {
        if let Some(event) = history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .into_iter()
            .find(|event| matches(event.get_data()))
        {
            return Ok(event);
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    anyhow::bail!("expected workflow event did not arrive")
}

#[actix::test]
async fn replayed_c7_work_cannot_replace_the_recovered_share_batch() -> Result<()> {
    use e3_events::DecryptedSharesAggregationProofResponse;
    use e3_trbfv::calculate_threshold_decryption::CalculateThresholdDecryptionResponse;
    let id = E3id::new("42", 1);
    let ciphertexts = test_ciphertexts();
    let plaintext = vec![ArcBytes::from_bytes(&0u64.to_le_bytes()); ciphertexts.len()];
    let a: Vec<_> = (0..10)
        .map(|party| {
            let (shares, _) = share_with_matching_commitment(&id, party, &ciphertexts);
            (party, shares)
        })
        .collect();
    let initial = ThresholdPlaintextAggregatorState::init(
        9,
        19,
        Seed([0; 32]),
        ciphertexts.clone(),
        test_params(),
    );
    let old_state = ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
        threshold_m: 9,
        threshold_n: 19,
        shares: a.clone(),
        plaintext: plaintext.clone(),
    });
    let (mut aggregator, history, _) = build_plaintext_aggregator(old_state, true).await?;
    aggregator.committee_size = CiphernodesCommitteeSize::Small;
    aggregator.committee_addresses = (0..19).map(|party| test_signer(party).address()).collect();
    aggregator.honest_committee_addresses = aggregator.committee_addresses[..14].to_vec();
    assert!(14 > aggregator.committee_size.values().threshold + 1);
    aggregator.effects_enabled = false;
    aggregator
        .recovery
        .try_mutate_without_context(|mut recovery| {
            recovery.last_ec = Some(test_ctx(EffectsEnabled::new()));
            recovery.honest_c6_proofs =
                vec![(0, vec![dummy_proof(CircuitName::ThresholdShareDecryption)])];
            Ok(recovery)
        })?;
    let mut events = vec![ciphertext_event(&id)];
    for party in 1..=10 {
        events.push(share_event(&id, party, false, party + 1));
    }
    let old_pending = AggregationProofPending {
        e3_id: id.clone(),
        shares: a.clone(),
        plaintext: plaintext.clone(),
        proof_request: DecryptedSharesAggregationProofRequest {
            d_share_polys: a,
            plaintext: plaintext.clone(),
            threshold_m: 9,
            threshold_n: 19,
            params_preset: BfvPreset::InsecureThreshold64,
            committee_size: CiphernodesCommitteeSize::Small,
        },
    };
    events.push(event(old_pending, EventSource::Local, 12));
    let reader = history_reader(&events)?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    aggregator
        .repair_recovered_state(initial, &reader, &plaintext_repositories(&store, &id))
        .await?;
    let bus = aggregator.bus.clone();
    let prover = e3_zk_prover::ProofRequestActor::setup(&bus, test_signer(0), true);
    let addr = aggregator.start();
    let recipient: Recipient<InterfoldEvent> = addr.clone().recipient();
    replay_suffix(&bus, &store, &reader, 12, &recipient, &history).await?;
    let old_compute = wait_for_event(&history, |data| {
        matches!(data,
        InterfoldEventData::ComputeRequest(ComputeRequest { request: ComputeRequestKind::Zk(
            ZkRequest::DecryptedSharesAggregation(req)), .. }) if req.d_share_polys[0].0 == 0)
    })
    .await?;
    let InterfoldEventData::ComputeRequest(old_compute) = old_compute.into_data() else {
        unreachable!()
    };
    let verification = wait_for_event(&history, |data| {
        matches!(data, InterfoldEventData::ShareVerificationDispatched(_))
    })
    .await?;
    let outcome = ShareVerificationComplete {
        e3_id: id.clone(),
        kind: VerificationKind::ThresholdDecryptionProofs,
        dishonest_parties: BTreeSet::new(),
    };
    bus.publish(outcome, verification.get_ctx().clone())?;
    let threshold = wait_for_event(&history, |data| {
        matches!(
            data,
            InterfoldEventData::ComputeRequest(ComputeRequest {
                request: ComputeRequestKind::TrBFV(TrBFVRequest::CalculateThresholdDecryption(_)),
                ..
            })
        )
    })
    .await?;
    let threshold_ec = threshold.get_ctx().clone();
    let InterfoldEventData::ComputeRequest(threshold) = threshold.into_data() else {
        unreachable!()
    };
    addr.send(TypedEvent::new(
        ComputeResponse::trbfv(
            TrBFVResponse::CalculateThresholdDecryption(CalculateThresholdDecryptionResponse {
                plaintext,
            }),
            threshold.correlation_id,
            id.clone(),
        ),
        test_ctx(EffectsEnabled::new()),
    ))
    .await?;
    let current = wait_for_event(&history, |data| {
        matches!(data,
        InterfoldEventData::ComputeRequest(ComputeRequest { request: ComputeRequestKind::Zk(
            ZkRequest::DecryptedSharesAggregation(req)), .. }) if req.d_share_polys[0].0 == 1)
    })
    .await?;
    let current_ec = current.get_ctx().clone();
    let InterfoldEventData::ComputeRequest(current) = current.into_data() else {
        unreachable!()
    };
    let old_proofs = batch_c7_proofs(&(0..10).collect::<Vec<_>>(), ciphertexts.len());
    // A signed result can already be in the journal independently of the live proof worker.
    addr.send(TypedEvent::new(
        AggregationProofSigned {
            e3_id: id.clone(),
            signed_proofs: old_proofs
                .iter()
                .cloned()
                .map(|proof| {
                    SignedProofPayload::sign(
                        ProofPayload {
                            e3_id: id.clone(),
                            proof_type: ProofType::C7DecryptedSharesAggregation,
                            proof,
                        },
                        &test_signer(0),
                    )
                    .unwrap()
                })
                .collect(),
        },
        test_ctx(EffectsEnabled::new()),
    ))
    .await?;
    bus.flush_event_pipeline().await?;
    assert!(
        !history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .iter()
            .any(|event| matches!(
                event.get_data(),
                InterfoldEventData::ComputeRequest(ComputeRequest {
                    request: ComputeRequestKind::Zk(ZkRequest::DecryptionAggregation(_)),
                    ..
                })
            )),
        "stale C7 result started final aggregation"
    );
    prover
        .send(TypedEvent::new(
            ComputeResponse::zk(
                ZkResponse::DecryptedSharesAggregation(DecryptedSharesAggregationProofResponse {
                    proofs: old_proofs,
                }),
                old_compute.correlation_id,
                id.clone(),
            ),
            threshold_ec,
        ))
        .await?;
    let correct = batch_c7_proofs(&(1..=10).collect::<Vec<_>>(), ciphertexts.len());
    prover
        .send(TypedEvent::new(
            ComputeResponse::zk(
                ZkResponse::DecryptedSharesAggregation(DecryptedSharesAggregationProofResponse {
                    proofs: correct.clone(),
                }),
                current.correlation_id,
                id.clone(),
            ),
            current_ec,
        ))
        .await?;
    let final_request = wait_for_event(&history, |data| {
        matches!(
            data,
            InterfoldEventData::ComputeRequest(ComputeRequest {
                request: ComputeRequestKind::Zk(ZkRequest::DecryptionAggregation(_)),
                ..
            })
        )
    })
    .await?;
    let InterfoldEventData::ComputeRequest(ComputeRequest {
        request: ComputeRequestKind::Zk(ZkRequest::DecryptionAggregation(request)),
        ..
    }) = final_request.into_data()
    else {
        unreachable!()
    };
    assert_eq!(request.c6_total_slots, 10);
    for (job, proof) in request.jobs.iter().zip(correct) {
        assert_eq!(job.c7_proof, proof);
    }
    assert_eq!(
        history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .iter()
            .filter(|event| matches!(
                event.get_data(),
                InterfoldEventData::AggregationProofSigned(_)
            ))
            .count(),
        1,
        "superseded worker result must not publish a signed proof"
    );
    Ok(())
}

#[actix::test]
async fn hydration_regenerates_c7_for_the_retained_share_batch() -> Result<()> {
    let id = E3id::new("42", 1);
    let ciphertexts = test_ciphertexts();
    let plaintext = vec![ArcBytes::from_bytes(&0u64.to_le_bytes()); ciphertexts.len()];
    let shares: Vec<_> = (1..=10)
        .map(|party| {
            let (shares, _) = share_with_matching_commitment(&id, party, &ciphertexts);
            (party, shares)
        })
        .collect();
    let c6: Vec<_> = (1..=10)
        .map(|party| {
            let (_, proofs) = share_with_matching_commitment(&id, party, &ciphertexts);
            (
                party,
                proofs
                    .into_iter()
                    .map(|proof| proof.payload.proof)
                    .collect(),
            )
        })
        .collect();
    for complete in [false, true] {
        for mismatch in ["party", "commitment", "plaintext"] {
            let state = if complete {
                ThresholdPlaintextAggregatorState::Complete(Complete {
                    shares: shares.clone(),
                    decrypted: plaintext.clone(),
                })
            } else {
                ThresholdPlaintextAggregatorState::GeneratingC7Proof(GeneratingC7Proof {
                    shares: shares.clone(),
                    plaintext: plaintext.clone(),
                    threshold_m: 9,
                    threshold_n: 19,
                })
            };
            let (mut aggregator, history, _) = build_plaintext_aggregator(state, true).await?;
            let mut proofs = batch_c7_proofs(&(1..=10).collect::<Vec<_>>(), ciphertexts.len());
            let mut fields = proofs[0].public_signals.to_vec();
            let offset = match mismatch {
                "party" => 10 * 32 + 31,
                "commitment" => 31,
                _ => 20 * 32 + 31,
            };
            fields[offset] ^= 1;
            proofs[0].public_signals = ArcBytes::from_bytes(&fields);
            aggregator
                .recovery
                .try_mutate_without_context(|mut recovery| {
                    recovery.last_ec = Some(test_ctx(EffectsEnabled::new()));
                    recovery.honest_c6_proofs = c6.clone();
                    recovery.c7_proofs = Some(proofs.clone());
                    recovery.decryption_aggregator_proofs =
                        Some(vec![
                            dummy_proof(CircuitName::DecryptionAggregator);
                            ciphertexts.len()
                        ]);
                    Ok(recovery)
                })?;
            aggregator.pending.honest_c6_proofs_for_agg = Some(c6.clone());
            aggregator.pending.c7_proofs_pending = Some(proofs);
            aggregator.pending.decryption_aggregator_proofs =
                aggregator.recovery.try_get()?.decryption_aggregator_proofs;
            let store = DataStore::from_in_mem(&InMemStore::new(false).start());
            aggregator
                .repair_recovered_state(
                    ThresholdPlaintextAggregatorState::init(
                        9,
                        19,
                        Seed([0; 32]),
                        ciphertexts.clone(),
                        test_params(),
                    ),
                    &history_reader(&[])?,
                    &plaintext_repositories(&store, &id),
                )
                .await?;
            aggregator.resume_in_flight_work(test_ctx(EffectsEnabled::new()))?;
            let next = next_event(&history).await?;
            assert!(matches!(next.get_data(), InterfoldEventData::AggregationProofPending(pending)
                if pending.shares == shares && pending.plaintext == plaintext),
                "retained C7 {mismatch} mismatch must regenerate the selected batch (complete={complete})");
            let recovered = plaintext_repositories(&store, &id)
                .trbfv_plaintext_recovery(&id)
                .read()
                .await?
                .unwrap();
            assert!(recovered.c7_proofs.is_none());
            assert!(recovered.decryption_aggregator_proofs.is_none());
        }
    }
    Ok(())
}
