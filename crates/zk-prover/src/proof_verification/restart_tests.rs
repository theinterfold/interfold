// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::{setup_zk_actors, ZkActorRecovery};
use e3_ciphernode_builder::{EventStoreAddrs, EventSystem};
use e3_data::RepositoriesFactory;
use e3_events::{
    AggregateConfig, AggregateId, DocumentReceived, Event, EventConstructorWithTimestamp,
    EventContextSeq, EventSource, EvmEventConfig, EvmEventConfigChain, FlushPendingSnapshots,
    HistoricalEvmEventsReceived, HistoricalNetSyncEventsReceived, NetReady, StoreEventRequested,
    StoreEventResponse, SyncEnded, TestEvent,
};
use e3_net::{
    create_channel_bridge, events::DocumentPublishedNotification, events::NetCommand,
    recover_document_state, ContentHash, DocumentPublisher, EventConverter, NetInterface,
    NetInterfaceInverted,
};
use e3_sortition::{
    CiphernodeSelectorFactory, CiphernodeSelectorState, FinalizedCommitteesRepositoryFactory,
};
use e3_sync::SyncRepositoryFactory;
use e3_utils::actix::channel;
use std::collections::HashSet;

pub(super) async fn check_c0_restart(
    backend: &ZkBackend,
    vk: &std::path::Path,
    signer: &PrivateKeySigner,
    pk: &[u8],
    proof: &Proof,
    legacy_records: u64,
    legacy_bytes: usize,
) -> std::thread::Result<()> {
    let temp = crate::test_utils::get_tempdir().unwrap();
    let e3_id = E3id::new("8", 31_337);
    let observer = PrivateKeySigner::random();
    let mut members = vec![
        signer.address(),
        observer.address(),
        PrivateKeySigner::random().address(),
    ];
    members.sort();
    let party_id = members
        .iter()
        .position(|member| *member == signer.address())
        .unwrap() as u64;
    let key = Arc::new(
        EncryptionKey::new(party_id, ArcBytes::from_bytes(pk))
            .with_proof(proof.clone())
            .with_signed_payload(
                SignedProofPayload::sign(
                    ProofPayload {
                        e3_id: e3_id.clone(),
                        proof_type: ProofType::C0PkBfv,
                        proof: proof.clone(),
                    },
                    signer,
                )
                .unwrap(),
            ),
    );
    let source_bus = test_bus();
    EventConverter::setup(&source_bus);
    let publication = source_bus.wait_for(EventType::PublishDocumentRequested);
    source_bus
        .publish_without_context(EncryptionKeyCreated {
            e3_id: e3_id.clone(),
            key: key.clone(),
            external: false,
        })
        .unwrap();
    let InterfoldEventData::PublishDocumentRequested(publication) =
        publication.await.unwrap().into_data()
    else {
        panic!("C0 document was not published");
    };
    let document = DocumentReceived {
        meta: publication.meta,
        value: publication.value,
    };
    let saved_vk = vk.with_extension("saved");
    fs::rename(vk, &saved_vk).unwrap();

    for boot in 0..3 {
        let backend = backend.clone();
        let root = temp.path().to_path_buf();
        let e3_id = e3_id.clone();
        let members = members.clone();
        let observer = observer.clone();
        let key = key.clone();
        let document = document.clone();
        // Dropping each runtime closes every actor and event-log handle before the next boot.
        let boot_task = std::thread::spawn(move || {
            actix::System::new().block_on(async move {
            let aggregate = AggregateId::new(31_337);
            let config = AggregateConfig::new(HashMap::from([(aggregate, Duration::ZERO)]));
            let system = EventSystem::persisted(root.join("log"), root.join("sled"))
                .with_fresh_bus().with_aggregate_config(config.clone());
            let bus = system.handle().unwrap().enable("c0-restart");
            let store = system.store().unwrap();
            let repositories = store.repositories();
            let reader = system.eventstore_reader().unwrap().seq();
            let aggregates: Vec<_> = config.indexed_ids().into_iter().map(AggregateId::new).collect();
            e3_sync::preflight_schema_version(&repositories, &config, &reader).await.unwrap();
            e3_request::ensure_request_router_checkpoint(&repositories, aggregates.clone()).await.unwrap();
            if boot == 0 {
                let committees = HashMap::from([(e3_id.clone(), Committee::new(members.iter().map(ToString::to_string).collect()))]);
                repositories.finalized_committees().write_sync(&committees).await.unwrap();
                repositories.ciphernode_selector().write_sync(&CiphernodeSelectorState {
                    committees,
                    e3_cache: HashMap::from([(e3_id.clone(), E3Meta {
                        threshold_m: 1, threshold_n: 3, seed: Seed([0; 32]),
                        params_preset: BfvPreset::InsecureThreshold,
                        params: ArcBytes::default(), error_size: ArcBytes::default(),
                    })]),
                    ..Default::default()
                }).await.unwrap();
            }
            let mut recovery = ZkActorRecovery::new(
                repositories.finalized_committees().read().await.unwrap().unwrap(),
                repositories.ciphernode_selector().read().await.unwrap().unwrap().e3_cache,
                HashMap::new(),
            );
            recovery.hydrate(&repositories, &HashMap::new(), &reader, &aggregates).await.unwrap();
            let history = bus.history();
            let actors = setup_zk_actors(&bus, &backend, observer.clone(), HashMap::new(), recovery, false, repositories.clone());
            let accusations = AccusationManager::setup(&bus, e3_id.clone(), observer,
                Address::repeat_byte(9), members, 1, 300, 30, BfvPreset::InsecureThreshold);
            EventConverter::setup(&bus);
            let recovered_documents = recover_document_state(&reader, &aggregates, &HashSet::from([e3_id.clone()])).await.unwrap();
            let hash = ContentHash::from_content(&document.value);
            if boot > 0 {
                assert!(recovered_documents.received.contains(&(e3_id.clone(), hash.clone())), "document receipt was not restored");
            }
            let (interface, bridge) = create_channel_bridge();
            let mut commands = bridge.cmd_rx();
            let documents = DocumentPublisher::setup_before_effects(&bus, &interface.tx(), &interface.events(),
                "c0-restart", HashMap::from([(e3_id.clone(), party_id)]), recovered_documents);
            bus.event_bus().send(EventBusBarrier).await.unwrap();
            actors.proof_verification.send(VerificationBarrier).await.unwrap();
            actors.zk_actor.send(VerificationBarrier).await.unwrap();
            bus.flush_event_pipeline().await.unwrap();
            assert!(history.send(GetEvents::new()).await.unwrap().is_empty(), "C0 recovery ran before EffectsEnabled");

            if boot == 0 {
                // Seed a legacy prefix with a durable receipt and records in the wrong store.
                let EventStoreAddrs::Persisted(stores) = system.eventstore_addrs().unwrap() else {
                    panic!("expected persisted event stores");
                };
                let padding = "x".repeat(legacy_bytes);
                let records = std::iter::once(InterfoldEventData::from(document.clone()))
                    .chain((0..legacy_records).map(|index| {
                        TestEvent::new(&padding, index).with_e3_id(E3id::new("9", 1)).into()
                    }));
                for (index, data) in records.enumerate() {
                    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                        data, None, index as u128 + 1, None, EventSource::Local);
                    let (recipient, response) = channel::oneshot::<StoreEventResponse>();
                    stores[&31_337].send(StoreEventRequested::new(event, recipient)).await.unwrap();
                    response.await.unwrap();
                }
                bus.publish_without_context(EffectsEnabled::new()).unwrap();
                bus.publish_without_context(SyncEnded::new()).unwrap();
                bus.publish_without_context(document.clone()).unwrap();
            } else {
                let chain_history = bus.wait_for(EventType::HistoricalEvmSyncStart);
                tokio::spawn(async move {
                    let InterfoldEventData::HistoricalEvmSyncStart(request) = chain_history.await.unwrap().into_data() else { unreachable!() };
                    request.sender.unwrap().try_send(HistoricalEvmEventsReceived::new(Vec::new(), 31_337)).unwrap();
                });
                let peer_history = bus.wait_for(EventType::HistoricalNetSyncStart);
                let history_bus = bus.clone();
                tokio::spawn(async move {
                    peer_history.await.unwrap();
                    history_bus.publish_without_context(HistoricalNetSyncEventsReceived::new(Vec::new())).unwrap();
                });
                let ready = bus.wait_for(EventType::NetReady);
                bus.publish_without_context(NetReady::new()).unwrap();
                e3_sync::sync_with_net_ready(&bus, &EvmEventConfig::from_config([(31_337, EvmEventConfigChain::new(0))]), &repositories, &config, &reader, ready).await.unwrap();
                documents.send(DocumentPublishedNotification::new(document.meta.clone(), hash, 1)).await.unwrap();
            }
            bus.flush_event_pipeline().await.unwrap();
            actors.proof_verification.send(VerificationBarrier).await.unwrap();
            actors.zk_actor.send(VerificationBarrier).await.unwrap();
            actors.proof_verification.send(VerificationBarrier).await.unwrap();
            bus.flush_event_pipeline().await.unwrap();
            accusations.send(VerificationBarrier).await.unwrap();
            bus.flush_event_pipeline().await.unwrap();
            let events = history.send(GetEvents::new()).await.unwrap();
            let data: Vec<_> = events.iter().map(|event| event.get_data().clone()).collect();
            assert_no_blame(&data);
            let accepted = data.iter().filter(|event| matches!(event,
                InterfoldEventData::EncryptionKeyCreated(created) if created.external && created.key == key)).count();
            assert_eq!(accepted, usize::from(boot == 1), "restart must accept the pending C0 exactly once");
            if boot > 0 {
                assert!(!data.iter().any(|event| matches!(event, InterfoldEventData::EncryptionKeyReceived(_))), "snapshot prefix was replayed or document was fetched again");
                while let Ok(command) = commands.try_recv() {
                    assert!(!matches!(command, NetCommand::DhtGetRecord { .. }), "restored document receipt allowed another fetch");
                }
            }
            bus.publish_without_context(TestEvent::new("snapshot after C0", boot).with_e3_id(e3_id)).unwrap();
            bus.flush_event_pipeline().await.unwrap();
            system.buffer().unwrap().send(FlushPendingSnapshots).await.unwrap().unwrap();
            let cursor = repositories.aggregate_seq(aggregate).read().await.unwrap().unwrap();
            if boot == 0 {
                let input = events.iter().find(|event| matches!(event.get_data(), InterfoldEventData::EncryptionKeyReceived(_))).unwrap();
                assert!(input.seq() > legacy_records + 1, "C0 input must follow the quarantined records");
                assert!(input.seq() < cursor, "C0 input must precede the snapshot cursor");
                // Legacy nodes can have a current checkpoint beyond the quarantined prefix.
                let checkpoint_store = repositories.request_router_checkpoint();
                let mut checkpoint = checkpoint_store.read().await.unwrap().unwrap();
                checkpoint.replay_cursors.insert(aggregate, cursor);
                checkpoint_store.write_sync(&checkpoint).await.unwrap();
            }
            e3_sync::reconcile_request_router_checkpoint(&repositories, aggregates, &reader).await.unwrap();
            store.shutdown().await.unwrap();
        });
        });
        let result = boot_task.join();
        if boot == 0 {
            fs::rename(&saved_vk, vk).unwrap();
        }
        result?;
    }
    Ok(())
}
