// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::domain::net_event_batch::{BatchCursor, EventBatch};
use crate::net_interface_handle::{NetEventChannel, NetEventSubscriber};
use crate::{
    direct_responder::ChannelType,
    domain::closed_e3s::MAX_CLOSED_E3S,
    events::{IncomingRequest, NetCommand},
};
use actix::{Actor, Context as ActixContext, Handler, Message, MessageResult};
use e3_ciphernode_builder::EventSystem;
use e3_config::NetworkProfile;
use e3_events::{
    AggregateConfig, DecryptionshareCreated, DkgCoordination, DkgCoordinationKind, DkgDealer,
    E3Failed, E3Stage, E3StageChanged, E3id, EventSource, FailureReason, HistoricalNetSyncFailed,
    InterfoldEvent, KeyshareCreated, TestEvent, Unsequenced,
};
use e3_utils::ArcBytes;
use tokio::sync::{mpsc, mpsc::UnboundedSender};

/// Minimal EventStore stand-in so `NetSyncManager::new` can be constructed in tests; the
/// re-broadcast unit test drives `handle_rebroadcast_response` directly and never queries it.
struct NoopEventStore;
impl Actor for NoopEventStore {
    type Context = ActixContext<Self>;
}
impl Handler<EventStoreQueryBy<TsAgg>> for NoopEventStore {
    type Result = ();
    fn handle(&mut self, _: EventStoreQueryBy<TsAgg>, _: &mut Self::Context) {}
}

struct RecordingEventStore {
    queries: UnboundedSender<(Option<u64>, Option<u64>, bool)>,
}

impl Actor for RecordingEventStore {
    type Context = ActixContext<Self>;
}

impl Handler<EventStoreQueryBy<TsAgg>> for RecordingEventStore {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<TsAgg>, _: &mut Self::Context) {
        let _ = self
            .queries
            .send((msg.limit(), msg.max_bytes(), msg.timestamp_order()));
        // Intentionally retain no response. Tests exercise the manager's in-flight bounds.
    }
}

fn manager_with_recording_store(
    query_tx: UnboundedSender<(Option<u64>, Option<u64>, bool)>,
) -> (NetSyncManager, mpsc::Receiver<NetCommand>) {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let evt_rx = NetEventSubscriber::from(&evt_tx);
    let eventstore = RecordingEventStore { queries: query_tx }
        .start()
        .recipient();

    (
        NetSyncManager::new(
            &bus,
            &tx,
            &evt_rx,
            eventstore,
            "my-topic",
            NetworkPolicy::local_unrestricted(),
        ),
        rx,
    )
}

fn incoming_sync_request(
    peer: PeerId,
    id: u64,
    limit: usize,
    tx: &mpsc::Sender<NetCommand>,
) -> IncomingRequest {
    let request: Vec<u8> = FetchEventsSince::new(AggregateId::new(1), 0, limit)
        .try_into()
        .unwrap();
    let responder = DirectResponder::new(id, ChannelType::Test(format!("request-{id}")), tx)
        .with_request(request);
    IncomingRequest { peer, responder }
}

fn protocol_response(command: NetCommand) -> ProtocolResponse {
    let NetCommand::IncomingResponse(incoming) = command else {
        panic!("expected IncomingResponse, got {command:?}");
    };
    incoming.responder.to_response().unwrap().1
}

fn local_forwardable_event(e3: &str) -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
            e3_id: E3id::new(e3, 1),
            node: "node-1".to_string(),
            party_id: 1,
            signed_pk_generation_proof: None,
        }
        .into(),
        None,
        10,
        None,
        EventSource::Local,
    )
    .into_sequenced(1)
}

fn local_non_forwardable_event() -> InterfoldEvent {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        TestEvent::new("not-forwardable", 1).into(),
        None,
        11,
        None,
        EventSource::Local,
    )
    .into_sequenced(2)
}

fn remote_unsequenced(event: InterfoldEvent) -> InterfoldEvent<Unsequenced> {
    event.clone_unsequenced().with_source(EventSource::Net)
}

struct IgnoreStoreResponses;
impl Actor for IgnoreStoreResponses {
    type Context = ActixContext<Self>;
}
impl Handler<e3_events::StoreEventResponse> for IgnoreStoreResponses {
    type Result = ();
    fn handle(&mut self, _: e3_events::StoreEventResponse, _: &mut Self::Context) {}
}

fn keyshare_at(ts: u128) -> InterfoldEvent<Unsequenced> {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3, 4]),
            e3_id: E3id::new(ts.to_string(), 1),
            node: "node-1".to_string(),
            party_id: 1,
            signed_pk_generation_proof: None,
        }
        .into(),
        None,
        ts,
        None,
        EventSource::Net,
    )
}

/// Page through this node's history the way a peer does and return the timestamps it receives.
async fn served_history(
    manager: &Addr<NetSyncManager>,
    net_tx: &mpsc::Sender<NetCommand>,
    net_rx: &mut mpsc::Receiver<NetCommand>,
    limit: usize,
) -> Vec<u128> {
    let mut since = 0;
    let mut served = Vec::new();
    for id in 0..64 {
        let request: Vec<u8> = FetchEventsSince::new(AggregateId::new(1), since, limit)
            .try_into()
            .unwrap();
        let responder = DirectResponder::new(id, ChannelType::Test(format!("page-{id}")), net_tx)
            .with_request(request);
        manager
            .send(IncomingRequest {
                peer: PeerId::random(),
                responder,
            })
            .await
            .unwrap();
        let command = tokio::time::timeout(Duration::from_secs(5), net_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let ProtocolResponse::Ok(bytes) = protocol_response(command) else {
            panic!("expected a history page");
        };
        let batch = EventBatch::<InterfoldEvent<Unsequenced>>::try_from(bytes).unwrap();
        served.extend(batch.events.iter().map(|event| event.ts()));
        match batch.next {
            BatchCursor::Next(next) => since = next,
            BatchCursor::Done => return served,
        }
    }
    panic!("history did not end");
}

#[actix::test]
async fn history_pages_serve_every_record_when_the_log_holds_older_timestamps_later() {
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::ZERO,
        )])));
    let bus = system.handle().unwrap().enable("test");
    // The log holds timestamp 20 after 30, as when startup appends history, and a record that
    // the reply filters.
    let store = system.eventstore_router().unwrap();
    let responses = IgnoreStoreResponses.start();
    for event in [
        keyshare_at(10),
        keyshare_at(30),
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("local-only", 1).into(),
            None,
            15,
            None,
            EventSource::Local,
        ),
        keyshare_at(20),
    ] {
        store
            .send(e3_events::StoreEventRequested::new(
                event,
                responses.clone().recipient(),
            ))
            .await
            .unwrap();
    }
    let (net_tx, mut net_rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let manager = NetSyncManager::new(
        &bus,
        &net_tx,
        &NetEventSubscriber::from(&evt_tx),
        system.eventstore_reader().unwrap().ts(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
    )
    .start();

    assert_eq!(
        served_history(&manager, &net_tx, &mut net_rx, 2).await,
        vec![10, 20, 30]
    );
}

/// A legacy log can hold another chain's records in this aggregate's store. The router drops them,
/// so a whole page can return no record. The reply then names the next timestamp instead of
/// `Done`, and the peer still receives the valid record after those pages.
#[actix::test]
async fn history_pages_continue_past_pages_of_quarantined_records() {
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::ZERO,
        )])));
    let bus = system.handle().unwrap().enable("test");
    let e3_ciphernode_builder::EventStoreAddrs::InMem(stores) = system.eventstore_addrs().unwrap()
    else {
        panic!("expected in-memory stores");
    };
    let store = stores.get(&1).expect("aggregate 1 store").clone();
    let responses = IgnoreStoreResponses.start();
    let misrouted = |ts: u128| {
        let mut event = keyshare_at(ts);
        if let InterfoldEventData::KeyshareCreated(data) = event.get_data().clone() {
            event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
                KeyshareCreated {
                    e3_id: E3id::new(ts.to_string(), 2),
                    ..data
                }
                .into(),
                None,
                ts,
                None,
                EventSource::Net,
            );
        }
        event
    };
    for event in [
        misrouted(10),
        misrouted(11),
        misrouted(12),
        misrouted(13),
        keyshare_at(20),
    ] {
        store
            .send(e3_events::StoreEventRequested::new(
                event,
                responses.clone().recipient(),
            ))
            .await
            .unwrap();
    }
    let (net_tx, mut net_rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let manager = NetSyncManager::new(
        &bus,
        &net_tx,
        &NetEventSubscriber::from(&evt_tx),
        system.eventstore_reader().unwrap().ts(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
    )
    .start();

    assert_eq!(
        served_history(&manager, &net_tx, &mut net_rx, 2).await,
        vec![20]
    );
}

#[test]
fn historical_sync_rejects_non_forwardable_remote_events() {
    let error = validate_historical_events(
        AggregateId::new(0),
        vec![remote_unsequenced(local_non_forwardable_event())],
        &NetworkPolicy::local_unrestricted(),
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("non-forwardable event type TestEvent"));
}

#[test]
fn historical_sync_rejects_events_from_another_aggregate() {
    let event = remote_unsequenced(local_forwardable_event("1234"));

    let error = validate_historical_events(
        AggregateId::new(999),
        vec![event],
        &NetworkPolicy::local_unrestricted(),
    )
    .unwrap_err();

    assert!(error.to_string().contains("while fetching 999"));
}

#[test]
fn historical_sync_cursor_keeps_only_active_network_chains() {
    let policy = NetworkPolicy::new(NetworkProfile::mainnet(), [(31_337, [1; 20])]).unwrap();
    let cursor = BTreeMap::from([
        (AggregateId::new(0), 10),
        (AggregateId::new(31_337), 20),
        (AggregateId::new(11_155_111), 30),
    ]);

    assert_eq!(
        eligible_sync_cursor(&cursor, &policy),
        BTreeMap::from([(AggregateId::new(31_337), 20)])
    );
}

#[actix::test]
async fn local_only_cursor_completes_without_a_peer_request() {
    let (net_tx, mut net_rx) = mpsc::channel::<NetCommand>(1);
    let event_tx = NetEventChannel::new(1);
    let _event_rx = event_tx.subscribe();
    let event_rx = NetEventSubscriber::from(&event_tx);
    let (response_tx, response_rx) =
        e3_utils::actix::channel::oneshot::<TypedEvent<SyncRequestSucceeded>>();
    let start = HistoricalNetSyncStart::new(BTreeMap::from([(AggregateId::new(0), 10)]));
    let context: e3_events::EventContext<Unsequenced> =
        InterfoldEventData::HistoricalNetSyncStart(start.clone()).into();

    handle_sync_request_event(
        net_tx,
        event_rx,
        TypedEvent::new(start, context.sequence(1)),
        response_tx,
        true,
        NetworkPolicy::local_unrestricted(),
    )
    .await
    .unwrap();

    let response = response_rx.await.unwrap().into_inner().response;
    assert!(response.events.is_empty());
    assert_eq!(response.ts, 0);
    assert!(
        net_rx.try_recv().is_err(),
        "local aggregate caused an outbound peer request"
    );
}

#[actix::test]
async fn rebroadcast_only_gossips_forwardable_own_artifacts() {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, mut rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let evt_rx = NetEventSubscriber::from(&evt_tx);
    let eventstore = NoopEventStore.start().recipient();

    let mut mgr = NetSyncManager::new(
        &bus,
        &tx,
        &evt_rx,
        eventstore,
        "my-topic",
        NetworkPolicy::local_unrestricted(),
    );

    mgr.handle_rebroadcast_response(vec![
        local_forwardable_event("1234"),
        local_non_forwardable_event(),
    ]);

    // Exactly one GossipPublish for the forwardable artifact, on the configured topic.
    let cmd = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timed out waiting for GossipPublish")
        .expect("network command channel closed");
    let NetCommand::GossipPublish { topic, data, .. } = cmd else {
        panic!("expected GossipPublish, got {cmd:?}");
    };
    assert_eq!(topic, "my-topic");
    let event: InterfoldEvent<Unsequenced> = data.try_into().unwrap();
    assert!(matches!(
        event.get_data(),
        InterfoldEventData::KeyshareCreated(_)
    ));

    // The non-forwardable event must not have produced a second command.
    assert!(
        rx.try_recv().is_err(),
        "non-forwardable event should not be re-broadcast"
    );
}

#[actix::test]
async fn periodic_dkg_reannouncement_uses_the_latest_ready_superset() {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, mut rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let evt_rx = NetEventSubscriber::from(&evt_tx);
    let eventstore = NoopEventStore.start().recipient();
    let mut manager = NetSyncManager::new(
        &bus,
        &tx,
        &evt_rx,
        eventstore,
        "my-topic",
        NetworkPolicy::local_unrestricted(),
    );
    manager.net_ready = true;
    manager.replay_finished = true;

    let e3_id = E3id::new("ready-reannounce", 1);
    for (timestamp, dealer_ids) in [(10, vec![0, 1]), (11, vec![0, 1, 2])] {
        let message = DkgCoordination {
            e3_id: e3_id.clone(),
            interfold_address: Default::default(),
            party_id: 0,
            kind: DkgCoordinationKind::Ready,
            dealers: dealer_ids
                .into_iter()
                .map(|party_id| DkgDealer {
                    party_id,
                    contribution_hash: [party_id as u8; 32],
                })
                .collect(),
            signature: ArcBytes::from_bytes(&[]),
        };
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            message.clone().into(),
            None,
            timestamp,
            None,
            EventSource::Local,
        )
        .into_sequenced(timestamp as u64);
        manager.remember_dkg_coordination(event);
    }

    let start = Instant::now();
    manager.reannounce_due(start);
    assert!(
        rx.try_recv().is_err(),
        "nothing is due before the first interval"
    );

    manager.reannounce_due(start + DKG_REANNOUNCE_BASE);
    let command = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timed out waiting for DKG re-announcement")
        .expect("network command channel closed");
    let NetCommand::GossipPublish {
        data,
        delivery_id: first_delivery_id,
        ..
    } = command
    else {
        panic!("expected GossipPublish, got {command:?}");
    };
    assert!(first_delivery_id.is_some());
    let event: InterfoldEvent<Unsequenced> = data.try_into().unwrap();
    let InterfoldEventData::DkgCoordination(message) = event.into_data() else {
        panic!("expected DkgCoordination");
    };
    assert_eq!(message.dealers.len(), 3);

    manager.reannounce_due(start + DKG_REANNOUNCE_BASE + Duration::from_secs(1));
    assert!(
        rx.try_recv().is_err(),
        "the second re-send waits for the backoff"
    );

    manager.reannounce_due(start + DKG_REANNOUNCE_BASE * 4);
    let second = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timed out waiting for the second DKG re-announcement")
        .expect("network command channel closed");
    let NetCommand::GossipPublish {
        delivery_id: second_delivery_id,
        ..
    } = second
    else {
        panic!("expected GossipPublish, got {second:?}");
    };
    assert!(second_delivery_id.is_some());
    assert_ne!(first_delivery_id, second_delivery_id);
    assert!(rx.try_recv().is_err());
}

fn local_decryption_share(e3_id: &E3id, party_id: u64) -> (InterfoldEvent, DecryptionshareCreated) {
    let share = DecryptionshareCreated {
        party_id,
        decryption_share: vec![ArcBytes::from_bytes(&[7; 16])],
        e3_id: e3_id.clone(),
        node: "node-1".to_string(),
        signed_decryption_proofs: vec![],
    };
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        share.clone().into(),
        None,
        20,
        None,
        EventSource::Local,
    )
    .into_sequenced(3);
    (event, share)
}

fn ready_manager() -> (NetSyncManager, mpsc::Receiver<NetCommand>) {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let evt_rx = NetEventSubscriber::from(&evt_tx);
    let eventstore = NoopEventStore.start().recipient();
    let mut manager = NetSyncManager::new(
        &bus,
        &tx,
        &evt_rx,
        eventstore,
        "my-topic",
        NetworkPolicy::local_unrestricted(),
    );
    // A running node: peers are connected and local replay has finished.
    manager.net_ready = true;
    manager.replay_finished = true;
    (manager, rx)
}

async fn next_gossiped_share(rx: &mut mpsc::Receiver<NetCommand>) -> DecryptionshareCreated {
    let command = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timed out waiting for a re-announcement")
        .expect("network command channel closed");
    let NetCommand::GossipPublish {
        data,
        delivery_id: Some(_),
        ..
    } = command
    else {
        panic!("expected a fresh GossipPublish, got {command:?}");
    };
    let event: InterfoldEvent<Unsequenced> = data.try_into().unwrap();
    let InterfoldEventData::DecryptionshareCreated(share) = event.into_data() else {
        panic!("expected DecryptionshareCreated");
    };
    share
}

/// Gossip goes out from a spawned task, so wait a moment before concluding that nothing was sent.
async fn assert_nothing_gossiped(rx: &mut mpsc::Receiver<NetCommand>, why: &str) {
    let command = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(command.is_err(), "{why}: got {command:?}");
}

/// Lists the messages that a running manager will re-send.
#[derive(Message)]
#[rtype(result = "Vec<AnnouncementKey>")]
struct ScheduledAnnouncements;

impl Handler<ScheduledAnnouncements> for NetSyncManager {
    type Result = MessageResult<ScheduledAnnouncements>;
    fn handle(&mut self, _: ScheduledAnnouncements, _: &mut Self::Context) -> Self::Result {
        MessageResult(self.announcements.keys().cloned().collect())
    }
}

#[actix::test]
async fn a_published_decryption_share_is_scheduled_for_resending() {
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::ZERO,
        )])));
    let bus = system.handle().unwrap().enable("test");
    let (tx, _rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let manager = NetSyncManager::setup(
        &bus,
        &tx,
        &NetEventSubscriber::from(&evt_tx),
        NoopEventStore.start().recipient(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
        false,
    );
    let e3_id = E3id::new("decrypting", 1);
    let (_, share) = local_decryption_share(&e3_id, 4);
    bus.publish_without_context(share).unwrap();

    let expected = AnnouncementKey::DecryptionShare(e3_id, 4);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let scheduled = manager.send(ScheduledAnnouncements).await.unwrap();
        if scheduled.contains(&expected) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the manager did not receive the published share: {scheduled:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[actix::test]
async fn own_decryption_share_is_resent_with_backoff_until_the_e3_ends() {
    let (mut manager, mut rx) = ready_manager();
    let e3_id = E3id::new("decrypting", 1);
    let (event, share) = local_decryption_share(&e3_id, 4);
    manager.remember_decryption_share(event);

    let start = Instant::now();
    manager.reannounce_due(start + SHARE_REANNOUNCE_BASE);
    assert_eq!(next_gossiped_share(&mut rx).await, share);
    manager.reannounce_due(start + SHARE_REANNOUNCE_BASE * 2);
    assert!(
        rx.try_recv().is_err(),
        "the second re-send waits for the backoff"
    );
    manager.reannounce_due(start + SHARE_REANNOUNCE_BASE * 4);
    assert_eq!(next_gossiped_share(&mut rx).await, share);

    manager.forget_e3_announcements(&e3_id);
    manager.reannounce_due(start + Duration::from_secs(60 * 60));
    assert!(rx.try_recv().is_err(), "a finished E3 is not re-sent");
}

#[actix::test]
async fn key_publication_keeps_decryption_shares_and_drops_dkg_messages() {
    let (mut manager, mut rx) = ready_manager();
    let e3_id = E3id::new("mixed", 1);
    let (event, share) = local_decryption_share(&e3_id, 2);
    manager.remember_decryption_share(event);
    let ready = DkgCoordination {
        e3_id: e3_id.clone(),
        interfold_address: Default::default(),
        party_id: 2,
        kind: DkgCoordinationKind::Ready,
        dealers: vec![],
        signature: ArcBytes::from_bytes(&[]),
    };
    let ready_event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        ready.clone().into(),
        None,
        21,
        None,
        EventSource::Local,
    )
    .into_sequenced(4);
    manager.remember_dkg_coordination(ready_event);

    manager.forget_dkg_coordination(&e3_id);
    manager.reannounce_due(Instant::now() + SHARE_REANNOUNCE_BASE);
    assert_eq!(next_gossiped_share(&mut rx).await, share);
    assert!(rx.try_recv().is_err(), "the DKG message was forgotten");
}

/// Starts a manager through the production setup.
fn started_manager() -> (Addr<NetSyncManager>, EventSystem) {
    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::new(1),
            Duration::ZERO,
        )])));
    let bus = system.handle().unwrap().enable("test");
    let (tx, _rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    let manager = NetSyncManager::setup(
        &bus,
        &tx,
        &NetEventSubscriber::from(&evt_tx),
        NoopEventStore.start().recipient(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
        false,
    );
    (manager, system)
}

/// Delivers `data` to the manager as an event from `source`, as replay or live routing does.
async fn deliver(
    manager: &Addr<NetSyncManager>,
    data: impl Into<InterfoldEventData>,
    source: EventSource,
    seq: u64,
) {
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        data.into(),
        None,
        seq.into(),
        None,
        source,
    )
    .into_sequenced(seq);
    manager.send(event).await.unwrap();
}

/// Delivers a local share for `ended`, then one for `running`, and returns the scheduled re-sends.
async fn scheduled_after_shares(
    manager: &Addr<NetSyncManager>,
    ended: &E3id,
    running: &E3id,
) -> Vec<AnnouncementKey> {
    for (seq, e3_id) in [(10, ended), (11, running)] {
        let (_, share) = local_decryption_share(e3_id, 4);
        deliver(manager, share, EventSource::Local, seq).await;
    }
    let mut scheduled = manager.send(ScheduledAnnouncements).await.unwrap();
    scheduled.sort_by_key(|key| key.e3_id().to_string());
    scheduled
}

fn stage_change(e3_id: &E3id, new_stage: E3Stage) -> E3StageChanged {
    E3StageChanged {
        e3_id: e3_id.clone(),
        previous_stage: E3Stage::CiphertextReady,
        new_stage,
    }
}

#[actix::test]
async fn a_replayed_end_from_the_chain_stops_later_resends_of_its_e3() {
    let ended = E3id::new("ended", 1);
    let running = E3id::new("running", 1);
    for stage in [E3Stage::Complete, E3Stage::Failed] {
        let (manager, _system) = started_manager();
        // Restart replay delivers the E3's end before the re-broadcast returns its share.
        deliver(&manager, stage_change(&ended, stage), EventSource::Evm, 1).await;

        let scheduled = scheduled_after_shares(&manager, &ended, &running).await;
        assert_eq!(
            scheduled,
            vec![AnnouncementKey::DecryptionShare(running.clone(), 4)],
            "only the share of the running E3 is re-sent"
        );
    }
}

#[actix::test]
async fn a_local_failure_stops_current_resends_but_not_later_ones() {
    let failed_here = E3id::new("failed-here", 1);
    let running = E3id::new("running", 1);
    let local_ends: [InterfoldEventData; 2] = [
        E3Failed {
            e3_id: failed_here.clone(),
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::DecryptionInvalidShares,
        }
        .into(),
        stage_change(&failed_here, E3Stage::Failed).into(),
    ];
    for local_end in local_ends {
        let (manager, _system) = started_manager();
        let (_, share) = local_decryption_share(&failed_here, 4);
        deliver(&manager, share, EventSource::Local, 1).await;
        deliver(&manager, local_end, EventSource::Local, 2).await;
        assert!(
            manager
                .send(ScheduledAnnouncements)
                .await
                .unwrap()
                .is_empty(),
            "the local failure stops the current re-send"
        );

        // The E3 continues on chain, so a share that arrives later is re-sent again.
        let scheduled = scheduled_after_shares(&manager, &failed_here, &running).await;
        assert_eq!(
            scheduled,
            vec![
                AnnouncementKey::DecryptionShare(failed_here.clone(), 4),
                AnnouncementKey::DecryptionShare(running.clone(), 4),
            ]
        );
    }
}

/// Reports whether a running manager has seen local replay finish.
#[derive(Message)]
#[rtype(result = "bool")]
struct LocalReplayFinished;

impl Handler<LocalReplayFinished> for NetSyncManager {
    type Result = bool;
    fn handle(&mut self, _: LocalReplayFinished, _: &mut Self::Context) -> bool {
        self.replay_finished
    }
}

#[actix::test]
async fn no_message_is_resent_before_local_replay_finishes() {
    let (mut manager, mut rx) = ready_manager();
    // Peers connected before local replay finished.
    manager.replay_finished = false;
    let (event, share) = local_decryption_share(&E3id::new("replaying", 1), 4);
    manager.remember_decryption_share(event);

    let start = Instant::now();
    manager.reannounce_due(start + SHARE_REANNOUNCE_BASE);
    assert_nothing_gossiped(
        &mut rx,
        "nothing is re-sent while the replay can still reach the end of the share's E3",
    )
    .await;

    manager.finish_local_replay();
    manager.reannounce_due(start + SHARE_REANNOUNCE_BASE);
    assert_eq!(next_gossiped_share(&mut rx).await, share);
}

#[actix::test]
async fn historical_sync_start_marks_local_replay_finished() {
    let (manager, _system) = started_manager();
    assert!(!manager.send(LocalReplayFinished).await.unwrap());

    deliver(
        &manager,
        HistoricalNetSyncStart::new(BTreeMap::from([(AggregateId::new(1), 0)])),
        EventSource::Local,
        1,
    )
    .await;
    assert!(manager.send(LocalReplayFinished).await.unwrap());
}

/// An event store that answers every query with the same events.
struct ReplyingEventStore(Vec<InterfoldEvent>);
impl Actor for ReplyingEventStore {
    type Context = ActixContext<Self>;
}
impl Handler<EventStoreQueryBy<TsAgg>> for ReplyingEventStore {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<TsAgg>, _: &mut Self::Context) {
        let id = msg.id();
        msg.sender()
            .try_send(EventStoreQueryResponse::from_result(id, Ok(self.0.clone())))
            .expect("the manager accepts the query response");
    }
}

#[actix::test]
async fn the_restart_rebroadcast_leaves_resends_to_replay() {
    let share_then_end = E3id::new("share-then-end", 1);
    let end_then_share = E3id::new("end-then-share", 1);
    let running = E3id::new("running", 1);
    let (early_share, _) = local_decryption_share(&share_then_end, 4);
    let (late_share, _) = local_decryption_share(&end_then_share, 4);
    let (running_share, _) = local_decryption_share(&running, 4);
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, mut rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    // The restart query returns all three shares.
    let eventstore = ReplyingEventStore(vec![
        early_share.clone(),
        late_share.clone(),
        running_share.clone(),
    ]);
    let manager = NetSyncManager::setup(
        &bus,
        &tx,
        &NetEventSubscriber::from(&evt_tx),
        eventstore.start().recipient(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
        false,
    );

    // Replay, in log order: one E3 ends after this node's share, the other before a late share.
    // More chain ends follow than the capped record keeps, so it forgets both ends.
    manager.send(early_share).await.unwrap();
    deliver(
        &manager,
        stage_change(&share_then_end, E3Stage::Complete),
        EventSource::Evm,
        4,
    )
    .await;
    deliver(
        &manager,
        stage_change(&end_then_share, E3Stage::Failed),
        EventSource::Evm,
        5,
    )
    .await;
    manager.send(late_share).await.unwrap();
    for id in 0..MAX_CLOSED_E3S {
        let later = E3id::new(format!("later-{id}"), 1);
        let seq = 6 + id as u64;
        deliver(
            &manager,
            stage_change(&later, E3Stage::Complete),
            EventSource::Evm,
            seq,
        )
        .await;
    }
    manager.send(running_share).await.unwrap();

    // No peer is configured, so the node is ready. Replay ends and the re-broadcast runs.
    manager
        .send(AllPeersDialed {
            connected: 0,
            total: 0,
        })
        .await
        .unwrap();
    deliver(
        &manager,
        HistoricalNetSyncStart::new(BTreeMap::from([(AggregateId::new(1), 0)])),
        EventSource::Local,
        2_000,
    )
    .await;
    // The historical sync also asks peers for history; count only the re-sent shares.
    let mut resent = 0;
    while resent < 3 {
        let command = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for the re-broadcast")
            .expect("network command channel closed");
        if matches!(command, NetCommand::GossipPublish { .. }) {
            resent += 1;
        }
    }

    assert_eq!(
        manager.send(ScheduledAnnouncements).await.unwrap(),
        vec![AnnouncementKey::DecryptionShare(running, 4)],
        "the re-broadcast sends each share once; only replay schedules re-sends"
    );
}

#[actix::test]
async fn restart_rebroadcast_skips_the_messages_of_an_ended_e3() {
    let (mut manager, mut rx) = ready_manager();
    let ended = E3id::new("ended", 1);
    let running = E3id::new("running", 1);
    manager.mark_e3_ended(&ended);
    let (ended_share, _) = local_decryption_share(&ended, 4);
    let ended_ready = DkgCoordination {
        e3_id: ended.clone(),
        interfold_address: Default::default(),
        party_id: 4,
        kind: DkgCoordinationKind::Ready,
        dealers: vec![],
        signature: ArcBytes::from_bytes(&[]),
    };
    let ended_ready = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        ended_ready.into(),
        None,
        21,
        None,
        EventSource::Local,
    )
    .into_sequenced(4);
    let (running_share, share) = local_decryption_share(&running, 4);

    manager.handle_rebroadcast_response(vec![ended_share, ended_ready, running_share]);

    assert_eq!(next_gossiped_share(&mut rx).await, share);
    assert_nothing_gossiped(
        &mut rx,
        "the share and the Ready message of the ended E3 are not re-sent",
    )
    .await;
    assert!(
        manager.announcements.is_empty(),
        "the re-broadcast schedules no re-send"
    );
}

#[actix::test]
async fn remote_decryption_shares_and_expired_messages_are_not_resent() {
    let (mut manager, mut rx) = ready_manager();
    let e3_id = E3id::new("remote", 1);
    let (event, _) = local_decryption_share(&e3_id, 3);
    manager.remember_decryption_share(event.clone().with_source(EventSource::Net));
    manager.reannounce_due(Instant::now() + SHARE_REANNOUNCE_BASE);
    assert!(
        rx.try_recv().is_err(),
        "a peer's share is not re-sent by this node"
    );

    manager.remember_decryption_share(event);
    manager.reannounce_due(Instant::now() + REANNOUNCE_LIFETIME);
    assert!(
        rx.try_recv().is_err(),
        "a message past its lifetime is dropped"
    );
}

#[actix::test]
async fn malicious_huge_limit_is_capped_before_storage_query() {
    let (query_tx, mut query_rx) = mpsc::unbounded_channel();
    let (manager, _net_rx) = manager_with_recording_store(query_tx);
    let net_tx = manager.tx.clone();
    let manager = manager.start();

    manager
        .send(incoming_sync_request(
            PeerId::random(),
            1,
            usize::MAX,
            &net_tx,
        ))
        .await
        .unwrap();

    let queried_bounds = tokio::time::timeout(Duration::from_secs(1), query_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        queried_bounds,
        (
            Some(sync_scan_limit(usize::MAX) as u64),
            Some(MAX_SYNC_SCAN_BYTES),
            true,
        )
    );
}

#[actix::test]
async fn concurrent_sync_requests_are_globally_bounded() {
    let (query_tx, mut query_rx) = mpsc::unbounded_channel();
    let (manager, mut net_rx) = manager_with_recording_store(query_tx);
    let net_tx = manager.tx.clone();
    let manager = manager.start();

    for id in 0..MAX_IN_FLIGHT_SYNC_REQUESTS as u64 {
        manager
            .send(incoming_sync_request(PeerId::random(), id, 1, &net_tx))
            .await
            .unwrap();
    }
    manager
        .send(incoming_sync_request(
            PeerId::random(),
            MAX_IN_FLIGHT_SYNC_REQUESTS as u64,
            1,
            &net_tx,
        ))
        .await
        .unwrap();

    for _ in 0..MAX_IN_FLIGHT_SYNC_REQUESTS {
        tokio::time::timeout(Duration::from_secs(1), query_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        query_rx.try_recv().is_err(),
        "overflow request reached storage"
    );
    let response = tokio::time::timeout(Duration::from_secs(1), net_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        protocol_response(response),
        ProtocolResponse::BadRequest(reason) if reason.contains("too many in-flight")
    ));
}

#[actix::test]
async fn concurrent_sync_requests_are_bounded_per_authenticated_peer() {
    let (query_tx, mut query_rx) = mpsc::unbounded_channel();
    let (manager, mut net_rx) = manager_with_recording_store(query_tx);
    let net_tx = manager.tx.clone();
    let manager = manager.start();
    let peer = PeerId::random();

    for id in 0..=MAX_IN_FLIGHT_SYNC_REQUESTS_PER_PEER as u64 {
        manager
            .send(incoming_sync_request(peer, id, 1, &net_tx))
            .await
            .unwrap();
    }

    for _ in 0..MAX_IN_FLIGHT_SYNC_REQUESTS_PER_PEER {
        tokio::time::timeout(Duration::from_secs(1), query_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        query_rx.try_recv().is_err(),
        "per-peer overflow reached storage"
    );
    let response = tokio::time::timeout(Duration::from_secs(1), net_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        protocol_response(response),
        ProtocolResponse::BadRequest(reason) if reason.contains("this peer")
    ));
}

#[actix::test]
async fn timed_out_sync_request_releases_its_in_flight_slot() {
    let (query_tx, _query_rx) = mpsc::unbounded_channel();
    let (mut manager, mut net_rx) = manager_with_recording_store(query_tx);
    let net_tx = manager.tx.clone();
    let peer = PeerId::random();
    let IncomingRequest { responder, .. } = incoming_sync_request(peer, 1, 1, &net_tx);
    let id = CorrelationId::new();
    manager
        .requests
        .insert(id, PendingSyncRequest { peer, responder });

    manager.expire_sync_request(id);

    assert!(manager.requests.is_empty());
    let response = tokio::time::timeout(Duration::from_secs(1), net_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        protocol_response(response),
        ProtocolResponse::Error(reason) if reason.contains("timed out")
    ));
}

/// Starts a manager with no peer, then asks it for the history of an open aggregate. Returns the
/// wait for the history and the receiver of the fetch failure.
fn start_history_fetch_without_peers(
    peer_history_optional: bool,
) -> (
    impl std::future::Future<Output = anyhow::Result<InterfoldEvent<Sequenced>>>,
    tokio::sync::oneshot::Receiver<HistoricalNetSyncFailed>,
) {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, rx) = mpsc::channel::<NetCommand>(100);
    let evt_tx = NetEventChannel::new(100);
    let _evt_rx = evt_tx.subscribe();
    NetSyncManager::setup(
        &bus,
        &tx,
        &NetEventSubscriber::from(&evt_tx),
        NoopEventStore.start().recipient(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
        peer_history_optional,
    );
    let (failure, failed) = e3_utils::actix::channel::oneshot::<HistoricalNetSyncFailed>();
    let received = bus.wait_for(EventType::HistoricalNetSyncEventsReceived);
    bus.publish_without_context(
        HistoricalNetSyncStart::new(BTreeMap::from([(AggregateId::new(1), 0)]))
            .with_failure_recipient(failure),
    )
    .unwrap();
    let received = async move {
        // Keep the channels and the system alive until the caller has its answer.
        let _keep = (system, tx, rx, evt_tx);
        received.await
    };
    (received, failed)
}

#[actix::test]
async fn optional_peer_history_lets_startup_continue_when_no_peer_serves_it() {
    tokio::time::pause();
    let (received, mut failed) = start_history_fetch_without_peers(true);
    let received = tokio::time::timeout(Duration::from_secs(10 * 60), received)
        .await
        .expect("startup must not wait for history that no peer serves")
        .unwrap();
    let InterfoldEventData::HistoricalNetSyncEventsReceived(history) = received.into_data() else {
        panic!("expected the historical net events");
    };
    assert!(history.events.is_empty());
    assert!(
        failed.try_recv().is_err(),
        "an optional history fetch must not report a failure to startup"
    );
}

#[actix::test]
async fn required_peer_history_failure_is_returned_to_startup() {
    tokio::time::pause();
    let (received, failed) = start_history_fetch_without_peers(false);
    let failed = tokio::time::timeout(Duration::from_secs(10 * 60), failed)
        .await
        .expect("startup must learn that no peer served the required history")
        .expect("the failure must reach startup");
    assert!(
        failed
            .reason
            .contains("No peer connections established within timeout"),
        "unexpected failure reason: {}",
        failed.reason
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(10 * 60), received)
            .await
            .is_err(),
        "a full node must not continue without the history of its open E3s"
    );
}
