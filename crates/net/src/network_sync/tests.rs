// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    direct_responder::ChannelType,
    events::{IncomingRequest, NetCommand},
};
use actix::{Actor, Context as ActixContext, Handler, Message, MessageResult};
use e3_ciphernode_builder::EventSystem;
use e3_config::NetworkProfile;
use e3_events::{
    AggregateConfig, DecryptionshareCreated, DkgCoordination, DkgCoordinationKind, DkgDealer, E3id,
    EventSource, InterfoldEvent, KeyshareCreated, TestEvent, Unsequenced,
};
use e3_utils::ArcBytes;
use tokio::sync::{broadcast, mpsc, mpsc::UnboundedSender};

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
    queries: UnboundedSender<(Option<u64>, Option<u64>)>,
}

impl Actor for RecordingEventStore {
    type Context = ActixContext<Self>;
}

impl Handler<EventStoreQueryBy<TsAgg>> for RecordingEventStore {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<TsAgg>, _: &mut Self::Context) {
        let _ = self.queries.send((msg.limit(), msg.max_bytes()));
        // Intentionally retain no response. Tests exercise the manager's in-flight bounds.
    }
}

fn manager_with_recording_store(
    query_tx: UnboundedSender<(Option<u64>, Option<u64>)>,
) -> (NetSyncManager, mpsc::Receiver<NetCommand>) {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle().unwrap().enable("test");
    let (tx, rx) = mpsc::channel::<NetCommand>(100);
    let (evt_tx, _evt_rx) = broadcast::channel::<NetEvent>(100);
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
    let (event_tx, _event_rx) = broadcast::channel::<NetEvent>(1);
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
    let (evt_tx, _evt_rx) = broadcast::channel::<NetEvent>(100);
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
    let (evt_tx, _evt_rx) = broadcast::channel::<NetEvent>(100);
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
        manager.remember_dkg_coordination(event, &message);
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
    let (evt_tx, _evt_rx) = broadcast::channel::<NetEvent>(100);
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
    let (evt_tx, _evt_rx) = broadcast::channel::<NetEvent>(100);
    let manager = NetSyncManager::setup(
        &bus,
        &tx,
        &NetEventSubscriber::from(&evt_tx),
        NoopEventStore.start().recipient(),
        "my-topic",
        NetworkPolicy::local_unrestricted(),
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
    manager.remember_decryption_share(event, &share);

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
    manager.remember_decryption_share(event, &share);
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
    manager.remember_dkg_coordination(ready_event, &ready);

    manager.forget_dkg_coordination(&e3_id);
    manager.reannounce_due(Instant::now() + SHARE_REANNOUNCE_BASE);
    assert_eq!(next_gossiped_share(&mut rx).await, share);
    assert!(rx.try_recv().is_err(), "the DKG message was forgotten");
}

#[actix::test]
async fn remote_decryption_shares_and_expired_messages_are_not_resent() {
    let (mut manager, mut rx) = ready_manager();
    let e3_id = E3id::new("remote", 1);
    let (event, share) = local_decryption_share(&e3_id, 3);
    manager.remember_decryption_share(event.clone().with_source(EventSource::Net), &share);
    manager.reannounce_due(Instant::now() + SHARE_REANNOUNCE_BASE);
    assert!(
        rx.try_recv().is_err(),
        "a peer's share is not re-sent by this node"
    );

    manager.remember_decryption_share(event, &share);
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
