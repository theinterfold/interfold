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
use actix::{Actor, Context as ActixContext, Handler};
use e3_ciphernode_builder::EventSystem;
use e3_config::NetworkProfile;
use e3_events::{E3id, EventSource, InterfoldEvent, KeyshareCreated, TestEvent, Unsequenced};
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
    queries: UnboundedSender<Option<u64>>,
}

impl Actor for RecordingEventStore {
    type Context = ActixContext<Self>;
}

impl Handler<EventStoreQueryBy<TsAgg>> for RecordingEventStore {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<TsAgg>, _: &mut Self::Context) {
        let _ = self.queries.send(msg.limit());
        // Intentionally retain no response. Tests exercise the manager's in-flight bounds.
    }
}

fn manager_with_recording_store(
    query_tx: UnboundedSender<Option<u64>>,
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
        false,
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

/// A node whose only bootstrap peer is unreachable still publishes `NetReady`
/// through the connect-timeout fallback. Historical sync must then complete the
/// phase instead of attempting fetches that can only fail: the failure path
/// `bail!`s into an error event rather than a completion, so startup would wait
/// on a `SyncRequestSucceeded` that never arrives and exit at
/// `startup_timeout_secs` — a crash loop on every restart.
#[actix::test]
async fn no_connected_peers_completes_sync_instead_of_hanging_startup() {
    let (net_tx, mut net_rx) = mpsc::channel::<NetCommand>(1);
    let (event_tx, _event_rx) = broadcast::channel::<NetEvent>(1);
    let event_rx = NetEventSubscriber::from(&event_tx);
    let (response_tx, response_rx) =
        e3_utils::actix::channel::oneshot::<TypedEvent<SyncRequestSucceeded>>();
    // A real, peer-syncable chain aggregate — not the local aggregate 0.
    let start = HistoricalNetSyncStart::new(BTreeMap::from([(AggregateId::new(31_337), 10)]));
    let context: e3_events::EventContext<Unsequenced> =
        InterfoldEventData::HistoricalNetSyncStart(start.clone()).into();

    handle_sync_request_event(
        net_tx,
        event_rx,
        TypedEvent::new(start, context.sequence(1)),
        response_tx,
        // AllPeersDialed already observed, so the function does not wait...
        false,
        // ...but no connection was ever established.
        false,
        NetworkPolicy::local_unrestricted(),
    )
    .await
    .expect("sync must complete rather than bail when no peers are connected");

    let response = response_rx.await.unwrap().into_inner().response;
    assert!(response.events.is_empty());
    assert_eq!(response.ts, 0);
    assert!(
        net_rx.try_recv().is_err(),
        "no outbound peer request should be attempted without a connected peer"
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

    let queried_limit = tokio::time::timeout(Duration::from_secs(1), query_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queried_limit, Some(sync_scan_limit(usize::MAX) as u64));
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
