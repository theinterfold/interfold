// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, AsyncContext, Handler, Message, Recipient, ResponseFuture};
use anyhow::{bail, Context, Result};
use e3_events::{
    prelude::*, trap, trap_fut, AggregateId, BusHandle, CorrelationId, E3id, EType, EventSource,
    EventStoreFilter, EventStoreQueryBy, EventStoreQueryResponse, EventType,
    HistoricalNetSyncEventsReceived, HistoricalNetSyncStart, InterfoldEvent, InterfoldEventData,
    NetReady, PublishDocumentRequested, TsAgg, TypedEvent, Unsequenced,
};
use e3_utils::MAILBOX_LIMIT;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    actors::handle_publish_document_requested,
    direct_requester::DirectRequester,
    direct_responder::DirectResponder,
    domain::{
        build_sync_batch,
        net_event_batch::{fetch_all_batched_events, FetchEventsSince},
        EventConversionService, EventTranslationService, NetReadiness, ReadinessDecision,
        SyncBatchOutcome,
    },
    events::{await_event, GossipData, IncomingRequest, NetCommand, NetEvent, PeerTarget},
};

/// Maximum time to wait for a `ConnectionEstablished` event after all dials
/// failed before publishing `NetReady` anyway.
const NET_READY_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Direct-request retry settings for a single historical sync fetch attempt.
const SYNC_FETCH_MAX_RETRIES: u32 = 3;
const SYNC_FETCH_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// If a historical sync fetch fails, wait this long for a fresh connection
/// before retrying anyway against currently connected peers.
const SYNC_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// Number of recovery rounds to try for failed aggregates after the initial fetch pass.
/// 20 rounds × 15s interval = 300s (5 min) recovery window — enough for P2P bootstrap
/// after a single-node restart even on slow networks.
const SYNC_RECOVERY_MAX_ATTEMPTS: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponseValue {
    pub events: Vec<InterfoldEvent<Unsequenced>>,
    pub ts: u128,
}

impl TryInto<Vec<u8>> for SyncResponseValue {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        bincode::serialize(&self).context("failed to serialize sync response")
    }
}

impl TryFrom<Vec<u8>> for SyncResponseValue {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::deserialize(&value).context("failed to deserialize sync response")
    }
}

#[derive(Debug, Clone)]
pub struct SyncRequestSucceeded {
    pub response: SyncResponseValue,
}

pub struct NetSyncManager {
    /// Interfold EventBus
    bus: BusHandle,
    /// NetCommand sender to forward commands to the Libp2pNetInterface
    tx: mpsc::Sender<NetCommand>,
    /// NetEvents receiver to receive events
    rx: Arc<broadcast::Receiver<NetEvent>>,
    eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
    requests: HashMap<CorrelationId, DirectResponder>,
    /// Pure readiness state machine.
    readiness: NetReadiness,
    /// Gossipsub topic used to re-broadcast our own forwardable artifacts after a restart.
    topic: String,
    /// Snapshot-cursor map captured from `HistoricalNetSyncStart`. Bounds the post-restart
    /// re-broadcast query to the in-flight (un-snapshotted) window.
    rebroadcast_since: Option<HashMap<AggregateId, u128>>,
    /// Correlation ids of in-flight re-broadcast EventStore queries, so their responses can be
    /// distinguished from ordinary sync-request responses.
    rebroadcast_query_ids: HashSet<CorrelationId>,
    /// Set once `NetReady` has been published (peers connected or fallback timeout elapsed).
    net_ready: bool,
    /// Guard so the post-restart re-broadcast fires at most once per process.
    rebroadcast_started: bool,
    /// In-flight EventStore queries answering a peer's `DkgDocumentResyncRequest`, mapped to the
    /// requested E3 so the response re-announces only that E3's document artifacts.
    resync_query_e3: HashMap<CorrelationId, E3id>,
}

impl NetSyncManager {
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        topic: &str,
    ) -> Self {
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            rx: Arc::clone(rx),
            eventstore,
            requests: HashMap::new(),
            readiness: NetReadiness::new(),
            topic: topic.to_string(),
            rebroadcast_since: None,
            rebroadcast_query_ids: HashSet::new(),
            net_ready: false,
            rebroadcast_started: false,
            resync_query_e3: HashMap::new(),
        }
    }

    fn publish_net_ready(&self) -> Result<()> {
        info!("NetSyncManager: publishing NetReady");
        self.bus.publish_without_context(NetReady::new())?;
        Ok(())
    }

    /// After a restart, proactively re-emit this node's own already-produced DKG artifacts
    /// (H3/H11). Resume from a persisted phase is otherwise passive: the restored
    /// keyshare/aggregator actors wait for peer documents and never re-emit their own outputs, so
    /// peers that missed the original broadcast (cache expiry, DHT miss, peer churn, a crash mid-
    /// broadcast) can stall the node to its phase timeout.
    ///
    /// Two channels are covered, both bounded to the snapshot-cursor window so only the in-flight
    /// (un-delivered) artifacts are re-sent:
    ///   * Gossip artifacts (`KeyshareCreated`, `DecryptionshareCreated`, `PublicKeyAggregated`,
    ///     …) are sent straight to libp2p as `GossipPublish`, bypassing both the EventBus dedup
    ///     bloom (which already tracked them during replay) and the translator (which is only
    ///     created on `EffectsEnabled`).
    ///   * Document artifacts — the DKG share exchange (`EncryptionKeyCreated`,
    ///     `ThresholdShareCreated`, `DecryptionKeyShared`) — travel over the DHT, not gossip, so
    ///     they are re-PUT to the DHT and their publish notification re-broadcast via the same
    ///     path the live `DocumentPublisher` uses.
    ///
    /// Re-emitting the byte-identical original payload is equivocation-safe and idempotent: peers
    /// dedup gossip by event id and document shares by sender `party_id`, and the DHT key is the
    /// content hash so a re-PUT overwrites with the same record.
    fn maybe_rebroadcast_own_artifacts(&mut self, ctx: &mut actix::Context<Self>) {
        if self.rebroadcast_started || !self.net_ready {
            return;
        }
        let Some(since) = self.rebroadcast_since.clone() else {
            return;
        };
        self.rebroadcast_started = true;

        let id = CorrelationId::new();
        self.rebroadcast_query_ids.insert(id);
        info!("NetSyncManager: querying own forwardable artifacts for post-restart re-broadcast");
        if let Err(e) = self.eventstore.try_send(
            EventStoreQueryBy::<TsAgg>::new(id, since, ctx.address().recipient())
                .with_filter(EventStoreFilter::Source(EventSource::Local)),
        ) {
            error!("Failed to query EventStore for re-broadcast: {e}");
            self.rebroadcast_query_ids.remove(&id);
            self.rebroadcast_started = false;
        }
    }

    /// Build a document re-publish request for one of this node's own DKG share-exchange
    /// artifacts (the DHT-channel counterpart to gossip re-broadcast). Returns `None` for
    /// non-document events; the conversion itself returns `None` for externally-sourced
    /// artifacts, so peer documents are never re-published even if they slip the source filter.
    fn own_document_request(event: &InterfoldEvent) -> Option<PublishDocumentRequested> {
        match event.get_data() {
            InterfoldEventData::ThresholdShareCreated(d) => {
                EventConversionService::threshold_share_to_request(d.clone())
                    .ok()
                    .flatten()
            }
            InterfoldEventData::EncryptionKeyCreated(d) => {
                EventConversionService::encryption_key_to_request(d.clone())
                    .ok()
                    .flatten()
            }
            InterfoldEventData::DecryptionKeyShared(d) => {
                EventConversionService::decryption_key_to_request(d.clone())
                    .ok()
                    .flatten()
            }
            _ => None,
        }
    }

    /// A peer is resuming an in-flight DKG and asked us to re-announce our DKG documents for
    /// `e3_id`. Query our own `EventSource::Local` events (unbounded — `since` 0) for that E3's
    /// chain and re-PUT/re-notify the document artifacts, so the rejoining node can fetch the shares
    /// whose original (ephemeral) notifications it missed while down.
    fn handle_resync_request(&mut self, e3_id: E3id, ctx: &mut actix::Context<Self>) {
        let id = CorrelationId::new();
        self.resync_query_e3.insert(id, e3_id.clone());
        let since: HashMap<AggregateId, u128> =
            HashMap::from([(AggregateId::from_chain_id(Some(e3_id.chain_id())), 0u128)]);
        info!("NetSyncManager: peer requested DKG document resync for {e3_id}; re-announcing our documents");
        if let Err(e) = self.eventstore.try_send(
            EventStoreQueryBy::<TsAgg>::new(id, since, ctx.address().recipient())
                .with_filter(EventStoreFilter::Source(EventSource::Local)),
        ) {
            error!("Failed to query EventStore for resync response: {e}");
            self.resync_query_e3.remove(&id);
        }
    }

    /// Respond to a peer's resync for `e3_id` by re-emitting our own artifacts for it on **both**
    /// channels: forwardable gossip artifacts (e.g. `DKGRecursiveAggregationComplete`,
    /// `KeyshareCreated`) are re-gossiped, and DKG share documents are re-PUT/re-notified. A node
    /// rejoining mid-DKG can miss either kind, so both must be re-delivered.
    fn handle_resync_response(&mut self, e3_id: E3id, events: Vec<InterfoldEvent>) {
        let mut doc_count = 0usize;
        let mut gossip_count = 0usize;
        for event in events {
            // Forwardable gossip artifacts for this E3 — re-gossip straight to libp2p.
            if EventTranslationService::is_forwardable_event(&event) {
                if event.get_e3_id().as_ref() != Some(&e3_id) {
                    continue;
                }
                match GossipData::try_from(event) {
                    Ok(data) => {
                        if let Err(e) = self.tx.try_send(NetCommand::GossipPublish {
                            topic: self.topic.clone(),
                            data,
                            correlation_id: CorrelationId::new(),
                        }) {
                            warn!("Failed to re-gossip artifact for resync: {e}");
                        } else {
                            gossip_count += 1;
                        }
                    }
                    Err(e) => warn!("Failed to convert artifact to gossip data for resync: {e}"),
                }
                continue;
            }
            // DKG share documents — re-PUT to the DHT and re-notify.
            let Some(request) = Self::own_document_request(&event) else {
                continue;
            };
            if request.meta.e3_id != e3_id {
                continue;
            }
            let tx = self.tx.clone();
            let rx = self.rx.clone();
            let bus = self.bus.clone();
            let topic = self.topic.clone();
            actix::spawn(async move {
                if let Err(e) = handle_publish_document_requested(tx, rx, request, topic, bus).await
                {
                    warn!("Failed to re-announce DKG document for resync: {e}");
                }
            });
            doc_count += 1;
        }
        info!("NetSyncManager: re-announced {doc_count} document(s) and re-gossiped {gossip_count} artifact(s) for {e3_id} resync");
    }

    /// Re-emit the node's own artifacts returned by the re-broadcast query: gossip artifacts go
    /// straight to libp2p; DKG document shares are re-PUT to the DHT and re-notified.
    fn handle_rebroadcast_response(&mut self, events: Vec<InterfoldEvent>) {
        let mut gossip_count = 0usize;
        let mut doc_count = 0usize;
        for event in events {
            // Gossip-channel artifacts: re-gossip the byte-identical payload straight to libp2p.
            if EventTranslationService::is_forwardable_event(&event) {
                let data: GossipData = match event.try_into() {
                    Ok(data) => data,
                    Err(e) => {
                        warn!("Failed to convert own artifact to gossip data: {e}");
                        continue;
                    }
                };
                if let Err(e) = self.tx.try_send(NetCommand::GossipPublish {
                    topic: self.topic.clone(),
                    data,
                    correlation_id: CorrelationId::new(),
                }) {
                    warn!("Failed to re-broadcast own artifact (channel full or closed): {e}");
                } else {
                    gossip_count += 1;
                }
                continue;
            }

            // Document-channel artifacts (the DKG share exchange): re-PUT to the DHT and
            // re-broadcast the publish notification so peers that missed the original (crash mid-
            // broadcast, DHT miss, peer churn) can fetch our share and stop waiting on us.
            if let Some(request) = Self::own_document_request(&event) {
                let tx = self.tx.clone();
                let rx = self.rx.clone();
                let bus = self.bus.clone();
                let topic = self.topic.clone();
                actix::spawn(async move {
                    if let Err(e) =
                        handle_publish_document_requested(tx, rx, request, topic, bus).await
                    {
                        warn!("Failed to re-publish own DKG document after restart: {e}");
                    }
                });
                doc_count += 1;
            }
        }
        info!(
            "NetSyncManager: re-broadcast {gossip_count} gossip and {doc_count} document artifact(s) after restart"
        );
    }

    /// Apply a readiness decision: publish `NetReady`, or schedule the fallback timeout.
    fn apply_readiness(&mut self, decision: ReadinessDecision, ctx: &mut actix::Context<Self>) {
        match decision {
            ReadinessDecision::PublishReady => {
                if let Err(e) = self.publish_net_ready() {
                    error!("Failed to publish NetReady: {e}");
                }
                self.net_ready = true;
                self.maybe_rebroadcast_own_artifacts(ctx);
            }
            ReadinessDecision::WaitForConnection => {
                info!(
                    "All peer dials failed, waiting for connections before publishing NetReady..."
                );
                ctx.run_later(NET_READY_CONNECT_TIMEOUT, move |this, ctx| {
                    if let ReadinessDecision::PublishReady = this.readiness.on_connect_timeout() {
                        warn!("No peer connections established within 60s timeout, publishing NetReady anyway");
                        if let Err(e) = this.publish_net_ready() {
                            error!("Failed to publish NetReady: {e}");
                        }
                        this.net_ready = true;
                        this.maybe_rebroadcast_own_artifacts(ctx);
                    }
                });
            }
            ReadinessDecision::Idle => {}
        }
    }

    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        topic: &str,
    ) -> Addr<Self> {
        let mut events = rx.resubscribe();
        let addr = Self::new(bus, tx, rx, eventstore, topic).start();

        bus.subscribe(EventType::HistoricalNetSyncStart, addr.clone().recipient());
        bus.subscribe(
            EventType::DkgDocumentResyncRequest,
            addr.clone().recipient(),
        );

        // Forward from NetEvent
        tokio::spawn({
            debug!("Spawning event receive loop!");
            let addr = addr.clone();
            async move {
                while let Ok(event) = events.recv().await {
                    debug!("Received event {:?}", event);
                    match event {
                        // Someone is asking for our sync
                        NetEvent::IncomingRequest(value) => addr.do_send(value),
                        NetEvent::AllPeersDialed { connected, total } => {
                            addr.do_send(AllPeersDialed { connected, total })
                        }
                        NetEvent::ConnectionEstablished { .. } => addr.do_send(PeerConnected),
                        _ => (),
                    }
                }
            }
        });

        addr
    }
}

impl Actor for NetSyncManager {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

/// Event broadcast from event bus
impl Handler<InterfoldEvent> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let source = msg.source();
        // Our own resync request: push it straight to libp2p. NetSyncManager exists from process
        // start, so this is reliable regardless of when the gossip translator is created during boot
        // (the translator also gossips it once up; receivers dedup by event id).
        if source == EventSource::Local {
            if let InterfoldEventData::DkgDocumentResyncRequest(_) = msg.get_data() {
                match GossipData::try_from(msg.clone()) {
                    Ok(data) => {
                        if let Err(e) = self.tx.try_send(NetCommand::GossipPublish {
                            topic: self.topic.clone(),
                            data,
                            correlation_id: CorrelationId::new(),
                        }) {
                            warn!("Failed to gossip DkgDocumentResyncRequest: {e}");
                        }
                    }
                    Err(e) => warn!("Failed to convert DkgDocumentResyncRequest to gossip: {e}"),
                }
            }
        }

        let (msg, ec) = msg.into_components();
        match msg {
            // We are making a sync request of another node
            InterfoldEventData::HistoricalNetSyncStart(data) => {
                // Capture the snapshot-cursor map so we can bound the post-restart re-broadcast of
                // our own forwardable artifacts to the in-flight window (H3/H11).
                self.rebroadcast_since = Some(data.since.clone().into_iter().collect());
                self.maybe_rebroadcast_own_artifacts(ctx);
                ctx.notify(TypedEvent::new(data, ec))
            }
            // A DKG resync request — re-announce our own documents for the E3 byte-identically.
            // Fires for both a peer's request (we are a committee member with shares it needs) and
            // our own request on resume (so peers waiting on us re-receive our shares). The Local
            // copy was also gossiped out above so peers re-announce theirs to us.
            InterfoldEventData::DkgDocumentResyncRequest(data) => {
                self.handle_resync_request(data.e3_id, ctx);
            }
            _ => {}
        }
    }
}

/// SyncRequest is called on start up to fetch remote events
impl Handler<TypedEvent<HistoricalNetSyncStart>> for NetSyncManager {
    type Result = ResponseFuture<()>;
    fn handle(
        &mut self,
        msg: TypedEvent<HistoricalNetSyncStart>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        info!("HISTORICAL_NET_SYNC_START");
        trap_fut(
            EType::Net,
            &self.bus.with_ec(msg.get_ctx()),
            handle_sync_request_event(
                self.tx.clone(),
                self.rx.clone(),
                msg,
                ctx.address(),
                !self.readiness_all_peers_dialed(),
            ),
        )
    }
}

impl NetSyncManager {
    fn readiness_all_peers_dialed(&self) -> bool {
        // `handle_sync_request_event` waits for a connection only if we have not yet observed the
        // AllPeersDialed signal. The readiness machine tracks this; mirror its view here.
        self.readiness.all_peers_dialed()
    }
}

/// We have received the sync response from the remote peer
impl Handler<TypedEvent<SyncRequestSucceeded>> for NetSyncManager {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<SyncRequestSucceeded>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Net, &self.bus.with_ec(msg.get_ctx()), || {
            info!("SYNC REQUEST SUCCEEDED");
            let (msg, ctx) = msg.into_components();
            let response = msg.response;
            self.bus.publish_from_remote_as_response(
                HistoricalNetSyncEventsReceived {
                    events: response.events.to_vec(),
                },
                response.ts,
                ctx,
                None,
                EventSource::Net,
            )?;

            Ok(())
        });
    }
}

/// We have received a sync request from a remote peer
impl Handler<IncomingRequest> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, msg: IncomingRequest, ctx: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus, || {
            let id = CorrelationId::new();
            info!("Processing incoming request with correlation={}", id);
            let fetch_request: FetchEventsSince = msg.responder.try_request_into()?;
            self.requests.insert(id, msg.responder);
            let query: HashMap<AggregateId, u128> =
                HashMap::from([(fetch_request.aggregate_id(), fetch_request.since())]);
            self.eventstore.try_send(EventStoreQueryBy::<TsAgg>::new(
                id,
                query,
                ctx.address().recipient(),
            ))?;
            Ok(())
        });
    }
}

/// Receive Events from EventStore
impl Handler<EventStoreQueryResponse> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryResponse, _: &mut Self::Context) -> Self::Result {
        // Response to a peer's DkgDocumentResyncRequest — re-announce our docs for that E3.
        if let Some(e3_id) = self.resync_query_e3.remove(&msg.id()) {
            self.handle_resync_response(e3_id, msg.into_events());
            return;
        }
        // Post-restart re-broadcast response (own forwardable artifacts) — handled separately from
        // peer sync-request responses.
        if self.rebroadcast_query_ids.remove(&msg.id()) {
            self.handle_rebroadcast_response(msg.into_events());
            return;
        }
        trap(EType::Net, &self.bus.clone(), || {
            info!("Received response from eventstore.");
            let Some(responder) = self.requests.remove(&msg.id()) else {
                bail!("responder not found for {}", msg.id());
            };

            let fetch_request: FetchEventsSince = responder.try_request_into()?;
            match build_sync_batch(msg.into_events(), &fetch_request) {
                SyncBatchOutcome::BadRequest(reason) => responder.bad_request(reason)?,
                SyncBatchOutcome::Batch(batch) => responder.ok(batch)?,
            }

            Ok(())
        })
    }
}

impl Handler<AllPeersDialed> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, msg: AllPeersDialed, ctx: &mut Self::Context) -> Self::Result {
        info!(
            "NetSyncManager: AllPeersDialed (connected={}, total={})",
            msg.connected, msg.total
        );
        let decision = self.readiness.on_all_peers_dialed(msg.connected, msg.total);
        self.apply_readiness(decision, ctx);
    }
}

impl Handler<PeerConnected> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, _: PeerConnected, ctx: &mut Self::Context) -> Self::Result {
        let decision = self.readiness.on_peer_connected();
        if let ReadinessDecision::PublishReady = decision {
            info!("NetSyncManager: first peer connected");
        }
        self.apply_readiness(decision, ctx);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct AllPeersDialed {
    connected: usize,
    total: usize,
}

#[derive(Message)]
#[rtype(result = "()")]
struct PeerConnected;

async fn fetch_historical_events_for_aggregate(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &Arc<broadcast::Receiver<NetEvent>>,
    aggregate_id: AggregateId,
    since: u128,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
        .max_retries(SYNC_FETCH_MAX_RETRIES)
        .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
        .build();

    fetch_all_batched_events::<InterfoldEvent<Unsequenced>>(
        requester,
        PeerTarget::Random,
        aggregate_id,
        since,
        100,
    )
    .await
}

async fn handle_sync_request_event(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: Arc<broadcast::Receiver<NetEvent>>,
    event: TypedEvent<HistoricalNetSyncStart>,
    address: impl Into<Recipient<TypedEvent<SyncRequestSucceeded>>>,
    wait_for_event: bool,
) -> Result<()> {
    info!("Sync request event received");
    let (event, ctx) = event.into_components();
    info!("Checking for AllPeersDialed...");
    if wait_for_event {
        info!("Waiting for peer connection...");
        let has_peers = await_event(
            &net_events,
            |e| match e {
                NetEvent::ConnectionEstablished { .. } => {
                    info!("Peer connection established");
                    Some(true)
                }
                NetEvent::AllPeersDialed { total: 0, .. } => {
                    info!("No peers configured, proceeding without sync");
                    Some(false)
                }
                _ => None,
            },
            NET_READY_CONNECT_TIMEOUT,
        )
        .await
        .context("No peer connections established within timeout")?;

        if !has_peers {
            let value = SyncRequestSucceeded {
                response: SyncResponseValue {
                    events: vec![],
                    ts: 0,
                },
            };

            address.into().try_send(TypedEvent::new(value, ctx))?;
            return Ok(());
        }
    }
    info!("handle_sync_request_event: ready to sync");

    let mut all_events: Vec<InterfoldEvent<Unsequenced>> = Vec::new();
    let mut latest_timestamp: u128 = 0;
    let mut failed_aggregates: Vec<AggregateId> = Vec::new();

    for (aggregate_id, since) in event.since.iter() {
        info!(
            "Requesting batched events for aggregate_id={} since={}",
            aggregate_id, since
        );
        match fetch_historical_events_for_aggregate(&net_cmds, &net_events, *aggregate_id, *since)
            .await
        {
            Ok(events) => {
                info!(
                    "Received {} events for aggregate_id={}",
                    events.len(),
                    aggregate_id
                );
                for interfold_event in events {
                    let ts = interfold_event.ts();
                    if ts > latest_timestamp {
                        latest_timestamp = ts;
                    }
                    all_events.push(interfold_event);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to fetch events for aggregate_id={}: {e}. Continuing with available events.",
                    aggregate_id
                );
                failed_aggregates.push(*aggregate_id);
            }
        }
    }

    // If any aggregate failed, retry a few recovery rounds. Prefer a fresh
    // ConnectionEstablished signal when one arrives, but do not depend on it:
    // a connected peer may simply be slow or temporarily stalled.
    if !failed_aggregates.is_empty() {
        info!(
            "Sync fetch failed for {} aggregates — starting recovery retries...",
            failed_aggregates.len()
        );
        let mut recovery_attempt = 0;

        while !failed_aggregates.is_empty() && recovery_attempt < SYNC_RECOVERY_MAX_ATTEMPTS {
            recovery_attempt += 1;

            match await_event(
                &net_events,
                |e| {
                    if matches!(e, NetEvent::ConnectionEstablished { .. }) {
                        Some(())
                    } else {
                        None
                    }
                },
                SYNC_RECOVERY_RETRY_INTERVAL,
            )
            .await
            {
                Ok(()) => {
                    info!(
                        attempt = recovery_attempt,
                        "Peer reconnected, retrying failed aggregates"
                    );
                }
                Err(_) => {
                    info!(
                        attempt = recovery_attempt,
                        retry_after = ?SYNC_RECOVERY_RETRY_INTERVAL,
                        "No new peer connection observed; retrying failed aggregates against current peers"
                    );
                }
            }

            let mut still_failed = Vec::new();
            for aggregate_id in failed_aggregates {
                let since = event.since.get(&aggregate_id).copied().unwrap_or(0);
                match fetch_historical_events_for_aggregate(
                    &net_cmds,
                    &net_events,
                    aggregate_id,
                    since,
                )
                .await
                {
                    Ok(events) => {
                        info!(
                            attempt = recovery_attempt,
                            "Retry succeeded: {} events for aggregate_id={}",
                            events.len(),
                            aggregate_id
                        );
                        for interfold_event in events {
                            let ts = interfold_event.ts();
                            if ts > latest_timestamp {
                                latest_timestamp = ts;
                            }
                            all_events.push(interfold_event);
                        }
                    }
                    Err(e) => {
                        warn!(
                            attempt = recovery_attempt,
                            "Retry failed for aggregate_id={}: {e}", aggregate_id
                        );
                        still_failed.push(aggregate_id);
                    }
                }
            }

            failed_aggregates = still_failed;
        }

        if !failed_aggregates.is_empty() {
            bail!(
                "failed to fetch historical net events for aggregates: {:?} after {} recovery attempts",
                failed_aggregates,
                SYNC_RECOVERY_MAX_ATTEMPTS
            );
        }
    }

    info!(
        "Sync complete: collected {} events across {} aggregates, latest_timestamp={}",
        all_events.len(),
        event.since.len(),
        latest_timestamp
    );

    let value = SyncRequestSucceeded {
        response: SyncResponseValue {
            events: all_events,
            ts: latest_timestamp,
        },
    };

    address.into().try_send(TypedEvent::new(value, ctx))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::NetCommand;
    use actix::{Actor, Context as ActixContext, Handler};
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        E3id, EventSource, InterfoldEvent, PlaintextAggregated, TestEvent, Unsequenced,
    };
    use e3_utils::ArcBytes;
    use tokio::sync::{broadcast, mpsc};

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

    fn local_forwardable_event(e3: &str) -> InterfoldEvent {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            PlaintextAggregated {
                e3_id: E3id::new(e3, 1),
                decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3, 4])],
                decryption_aggregator_proofs: vec![],
            }
            .into(),
            None,
            10,
            None,
            EventSource::Local,
        )
        .into_sequenced(1)
    }

    /// This node's own (non-external) DKG encryption-key document artifact.
    fn local_own_document_event() -> InterfoldEvent {
        use e3_events::{EncryptionKey, EncryptionKeyCreated};
        use std::sync::Arc;
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            EncryptionKeyCreated {
                e3_id: E3id::new("1234", 1),
                key: Arc::new(EncryptionKey::new(0u64, ArcBytes::from_bytes(&[9, 9, 9]))),
                external: false,
            }
            .into(),
            None,
            12,
            None,
            EventSource::Local,
        )
        .into_sequenced(3)
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

    #[actix::test]
    async fn rebroadcast_only_gossips_forwardable_own_artifacts() {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle().unwrap().enable("test");
        let (tx, mut rx) = mpsc::channel::<NetCommand>(100);
        let (_evt_tx, evt_rx) = broadcast::channel::<NetEvent>(100);
        let evt_rx = Arc::new(evt_rx);
        let eventstore = NoopEventStore.start().recipient();

        let mut mgr = NetSyncManager::new(&bus, &tx, &evt_rx, eventstore, "my-topic");

        mgr.handle_rebroadcast_response(vec![
            local_forwardable_event("1234"),
            local_non_forwardable_event(),
        ]);

        // Exactly one GossipPublish for the forwardable artifact, on the configured topic.
        let cmd = rx.try_recv().expect("expected a GossipPublish command");
        let NetCommand::GossipPublish { topic, data, .. } = cmd else {
            panic!("expected GossipPublish, got {cmd:?}");
        };
        assert_eq!(topic, "my-topic");
        let event: InterfoldEvent<Unsequenced> = data.try_into().unwrap();
        assert!(matches!(
            event.get_data(),
            InterfoldEventData::PlaintextAggregated(_)
        ));

        // The non-forwardable event must not have produced a second command.
        assert!(
            rx.try_recv().is_err(),
            "non-forwardable event should not be re-broadcast"
        );
    }

    #[actix::test]
    async fn rebroadcast_reputs_own_dkg_document_artifacts() {
        use std::time::Duration;
        use tokio::time::timeout;

        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle().unwrap().enable("test");
        let (tx, mut rx) = mpsc::channel::<NetCommand>(100);
        let (_evt_tx, evt_rx) = broadcast::channel::<NetEvent>(100);
        let evt_rx = Arc::new(evt_rx);
        let eventstore = NoopEventStore.start().recipient();

        let mut mgr = NetSyncManager::new(&bus, &tx, &evt_rx, eventstore, "my-topic");

        // An own DKG document artifact must be re-PUT to the DHT (not gossiped).
        mgr.handle_rebroadcast_response(vec![local_own_document_event()]);

        // The re-publish runs on a spawned task; expect a DhtPutRecord on the net command channel.
        let cmd = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("expected a net command")
            .expect("channel closed");
        assert!(
            matches!(cmd, NetCommand::DhtPutRecord { .. }),
            "expected DhtPutRecord for own document artifact, got {cmd:?}"
        );
    }
}
