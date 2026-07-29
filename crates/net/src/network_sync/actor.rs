// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, AsyncContext, Handler, Message, Recipient, ResponseFuture};
use anyhow::{bail, Context, Result};
use e3_events::{
    prelude::*, trap, trap_fut, AggregateId, BusHandle, CorrelationId, EType, EventSource,
    EventStoreFilter, EventStoreQueryBy, EventStoreQueryResponse, EventType,
    HistoricalNetSyncEventsReceived, HistoricalNetSyncStart, InterfoldEvent, InterfoldEventData,
    NetReady, TsAgg, TypedEvent, Unsequenced,
};
use e3_utils::MAILBOX_LIMIT;
use libp2p::PeerId;
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
    direct_requester::DirectRequester,
    direct_responder::DirectResponder,
    domain::{
        build_sync_batch,
        net_event_batch::{
            fetch_all_batched_events_with_budget, FetchEventsSince, SyncFetchBudget,
        },
        sync_coordinator::sync_scan_limit,
        wire::{decode, MAX_DIRECT_MESSAGE_BYTES},
        EventTranslationService, NetReadiness, ReadinessDecision, SyncBatchOutcome,
    },
    events::{
        await_event, GossipData, IncomingRequest, NetCommand, NetEvent, PeerTarget,
        ProtocolResponse,
    },
    NetworkAuthorizationState, ProtocolAdmission, ProtocolSigner,
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
const SYNC_RECOVERY_MAX_ATTEMPTS: usize = 3;

/// Bound remote work independently of the actor mailbox. Per-peer admission prevents one
/// authenticated transport identity from occupying the global allowance.
const MAX_IN_FLIGHT_SYNC_REQUESTS: usize = 16;
const MAX_IN_FLIGHT_SYNC_REQUESTS_PER_PEER: usize = 2;

/// Expire storage requests before libp2p's 30-second request timeout so a failed local query cannot
/// retain a responder and permanently consume one of the bounded in-flight slots.
const INCOMING_SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(25);

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
        decode(&value, MAX_DIRECT_MESSAGE_BYTES).context("failed to deserialize sync response")
    }
}

#[derive(Debug, Clone)]
pub struct SyncRequestSucceeded {
    pub response: SyncResponseValue,
}

struct PendingSyncRequest {
    peer: PeerId,
    responder: DirectResponder,
}

pub struct NetSyncManager {
    /// Interfold EventBus
    bus: BusHandle,
    /// NetCommand sender to forward commands to the Libp2pNetInterface
    tx: mpsc::Sender<NetCommand>,
    /// NetEvents receiver to receive events
    rx: Arc<broadcast::Receiver<NetEvent>>,
    eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
    requests: HashMap<CorrelationId, PendingSyncRequest>,
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
    protocol_signer: ProtocolSigner,
    protocol_authorization: NetworkAuthorizationState,
}

impl NetSyncManager {
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
        topic: &str,
        protocol_signer: ProtocolSigner,
        protocol_authorization: NetworkAuthorizationState,
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
            protocol_signer,
            protocol_authorization,
        }
    }
}

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

use effects::historical_sync::handle_sync_request_event;
use handlers::{AllPeersDialed, PeerConnected};

#[cfg(test)]
use effects::historical_sync::validate_historical_events;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
