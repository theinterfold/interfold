// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing for local replay, remote sync requests, and readiness signals.

use super::*;

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
        let (msg, ec) = msg.into_components();
        // We are making a sync request of another node
        if let InterfoldEventData::HistoricalNetSyncStart(data) = msg {
            // Capture the snapshot-cursor map so we can bound the post-restart re-broadcast of our
            // own forwardable artifacts to the in-flight window (H3/H11).
            self.rebroadcast_since = Some(data.since.clone().into_iter().collect());
            self.maybe_rebroadcast_own_artifacts(ctx);
            ctx.notify(TypedEvent::new(data, ec))
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
                self.readiness_has_connections(),
                self.network.clone(),
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

    /// Whether any peer connection exists. When `AllPeersDialed` has already been
    /// observed with no connections, historical sync has nothing to fetch from and
    /// must not attempt requests that can only fail.
    fn readiness_has_connections(&self) -> bool {
        self.readiness.has_connections()
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
        trap(EType::Net, &self.bus.clone(), || {
            let IncomingRequest { peer, responder } = msg;
            let fetch_request: FetchEventsSince = match responder.try_request_into() {
                Ok(request) => request,
                Err(error) => {
                    warn!(%peer, %error, "Rejecting malformed historical-sync request");
                    responder.bad_request("malformed historical sync request")?;
                    return Ok(());
                }
            };
            if fetch_request.limit() == 0 {
                responder.bad_request("limit must be greater than 0")?;
                return Ok(());
            }
            let Some(chain_id) = fetch_request.aggregate_id().to_chain_id() else {
                responder.bad_request("aggregate ID does not contain a chain ID")?;
                return Ok(());
            };
            if !self.network.allows_chain(chain_id) {
                responder.bad_request("aggregate chain is not part of this network")?;
                return Ok(());
            }
            if let Some(reason) = self.request_capacity_error(&peer) {
                warn!(
                    %peer,
                    in_flight = self.requests.len(),
                    "Rejecting historical-sync request: {reason}"
                );
                responder.bad_request(reason)?;
                return Ok(());
            }

            let id = CorrelationId::new();
            let scan_limit = sync_scan_limit(fetch_request.limit());
            info!(
                peer = %peer,
                correlation_id = %id,
                requested_limit = fetch_request.limit(),
                scan_limit,
                "Processing incoming historical-sync request"
            );
            let query: HashMap<AggregateId, u128> =
                HashMap::from([(fetch_request.aggregate_id(), fetch_request.since())]);
            self.requests
                .insert(id, PendingSyncRequest { peer, responder });
            let storage_query =
                EventStoreQueryBy::<TsAgg>::new(id, query, ctx.address().recipient())
                    .with_limit(scan_limit as u64);
            if let Err(error) = self.eventstore.try_send(storage_query) {
                if let Some(pending) = self.requests.remove(&id) {
                    pending.responder.respond(ProtocolResponse::Error(
                        "historical sync storage unavailable".to_string(),
                    ))?;
                }
                warn!(%peer, correlation_id = %id, %error, "Failed to query EventStore for sync");
                return Ok(());
            }
            ctx.run_later(INCOMING_SYNC_REQUEST_TIMEOUT, move |this, _| {
                this.expire_sync_request(id);
            });
            Ok(())
        });
    }
}

/// Receive Events from EventStore
impl Handler<EventStoreQueryResponse> for NetSyncManager {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryResponse, _: &mut Self::Context) -> Self::Result {
        let response_id = msg.id();
        let is_rebroadcast = self.rebroadcast_query_ids.remove(&response_id);
        trap(EType::Net, &self.bus.clone(), || {
            let events = match msg.into_events() {
                Ok(events) => events,
                Err(error) => {
                    if !is_rebroadcast {
                        if let Some(pending) = self.requests.remove(&response_id) {
                            pending.responder.respond(ProtocolResponse::Error(
                                "historical sync storage unavailable".to_string(),
                            ))?;
                        }
                    }
                    return Err(error);
                }
            };

            // Post-restart re-broadcast response (own forwardable artifacts) — handled separately from
            // peer sync-request responses.
            if is_rebroadcast {
                self.handle_rebroadcast_response(events);
                return Ok(());
            }

            info!("Received response from eventstore.");
            let Some(pending) = self.requests.remove(&response_id) else {
                bail!("responder not found for {response_id}");
            };

            let fetch_request: FetchEventsSince = pending.responder.try_request_into()?;
            for event in &events {
                if EventTranslationService::is_forwardable_event(event) {
                    if let Err(error) = self.network.validate_event(event) {
                        pending.responder.respond(ProtocolResponse::Error(
                            "historical sync returned an event outside this network policy"
                                .to_string(),
                        ))?;
                        return Err(error
                            .context("event store returned an invalid event for historical sync"));
                    }
                }
            }
            match build_sync_batch(events, &fetch_request) {
                SyncBatchOutcome::BadRequest(reason) => pending.responder.bad_request(reason)?,
                SyncBatchOutcome::Batch(batch) => pending.responder.ok(batch)?,
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
pub(super) struct AllPeersDialed {
    pub(super) connected: usize,
    pub(super) total: usize,
}

#[derive(Message)]
#[rtype(result = "()")]
pub(super) struct PeerConnected;
