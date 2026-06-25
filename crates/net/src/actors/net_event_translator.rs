// SPDX-License-Identifier: LGPL-3.0-only
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::EventTranslationService;
use crate::events::{GossipData, NetCommand, NetEvent};
use actix::prelude::*;
use anyhow::Result;
use e3_events::{
    prelude::*, trap, BusHandle, CorrelationId, EType, EventContextAccessors, EventSource,
    EventType, InterfoldEvent,
};
use e3_utils::MAILBOX_LIMIT;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// NetEventTranslator Actor converts between EventBus events and Libp2p events forwarding them to a
/// Libp2pNetInterface for propagation over the p2p network. All translation/dedup/retry decisions
/// live in [`EventTranslationService`].
pub struct NetEventTranslator {
    bus: BusHandle,
    tx: mpsc::Sender<NetCommand>,
    service: EventTranslationService,
}

impl Actor for NetEventTranslator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

/// Libp2pEvent is used to send data to the Libp2pNetInterface from the NetEventTranslator
#[derive(Message, Clone, Debug, PartialEq, Eq)]
#[rtype(result = "()")]
struct LibP2pEvent(pub GossipData);

/// A gossip publish completed — clean up pending tracking.
#[derive(Message)]
#[rtype(result = "()")]
struct GossipPublishAcknowledged {
    correlation_id: CorrelationId,
}

/// A gossip publish failed — check if it should be queued for retry.
#[derive(Message)]
#[rtype(result = "()")]
struct GossipPublishFailed {
    correlation_id: CorrelationId,
    error: Arc<libp2p::gossipsub::PublishError>,
}

/// A new peer connection was established — flush the retry queue.
#[derive(Message)]
#[rtype(result = "()")]
struct PeerConnected;

impl NetEventTranslator {
    /// Create a new NetEventTranslator actor
    pub fn new(bus: &BusHandle, tx: &mpsc::Sender<NetCommand>, topic: &str) -> Self {
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            service: EventTranslationService::new(topic),
        }
    }

    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &Arc<broadcast::Receiver<NetEvent>>,
        topic: &str,
    ) -> Addr<Self> {
        let mut rx = rx.resubscribe();
        let addr = NetEventTranslator::new(bus, tx, topic).start();

        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());
        info!("NetEventTranslator is running");
        tokio::spawn({
            let addr = addr.clone();
            async move {
                while let Ok(event) = rx.recv().await {
                    match event {
                        NetEvent::GossipData(data) => {
                            if let GossipData::GossipBytes(_) = data {
                                addr.do_send(LibP2pEvent(data));
                            }
                        }
                        NetEvent::GossipPublishError {
                            correlation_id,
                            error,
                        } => {
                            addr.do_send(GossipPublishFailed {
                                correlation_id,
                                error,
                            });
                        }
                        NetEvent::GossipPublished { correlation_id, .. } => {
                            addr.do_send(GossipPublishAcknowledged { correlation_id });
                        }
                        NetEvent::ConnectionEstablished { .. } => {
                            addr.do_send(PeerConnected);
                        }
                        _ => {}
                    }
                }
            }
        });

        addr
    }

    /// Function to determine which events are allowed to be automatically broadcast to the
    /// network. Kept here so the rule can be referenced via `NetEventTranslator` while the
    /// implementation lives in the pure service.
    pub fn is_forwardable_event(event: &InterfoldEvent) -> bool {
        EventTranslationService::is_forwardable_event(event)
    }

    fn handle_interfold_event(&mut self, msg: InterfoldEvent) -> Result<()> {
        if let Some(data) = self.service.prepare_outbound(msg)? {
            let topic = self.service.topic().to_owned();
            let correlation_id = CorrelationId::new();
            self.service
                .track_publish(correlation_id, data.clone(), topic.clone());
            if let Err(e) = self.tx.try_send(NetCommand::GossipPublish {
                topic,
                data,
                correlation_id,
            }) {
                warn!("Failed to send gossip command (channel full or closed): {e}");
                self.service.on_published(correlation_id);
            }
        }
        Ok(())
    }

    fn handle_remote_event(&mut self, msg: LibP2pEvent) -> Result<()> {
        let event = self.service.prepare_inbound(msg.0)?;
        let (data, ec) = event.into_components();
        self.bus
            .publish_from_remote(data, ec.ts(), None, EventSource::Net)?;
        Ok(())
    }

    /// Re-send items returned by the domain. The domain already tracked each
    /// correlation_id — the actor just sends the GossipPublish commands.
    fn resend_queued(&mut self, items: Vec<(CorrelationId, GossipData, String)>) {
        let mut unsent = Vec::new();
        for (correlation_id, data, topic) in items {
            if self
                .tx
                .try_send(NetCommand::GossipPublish {
                    topic: topic.clone(),
                    data: data.clone(),
                    correlation_id,
                })
                .is_err()
            {
                warn!("Failed to flush gossip retry (channel full or closed)");
                // Clean up the domain's pending tracking and re-queue.
                self.service.on_published(correlation_id);
                unsent.push((data, topic));
            }
        }
        // Re-queue all unsent items. Retry count starts fresh since these
        // were never actually published — the channel was full.
        for (data, topic) in unsent {
            self.service.queue_back(data, topic, 0);
        }
    }

    fn is_insufficient_peers(error: &libp2p::gossipsub::PublishError) -> bool {
        matches!(error, libp2p::gossipsub::PublishError::InsufficientPeers)
    }
}

impl Handler<LibP2pEvent> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: LibP2pEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus.clone(), || {
            self.handle_remote_event(msg)
        })
    }
}

impl Handler<InterfoldEvent> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus.with_ec(msg.get_ctx()), || {
            self.handle_interfold_event(msg)
        })
    }
}

impl Handler<GossipPublishAcknowledged> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: GossipPublishAcknowledged, _: &mut Self::Context) -> Self::Result {
        self.service.on_published(msg.correlation_id);
    }
}

impl Handler<GossipPublishFailed> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, msg: GossipPublishFailed, _: &mut Self::Context) -> Self::Result {
        let is_insufficient = Self::is_insufficient_peers(&msg.error);
        self.service
            .on_publish_error(msg.correlation_id, is_insufficient);
    }
}

impl Handler<PeerConnected> for NetEventTranslator {
    type Result = ();
    fn handle(&mut self, _: PeerConnected, _: &mut Self::Context) -> Self::Result {
        let items = self.service.on_peer_connected();
        if !items.is_empty() {
            info!(count = items.len(), "Flushing gossip retry queue");
        }
        self.resend_queued(items);
    }
}
