// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::net_interface_handle::NetEventSubscriber;
use crate::{
    domain::{datetime_to_instant_from_now, DocumentPublishingService},
    events::{
        call_and_await_response, DocumentPublishedNotification, GossipData, GossipPublishFailure,
        NetCommand, NetEvent,
    },
    ContentHash,
};
use actix::prelude::*;
use anyhow::{Context, Result};
use e3_events::{
    prelude::*, trap, trap_fut, BusHandle, CiphernodeSelected, CorrelationId, DocumentReceived,
    E3RequestComplete, E3id, EType, EventSource, EventType, InterfoldEvent, InterfoldEventData,
    PartyId, PublishDocumentRequested, TypedEvent,
};
use e3_utils::ArcBytes;
use e3_utils::NotifySync;
use e3_utils::{
    retry::{retry_with_backoff, to_retry},
    MAILBOX_LIMIT,
};
use futures::TryFutureExt;
use std::{collections::HashMap, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::event_converter::EventConverter;

const KADEMLIA_PUT_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_GET_TIMEOUT: Duration = Duration::from_secs(30);
const KADEMLIA_BROADCAST_TIMEOUT: Duration = Duration::from_secs(30);

/// DocumentPublisher is an actor that monitors events from both the Libp2pNetInterface and the
/// Interfold EventBus in order to manage document publishing interactions. The decision/state logic
/// lives in [`DocumentPublishingService`]; this actor only wires events to that service and
/// performs the resulting libp2p/Kademlia I/O.
pub struct DocumentPublisher {
    /// Interfold EventBus
    bus: BusHandle,
    /// NetCommand sender to forward commands to the Libp2pNetInterface
    tx: mpsc::Sender<NetCommand>,
    /// Subscriber used to open a fresh NetEvent receiver per publish operation.
    rx: NetEventSubscriber,
    /// The gossipsub broadcast topic
    topic: String,
    /// Pure decision/state service.
    service: DocumentPublishingService,
}

impl DocumentPublisher {
    /// Create a new DocumentPublisher actor
    pub fn new(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
    ) -> Self {
        Self::new_with_interests(bus, tx, rx, topic, HashMap::new())
    }

    pub fn new_with_interests(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
    ) -> Self {
        let service = if interests.is_empty() {
            DocumentPublishingService::new()
        } else {
            DocumentPublishingService::with_interests(interests)
        };
        Self {
            bus: bus.clone(),
            tx: tx.clone(),
            rx: rx.clone(),
            topic: topic.into(),
            service,
        }
    }

    /// This is needed to create simulation libp2p event routers
    pub fn is_document_publisher_event(event: &InterfoldEvent) -> bool {
        // Add a list of events with paylods for the DHT
        matches!(
            event.get_data(),
            InterfoldEventData::PublishDocumentRequested(_)
                | InterfoldEventData::ThresholdShareCreated(_)
                | InterfoldEventData::EncryptionKeyCreated(_)
                | InterfoldEventData::DecryptionKeyShared(_)
        )
    }

    /// Setup the DocumentPublisher and start listening for GossipEvents
    pub fn setup(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
    ) -> Addr<Self> {
        Self::setup_with_interests(bus, tx, rx, topic, HashMap::new())
    }

    pub fn setup_with_interests(
        bus: &BusHandle,
        tx: &mpsc::Sender<NetCommand>,
        rx: &NetEventSubscriber,
        topic: impl Into<String>,
        interests: HashMap<E3id, PartyId>,
    ) -> Addr<Self> {
        let mut events = rx.subscribe();
        let addr = Self::new_with_interests(bus, tx, rx, topic, interests).start();
        EventConverter::setup(bus);
        // Listen on all events
        bus.subscribe(EventType::All, addr.clone().recipient());

        // Forward gossip data from NetEvent
        tokio::spawn({
            debug!("Spawning event receive loop!");
            let addr = addr.clone();
            async move {
                while let Some(event) =
                    crate::event_subscription::recv_net_event(&mut events, "DocumentPublisher")
                        .await
                {
                    debug!("Received event {:?}", event);
                    match event {
                        NetEvent::GossipData(GossipData::DocumentPublishedNotification(data)) => {
                            if let Err(error) = addr.send(data).await {
                                tracing::warn!(
                                    %error,
                                    "DocumentPublisher stopped; ending DHT notification ingress"
                                );
                                break;
                            }
                        }
                        // A peer (re)joined the topic after our pointers went out. Re-announce
                        // so it can fetch the records; without this a node that restarts
                        // mid-DKG never learns the content hashes it needs.
                        NetEvent::GossipSubscribed { .. } => {
                            if addr.send(handlers::PeerSubscribed).await.is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        addr
    }

    fn handle_ciphernode_selected(&mut self, event: CiphernodeSelected) -> Result<()> {
        let CiphernodeSelected {
            e3_id, party_id, ..
        } = event;
        self.service.register_interest(e3_id, party_id);
        Ok(())
    }

    fn handle_e3_request_complete(&mut self, event: E3RequestComplete) -> Result<()> {
        let keys = self.service.complete_e3(&event.e3_id);
        if !keys.is_empty() {
            info!(
                "Pruning {} DHT records for completed E3 {}",
                keys.len(),
                event.e3_id
            );
            let _ = self.tx.try_send(NetCommand::DhtRemoveRecords { keys });
        }
        Ok(())
    }
}

#[path = "effects.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

pub use effects::{
    handle_document_published_notification, handle_publish_document_requested,
    repeat_document_published_notification,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
