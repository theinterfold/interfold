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
/// Libp2pNetInterface for propagation over the p2p network. All translation/dedup decisions live
/// in [`EventTranslationService`].
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
                    if let NetEvent::GossipData(data) = event {
                        if let GossipData::GossipBytes(_) = data {
                            addr.do_send(LibP2pEvent(data));
                        }
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
            if let Err(e) = self.tx.try_send(NetCommand::GossipPublish {
                topic,
                data,
                correlation_id: CorrelationId::new(),
            }) {
                warn!("Failed to send gossip command (channel full or closed): {e}");
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
