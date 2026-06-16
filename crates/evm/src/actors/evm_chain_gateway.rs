// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::chain_sync_state::SyncStatus;
use crate::messages::HistoricalSyncComplete;
use crate::messages::InterfoldEvmEvent;
use actix::{Actor, Handler};
use actix::{Addr, Recipient};
use anyhow::Context;
use anyhow::Result;
use e3_events::EType;
use e3_events::{
    trap, BusHandle, EventSubscriber, EventType, HistoricalEvmEventsReceived,
    HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData, SyncEnded, Unsequenced,
};
use e3_events::{Event, EventPublisher};
use e3_utils::MAILBOX_LIMIT;
use tracing::warn;

/// This component sits between the Evm ingestion for a chain and the Sync actor and the Bus.
/// It coordinates event flow between these components.
pub struct EvmChainGateway {
    bus: BusHandle,
    status: SyncStatus<Recipient<HistoricalEvmEventsReceived>>,
}

impl EvmChainGateway {
    pub fn new(bus: &BusHandle) -> Self {
        Self {
            bus: bus.clone(),
            status: SyncStatus::default(),
        }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        let addr = Self::new(bus).start();
        bus.subscribe_all(
            &[EventType::HistoricalEvmSyncStart, EventType::SyncEnded],
            addr.clone().recipient(),
        );
        addr
    }

    fn handle_sync_start(&mut self, msg: HistoricalEvmSyncStart) -> Result<()> {
        let sender = msg
            .sender
            .context("No sender on HistoricalEvmSyncStart Message")?;
        let (mut buffer, pending_sync_complete) = self.status.forward_to_sync_actor(sender)?;

        for evt in buffer.drain(..) {
            self.process_evm_event(evt)?;
        }

        // HistoricalSyncComplete may have arrived before HistoricalEvmSyncStart
        if let Some(event) = pending_sync_complete {
            warn!("Processing buffered HistoricalSyncComplete that arrived during Init");
            self.forward_historical_sync_complete(event)?;
        }
        Ok(())
    }

    fn handle_sync_ended(&mut self, _: SyncEnded) -> Result<()> {
        let buffer = self.status.live()?;
        for evt in buffer {
            self.publish_evm_event(evt)?;
        }
        Ok(())
    }

    fn publish_evm_event(&mut self, msg: InterfoldEvent<Unsequenced>) -> Result<()> {
        self.bus.naked_dispatch(msg);
        Ok(())
    }

    fn handle_evm_event(&mut self, msg: InterfoldEvmEvent) -> Result<()> {
        match msg {
            InterfoldEvmEvent::HistoricalSyncComplete(e) => {
                self.forward_historical_sync_complete(e)?;
                Ok(())
            }
            InterfoldEvmEvent::Event(event) => {
                self.process_evm_event(event.into_interfold_event(&self.bus)?)?;
                Ok(())
            }
            _ => panic!("EvmChainGateway is only designed to receive InterfoldEvmEvent::HistoricalSyncComplete or InterfoldEvmEvent::Event events"),
        }
    }

    fn forward_historical_sync_complete(&mut self, event: HistoricalSyncComplete) -> Result<()> {
        // Buffer if we're still in Init - will be replayed when HistoricalEvmSyncStart arrives
        if let SyncStatus::Init {
            pending_sync_complete,
            ..
        } = &mut self.status
        {
            warn!(
                chain_id = event.chain_id,
                "HistoricalSyncComplete arrived during Init, buffering"
            );
            *pending_sync_complete = Some(event);
            return Ok(());
        }

        let state = self.status.buffer_until_live()?;
        let sender = state
            .sender
            .context("ForwardToSyncActor state must hold a sender")?;
        let event = HistoricalEvmEventsReceived::new(state.buffer, event.chain_id);
        sender.try_send(event)?;
        Ok(())
    }

    fn process_evm_event(&mut self, msg: InterfoldEvent<Unsequenced>) -> Result<()> {
        match &mut self.status {
            SyncStatus::Init { buffer, .. } => buffer.push(msg),
            SyncStatus::BufferUntilLive(buffer) => buffer.push(msg),
            SyncStatus::ForwardToSyncActor(state) => state.add_event(msg),
            SyncStatus::Live => self.publish_evm_event(msg)?,
        };
        Ok(())
    }
}

impl Actor for EvmChainGateway {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvent> for EvmChainGateway {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Evm, &self.bus.with_ec(msg.get_ctx()), || {
            match msg.into_data() {
                InterfoldEventData::HistoricalEvmSyncStart(e) => self.handle_sync_start(e)?,
                InterfoldEventData::SyncEnded(e) => self.handle_sync_ended(e)?,
                _ => (),
            }
            Ok(())
        })
    }
}

impl Handler<InterfoldEvmEvent> for EvmChainGateway {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Evm, &self.bus.clone(), || self.handle_evm_event(msg))
    }
}

#[cfg(test)]
mod tests {
    use crate::EvmEvent;

    use super::*;
    use e3_ciphernode_builder::EventSystem;

    use e3_events::{CorrelationId, EvmEventConfig, EvmEventConfigChain, TakeEvents, TestEvent};
    use tokio::sync::mpsc;
    use tracing_subscriber::{fmt, EnvFilter};

    struct SyncEventCollector {
        tx: mpsc::UnboundedSender<HistoricalEvmEventsReceived>,
    }

    impl Actor for SyncEventCollector {
        type Context = actix::Context<Self>;
    }

    impl Handler<HistoricalEvmEventsReceived> for SyncEventCollector {
        type Result = ();
        fn handle(&mut self, msg: HistoricalEvmEventsReceived, _: &mut Self::Context) {
            let _ = self.tx.send(msg);
        }
    }

    #[actix::test]
    async fn test_evm_chain_gateway() -> Result<()> {
        let _foo = tracing::subscriber::set_default(
            fmt()
                .with_env_filter(EnvFilter::new("info"))
                .with_test_writer()
                .finish(),
        );

        let system = EventSystem::new().with_fresh_bus();
        let bus: BusHandle = system.handle()?.enable("test");

        let history_collector = bus.history();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let collector = SyncEventCollector { tx }.start();

        let addr = EvmChainGateway::setup(&bus);

        let chain_id = 1u64;

        // HistoricalEvmSyncStart: Init -> ForwardToSyncActor
        let mut evm_config = EvmEventConfig::new();
        evm_config.insert(chain_id, EvmEventConfigChain::new(0));
        bus.publish_without_context(HistoricalEvmSyncStart::new(collector.clone(), evm_config))
            .unwrap();

        // Send EVM event while forwarding - should reach collector
        let evm_event = EvmEvent::new(
            CorrelationId::new(),
            TestEvent::new("Before Complete", 1).into(),
            100,
            12345,
            chain_id,
        );

        // This will actually arrive earlier than HistoricalEvmSyncStart but aught to be buffered
        addr.send(InterfoldEvmEvent::Event(evm_event)).await?;

        // HistoricalSyncComplete: ForwardToSyncActor -> BufferUntilLive
        addr.send(InterfoldEvmEvent::HistoricalSyncComplete(
            HistoricalSyncComplete::new(chain_id, None),
        ))
        .await?;

        // Normal Synchronizer will take this and wait for other events before flushing events to
        // the bus here we simulate it
        let received = rx.recv().await.unwrap();
        for event in received.events {
            bus.naked_dispatch(event);
        }

        // Send EVM event while buffering - should be buffered (not received)
        let buffered_event = EvmEvent::new(
            CorrelationId::new(),
            TestEvent::new("Before SyncEnded", 2).into(),
            101,
            12346,
            chain_id,
        );
        addr.send(InterfoldEvmEvent::Event(buffered_event)).await?;

        // The Synchronizer will publish the SyncEnded event when it has all the information it needs
        // and has published everything to the bus
        bus.publish_without_context(SyncEnded::new())?;

        let after_event = EvmEvent::new(
            CorrelationId::new(),
            TestEvent::new("After SyncEnded", 2).into(),
            101,
            12346,
            chain_id,
        );

        addr.send(InterfoldEvmEvent::Event(after_event)).await?;

        let full = history_collector.send(TakeEvents::new(5)).await?;

        let test_events: Vec<String> = full
            .events
            .iter()
            .filter_map(|e| {
                if let InterfoldEventData::TestEvent(TestEvent { msg, .. }) = e.get_data() {
                    Some(msg.to_string())
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(
            test_events,
            vec!["Before Complete", "Before SyncEnded", "After SyncEnded"]
        );

        let event_types: Vec<String> = full.events.iter().map(|e| e.event_type()).collect();

        assert_eq!(
            event_types,
            vec![
                "HistoricalEvmSyncStart",
                "TestEvent",
                "SyncEnded",
                "TestEvent",
                "TestEvent"
            ]
        );
        Ok(())
    }
}
