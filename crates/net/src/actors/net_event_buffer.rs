// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, AsyncContext, Handler, Message};
use anyhow::{anyhow, Result};
use e3_events::{
    trap, BusHandle, EType, Event, EventSubscriber, EventType, InterfoldEvent, InterfoldEventData,
};
use tokio::sync::broadcast::{self, error::RecvError};

use crate::domain::net_buffer::{BufferDecision, NetEventBufferState};
use crate::events::NetEvent;

/// Actor that controls a broadcast channel which will buffer NetEvents until it receives a
/// `SyncEnded` event, at which time it releases all buffered events to the output channel. The
/// buffering decision logic lives in [`NetEventBufferState`].
pub struct NetEventBuffer {
    state: NetEventBufferState,
    input_rx: Option<broadcast::Receiver<NetEvent>>,
    output_tx: broadcast::Sender<NetEvent>,
    bus: BusHandle,
}

impl NetEventBuffer {
    pub fn setup(
        bus: &BusHandle,
        input_rx: &broadcast::Receiver<NetEvent>,
    ) -> broadcast::Receiver<NetEvent> {
        let input_rx = input_rx.resubscribe();
        let (output_tx, output_rx) = broadcast::channel(1024);

        let actor = Self {
            state: NetEventBufferState::syncing(),
            input_rx: Some(input_rx),
            output_tx: output_tx.clone(),
            bus: bus.clone(),
        };

        let addr = actor.start();

        // Subscribe to InterfoldEvent on the bus
        bus.subscribe(EventType::SyncEnded, addr.clone().recipient());

        output_rx
    }

    fn handle_interfold_event(&mut self, msg: InterfoldEvent) -> Result<()> {
        if let InterfoldEventData::SyncEnded(_) = msg.get_data() {
            return self.process_sync_ended();
        }
        Ok(())
    }

    fn process_sync_ended(&mut self) -> Result<()> {
        let pending = self.state.run()?;
        for event in pending {
            self.forward_event(event)?;
        }
        Ok(())
    }

    fn forward_event(&mut self, event: NetEvent) -> Result<()> {
        self.output_tx
            .send(event)
            .map_err(|e| anyhow!("Failed to forward event: {}", e))?;
        Ok(())
    }
}

impl Actor for NetEventBuffer {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // Spawn task to read from broadcast channel
        let addr = ctx.address();
        let mut input_rx = self.input_rx.take().expect("input_rx should be present");

        actix::spawn(async move {
            loop {
                match input_rx.recv().await {
                    Ok(event) => addr.do_send(IncomingNetEvent(event)),
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct IncomingNetEvent(NetEvent);

impl Handler<IncomingNetEvent> for NetEventBuffer {
    type Result = ();

    fn handle(&mut self, msg: IncomingNetEvent, _: &mut Self::Context) {
        trap(EType::Net, &self.bus.clone(), || {
            if let BufferDecision::Forward(event) = self.state.observe(msg.0) {
                self.forward_event(event)?;
            }
            Ok(())
        })
    }
}

impl Handler<InterfoldEvent> for NetEventBuffer {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Net, &self.bus.with_ec(msg.get_ctx()), || {
            self.handle_interfold_event(msg)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::events::{GossipData, NetEvent};
    use e3_ciphernode_builder::EventSystem;
    use e3_events::EventPublisher;
    use e3_events::SyncEnded;
    use tokio::{
        sync::broadcast,
        time::{sleep, timeout},
    };

    #[actix::test]
    async fn test_buffers_until_sync_ended() -> Result<()> {
        // Setup
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("test");
        let (input_tx, input_rx) = broadcast::channel(16);
        let mut output_rx = NetEventBuffer::setup(&bus, &input_rx);

        // Send events while syncing - should be buffered
        let event1 = NetEvent::GossipData(GossipData::GossipBytes(vec![1, 2, 3]));
        let event2 = NetEvent::GossipData(GossipData::GossipBytes(vec![4, 5, 6]));
        input_tx.send(event1.clone()).unwrap();
        input_tx.send(event2.clone()).unwrap();

        // Give actor time to process
        sleep(Duration::from_millis(10)).await;

        // Verify no events forwarded yet (should timeout)
        assert!(
            timeout(Duration::from_millis(50), output_rx.recv())
                .await
                .is_err(),
            "Events should be buffered, not forwarded during sync"
        );

        // Send SyncEnded event
        bus.publish_without_context(SyncEnded::new()).unwrap();

        // Now buffered events should be forwarded
        let received1 = output_rx.recv().await.unwrap();
        let received2 = output_rx.recv().await.unwrap();

        assert!(
            matches!(received1, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![1, 2, 3])
        );
        assert!(
            matches!(received2, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![4, 5, 6])
        );

        // Send new event after sync - should forward immediately
        let event3 = NetEvent::GossipData(GossipData::GossipBytes(vec![7, 8, 9]));
        input_tx.send(event3.clone()).unwrap();

        let received3 =
            tokio::time::timeout(tokio::time::Duration::from_millis(100), output_rx.recv())
                .await
                .expect("Event should be forwarded immediately after sync")
                .unwrap();

        assert!(
            matches!(received3, NetEvent::GossipData(GossipData::GossipBytes(ref bytes)) if bytes == &vec![7, 8, 9])
        );

        Ok(())
    }
}
