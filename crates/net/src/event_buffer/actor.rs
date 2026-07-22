// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, ActorContext, ActorFutureExt, AsyncContext, Handler, Message, WrapFuture};
use anyhow::{anyhow, Context, Result};
use e3_events::{
    BusHandle, EType, ErrorDispatcher, Event, EventSubscriber, EventType, InterfoldEvent,
    InterfoldEventData,
};
use e3_utils::MAILBOX_LIMIT;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::warn;

use crate::domain::net_buffer::{BufferDecision, NetEventBufferState};
use crate::events::{GossipAcceptance, GossipData, NetCommand, NetEvent};
use crate::{NetworkAuthorizationState, ProtocolAdmission};

pub const DEFAULT_MAX_BUFFERED_NET_EVENTS: usize = 1_024;
pub const DEFAULT_MAX_BUFFERED_NET_BYTES: usize = 256 * 1024 * 1024;

pub struct NetEventBufferHandle {
    readiness: oneshot::Receiver<std::result::Result<(), String>>,
}

impl NetEventBufferHandle {
    pub async fn wait_until_running(self) -> Result<()> {
        self.readiness
            .await
            .context("network event buffer stopped before reporting startup status")?
            .map_err(anyhow::Error::msg)
    }
}

/// Actor that controls a broadcast channel which will buffer NetEvents until it receives a
/// `SyncEnded` event, at which time it releases all buffered events to the output channel. The
/// buffering decision logic lives in [`NetEventBufferState`].
pub struct NetEventBuffer {
    state: NetEventBufferState,
    input_rx: Option<broadcast::Receiver<NetEvent>>,
    output_tx: broadcast::Sender<NetEvent>,
    bus: BusHandle,
    max_events: usize,
    max_bytes: usize,
    readiness: Option<oneshot::Sender<std::result::Result<(), String>>>,
    net_commands: mpsc::Sender<NetCommand>,
    protocol_admission: ProtocolAdmission,
}

impl NetEventBuffer {
    pub(crate) fn setup_with_limits(
        bus: &BusHandle,
        input_rx: &broadcast::Receiver<NetEvent>,
        net_commands: mpsc::Sender<NetCommand>,
        authorization: NetworkAuthorizationState,
        max_events: usize,
        max_bytes: usize,
    ) -> (broadcast::Receiver<NetEvent>, NetEventBufferHandle) {
        let input_rx = input_rx.resubscribe();
        let (output_tx, output_rx) = broadcast::channel(max_events);
        let (readiness_tx, readiness) = oneshot::channel();

        let actor = Self {
            state: NetEventBufferState::syncing(),
            input_rx: Some(input_rx),
            output_tx,
            bus: bus.clone(),
            max_events,
            max_bytes,
            readiness: Some(readiness_tx),
            net_commands,
            protocol_admission: ProtocolAdmission::new(authorization),
        };

        let addr = actor.start();

        // Subscribe to InterfoldEvent on the bus
        bus.subscribe(EventType::All, addr.clone().recipient());

        (output_rx, NetEventBufferHandle { readiness })
    }

    fn handle_interfold_event(&mut self, msg: InterfoldEvent) -> Result<()> {
        self.protocol_admission.observe(&msg);
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
        self.signal_startup(Ok(()));
        Ok(())
    }

    fn forward_event(&mut self, event: NetEvent) -> Result<()> {
        self.output_tx
            .send(event)
            .map_err(|e| anyhow!("Failed to forward event: {}", e))?;
        Ok(())
    }

    fn signal_startup(&mut self, result: std::result::Result<(), String>) {
        if let Some(sender) = self.readiness.take() {
            let _ = sender.send(result);
        }
    }

    fn fail_closed(&mut self, error: anyhow::Error, ctx: &mut actix::Context<Self>) {
        let reason = format!(
            "network event buffer failed closed: {error:#}; startup will stop rather than drop \
             live protocol input. Increase the configured buffer only after measuring the sync \
             backlog, or restore peer/RPC health and restart"
        );
        self.signal_startup(Err(reason.clone()));
        self.bus.err(EType::Net, anyhow!(reason));
        ctx.stop();
    }
}

#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
