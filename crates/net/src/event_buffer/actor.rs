// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, ActorContext, AsyncContext, Handler, Message};
use anyhow::{anyhow, Context, Result};
use e3_events::{
    BusHandle, EType, ErrorDispatcher, Event, EventSubscriber, EventType, InterfoldEvent,
    InterfoldEventData,
};
use e3_utils::MAILBOX_LIMIT;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::oneshot;
use tracing::warn;

use crate::domain::net_buffer::{BufferDecision, NetEventBufferState};
use crate::events::NetEvent;
use crate::net_interface_handle::NetEventSubscriber;

pub const DEFAULT_MAX_BUFFERED_NET_EVENTS: usize = 1_024;
pub const DEFAULT_MAX_BUFFERED_NET_BYTES: usize = 256 * 1024 * 1024;

pub struct NetEventBufferHandle {
    readiness: oneshot::Receiver<std::result::Result<(), String>>,
    #[cfg(test)]
    actor: actix::Addr<NetEventBuffer>,
}

impl NetEventBufferHandle {
    pub async fn wait_until_running(self) -> Result<()> {
        self.readiness
            .await
            .context("network event buffer stopped before reporting startup status")?
            .map_err(anyhow::Error::msg)
    }
}

/// Actor that buffers application NetEvents until it receives `SyncEnded` and then releases them
/// to the output channel. Sync and connection-control events bypass this actor. The buffering
/// decision logic lives in [`NetEventBufferState`].
pub struct NetEventBuffer {
    state: NetEventBufferState,
    input_rx: Option<broadcast::Receiver<NetEvent>>,
    output_tx: broadcast::Sender<NetEvent>,
    bus: BusHandle,
    max_events: usize,
    max_bytes: usize,
    readiness: Option<oneshot::Sender<std::result::Result<(), String>>>,
    last_drop_warn: Option<Instant>,
}

impl NetEventBuffer {
    pub(crate) fn setup_with_limits(
        bus: &BusHandle,
        input: &NetEventSubscriber,
        max_events: usize,
        max_bytes: usize,
    ) -> (NetEventSubscriber, NetEventBufferHandle) {
        let input_rx = input.subscribe();
        let (output_tx, _) = broadcast::channel(max_events);
        let output = NetEventSubscriber::from(&output_tx);
        let (readiness_tx, readiness) = oneshot::channel();

        let actor = Self {
            state: NetEventBufferState::syncing(),
            input_rx: Some(input_rx),
            output_tx,
            bus: bus.clone(),
            max_events,
            max_bytes,
            readiness: Some(readiness_tx),
            last_drop_warn: None,
        };

        let addr = actor.start();

        // Subscribe to InterfoldEvent on the bus
        bus.subscribe(EventType::SyncEnded, addr.clone().recipient());

        (
            output,
            NetEventBufferHandle {
                readiness,
                #[cfg(test)]
                actor: addr,
            },
        )
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
        self.signal_startup(Ok(()));
        Ok(())
    }

    fn forward_event(&mut self, event: NetEvent) -> Result<()> {
        // A broadcast send only fails when no receiver is alive. Consumers subscribe on
        // `EffectsEnabled`, which the sync service publishes before `SyncEnded`; if that ordering
        // ever slips the event is dropped, exactly as a late subscriber would have missed it.
        // Warn at most once per ten seconds so a full buffer flush cannot flood the log.
        if self.output_tx.send(event).is_err() {
            let now = Instant::now();
            let should_warn = self
                .last_drop_warn
                .is_none_or(|last| now.duration_since(last) > Duration::from_secs(10));
            if should_warn {
                warn!("Dropping buffered network event: no live subscribers on the output channel");
                self.last_drop_warn = Some(now);
            }
        }
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
