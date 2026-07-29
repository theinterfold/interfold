// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::chain_sync_state::SyncStatus;
use crate::messages::HistoricalSyncComplete;
use crate::messages::InterfoldEvmEvent;
use actix::{Actor, ActorContext, AsyncContext, Handler};
use actix::{Addr, Recipient};
use anyhow::{bail, Context, Result};
use e3_events::EType;
use e3_events::Event;
use e3_events::{
    BusHandle, ErrorDispatcher, EventSubscriber, EventType, HistoricalEvmEventsReceived,
    HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData, SyncEnded, Unsequenced,
};
use e3_utils::MAILBOX_LIMIT;
use tokio::sync::oneshot;
use tracing::warn;

/// Per-chain bound for events accumulated while the node is synchronizing.
///
/// Tests inject a smaller value. Production deliberately fails startup instead
/// of dropping an observed chain event if this window is exhausted.
pub const DEFAULT_MAX_BUFFERED_EVM_EVENTS: usize = 100_000;

pub struct EvmChainGatewayHandle {
    addr: Addr<EvmChainGateway>,
    readiness: oneshot::Receiver<std::result::Result<(), String>>,
}

impl EvmChainGatewayHandle {
    pub fn addr(&self) -> Addr<EvmChainGateway> {
        self.addr.clone()
    }

    pub async fn wait_until_live(self) -> Result<()> {
        self.readiness
            .await
            .context("EVM chain gateway stopped before reporting startup status")?
            .map_err(anyhow::Error::msg)
    }
}

/// This component sits between the Evm ingestion for a chain and the Sync actor and the Bus.
/// It coordinates event flow between these components.
pub struct EvmChainGateway {
    bus: BusHandle,
    status: SyncStatus<Recipient<HistoricalEvmEventsReceived>>,
    max_buffered_events: usize,
    readiness: Option<oneshot::Sender<std::result::Result<(), String>>>,
}

impl EvmChainGateway {
    pub fn new(bus: &BusHandle) -> Self {
        Self::with_options(bus, DEFAULT_MAX_BUFFERED_EVM_EVENTS, None)
    }

    fn with_options(
        bus: &BusHandle,
        max_buffered_events: usize,
        readiness: Option<oneshot::Sender<std::result::Result<(), String>>>,
    ) -> Self {
        Self {
            bus: bus.clone(),
            status: SyncStatus::default(),
            max_buffered_events,
            readiness,
        }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        Self::start_and_subscribe(bus, Self::new(bus))
    }

    pub fn setup_with_readiness(bus: &BusHandle) -> EvmChainGatewayHandle {
        Self::setup_with_readiness_and_limit(bus, DEFAULT_MAX_BUFFERED_EVM_EVENTS)
    }

    pub fn setup_with_readiness_and_limit(
        bus: &BusHandle,
        max_buffered_events: usize,
    ) -> EvmChainGatewayHandle {
        let (tx, readiness) = oneshot::channel();
        let actor = Self::with_options(bus, max_buffered_events, Some(tx));
        let addr = Self::start_and_subscribe(bus, actor);
        EvmChainGatewayHandle { addr, readiness }
    }

    fn start_and_subscribe(bus: &BusHandle, actor: Self) -> Addr<Self> {
        let addr = actor.start();
        bus.subscribe_all(
            &[EventType::HistoricalEvmSyncStart, EventType::SyncEnded],
            addr.clone().recipient(),
        );
        addr
    }

    fn signal_startup(&mut self, result: std::result::Result<(), String>) {
        if let Some(sender) = self.readiness.take() {
            let _ = sender.send(result);
        }
    }

    fn fail_closed(&mut self, error: anyhow::Error, ctx: &mut actix::Context<Self>) {
        let reason = format!(
            "EVM chain gateway failed closed: {error:#}. The gateway stopped and will not process \
             further chain events; inspect the snapshot/deploy block and RPC catch-up range, then \
             restart the node to replay chain history"
        );
        self.status.fail(reason.clone());
        self.signal_startup(Err(reason.clone()));
        self.bus.err(EType::Evm, anyhow::anyhow!(reason));
        // Stop on the next actor turn so the current mailbox request can receive
        // its acknowledgement before the mailbox closes.
        ctx.run_later(std::time::Duration::ZERO, |_, ctx| ctx.stop());
    }

    fn handle_sync_start(&mut self, msg: HistoricalEvmSyncStart) -> Result<()> {
        let sender = msg
            .sender
            .context("No sender on HistoricalEvmSyncStart Message")?;
        let (mut buffer, pending_sync_complete) = self.status.forward_to_sync_actor(sender)?;

        for evt in buffer.drain(..) {
            let publish = self.process_evm_event(evt)?;
            debug_assert!(publish.is_none());
        }

        // HistoricalSyncComplete may have arrived before HistoricalEvmSyncStart
        if let Some(event) = pending_sync_complete {
            warn!("Processing buffered HistoricalSyncComplete that arrived during Init");
            self.forward_historical_sync_complete(event)?;
        }
        Ok(())
    }

    fn handle_sync_ended(&mut self, _: SyncEnded) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
        self.status.begin_draining()
    }

    fn handle_evm_event(
        &mut self,
        msg: InterfoldEvmEvent,
    ) -> Result<Option<InterfoldEvent<Unsequenced>>> {
        match msg {
            InterfoldEvmEvent::HistoricalSyncComplete(e) => {
                self.forward_historical_sync_complete(e)?;
                Ok(None)
            }
            InterfoldEvmEvent::Event(event) => {
                self.process_evm_event(event.into_interfold_event(&self.bus)?)
            }
            InterfoldEvmEvent::Log(_) => {
                bail!("EvmChainGateway received an unparsed EVM log")
            }
            InterfoldEvmEvent::Rejected(rejected) => bail!(
                "chain {} rejected provider log {}: {}",
                rejected.chain_id,
                rejected.id,
                rejected.reason
            ),
            InterfoldEvmEvent::Processed(_) => {
                bail!("EvmChainGateway received an internal ordering marker")
            }
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

    fn process_evm_event(
        &mut self,
        msg: InterfoldEvent<Unsequenced>,
    ) -> Result<Option<InterfoldEvent<Unsequenced>>> {
        if matches!(self.status, SyncStatus::Live) {
            return Ok(Some(msg));
        }
        self.status
            .add_buffered_event(msg, self.max_buffered_events)?;
        Ok(None)
    }
}

#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
