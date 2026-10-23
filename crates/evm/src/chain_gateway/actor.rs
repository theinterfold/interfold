// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::chain_sync_state::SyncStatus;
use crate::domain::evm_log_observation::interfold_slashing_manager_set;
use crate::messages::HistoricalSyncComplete;
use crate::messages::InterfoldEvmEvent;
use actix::{Actor, ActorContext, Handler};
use actix::{Addr, Recipient};
use alloy::primitives::Address;
use anyhow::{bail, ensure, Context, Result};
use e3_events::EType;
use e3_events::{
    BusHandle, ErrorDispatcher, EventSubscriber, EventType, HistoricalEvmEventsReceived,
    HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData, SyncEnded, Unsequenced,
};
use e3_events::{Event, EventPublisher};
use e3_utils::MAILBOX_LIMIT;
use tokio::sync::{oneshot, watch};
use tracing::warn;

/// Per-chain bound for events accumulated while the node is synchronizing.
///
/// Tests inject a smaller value. Production deliberately fails startup instead
/// of dropping an observed chain event if this window is exhausted.
pub const DEFAULT_MAX_BUFFERED_EVM_EVENTS: usize = 100_000;

/// Receives the reason when a gateway fails closed.
pub type GatewayFailureReceiver = watch::Receiver<Option<String>>;

pub struct EvmChainGatewayHandle {
    addr: Addr<EvmChainGateway>,
    readiness: oneshot::Receiver<std::result::Result<(), String>>,
    failure: GatewayFailureReceiver,
}

impl EvmChainGatewayHandle {
    pub fn addr(&self) -> Addr<EvmChainGateway> {
        self.addr.clone()
    }

    pub fn failure_receiver(&self) -> GatewayFailureReceiver {
        self.failure.clone()
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
    failure: watch::Sender<Option<String>>,
    /// The SlashingManager that this node signs and submits for on this chain, when it has one.
    slashing_manager: Option<Address>,
}

impl EvmChainGateway {
    pub fn new(bus: &BusHandle) -> Self {
        Self::with_options(bus, DEFAULT_MAX_BUFFERED_EVM_EVENTS, None, None)
    }

    fn with_options(
        bus: &BusHandle,
        max_buffered_events: usize,
        readiness: Option<oneshot::Sender<std::result::Result<(), String>>>,
        slashing_manager: Option<Address>,
    ) -> Self {
        let (failure, _) = watch::channel(None);
        Self {
            bus: bus.clone(),
            status: SyncStatus::default(),
            max_buffered_events,
            readiness,
            failure,
            slashing_manager,
        }
    }

    pub fn setup(bus: &BusHandle) -> Addr<Self> {
        Self::start_and_subscribe(bus, Self::new(bus))
    }

    pub fn setup_with_readiness(bus: &BusHandle) -> EvmChainGatewayHandle {
        Self::setup_with_readiness_and_limit(bus, DEFAULT_MAX_BUFFERED_EVM_EVENTS, None)
    }

    /// `slashing_manager` is the SlashingManager that this node uses on the chain: the gateway
    /// fails closed when the Interfold contract replaces it.
    pub fn setup_with_readiness_and_limit(
        bus: &BusHandle,
        max_buffered_events: usize,
        slashing_manager: Option<Address>,
    ) -> EvmChainGatewayHandle {
        let (tx, readiness) = oneshot::channel();
        let actor = Self::with_options(bus, max_buffered_events, Some(tx), slashing_manager);
        let failure = actor.failure.subscribe();
        let addr = Self::start_and_subscribe(bus, actor);
        EvmChainGatewayHandle {
            addr,
            readiness,
            failure,
        }
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
        self.bus.err(EType::Evm, anyhow::anyhow!(reason.clone()));
        let _ = self.failure.send(Some(reason));
        ctx.stop();
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
        self.signal_startup(Ok(()));
        Ok(())
    }

    fn publish_evm_event(&mut self, msg: InterfoldEvent<Unsequenced>) -> Result<()> {
        self.check_slashing_manager(&msg)?;
        self.bus.naked_dispatch(msg);
        Ok(())
    }

    /// The Interfold contract can replace its SlashingManager once requests are paused and
    /// drained. This node signs accusation votes and submits slash proposals for the manager that
    /// it read at startup, so a replacement after startup stops the chain: a restart reads the new
    /// manager. Historical logs never reach this check.
    fn check_slashing_manager(&self, msg: &InterfoldEvent<Unsequenced>) -> Result<()> {
        let (Some(current), InterfoldEventData::EvmLogObserved(log)) =
            (self.slashing_manager, msg.get_data())
        else {
            return Ok(());
        };
        let Some(replacement) = interfold_slashing_manager_set(log) else {
            return Ok(());
        };
        let replacement = replacement?;
        ensure!(
            replacement == current,
            "the Interfold contract replaced the SlashingManager {current} with {replacement}. \
             Restart the node so that it signs accusation votes and submits slash proposals for \
             the new manager"
        );
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

    fn process_evm_event(&mut self, msg: InterfoldEvent<Unsequenced>) -> Result<()> {
        if matches!(self.status, SyncStatus::Live) {
            return self.publish_evm_event(msg);
        }
        self.status
            .add_buffered_event(msg, self.max_buffered_events)
    }
}

#[path = "handlers.rs"]
mod handlers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
