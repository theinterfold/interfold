// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::adapters::log_fetcher::{
    backfill_to_head, fetch_logs_chunked, process_live_log, TimestampTracker,
};
use crate::domain::backoff::Backoff;
use crate::helpers::{EthProvider, ProviderFactory};
use crate::messages::HistoricalSyncComplete;
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use crate::EvmIngestionStatus;
use actix::prelude::*;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy_primitives::Address;
use anyhow::anyhow;
use e3_events::{
    BusHandle, EType, ErrorDispatcher, Event, EventId, InterfoldEvent, InterfoldEventData,
};
use e3_events::{EventSubscriber, EventType};
use e3_utils::{retry_with_backoff, RetryError, MAILBOX_LIMIT};
use futures_util::stream::StreamExt;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::select;
use tokio::sync::oneshot;
use tracing::{error, info, instrument, warn};

#[path = "effects/mod.rs"]
mod effects;
#[path = "handlers.rs"]
mod handlers;

use effects::stream::stream_from_evm;

const MAX_RECONNECT_DELAY_SECS: u64 = 60;
/// Maximum attempts to recreate a provider via the factory before adding an
/// extra outer delay.
const PROVIDER_RECREATE_MAX_ATTEMPTS: u32 = 3;
/// Initial delay (ms) between provider-recreation attempts.
const PROVIDER_RECREATE_INITIAL_DELAY_MS: u64 = 2000;
/// Consecutive failures before we assume the provider is dead and recreate it.
const MAX_RETRIES_BEFORE_RECREATE: u32 = 3;
/// Polling is required even while the subscription is quiet: a log becomes confirmed because later
/// blocks arrive, and those blocks need not contain any matching contract event.
const CONFIRMED_BACKFILL_INTERVAL_SECS: u64 = 5;

#[derive(Default, serde::Serialize, serde::Deserialize, Clone)]
pub struct EvmReadInterfaceState {
    pub ids: HashSet<EventId>,
    pub last_block: Option<u64>,
}

#[derive(Clone, Default)]
pub struct Filters {
    historical: Filter,
    current: Filter,
    start_block: u64,
    /// Number of confirmations required before a log is ingested. `0` (default)
    /// reads to the chain head exactly as before; a positive value clamps the
    /// historical and backfill heads to make ingestion reorg-safe.
    confirmations: u64,
}

impl Filters {
    pub fn new(addresses: Vec<Address>, start_block: u64) -> Self {
        let historical = Filter::new()
            .address(addresses.clone())
            .from_block(start_block);
        let current = Filter::new()
            .address(addresses)
            .from_block(BlockNumberOrTag::Latest);

        Self {
            historical,
            current,
            start_block,
            confirmations: 0,
        }
    }

    /// Builder: require `confirmations` block confirmations before ingestion.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = confirmations;
        self
    }

    /// The configured confirmation depth (0 = read to head).
    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    pub fn from_routing_table<T>(table: &HashMap<Address, T>, start_block: u64) -> Self {
        let addresses: Vec<Address> = table.keys().cloned().collect();
        Self::new(addresses, start_block)
    }
}

/// Connects to Interfold.sol converting EVM events to InterfoldEvents
pub struct EvmReadInterface<P> {
    /// The alloy provider
    provider: Option<EthProvider<P>>,
    /// Optional factory to recreate the provider when the transport dies
    provider_factory: Option<ProviderFactory<P>>,
    /// A shutdown receiver to listen to for shutdown signals sent to the loop this is only used
    /// internally. You should send the Shutdown signal to the reader directly or via the EventBus
    shutdown_rx: Option<oneshot::Receiver<()>>,
    /// The sender for the shutdown signal this is only used internally
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Processor to forward events
    next: EvmEventProcessor,
    /// Event bus for error propagation only
    bus: BusHandle,
    /// Filters to configure when to seek from
    filters: Filters,
    /// Read-only progress status consumed by the readiness endpoint.
    ingestion_status: EvmIngestionStatus,
}

impl<P: Provider + Clone + 'static> EvmReadInterface<P> {
    pub fn setup(
        provider: &EthProvider<P>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
    ) -> Addr<Self> {
        let status = EvmIngestionStatus::new(
            format!("chain-{}", provider.chain_id()),
            provider.chain_id(),
        );
        Self::setup_with_factory(provider, None, next, bus, filters, status)
    }

    pub fn setup_with_factory(
        provider: &EthProvider<P>,
        provider_factory: Option<ProviderFactory<P>>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
        ingestion_status: EvmIngestionStatus,
    ) -> Addr<Self> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let reader = Self {
            provider: Some(provider.clone()),
            provider_factory,
            shutdown_rx: Some(shutdown_rx),
            shutdown_tx: Some(shutdown_tx),
            next: next.into(),
            bus: bus.clone(),
            filters,
            ingestion_status,
        };

        let addr = reader.start();
        bus.subscribe(EventType::Shutdown, addr.clone().into());
        addr
    }
}
