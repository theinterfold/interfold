// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::adapters::ingestion_progress::IngestionProgressSink;
use crate::adapters::log_fetcher::{
    backfill_to_head, consume_live_logs, HistoricalSync, LiveStop, TimestampTracker,
};
use crate::domain::backoff::Backoff;
use crate::domain::log_window::{LogWindow, MAX_LOG_WINDOW};
use crate::helpers::{EthProvider, ProviderFactory};
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use crate::messages::{EvmReaderStopped, HistoricalSyncComplete};
use actix::prelude::*;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy_primitives::Address;
use anyhow::anyhow;
use e3_events::{BusHandle, EType, ErrorDispatcher, Event, InterfoldEvent, InterfoldEventData};
use e3_events::{EventSubscriber, EventType};
use e3_utils::{retry_with_backoff, RetryError, MAILBOX_LIMIT};
use std::collections::HashMap;
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
/// How long a stopped reader waits for the next actor to accept its stop report.
const STOP_REPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Polling is required even while the subscription is quiet: a log becomes confirmed because later
/// blocks arrive, and those blocks need not contain any matching contract event. At zero
/// confirmations the poll delivers the logs that the subscription did not announce.
const CONFIRMED_BACKFILL_INTERVAL_SECS: u64 = 5;

#[derive(Clone)]
pub struct Filters {
    historical: Filter,
    current: Filter,
    start_block: u64,
    /// Number of confirmations required before a log is ingested. `0` (default)
    /// reads to the chain head exactly as before; a positive value clamps the
    /// historical and backfill heads to make ingestion reorg-safe.
    confirmations: u64,
    /// Widest `eth_getLogs` block range of one request (`rpc_log_range_blocks`).
    max_log_window: u64,
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
            max_log_window: MAX_LOG_WINDOW,
        }
    }

    /// Builder: require `confirmations` block confirmations before ingestion.
    pub fn with_confirmations(mut self, confirmations: u64) -> Self {
        self.confirmations = confirmations;
        self
    }

    /// Builder: start every `eth_getLogs` window at `blocks`, the chain's widest range.
    pub fn with_max_log_window(mut self, blocks: u64) -> Self {
        self.max_log_window = blocks;
        self
    }

    /// The selected confirmation depth (`0` reads the chain head).
    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    /// The window that a reader session starts with: the chain's widest range, narrowed only when
    /// the provider rejects it.
    pub(crate) fn log_window(&self) -> LogWindow {
        LogWindow::with_max(self.max_log_window)
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
    /// Receives each successful head read, for a local health check
    progress: Option<IngestionProgressSink>,
}

impl<P: Provider + Clone + 'static> EvmReadInterface<P> {
    pub fn setup(
        provider: &EthProvider<P>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
    ) -> Addr<Self> {
        Self::setup_with_factory(provider, None, next, bus, filters, None)
    }

    pub fn setup_with_factory(
        provider: &EthProvider<P>,
        provider_factory: Option<ProviderFactory<P>>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
        progress: Option<IngestionProgressSink>,
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
            progress,
        };

        let addr = reader.start();
        bus.subscribe(EventType::Shutdown, addr.clone().into());
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::providers::ProviderBuilder;
    use alloy::rpc::types::Log;
    use alloy::transports::mock::Asserter;
    use e3_event_system::test_support::EventFixture;
    use tokio::sync::mpsc;

    struct Collector(mpsc::UnboundedSender<InterfoldEvmEvent>);

    impl Actor for Collector {
        type Context = actix::Context<Self>;
    }

    impl Handler<InterfoldEvmEvent> for Collector {
        type Result = ();

        fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) {
            let _ = self.0.send(msg);
        }
    }

    /// A failed read retries the historical sync instead of ending the reader, and a reader that
    /// cannot recover reports that it stopped.
    #[actix::test]
    async fn the_history_is_retried_and_a_reader_that_cannot_recover_reports_it(
    ) -> anyhow::Result<()> {
        tokio::time::pause(); // Skip backoff delays
        let EventFixture { bus, .. } = EventFixture::new()?;
        let asserter = Asserter::new();
        asserter.push_success(&"0x1"); // eth_chainId
        asserter.push_failure_msg("connection reset"); // eth_blockNumber
        asserter.push_success(&"0x14"); // eth_blockNumber
        asserter.push_success(&Vec::<Log>::new()); // eth_getLogs

        // The live loop then gets no answer, and without a provider factory it cannot recover.
        let provider =
            EthProvider::new(ProviderBuilder::new().connect_mocked_client(asserter)).await?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _reader = EvmReadInterface::setup(
            &provider,
            Collector(tx).start().recipient(),
            &bus,
            Filters::new(vec![Address::ZERO], 1),
        );

        let deadline = Duration::from_secs(600);
        let Some(InterfoldEvmEvent::HistoricalSyncComplete(sync)) =
            tokio::time::timeout(deadline, rx.recv()).await?
        else {
            panic!("the historical sync must complete after the retry");
        };
        assert_eq!(sync.chain_id, 1);
        let Some(InterfoldEvmEvent::ReaderStopped(stopped)) =
            tokio::time::timeout(deadline, rx.recv()).await?
        else {
            panic!("a reader that cannot recover must report it");
        };
        assert_eq!(stopped.chain_id, 1);
        assert!(
            stopped.reason.contains("no provider factory"),
            "{stopped:?}"
        );
        Ok(())
    }

    #[test]
    fn the_reader_window_starts_at_the_configured_range() {
        let filters = Filters::new(Vec::new(), 0);
        assert_eq!(filters.log_window().width(), MAX_LOG_WINDOW);
        assert_eq!(
            filters.with_max_log_window(2_000).log_window().width(),
            2_000
        );
    }
}
