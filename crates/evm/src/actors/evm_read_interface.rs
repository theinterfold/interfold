// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::actors::log_fetcher::{
    backfill_to_head, fetch_logs_chunked, process_log, TimestampTracker,
};
use crate::domain::backoff::Backoff;
use crate::helpers::{EthProvider, ProviderFactory};
use crate::messages::HistoricalSyncComplete;
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
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

const MAX_RECONNECT_DELAY_SECS: u64 = 60;
/// Maximum attempts to recreate a provider via the factory before adding an
/// extra outer delay.
const PROVIDER_RECREATE_MAX_ATTEMPTS: u32 = 3;
/// Initial delay (ms) between provider-recreation attempts.
const PROVIDER_RECREATE_INITIAL_DELAY_MS: u64 = 2000;
/// Consecutive failures before we assume the provider is dead and recreate it.
const MAX_RETRIES_BEFORE_RECREATE: u32 = 3;

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
}

impl<P: Provider + Clone + 'static> EvmReadInterface<P> {
    pub fn setup(
        provider: &EthProvider<P>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
    ) -> Addr<Self> {
        Self::setup_with_factory(provider, None, next, bus, filters)
    }

    pub fn setup_with_factory(
        provider: &EthProvider<P>,
        provider_factory: Option<ProviderFactory<P>>,
        next: impl Into<EvmEventProcessor>,
        bus: &BusHandle,
        filters: Filters,
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
        };

        let addr = reader.start();
        bus.subscribe(EventType::Shutdown, addr.clone().into());
        addr
    }
}

impl<P: Provider + Clone + 'static> Actor for EvmReadInterface<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);

        let bus = self.bus.clone();
        let next = self.next.clone();
        let filters = self.filters.clone();
        let provider_factory = self.provider_factory.take();

        let Some(provider) = self.provider.take() else {
            error!("Could not start event reader as provider has already been used.");
            return;
        };

        let Some(shutdown) = self.shutdown_rx.take() else {
            bus.err(EType::Evm, anyhow!("shutdown already called"));
            return;
        };

        ctx.spawn(
            async move {
                stream_from_evm(provider, provider_factory, next, shutdown, &bus, filters).await
            }
            .into_actor(self),
        );
    }
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut oneshot::Receiver<()>) -> bool {
    select! {
        _ = tokio::time::sleep(duration) => false,
        _ = &mut *shutdown => {
            info!("Shutdown signal received during backoff");
            true
        }
    }
}

async fn recreate_provider<P: Provider + Clone + 'static>(
    factory: &ProviderFactory<P>,
    shutdown: &mut oneshot::Receiver<()>,
    chain_id: u64,
    backoff: &mut Backoff,
) -> Option<EthProvider<P>> {
    loop {
        if shutdown.try_recv().is_ok() {
            return None;
        }

        let delay = backoff.next_delay();
        warn!(
            chain_id,
            delay_secs = delay.as_secs(),
            "Waiting before provider recreation attempt"
        );
        if sleep_or_shutdown(delay, shutdown).await {
            return None;
        }

        let factory_clone = factory.clone();
        let result = retry_with_backoff(
            || {
                let f = factory_clone.clone();
                async move {
                    let provider = f().await.map_err(|e| {
                        warn!(chain_id, error = %e, "Factory failed to create provider");
                        RetryError::Retry(e)
                    })?;

                    // Health check: verify the new transport is actually alive
                    provider.provider().get_block_number().await.map_err(|e| {
                        warn!(chain_id, error = %e, "New provider failed health check");
                        RetryError::Retry(anyhow!("Health check failed: {}", e))
                    })?;

                    Ok(provider)
                }
            },
            PROVIDER_RECREATE_MAX_ATTEMPTS,
            PROVIDER_RECREATE_INITIAL_DELAY_MS,
        )
        .await;

        match result {
            Ok(new_provider) => {
                let new_chain_id = new_provider.chain_id();
                if new_chain_id != chain_id {
                    error!(
                        chain_id,
                        new_chain_id, "Recreated provider is on wrong chain — fatal"
                    );
                    return None;
                }
                info!(chain_id, "Provider recreated and verified");
                backoff.reset();
                return Some(new_provider);
            }
            Err(e) => {
                error!(
                    chain_id,
                    error = %e,
                    "All provider recreation attempts failed, will retry with longer backoff"
                );
                continue;
            }
        }
    }
}

async fn get_new_provider_or_exit<P: Provider + Clone + 'static>(
    factory: &Option<ProviderFactory<P>>,
    shutdown: &mut oneshot::Receiver<()>,
    chain_id: u64,
    backoff: &mut Backoff,
    bus: &BusHandle,
) -> Option<EthProvider<P>> {
    let Some(factory) = factory else {
        error!(
            chain_id,
            "Transport died and no provider factory configured"
        );
        bus.err(
            EType::Evm,
            anyhow!("Transport died and no provider factory configured"),
        );
        return None;
    };
    let result = recreate_provider(factory, shutdown, chain_id, backoff).await;
    if result.is_none() && shutdown.try_recv().is_err() {
        bus.err(
            EType::Evm,
            anyhow!("Provider recreation failed for chain {}", chain_id),
        );
    }
    result
}

#[instrument(name = "evm_interface", skip_all)]
async fn stream_from_evm<P: Provider + Clone + 'static>(
    provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    next: EvmEventProcessor,
    mut shutdown: oneshot::Receiver<()>,
    bus: &BusHandle,
    filters: Filters,
) {
    let chain_id = provider.chain_id();
    let mut timestamp_tracker = TimestampTracker::new();
    let mut backoff = Backoff::new(MAX_RECONNECT_DELAY_SECS);

    // ── Phase 1: Historical sync (must succeed, fatal on failure) ──

    let latest_block = match provider.provider().get_block_number().await {
        Ok(bn) => crate::domain::reorg::confirmed_head(bn, filters.confirmations()),
        Err(e) => {
            error!(chain_id, error = %e, "Failed to get latest block number");
            bus.err(EType::Evm, anyhow!(e));
            return;
        }
    };

    let last_id = match fetch_logs_chunked(
        provider.provider(),
        &filters.historical,
        filters.start_block,
        latest_block,
        chain_id,
        &next,
        &mut timestamp_tracker,
    )
    .await
    {
        Ok(id) => {
            info!(chain_id, "Historical sync succeeded");
            id
        }
        Err(e) => {
            error!(chain_id, error = %e, "Failed to fetch historical events — node cannot operate without full state, exiting");
            bus.err(EType::Evm, anyhow!(e));
            return;
        }
    };

    next.do_send(InterfoldEvmEvent::HistoricalSyncComplete(
        HistoricalSyncComplete::new(chain_id, last_id),
    ));

    // ── Phase 2: Live event loop with provider lifecycle management ──
    //
    // Single flat loop: backfill → subscribe → consume stream → repeat.
    // On transport death, immediately recreate the provider.
    // On transient errors, retry with exponential backoff.

    let mut last_block = latest_block;
    let mut current_provider = provider;
    let mut consecutive_failures: u32 = 0;

    loop {
        // Step 1: Backfill any blocks missed since last_block
        match backfill_to_head(
            current_provider.provider(),
            &filters.current,
            chain_id,
            &next,
            &mut timestamp_tracker,
            &mut last_block,
            filters.confirmations(),
        )
        .await
        {
            Ok(_) => {
                backoff.reset();
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(chain_id, error = %e, consecutive_failures, "Backfill failed");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                    continue;
                }
                if sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await {
                    return;
                }
                continue;
            }
        }

        // Step 2: Subscribe to live events
        let sub_result = current_provider
            .provider()
            .subscribe_logs(&filters.current)
            .await
            .map_err(|e| anyhow!("{}", e));

        match sub_result {
            Ok(subscription) => {
                backoff.reset();
                consecutive_failures = 0;
                let sub_id: B256 = *subscription.local_id();
                let mut stream = subscription.into_stream();
                info!(chain_id, "Live event subscription active");

                loop {
                    select! {
                        maybe_log = stream.next() => {
                            match maybe_log {
                                Some(log) => {
                                    if let Some(bn) = log.block_number {
                                        last_block = last_block.max(bn);
                                    }
                                    process_log(
                                        current_provider.provider(),
                                        log, chain_id, &next, &mut timestamp_tracker,
                                    ).await;
                                }
                                None => {
                                    // Stream ended (server-side close, idle timeout, etc.)
                                    consecutive_failures += 1;
                                    warn!(chain_id, consecutive_failures, "Live event stream ended, will reconnect");
                                    break;
                                }
                            }
                        }
                        _ = &mut shutdown => {
                            info!("Shutdown signal received, stopping EVM stream");
                            let _ = current_provider.provider().unsubscribe(sub_id).await;
                            return;
                        }
                    }
                }

                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                } else if consecutive_failures > 0
                    && sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await
                {
                    return;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                error!(chain_id, error = %e, consecutive_failures, "Failed to subscribe to live events");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                } else {
                    bus.err(EType::Evm, anyhow!("{}", e));
                    if sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await {
                        return;
                    }
                }
            }
        }
    }
}

impl<P: Provider + Clone + 'static> Handler<InterfoldEvent> for EvmReadInterface<P> {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let InterfoldEventData::Shutdown(_) = msg.into_data() {
            if let Some(shutdown) = self.shutdown_tx.take() {
                let _ = shutdown.send(());
            }
        }
    }
}
