// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use alloy::{primitives::Address, providers::Provider};
use anyhow::{bail, Result};
use e3_config::chain_config::DEFAULT_RPC_LOG_RANGE_BLOCKS;
use e3_events::{run_once, BusHandle, EventSubscriber, EventType, HistoricalEvmSyncStart};
use e3_evm::{
    EthProvider, EvmChainGateway, EvmChainGatewayHandle, EvmEventProcessor, EvmReadInterface,
    EvmRouter, Filters, FixHistoricalOrder, IngestionProgressSink, ProviderFactory,
    DEFAULT_MAX_BUFFERED_EVM_EVENTS,
};

pub trait RouteFn: FnOnce(EvmEventProcessor) -> EvmEventProcessor + Send {}
impl<F> RouteFn for F where F: FnOnce(EvmEventProcessor) -> EvmEventProcessor + Send {}

type RouteFactory = Box<dyn RouteFn>;

// Build the event system for a single chain
pub struct EvmSystemChainBuilder<P> {
    provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    bus: BusHandle,
    chain_id: u64,
    max_buffered_events: usize,
    max_log_window: u64,
    progress: Option<IngestionProgressSink>,
    route_factories: Vec<(Address, RouteFactory)>,
}

impl<P: Provider + Clone + 'static> EvmSystemChainBuilder<P> {
    pub fn new(bus: &BusHandle, provider: &EthProvider<P>) -> Self {
        let chain_id = provider.chain_id();
        Self {
            bus: bus.clone(),
            provider: provider.clone(),
            provider_factory: None,
            chain_id,
            max_buffered_events: DEFAULT_MAX_BUFFERED_EVM_EVENTS,
            max_log_window: DEFAULT_RPC_LOG_RANGE_BLOCKS,
            progress: None,
            route_factories: Vec::new(),
        }
    }

    pub fn with_buffer_limit(&mut self, max_buffered_events: usize) -> &mut Self {
        self.max_buffered_events = max_buffered_events;
        self
    }

    /// The chain's widest `eth_getLogs` block range (`rpc_log_range_blocks`).
    pub fn with_max_log_window(&mut self, blocks: u64) -> &mut Self {
        self.max_log_window = blocks;
        self
    }

    /// Report each successful head read of the chain reader to `sink`.
    pub fn with_progress_sink(&mut self, sink: IngestionProgressSink) -> &mut Self {
        self.progress = Some(sink);
        self
    }

    pub fn with_provider_factory(&mut self, factory: ProviderFactory<P>) -> &mut Self {
        self.provider_factory = Some(factory);
        self
    }

    pub fn with_contract<F: RouteFn + 'static>(
        &mut self,
        address: Address,
        route_fn: F,
    ) -> &mut Self {
        self.route_factories.push((address, Box::new(route_fn)));
        self
    }

    pub fn build(&mut self) -> Result<()> {
        self.build_with_readiness().map(drop)
    }

    /// Fails for a chain without a contract route. The reader's log filter is built from the
    /// routes, so without one it has no address and fetches every log on the chain. The router
    /// drops them all, so the chain would do nothing except load the provider.
    pub(crate) fn build_with_readiness(&mut self) -> Result<EvmChainGatewayHandle> {
        if self.route_factories.is_empty() {
            bail!(
                "chain {} has no contract reader; a chain reader needs at least one contract route",
                self.chain_id
            );
        }

        // Think about the following in reverse order

        // Gateway is the final step before connecting to the bus
        let gateway =
            EvmChainGateway::setup_with_readiness_and_limit(&self.bus, self.max_buffered_events);
        let next = gateway.addr();

        // Fix the historical order to avoid missing historical events
        let next = FixHistoricalOrder::setup(next);

        // This will run once when the HistoricalEvmSyncStart event is received
        let next = run_once::<HistoricalEvmSyncStart>({
            // Clone self refs for closure
            let bus = self.bus.clone();
            let provider = self.provider.clone();
            let provider_factory = self.provider_factory.clone();
            let chain_id = self.chain_id;
            let max_log_window = self.max_log_window;
            let progress = self.progress.clone();

            // Only gets consumed once so fine to use replace to clean out route_factories
            let route_factories = std::mem::take(&mut self.route_factories);

            // The event is defined here
            move |msg| {
                // Extract config
                let chain_config = msg.get_evm_config(chain_id)?;
                let deploy_block = chain_config.deploy_block();
                let confirmations = chain_config.confirmations();

                // Pass next to the router
                let router = configure_router(next, route_factories);

                // Extract filters from the router
                let filters =
                    filters_from_router(&router, deploy_block, confirmations, max_log_window);

                // Setup and start the read interface and the router
                EvmReadInterface::setup_with_factory(
                    &provider,
                    provider_factory,
                    router.start(),
                    &bus,
                    filters,
                    progress,
                );
                Ok(())
            }
        });

        // Finaly subscribe to the bus and wait for HistoricalEvmSyncStart
        self.bus
            .subscribe(EventType::HistoricalEvmSyncStart, next.recipient());

        Ok(gateway)
    }
}

/// Setup a router with a fallback and route factories all forwarding to next
fn configure_router(
    next: impl Into<EvmEventProcessor>,
    route_factories: Vec<(Address, Box<dyn RouteFn>)>,
) -> EvmRouter {
    let next = next.into();
    let mut router = EvmRouter::new().add_fallback(&next);
    for (address, route_fn) in route_factories {
        let processor = route_fn(next.clone());
        router = router.add_route(address, &processor);
    }
    router
}

fn filters_from_router(
    router: &EvmRouter,
    deploy_block: u64,
    confirmations: u64,
    max_log_window: u64,
) -> Filters {
    Filters::from_routing_table(router.get_routing_table(), deploy_block)
        .with_confirmations(confirmations)
        .with_max_log_window(max_log_window)
}
