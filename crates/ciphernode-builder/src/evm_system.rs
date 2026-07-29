// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use alloy::{primitives::Address, providers::Provider};
use e3_events::{run_once, BusHandle, EventSubscriber, EventType, HistoricalEvmSyncStart};
use e3_evm::{
    EthProvider, EvmChainGateway, EvmChainGatewayHandle, EvmEventProcessor, EvmIngestionStatus,
    EvmReadInterface, EvmRouter, Filters, FixHistoricalOrder, ProviderFactory,
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
    route_factories: Vec<(Address, RouteFactory)>,
    ingestion_status: EvmIngestionStatus,
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
            route_factories: Vec::new(),
            ingestion_status: EvmIngestionStatus::new(format!("chain-{chain_id}"), chain_id),
        }
    }

    pub fn with_chain_identity(
        &mut self,
        chain_name: impl Into<String>,
        expected_chain_id: u64,
    ) -> &mut Self {
        self.ingestion_status = EvmIngestionStatus::new(chain_name, expected_chain_id);
        self
    }

    pub fn with_buffer_limit(&mut self, max_buffered_events: usize) -> &mut Self {
        self.max_buffered_events = max_buffered_events;
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

    pub fn build(&mut self) {
        drop(self.build_with_readiness());
    }

    pub(crate) fn build_with_readiness(&mut self) -> (EvmChainGatewayHandle, EvmIngestionStatus) {
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
            let ingestion_status = self.ingestion_status.clone();

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
                let filters = filters_from_router(&router, deploy_block, confirmations);
                ingestion_status.configure(chain_id, confirmations);

                // Setup and start the read interface and the router
                EvmReadInterface::setup_with_factory(
                    &provider,
                    provider_factory,
                    router.start(),
                    &bus,
                    filters,
                    ingestion_status,
                );
                Ok(())
            }
        });

        // Finaly subscribe to the bus and wait for HistoricalEvmSyncStart
        self.bus
            .subscribe(EventType::HistoricalEvmSyncStart, next.recipient());

        (gateway, self.ingestion_status.clone())
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

fn filters_from_router(router: &EvmRouter, deploy_block: u64, confirmations: u64) -> Filters {
    Filters::from_routing_table(router.get_routing_table(), deploy_block)
        .with_confirmations(confirmations)
}
