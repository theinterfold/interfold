// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::messages::{EvmEventProcessor, EvmLog, InterfoldEvmEvent};
use actix::{Actor, Handler};
use alloy_primitives::Address;
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashMap;
use tracing::{debug, error, info};

/// Directs InterfoldEvmEvent::Log events to the correct upstream processors. Drops all other event
/// types
pub struct EvmRouter {
    routing_table: HashMap<Address, EvmEventProcessor>,
    fallback: Option<EvmEventProcessor>,
}

impl Default for EvmRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmRouter {
    pub fn new() -> Self {
        Self {
            routing_table: HashMap::new(),
            fallback: None,
        }
    }

    pub fn add_route(mut self, address: Address, dest: &EvmEventProcessor) -> Self {
        self.routing_table.insert(address, dest.clone());
        self
    }

    pub fn add_fallback(mut self, fallback: &EvmEventProcessor) -> Self {
        self.fallback = Some(fallback.clone());
        self
    }

    pub fn get_routing_table(&self) -> &HashMap<Address, EvmEventProcessor> {
        &self.routing_table
    }
}

impl Actor for EvmRouter {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvmEvent> for EvmRouter {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) -> Self::Result {
        match msg.clone() {
            // Take all log events and route them
            InterfoldEvmEvent::Log(EvmLog { log, .. }) => {
                let address = log.address();
                if let Some(dest) = self.routing_table.get(&address) {
                    debug!("Found address {address} in routing table forwarding to destination.");
                    dest.do_send(msg);
                } else {
                    error!(
                        "Could not find a route for log with address = {:?}",
                        log.address()
                    )
                }
            }
            _ => {
                if let Some(fallback) = self.fallback.clone() {
                    info!("Sending event({}) to fallback", msg.get_id());
                    fallback.do_send(msg)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::prelude::*;
    use alloy_primitives::address;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::time::sleep;

    struct TestProcessor(Arc<AtomicUsize>);

    impl Actor for TestProcessor {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvmEvent> for TestProcessor {
        type Result = ();
        fn handle(&mut self, _msg: InterfoldEvmEvent, _ctx: &mut Self::Context) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[actix::test]
    async fn test_evm_router_routes_log_to_correct_processor() {
        let received_count = Arc::new(AtomicUsize::new(0));
        let processor_addr = TestProcessor(received_count.clone()).start();
        let addr = address!("0x1111111111111111111111111111111111111111");
        let test_log = EvmLog::test_log(addr, 1, 0);
        let test_address = test_log.log.address();

        let router = EvmRouter::new()
            .add_route(test_address, &processor_addr.recipient())
            .start();

        router.do_send(InterfoldEvmEvent::Log(test_log));

        sleep(Duration::from_millis(10)).await;

        assert_eq!(received_count.load(Ordering::SeqCst), 1);
    }

    #[actix::test]
    async fn test_evm_router_ignores_log_with_unknown_address() {
        let received_count = Arc::new(AtomicUsize::new(0));
        let processor_addr = TestProcessor(received_count.clone()).start();

        let router_addr = address!("0x1111111111111111111111111111111111111111");
        let log_addr = address!("0x2222222222222222222222222222222222222222");

        let test_log = EvmLog::test_log(log_addr, 1, 0);

        let router = EvmRouter::new()
            .add_route(router_addr, &processor_addr.recipient())
            .start();

        router.do_send(InterfoldEvmEvent::Log(test_log));

        sleep(Duration::from_millis(10)).await;

        assert_eq!(received_count.load(Ordering::SeqCst), 0);
    }
}
