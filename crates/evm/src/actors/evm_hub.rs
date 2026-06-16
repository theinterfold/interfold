// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Handler};
use e3_utils::MAILBOX_LIMIT;

use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};

pub struct EvmHub {
    nexts: Vec<EvmEventProcessor>,
}

impl EvmHub {
    pub fn new(nexts: Vec<EvmEventProcessor>) -> Self {
        Self { nexts }
    }

    pub fn setup(nexts: Vec<EvmEventProcessor>) -> Addr<Self> {
        Self::new(nexts).start()
    }
}

impl Actor for EvmHub {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvmEvent> for EvmHub {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvmEvent, _: &mut Self::Context) -> Self::Result {
        let InterfoldEvmEvent::Log { .. } = msg.clone() else {
            return;
        };

        for next in self.nexts.clone() {
            next.do_send(msg.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::messages::EvmLog;

    use super::*;
    use actix::prelude::*;
    use alloy::primitives::address;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::time::sleep;

    #[actix::test]
    async fn test_evm_hub_forwards_log_events_to_all_processors() {
        // Arrange
        let call_count = Arc::new(AtomicUsize::new(0));

        // Create mock processors that track invocations
        let count1 = call_count.clone();
        let count2 = call_count.clone();

        let processor1 = TestProcessor { call_count: count1 }.start();
        let processor2 = TestProcessor { call_count: count2 }.start();

        let hub = EvmHub::setup(vec![
            processor1.clone().recipient(),
            processor2.clone().recipient(),
        ]);

        let log_event = InterfoldEvmEvent::Log(EvmLog::test_log(
            address!("0x1111111111111111111111111111111111111111"),
            1,
            0,
        ));

        hub.send(log_event).await.unwrap();

        sleep(Duration::from_millis(10)).await;
        // Assert
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    // Helper test actor
    struct TestProcessor {
        call_count: Arc<AtomicUsize>,
    }

    impl Actor for TestProcessor {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvmEvent> for TestProcessor {
        type Result = ();

        fn handle(&mut self, _msg: InterfoldEvmEvent, _ctx: &mut Self::Context) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }
}
