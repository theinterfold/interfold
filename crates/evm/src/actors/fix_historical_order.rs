// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::historical_order_fixer::HistoricalOrderFixer;
use crate::messages::{EvmEventProcessor, InterfoldEvmEvent};
use actix::{Actor, Addr, Handler};
use e3_utils::MAILBOX_LIMIT;
use tracing::debug;

pub struct FixHistoricalOrder {
    dest: EvmEventProcessor,
    fixer: HistoricalOrderFixer,
}

impl FixHistoricalOrder {
    pub fn new(dest: impl Into<EvmEventProcessor>) -> Self {
        Self {
            dest: dest.into(),
            fixer: HistoricalOrderFixer::new(),
        }
    }

    pub fn setup(dest: impl Into<EvmEventProcessor>) -> Addr<Self> {
        Self::new(dest).start()
    }
}

impl Actor for FixHistoricalOrder {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl Handler<InterfoldEvmEvent> for FixHistoricalOrder {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvmEvent, _ctx: &mut Self::Context) {
        debug!("Receiving InterfoldEvmEvent event({})", msg.get_id());
        for event in self.fixer.process(msg) {
            self.dest.do_send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::messages::{EvmLog, HistoricalSyncComplete, InterfoldEvmEvent};

    use super::*;
    use actix::prelude::*;
    use alloy_primitives::Address;
    use tokio::{sync::mpsc, time::sleep};

    struct Collector(mpsc::UnboundedSender<InterfoldEvmEvent>);

    impl Actor for Collector {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvmEvent> for Collector {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvmEvent, _ctx: &mut Self::Context) {
            let _ = self.0.send(msg);
        }
    }

    #[actix::test]
    async fn test_reorders_sync_complete_after_referenced_event() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let fix = FixHistoricalOrder::setup(Collector(tx).start());

        let log_1 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 1, 1));
        let log_2 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 2, 2));
        let log_3 = InterfoldEvmEvent::Log(EvmLog::test_log(Address::ZERO, 3, 3));

        let sync_complete = InterfoldEvmEvent::HistoricalSyncComplete(HistoricalSyncComplete::new(
            1,
            Some(log_3.get_id()),
        ));

        // Send logs 1, 2, 3
        fix.send(log_1.clone()).await.unwrap();
        // Send sync complete FIRST (out of order - references log_3 which hasn't been seen)
        fix.send(sync_complete.clone()).await.unwrap();
        fix.send(log_2.clone()).await.unwrap();
        fix.send(log_3.clone()).await.unwrap();

        sleep(Duration::from_secs(1)).await;

        // Collect results
        let mut received = vec![];
        while let Ok(msg) = rx.try_recv() {
            received.push(msg);
        }

        // The sync complete should have been held until log_3 was seen
        assert_eq!(received.len(), 4);
        assert_eq!(received[0], log_1);
        assert_eq!(received[1], log_2);
        assert_eq!(received[2], log_3);
        assert_eq!(received[3], sync_complete);
    }
}
