// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Opt-in isolated event runtime fixtures. No protocol or BFV setup.

use crate::EventSystem;
use actix::{Actor, Addr};
use anyhow::Result;
use e3_events::{
    AggregateConfig, AggregateId, BusHandle, EventBus, EventBusConfig, EventType, HistoryCollector,
    InterfoldEvent, Subscribe,
};
use std::{collections::HashMap, time::Duration};

pub struct EventFixture {
    pub bus: BusHandle,
    pub errors: Addr<HistoryCollector<InterfoldEvent>>,
    pub history: Addr<HistoryCollector<InterfoldEvent>>,
}

impl EventFixture {
    /// Create a fresh bus, collectors and in-memory stores inside an Actix runtime.
    pub fn new() -> Result<Self> {
        let bus = EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
        let errors = HistoryCollector::<InterfoldEvent>::new().start();
        let history = HistoryCollector::<InterfoldEvent>::new().start();
        bus.do_send(Subscribe::new(EventType::All, history.clone().recipient()));
        bus.do_send(Subscribe::new(
            EventType::InterfoldError,
            errors.clone().recipient(),
        ));
        let aggregate_config = AggregateConfig::new(HashMap::from([
            (AggregateId::new(1), Duration::ZERO),
            (AggregateId::new(2), Duration::ZERO),
        ]));
        let bus = EventSystem::in_mem()
            .with_event_bus(bus)
            .with_aggregate_config(aggregate_config)
            .handle()?
            .enable("cn1");
        Ok(Self {
            bus,
            errors,
            history,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{EventPublisher, GetEvents, TakeEvents, TestEvent};

    #[actix::test]
    async fn fixtures_do_not_share_event_buses() -> Result<()> {
        let first = EventFixture::new()?;
        let second = EventFixture::new()?;
        first
            .bus
            .publish_without_context(TestEvent::new("first", 1))?;
        first.bus.flush_event_pipeline().await?;
        let received = first
            .history
            .send(TakeEvents::<InterfoldEvent>::new(1))
            .await?;
        assert!(!received.timed_out);
        assert_eq!(received.events.len(), 1);
        assert!(second
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        assert!(first
            .errors
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        Ok(())
    }
}
