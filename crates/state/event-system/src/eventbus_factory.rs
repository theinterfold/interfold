// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use actix::Addr;
use e3_events::BusHandle;
use e3_events::Disabled;
use e3_events::EventBus;
use e3_events::InterfoldEvent;
use std::sync::OnceLock;

use crate::EventSystem;

/// The process-wide event bus, started on first use.
pub fn get_interfold_event_bus() -> Addr<EventBus<InterfoldEvent>> {
    static EVENT_BUS: OnceLock<Addr<EventBus<InterfoldEvent>>> = OnceLock::new();
    EVENT_BUS
        .get_or_init(|| EventBus::<InterfoldEvent>::default().start())
        .clone()
}

pub fn get_interfold_bus_handle() -> anyhow::Result<BusHandle<Disabled>> {
    let bus = get_interfold_event_bus();
    let system = EventSystem::new().with_event_bus(bus);
    system.store()?; // Ensure store is initialized before returning to avoid potentially dropping
                     // events.
    system.handle()
}
