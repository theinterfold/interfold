// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Handler, Message};
use e3_event_system::EventSystem;
use e3_events::{
    hlc::{Hlc, HlcTimestamp},
    prelude::*,
    BusHandle, EventPublisher, EventType, InterfoldEvent, InterfoldEventData, TestEvent,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

#[actix::test]
async fn restart_seed_keeps_next_event_after_durable_logical_time() -> anyhow::Result<()> {
    let bus = EventSystem::new()
        .with_fresh_bus()
        .handle()?
        .enable_with_hlc(Hlc::new(7).with_clock(|| 1_000));
    let persisted = HlcTimestamp::new(5_000, 17, 99);

    bus.seed_clock(persisted.to_u128())?;
    let next = HlcTimestamp::from(bus.ts()?);

    assert_eq!(next, HlcTimestamp::new(5_000, 18, 7));
    assert!(next > persisted);
    Ok(())
}

#[actix::test]
async fn test_hlc_events() -> anyhow::Result<()> {
    #[derive(Message)]
    #[rtype("Vec<InterfoldEvent>")]
    struct GetEventsOrdered;

    // Setup forwarder
    struct Forwarder {
        dest: BusHandle,
    }
    impl Actor for Forwarder {
        type Context = actix::Context<Self>;
    }

    impl Handler<InterfoldEvent> for Forwarder {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
            let ts = msg.ts();
            let block = msg.block();
            let source = msg.source();
            self.dest
                .publish_from_remote(msg.into_data(), ts, block, source)
                .unwrap()
        }
    }

    // Setup saver
    struct Saver {
        events: Vec<InterfoldEvent>,
    }

    impl Actor for Saver {
        type Context = actix::Context<Self>;
    }

    impl Handler<InterfoldEvent> for Saver {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
            self.events.push(msg);
        }
    }

    impl Handler<GetEventsOrdered> for Saver {
        type Result = Vec<InterfoldEvent>;
        fn handle(&mut self, _: GetEventsOrdered, _: &mut Self::Context) -> Self::Result {
            self.events.clone()
        }
    }

    // 1. setup up two separate busses with out of sync clocks A and B. B should be 30 seconds
    //    faster than A.
    let bus_a = EventSystem::new()
        .with_fresh_bus()
        .handle()?
        .enable_with_hlc(Hlc::new(1).with_clock(move || now_micros().saturating_sub(30_000_000))); // Late
    let bus_b = EventSystem::new()
        .with_fresh_bus()
        .handle()?
        .enable_with_hlc(Hlc::new(2));
    let bus_c = EventSystem::new()
        .with_fresh_bus()
        .handle()?
        .enable_with_hlc(Hlc::new(3));

    let forwarder = Forwarder {
        dest: bus_c.clone(),
    }
    .start();

    // pipe all bus_a and bus_b events to bus_c
    bus_a.subscribe(EventType::All, forwarder.clone().into());
    bus_b.subscribe(EventType::All, forwarder.into());

    // Create and subscribe the Saver to bus_c
    let saver = Saver { events: vec![] }.start();
    bus_c.subscribe(EventType::All, saver.clone().into());

    // Publish events in causal order across buses
    bus_a.publish_without_context(TestEvent::new("one", 1))?;
    sleep(Duration::from_millis(5)).await; // next tick
    bus_b.publish_without_context(TestEvent::new("two", 2))?;
    sleep(Duration::from_millis(5)).await; // next tick
    bus_a.publish_without_context(TestEvent::new("three", 3))?;
    sleep(Duration::from_millis(5)).await; // next tick
    bus_b.publish_without_context(TestEvent::new("four", 4))?;
    sleep(Duration::from_millis(50)).await; // next tick

    // Get events
    let events = saver.send(GetEventsOrdered).await?;

    // Sort by HLC timestamp
    let mut sorted_events = events.clone();
    sorted_events.sort_by_key(|e| e.ts());

    // Extract the payloads/names in HLC-sorted order
    let ordered_names: Vec<_> = sorted_events
        .iter()
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::TestEvent(e) => Some(e.msg.clone()),
            _ => None,
        })
        .collect();

    // ASSERTION 1: Causal order is preserved despite clock drift
    assert_eq!(
        ordered_names,
        vec!["one", "two", "three", "four"],
        "HLC should preserve causal ordering despite 30s clock drift on bus_a"
    );

    // ASSERTION 2: All timestamps are unique (HLC guarantee)
    let timestamps: Vec<_> = sorted_events.iter().map(|e| e.ts()).collect();
    let unique_timestamps: std::collections::HashSet<_> = timestamps.iter().collect();
    assert_eq!(
        timestamps.len(),
        unique_timestamps.len(),
        "All HLC timestamps should be unique"
    );

    // ASSERTION 3: Timestamps are strictly monotonically increasing when sorted
    for window in timestamps.windows(2) {
        assert!(
            window[0] < window[1],
            "HLC timestamps should be strictly increasing: {:?} should be < {:?}",
            window[0],
            window[1]
        );
    }

    Ok(())
}
