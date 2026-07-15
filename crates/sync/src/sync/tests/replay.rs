// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn infrastructure_events_are_filtered_during_replay() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-sync-replay");
    let history = bus.history();

    let events: Vec<InterfoldEvent> = vec![
        InterfoldEvent::<Unsequenced>::test_event("before")
            .id(1)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("sync")
            .data(SyncEnded::new())
            .seq(2)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("fx")
            .data(EffectsEnabled::new())
            .seq(3)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("evm")
            .data(make_historical_evm_sync_start())
            .seq(4)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("retry")
            .data(
                e3_events::EffectRetry::new(
                    e3_events::CommitteeFinalizeRequested {
                        e3_id: e3_events::E3id::new("1", 1),
                    }
                    .into(),
                )
                .unwrap(),
            )
            .seq(5)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("after")
            .id(2)
            .seq(6)
            .build(),
    ];

    let replayed = replay_eventstore_events(&bus, events).await?;
    assert_eq!(replayed, 2);

    let received = history.send(TakeEvents::new(2)).await?;

    let event_types: Vec<&'static str> = received
        .events
        .iter()
        .map(|e| match e.get_data() {
            InterfoldEventData::TestEvent(_) => "TestEvent",
            InterfoldEventData::SyncEnded(_) => "SyncEnded",
            InterfoldEventData::EffectsEnabled(_) => "EffectsEnabled",
            InterfoldEventData::HistoricalEvmSyncStart(_) => "HistoricalEvmSyncStart",
            _ => "other",
        })
        .collect();

    assert_eq!(event_types, vec!["TestEvent", "TestEvent"]);

    let msgs: Vec<String> = received
        .events
        .iter()
        .filter_map(|e| {
            if let InterfoldEventData::TestEvent(t) = e.get_data() {
                Some(t.msg.clone())
            } else {
                None
            }
        })
        .collect();

    assert_eq!(msgs, vec!["before", "after"]);
    Ok(())
}

#[actix::test]
async fn replay_backlog_larger_than_event_bus_mailbox_is_delivered() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-large-sync-replay");
    let history = bus.history();
    let count = MAILBOX_LIMIT_LARGE * 2;
    let events = (0..count)
        .map(|i| {
            InterfoldEvent::<Unsequenced>::test_event("replay")
                .id(i as u64 + 1)
                .seq(i as u64 + 1)
                .build()
        })
        .collect();

    let replayed = replay_eventstore_events(&bus, events).await?;
    assert_eq!(replayed, count);

    let received = history.send(TakeEvents::new(count)).await?;
    assert!(!received.timed_out, "all replay events should be delivered");
    assert_eq!(received.events.len(), count);
    Ok(())
}

#[actix::test]
async fn replay_restores_global_timestamp_order_across_aggregates() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-ordered-sync-replay");
    let history = bus.history();
    let events = vec![
        InterfoldEvent::<Unsequenced>::test_event("third")
            .id(3)
            .aggregate_id(3)
            .ts(30)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("first")
            .id(1)
            .aggregate_id(1)
            .ts(10)
            .seq(1)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("second")
            .id(2)
            .aggregate_id(2)
            .ts(20)
            .seq(1)
            .build(),
    ];

    replay_eventstore_events(&bus, events).await?;

    let received = history.send(TakeEvents::new(3)).await?;
    let timestamps = received
        .events
        .iter()
        .map(|event| event.ts())
        .collect::<Vec<_>>();
    assert_eq!(timestamps, vec![10, 20, 30]);
    Ok(())
}

#[actix::test]
async fn replay_seeds_clock_from_post_snapshot_log_history() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system
        .handle()?
        .enable_with_hlc(Hlc::new(7).with_clock(|| 1_000));
    let durable = HlcTimestamp::new(5_000, 17, 99);
    let events = vec![InterfoldEvent::<Unsequenced>::test_event("durable")
        .id(1)
        .ts(durable.to_u128())
        .seq(1)
        .build()];

    replay_eventstore_events(&bus, events).await?;

    assert!(HlcTimestamp::from(bus.ts()?) > durable);
    Ok(())
}
