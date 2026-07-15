// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[actix::test]
async fn startup_history_is_fenced_between_effects_and_live_mode() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-startup-history-fences");
    let history = bus.history();
    let historical = vec![
        InterfoldEvent::<Unsequenced>::test_event("first")
            .id(1)
            .ts(10)
            .build(),
        InterfoldEvent::<Unsequenced>::test_event("second")
            .id(2)
            .ts(20)
            .build(),
    ];

    let open_effects = vec![e3_events::CommitteeFinalizeRequested {
        e3_id: e3_events::E3id::new("3", 1),
    }
    .into()];
    publish_reconciled_history(&bus, open_effects, historical).await?;

    let received = history.send(GetEvents::new()).await?;
    let types = received
        .iter()
        .map(|event| event.event_type())
        .collect::<Vec<_>>();
    assert_eq!(
        types,
        [
            "EffectsEnabled",
            "EffectRetry",
            "TestEvent",
            "TestEvent",
            "SyncEnded"
        ]
    );
    Ok(())
}

/// Verify that `run_once::<EffectsEnabled>` correctly gates event subscriptions.
///
/// Simulates the sync flow:
/// 1. An event is published BEFORE EffectsEnabled (should be dropped — nobody listening)
/// 2. EffectsEnabled is published (triggers subscription)
/// 3. The same event is published AFTER EffectsEnabled (should be received)
///
/// This is the pattern used by Sortition (E3Requested), CommitteeFinalizer
/// (CommitteeRequested), Multithread (ComputeRequest), and the sol writers.
#[actix::test]
async fn effects_enabled_gates_event_subscriptions() -> anyhow::Result<()> {
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-effects-gating");

    let receive_count = Arc::new(AtomicU32::new(0));

    // Set up a gated subscription: only subscribe to TestEvent after EffectsEnabled
    let counter = receive_count.clone();
    let runner = e3_events::run_once::<EffectsEnabled>({
        let bus = bus.clone();
        move |_| {
            // Create a simple actor that counts received TestEvents
            use actix::{Actor, Context, Handler};

            struct Counter(Arc<AtomicU32>);
            impl Actor for Counter {
                type Context = Context<Self>;
            }
            impl Handler<InterfoldEvent> for Counter {
                type Result = ();
                fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
                    if matches!(msg.get_data(), InterfoldEventData::TestEvent(_)) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }

            let addr = Counter(counter).start();
            bus.subscribe(EventType::TestEvent, addr.recipient());
            Ok(())
        }
    });
    bus.subscribe(EventType::EffectsEnabled, runner.recipient());

    // 1. Publish a TestEvent BEFORE EffectsEnabled — should NOT be received
    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("before-effects")
            .id(1)
            .seq(1)
            .build(),
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        receive_count.load(Ordering::SeqCst),
        0,
        "Event before EffectsEnabled should not be received"
    );

    // 2. Publish EffectsEnabled — triggers the subscription
    bus.publish_without_context(EffectsEnabled::new())?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Publish a TestEvent AFTER EffectsEnabled — should be received
    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("after-effects")
            .id(2)
            .seq(2)
            .build(),
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        receive_count.load(Ordering::SeqCst),
        1,
        "Event after EffectsEnabled should be received exactly once"
    );

    Ok(())
}

/// Verify that ungated (immediate) subscriptions receive events both
/// before and after EffectsEnabled.
///
/// This mirrors how Sortition subscribes to state-building events
/// (CiphernodeAdded, E3Failed, etc.) immediately, while gating
/// E3Requested behind EffectsEnabled. The immediate subscriptions
/// must work during EventStore replay (before EffectsEnabled).
#[actix::test]
async fn immediate_subscriptions_receive_before_effects_enabled() -> anyhow::Result<()> {
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-immediate-sub");

    let immediate_count = Arc::new(AtomicU32::new(0));
    let gated_count = Arc::new(AtomicU32::new(0));

    // Helper actor that counts TestEvents
    use actix::{Actor, Context, Handler};

    struct Counter(Arc<AtomicU32>);
    impl Actor for Counter {
        type Context = Context<Self>;
    }
    impl Handler<InterfoldEvent> for Counter {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
            if matches!(msg.get_data(), InterfoldEventData::TestEvent(_)) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // Immediate subscription — receives all events, including before EffectsEnabled
    let immediate_actor = Counter(immediate_count.clone()).start();
    bus.subscribe(EventType::TestEvent, immediate_actor.recipient());

    // Gated subscription — only receives after EffectsEnabled
    let gated_counter = gated_count.clone();
    let runner = e3_events::run_once::<EffectsEnabled>({
        let bus = bus.clone();
        move |_| {
            let addr = Counter(gated_counter).start();
            bus.subscribe(EventType::TestEvent, addr.recipient());
            Ok(())
        }
    });
    bus.subscribe(EventType::EffectsEnabled, runner.recipient());

    // 1. Publish event BEFORE EffectsEnabled
    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("during-replay")
            .id(1)
            .seq(1)
            .build(),
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        immediate_count.load(Ordering::SeqCst),
        1,
        "Immediate subscription should receive events before EffectsEnabled"
    );
    assert_eq!(
        gated_count.load(Ordering::SeqCst),
        0,
        "Gated subscription should NOT receive events before EffectsEnabled"
    );

    // 2. Publish EffectsEnabled
    bus.publish_without_context(EffectsEnabled::new())?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Publish event AFTER EffectsEnabled
    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("after-effects")
            .id(2)
            .seq(2)
            .build(),
    )?;

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        immediate_count.load(Ordering::SeqCst),
        2,
        "Immediate subscription should receive events after EffectsEnabled too"
    );
    assert_eq!(
        gated_count.load(Ordering::SeqCst),
        1,
        "Gated subscription should receive events after EffectsEnabled"
    );

    Ok(())
}
