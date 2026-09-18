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

    publish_reconciled_history(&bus, historical).await?;

    let received = history.send(GetEvents::new()).await?;
    let types = received
        .iter()
        .map(|event| event.event_type())
        .collect::<Vec<_>>();
    assert_eq!(
        types,
        [
            "EffectsEnabled",
            "SyncEffect",
            "TestEvent",
            "TestEvent",
            "SyncEnded"
        ]
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
    use actix::{Actor, Context, Handler};
    use e3_events::EventBusBarrier;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{timeout, Duration};

    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-immediate-sub");
    let (deliveries, mut received) = mpsc::unbounded_channel();

    struct Recorder {
        name: &'static str,
        deliveries: mpsc::UnboundedSender<&'static str>,
    }
    impl Actor for Recorder {
        type Context = Context<Self>;
    }
    impl Handler<InterfoldEvent> for Recorder {
        type Result = ();
        fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
            if matches!(msg.get_data(), InterfoldEventData::TestEvent(_)) {
                self.deliveries.send(self.name).unwrap();
            }
        }
    }

    // Immediate subscription — receives all events, including before EffectsEnabled
    let immediate_actor = Recorder {
        name: "immediate",
        deliveries: deliveries.clone(),
    }
    .start();
    bus.subscribe(EventType::TestEvent, immediate_actor.recipient());

    // Gated subscription — only receives after EffectsEnabled
    let (subscription_ready, ready) = oneshot::channel();
    let runner = e3_events::run_once::<EffectsEnabled>({
        let bus = bus.clone();
        let deliveries = deliveries.clone();
        move |_| {
            let addr = Recorder {
                name: "gated",
                deliveries,
            }
            .start();
            bus.subscribe(EventType::TestEvent, addr.recipient());
            subscription_ready
                .send(())
                .map_err(|_| anyhow::anyhow!("test dropped the subscription acknowledgement"))?;
            Ok(())
        }
    });
    bus.subscribe(EventType::EffectsEnabled, runner.recipient());
    bus.event_bus().send(EventBusBarrier).await?;

    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("during-replay")
            .id(1)
            .seq(1)
            .build(),
    )?;
    bus.event_bus().send(EventBusBarrier).await?;
    assert_eq!(
        timeout(Duration::from_secs(1), received.recv())
            .await?
            .expect("recorder stopped before the replay event"),
        "immediate"
    );
    assert!(matches!(
        received.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    bus.publish_without_context(EffectsEnabled::new())?;
    timeout(Duration::from_secs(1), ready).await??;
    bus.event_bus().send(EventBusBarrier).await?;

    bus.event_bus().try_send(
        InterfoldEvent::<Unsequenced>::test_event("after-effects")
            .id(2)
            .seq(2)
            .build(),
    )?;
    bus.event_bus().send(EventBusBarrier).await?;

    let mut after = vec![
        timeout(Duration::from_secs(1), received.recv())
            .await?
            .expect("recorder stopped before the live event"),
        timeout(Duration::from_secs(1), received.recv())
            .await?
            .expect("recorder stopped before both live deliveries"),
    ];
    after.sort_unstable();
    assert_eq!(after, ["gated", "immediate"]);
    assert!(matches!(
        received.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    Ok(())
}
