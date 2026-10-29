// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Handler, Message};
use e3_event_system::EventSystem;
use e3_events::{
    EventPublisher, EventSource, FlushPendingSnapshots, GetEvents, InsertBatch, InterfoldEvent,
    TakeEvents, TestEvent, UpdateDestination,
};

#[derive(Default)]
struct SnapshotCollector(Vec<InsertBatch>);

impl Actor for SnapshotCollector {
    type Context = actix::Context<Self>;
}

impl Handler<InsertBatch> for SnapshotCollector {
    type Result = anyhow::Result<()>;

    fn handle(&mut self, batch: InsertBatch, _: &mut Self::Context) -> Self::Result {
        if !batch.commands().is_empty() {
            self.0.push(batch);
        }
        Ok(())
    }
}

#[derive(Message)]
#[rtype(result = "Vec<InsertBatch>")]
struct TakeSnapshots;

impl Handler<TakeSnapshots> for SnapshotCollector {
    type Result = Vec<InsertBatch>;

    fn handle(&mut self, _: TakeSnapshots, _: &mut Self::Context) -> Self::Result {
        std::mem::take(&mut self.0)
    }
}

#[actix::test]
async fn it_adds_seqence_numbers_to_events() -> anyhow::Result<()> {
    let system = EventSystem::new();
    let bus = system.handle()?.enable("test");
    let history = bus.history();

    let event_data = vec![
        TestEvent::new("one", 1),
        TestEvent::new("two", 2),
        TestEvent::new("three", 3),
    ];

    for d in event_data.clone() {
        bus.publish_without_context(d)?;
    }

    let expected = event_data
        .into_iter()
        .map(|d| InterfoldEvent::new_stored_event(d.clone().into(), 0, d.entropy))
        .collect::<Vec<_>>();
    let events = history.send(TakeEvents::new(3)).await?;

    assert_eq!(
        events
            .events
            .iter()
            .map(InterfoldEvent::strip_ts)
            .collect::<Vec<_>>(),
        expected
    );
    Ok(())
}

#[actix::test]
async fn it_handles_event_burst_without_overflow() -> anyhow::Result<()> {
    let count = 500usize;
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test-burst");
    let history = bus.history();

    let start = std::time::Instant::now();

    for i in 0..count {
        bus.publish_without_context(TestEvent::new(&format!("evt-{i}"), i as u64))?;
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let events: Vec<InterfoldEvent> = history.send(GetEvents::new()).await?;
        if events.len() >= count {
            let elapsed = start.elapsed();
            println!("All {count} events arrived in {elapsed:?}");
            assert_eq!(events.len(), count, "all events must arrive");
            break;
        }
        if tokio::time::Instant::now() > deadline {
            let got = events.len();
            panic!("test timed out — only {got}/{count} events arrived after 30s");
        }
        // Yield to let the actor system make progress.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}

#[actix::test]
async fn equal_evm_facts_reach_domain_and_snapshot_paths() -> anyhow::Result<()> {
    let system = EventSystem::new().with_fresh_bus();
    let snapshots = SnapshotCollector::default().start();
    let buffer = system.buffer()?;
    buffer
        .send(UpdateDestination::new(snapshots.clone().recipient()))
        .await?;
    let bus = system.handle()?.enable("same-evm-fact");
    let history = bus.history();

    let fact = TestEvent::new("same fact", 1);
    bus.publish_from_remote(fact.clone(), 1_000_000, Some(100), EventSource::Evm)?;
    bus.publish_from_remote(fact, 2_000_000, Some(101), EventSource::Evm)?;
    bus.flush_event_pipeline().await?;
    buffer.send(FlushPendingSnapshots).await??;

    let delivered = history.send(GetEvents::new()).await?;
    assert_eq!(
        delivered.len(),
        2,
        "both chain occurrences must be delivered"
    );

    let snapshot_batches = snapshots.send(TakeSnapshots).await?;
    let revisions = snapshot_batches
        .iter()
        .map(InsertBatch::snapshot_revision)
        .collect::<anyhow::Result<Vec<_>>>()?;
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].expect("first revision").seq(), 1);
    assert_eq!(revisions[1].expect("second revision").seq(), 2);
    Ok(())
}
