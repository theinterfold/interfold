// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded disk-backed merge for post-snapshot EventStore replay.

use actix::Recipient;
use anyhow::{bail, Context, Result};
use e3_events::{
    AggregateId, BusHandle, CorrelationId, EventBusBarrier, EventBusFanout, EventContextAccessors,
    EventContextSeq, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEvent, SeqAgg,
};
use e3_utils::actix::channel as actix_toolbox;
use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
};
use tempfile::NamedTempFile;
use tracing::info;

use crate::{ReplayDecision, SyncPlanner};

const REPLAY_QUERY_PAGE_SIZE: usize = 1_024;
const REPLAY_QUERY_PAGE_BYTES: usize = 256 * 1024 * 1024;
const REPLAY_MERGE_FAN_IN: usize = 32;
const MAX_SPOOLED_EVENT_BYTES: usize = e3_data::MAX_BLOB_BYTES + 1024;
const REPLAY_PROGRESS_INTERVAL: usize = 10_000;

fn first_replay_sequence(snapshot_cursor: u64) -> u64 {
    snapshot_cursor.max(1)
}

/// Sorted temporary runs plus the ordering metadata discovered while paging the
/// EventStore. Temporary files are deleted automatically on every exit path.
pub(crate) struct ReplaySpool {
    runs: Vec<NamedTempFile>,
    total_events: usize,
    max_timestamp: Option<u128>,
}

impl ReplaySpool {
    pub(crate) async fn load(
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        cursors: std::collections::HashMap<AggregateId, u64>,
    ) -> Result<Self> {
        let ranges = cursors
            .into_iter()
            .map(|(aggregate_id, cursor)| (aggregate_id, first_replay_sequence(cursor), None))
            .collect();
        Self::load_ranges(eventstore, ranges).await
    }

    /// Load complete EventStore prefixes through the supplied aggregate cursors.
    pub(crate) async fn load_bounded(
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        end_cursors: std::collections::HashMap<AggregateId, u64>,
    ) -> Result<Self> {
        let ranges = end_cursors
            .into_iter()
            .filter(|(_, end_cursor)| *end_cursor > 0)
            .map(|(aggregate_id, end_cursor)| (aggregate_id, 1, Some(end_cursor)))
            .collect();
        Self::load_ranges(eventstore, ranges).await
    }

    /// Load the missing suffix between two per-aggregate cursor maps.
    pub(crate) async fn load_between(
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        start_cursors: std::collections::HashMap<AggregateId, u64>,
        end_cursors: std::collections::HashMap<AggregateId, u64>,
    ) -> Result<Self> {
        let ranges = end_cursors
            .into_iter()
            .filter_map(|(aggregate_id, end_cursor)| {
                let start_cursor = start_cursors
                    .get(&aggregate_id)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1)
                    .max(1);
                (start_cursor <= end_cursor).then_some((
                    aggregate_id,
                    start_cursor,
                    Some(end_cursor),
                ))
            })
            .collect();
        Self::load_ranges(eventstore, ranges).await
    }

    async fn load_ranges(
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        ranges: Vec<(AggregateId, u64, Option<u64>)>,
    ) -> Result<Self> {
        Self::load_ranges_with_page_limits(
            eventstore,
            ranges,
            REPLAY_QUERY_PAGE_SIZE,
            REPLAY_QUERY_PAGE_BYTES,
        )
        .await
    }

    async fn load_ranges_with_page_limits(
        eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
        mut ranges: Vec<(AggregateId, u64, Option<u64>)>,
        page_size: usize,
        page_bytes: usize,
    ) -> Result<Self> {
        anyhow::ensure!(page_size > 0, "replay page size must be greater than zero");
        anyhow::ensure!(
            page_bytes > 0,
            "replay page byte budget must be greater than zero"
        );
        ranges.sort_by_key(|(aggregate_id, _, _)| *aggregate_id);

        let mut runs = Vec::new();
        let mut total_events = 0usize;
        let mut max_timestamp: Option<u128> = None;

        for (aggregate_id, first_cursor, end_cursor) in ranges {
            // Keep one run per aggregate in durable sequence order. The merger can then choose
            // between aggregate heads by HLC without ever exposing sequence N + 1 before N from
            // the same aggregate. A late network event may carry an older remote HLC even though
            // it received a later local sequence.
            let mut aggregate_run =
                NamedTempFile::new().context("failed to create EventStore replay spool file")?;
            let mut aggregate_has_events = false;
            let mut cursor = first_cursor;
            loop {
                if end_cursor.is_some_and(|end| cursor > end) {
                    break;
                }

                let mut page =
                    query_page(eventstore, aggregate_id, cursor, page_size, page_bytes).await?;
                if page.is_empty() {
                    if let Some(end) = end_cursor {
                        bail!(
                            "EventStore ended at sequence {} for aggregate {}, before required sequence {}",
                            cursor.saturating_sub(1),
                            aggregate_id,
                            end
                        );
                    }
                    break;
                }
                if page.len() > page_size {
                    bail!(
                        "EventStore returned {} replay events for aggregate {}, exceeding page limit {}",
                        page.len(),
                        aggregate_id,
                        page_size
                    );
                }

                let mut expected_sequence = cursor;
                for event in &page {
                    if event.aggregate_id() != aggregate_id {
                        bail!(
                            "EventStore returned aggregate {} while paging replay aggregate {}",
                            event.aggregate_id(),
                            aggregate_id
                        );
                    }
                    if event.seq() != expected_sequence {
                        bail!(
                            "EventStore replay sequence gap for aggregate {}: expected {}, got {}",
                            aggregate_id,
                            expected_sequence,
                            event.seq()
                        );
                    }
                    expected_sequence = expected_sequence
                        .checked_add(1)
                        .context("EventStore replay sequence overflow")?;
                }

                if let Some(end) = end_cursor {
                    page.retain(|event| event.seq() <= end);
                }
                for event in &page {
                    max_timestamp = Some(max_timestamp.map_or(event.ts(), |ts| ts.max(event.ts())));
                }
                cursor = page
                    .last()
                    .map(|event| event.seq().saturating_add(1))
                    .unwrap_or(expected_sequence);
                total_events = total_events
                    .checked_add(page.len())
                    .context("EventStore replay event count overflow")?;
                if !page.is_empty() {
                    append_run(&mut aggregate_run, page)?;
                    aggregate_has_events = true;
                }

                if end_cursor.is_some_and(|end| cursor > end) {
                    break;
                }
                // A byte-bounded query can return fewer than `page_size` events even when more
                // history exists. Only an empty query proves that this aggregate is exhausted.
            }
            if aggregate_has_events {
                runs.push(aggregate_run);
            }
        }

        let runs = compact_runs(runs)?;
        Ok(Self {
            runs,
            total_events,
            max_timestamp,
        })
    }

    pub(crate) fn total_events(&self) -> usize {
        self.total_events
    }

    pub(crate) fn project(
        self,
        mut apply: impl FnMut(&InterfoldEvent) -> Result<()>,
    ) -> Result<usize> {
        let total_events = self.total_events;
        let mut merger = RunMerger::new(&self.runs)?;
        while let Some(event) = merger.next_event()? {
            apply(&event)?;
        }
        Ok(total_events)
    }

    pub(crate) async fn replay(self, bus: &BusHandle) -> Result<usize> {
        if let Some(max_timestamp) = self.max_timestamp {
            bus.seed_clock(max_timestamp)?;
        }

        let total_events = self.total_events;
        let mut replayed = 0usize;
        let mut merger = RunMerger::new(&self.runs)?;
        while let Some(event) = merger.next_event()? {
            if SyncPlanner::classify_replay(&event) == ReplayDecision::SkipInfrastructure {
                continue;
            }
            bus.event_bus().send(EventBusFanout(event)).await??;
            replayed += 1;
            if replayed.is_multiple_of(REPLAY_PROGRESS_INTERVAL) {
                info!(
                    replayed_events = replayed,
                    total_events, "EventStore replay progress"
                );
            }
        }
        bus.event_bus().send(EventBusBarrier).await?;
        Ok(replayed)
    }
}

async fn query_page(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate_id: AggregateId,
    cursor: u64,
    page_size: usize,
    page_bytes: usize,
) -> Result<Vec<InterfoldEvent>> {
    let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
    eventstore
        .send(
            EventStoreQueryBy::<SeqAgg>::new(
                CorrelationId::new(),
                std::collections::HashMap::from([(aggregate_id, cursor)]),
                addr,
            )
            .with_limit(page_size as u64)
            .with_max_bytes(page_bytes as u64),
        )
        .await
        .context("EventStore router stopped during paged replay")?;
    rx.await
        .context("EventStore did not return a paged replay response")?
        .into_events()
        .context("EventStore paged replay query failed")
}

fn event_order_key(event: &InterfoldEvent) -> (u128, AggregateId, u64) {
    (event.ts(), event.aggregate_id(), event.seq())
}

fn append_run(
    file: &mut NamedTempFile,
    events: impl IntoIterator<Item = InterfoldEvent>,
) -> Result<()> {
    {
        let mut writer = BufWriter::new(file.as_file_mut());
        for event in events {
            write_event(&mut writer, &event)?;
        }
        writer.flush().context("failed to flush replay spool run")?;
    }
    Ok(())
}

fn compact_runs(mut runs: Vec<NamedTempFile>) -> Result<Vec<NamedTempFile>> {
    while runs.len() > REPLAY_MERGE_FAN_IN {
        let mut next = Vec::with_capacity(runs.len().div_ceil(REPLAY_MERGE_FAN_IN));
        let mut iter = runs.into_iter();
        loop {
            let group: Vec<_> = iter.by_ref().take(REPLAY_MERGE_FAN_IN).collect();
            if group.is_empty() {
                break;
            }
            if group.len() == 1 {
                next.extend(group);
            } else {
                next.push(merge_to_run(&group)?);
            }
        }
        runs = next;
    }
    Ok(runs)
}

fn merge_to_run(runs: &[NamedTempFile]) -> Result<NamedTempFile> {
    let mut output = NamedTempFile::new().context("failed to create merged replay spool file")?;
    {
        let mut writer = BufWriter::new(output.as_file_mut());
        let mut merger = RunMerger::new(runs)?;
        while let Some(event) = merger.next_event()? {
            write_event(&mut writer, &event)?;
        }
        writer
            .flush()
            .context("failed to flush merged replay run")?;
    }
    Ok(output)
}

fn write_event(writer: &mut impl Write, event: &InterfoldEvent) -> Result<()> {
    let bytes = bincode::serialize(event).context("failed to encode replay spool event")?;
    if bytes.len() > MAX_SPOOLED_EVENT_BYTES {
        bail!(
            "replay event encoded to {} bytes, exceeding spool record limit {}",
            bytes.len(),
            MAX_SPOOLED_EVENT_BYTES
        );
    }
    let len = u64::try_from(bytes.len()).context("replay event length does not fit u64")?;
    writer
        .write_all(&len.to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .context("failed to write replay spool event")
}

fn read_event(reader: &mut impl Read) -> Result<Option<InterfoldEvent>> {
    let mut len_bytes = [0u8; 8];
    match reader
        .read(&mut len_bytes[..1])
        .context("failed to read replay spool length")?
    {
        0 => return Ok(None),
        1 => reader
            .read_exact(&mut len_bytes[1..])
            .context("truncated replay spool length prefix")?,
        _ => unreachable!("single-byte read returned more than one byte"),
    }
    let len = usize::try_from(u64::from_le_bytes(len_bytes))
        .context("replay spool record length does not fit usize")?;
    if len > MAX_SPOOLED_EVENT_BYTES {
        bail!(
            "replay spool record length {} exceeds limit {}",
            len,
            MAX_SPOOLED_EVENT_BYTES
        );
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .context("cannot reserve memory for replay spool event")?;
    bytes.resize(len, 0);
    reader
        .read_exact(&mut bytes)
        .context("truncated replay spool event")?;
    e3_utils::deserialize_bounded(&bytes, MAX_SPOOLED_EVENT_BYTES as u64)
        .context("failed to decode replay spool event")
        .map(Some)
}

struct HeapItem {
    key: (u128, AggregateId, u64),
    run: usize,
    event: InterfoldEvent,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.run == other.run
    }
}

impl Eq for HeapItem {}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .key
            .cmp(&self.key)
            .then_with(|| other.run.cmp(&self.run))
    }
}

struct RunMerger {
    readers: Vec<BufReader<File>>,
    heap: BinaryHeap<HeapItem>,
}

impl RunMerger {
    fn new(runs: &[NamedTempFile]) -> Result<Self> {
        let mut readers = Vec::with_capacity(runs.len());
        let mut heap = BinaryHeap::new();
        for (run, file) in runs.iter().enumerate() {
            let mut reader = BufReader::new(
                file.reopen()
                    .context("failed to reopen EventStore replay spool run")?,
            );
            if let Some(event) = read_event(&mut reader)? {
                heap.push(HeapItem {
                    key: event_order_key(&event),
                    run,
                    event,
                });
            }
            readers.push(reader);
        }
        Ok(Self { readers, heap })
    }

    fn next_event(&mut self) -> Result<Option<InterfoldEvent>> {
        let Some(item) = self.heap.pop() else {
            return Ok(None);
        };
        if let Some(event) = read_event(&mut self.readers[item.run])? {
            self.heap.push(HeapItem {
                key: event_order_key(&event),
                run: item.run,
                event,
            });
        }
        Ok(Some(item.event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::{Actor, Handler, Message};
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        EventPublisher, FlushPendingSnapshots, InsertBatch, TestEvent, UpdateDestination,
    };

    #[derive(Default)]
    struct SnapshotCollector(Vec<InsertBatch>);

    impl Actor for SnapshotCollector {
        type Context = actix::Context<Self>;
    }

    impl Handler<InsertBatch> for SnapshotCollector {
        type Result = Result<()>;

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

    #[test]
    fn fresh_snapshot_cursor_starts_at_first_one_based_log_sequence() {
        assert_eq!(first_replay_sequence(0), 1);
        assert_eq!(first_replay_sequence(7), 7);
    }

    #[test]
    fn replay_spool_round_trips_event_above_old_limit() -> Result<()> {
        let message = "x".repeat(64 * 1024 * 1024);
        let event = InterfoldEvent::<e3_events::Unsequenced>::test_event(&message)
            .seq(1)
            .build();
        let mut file = NamedTempFile::new()?;
        write_event(file.as_file_mut(), &event)?;
        let mut reader = BufReader::new(file.reopen()?);
        let restored = read_event(&mut reader)?.context("missing replay event")?;
        assert!(restored == event);
        assert!(read_event(&mut reader)?.is_none());
        Ok(())
    }

    #[actix::test]
    async fn load_pages_a_fresh_log_larger_than_one_query() -> Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("replay-spool-paging");
        let count = REPLAY_QUERY_PAGE_SIZE + 1;
        for index in 0..count {
            bus.publish_without_context(TestEvent::new("paging", index as u64))?;
        }
        bus.flush_event_pipeline().await?;

        let eventstore = system.eventstore_reader()?.seq();
        let spool = ReplaySpool::load(
            &eventstore,
            std::collections::HashMap::from([(AggregateId::new(0), 0)]),
        )
        .await?;

        assert_eq!(spool.total_events(), count);
        assert_eq!(spool.runs.len(), 1);
        Ok(())
    }

    #[actix::test]
    async fn load_continues_after_a_byte_limited_short_page() -> Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("replay-spool-byte-paging");
        let message = "x".repeat(8 * 1024);
        for index in 0..4 {
            bus.publish_without_context(TestEvent::new(&message, index))?;
        }
        bus.flush_event_pipeline().await?;

        let eventstore = system.eventstore_reader()?.seq();
        let spool = ReplaySpool::load_ranges_with_page_limits(
            &eventstore,
            vec![(AggregateId::new(0), 1, None)],
            REPLAY_QUERY_PAGE_SIZE,
            12 * 1024,
        )
        .await?;

        assert_eq!(spool.total_events(), 4);
        Ok(())
    }

    #[actix::test]
    async fn replay_orders_heads_and_preserves_sequence() -> Result<()> {
        let system = EventSystem::new().with_fresh_bus().with_aggregate_config(
            e3_events::AggregateConfig::new(std::collections::HashMap::from([
                (AggregateId::new(1), std::time::Duration::ZERO),
                (AggregateId::new(2), std::time::Duration::ZERO),
            ])),
        );
        let bus = system.handle()?.enable("replay-spool-sequence");
        bus.naked_dispatch_async(
            InterfoldEvent::<e3_events::Unsequenced>::test_event("first")
                .id(1)
                .aggregate_id(1)
                .ts(200)
                .build(),
        )
        .await?;
        bus.naked_dispatch_async(
            InterfoldEvent::<e3_events::Unsequenced>::test_event("second")
                .id(2)
                .aggregate_id(1)
                .ts(100)
                .build(),
        )
        .await?;
        bus.naked_dispatch_async(
            InterfoldEvent::<e3_events::Unsequenced>::test_event("other first")
                .id(3)
                .aggregate_id(2)
                .ts(150)
                .build(),
        )
        .await?;
        bus.naked_dispatch_async(
            InterfoldEvent::<e3_events::Unsequenced>::test_event("other second")
                .id(4)
                .aggregate_id(2)
                .ts(200)
                .build(),
        )
        .await?;
        bus.flush_event_pipeline().await?;

        let spool = ReplaySpool::load_bounded(
            &system.eventstore_reader()?.seq(),
            std::collections::HashMap::from([(AggregateId::new(1), 2), (AggregateId::new(2), 2)]),
        )
        .await?;
        let mut order = Vec::new();
        spool.project(|event| {
            order.push((event.aggregate_id(), event.seq(), event.ts()));
            Ok(())
        })?;

        assert_eq!(
            order,
            [
                (AggregateId::new(2), 1, 150),
                (AggregateId::new(1), 1, 200),
                (AggregateId::new(1), 2, 100),
                (AggregateId::new(2), 2, 200),
            ]
        );
        Ok(())
    }

    #[actix::test]
    async fn replay_opens_snapshot_batches_before_domain_fanout() -> Result<()> {
        let aggregate_id = AggregateId::new(1);
        let config = e3_events::AggregateConfig::new(std::collections::HashMap::from([(
            aggregate_id,
            std::time::Duration::ZERO,
        )]));
        let source = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(config.clone());
        let source_bus = source.handle()?.enable("replay-snapshot-source");
        let chain_id = aggregate_id
            .to_chain_id()
            .context("test aggregate must map to a chain")?;
        for (id, message) in [(1, "first"), (2, "second")] {
            source_bus
                .naked_dispatch_async(
                    InterfoldEvent::<e3_events::Unsequenced>::test_event(message)
                        .id(id)
                        .aggregate_id(chain_id)
                        .ts(u128::from(id))
                        .build(),
                )
                .await?;
        }
        source_bus.flush_event_pipeline().await?;

        let target = EventSystem::new()
            .with_fresh_bus()
            .with_aggregate_config(config);
        let snapshots = SnapshotCollector::default().start();
        let buffer = target.buffer()?;
        buffer
            .send(UpdateDestination::new(snapshots.clone().recipient()))
            .await?;
        let target_bus = target.handle()?.enable("replay-snapshot-target");
        let spool = ReplaySpool::load(
            &source.eventstore_reader()?.seq(),
            std::collections::HashMap::from([(aggregate_id, 0)]),
        )
        .await?;

        let replayed = spool.replay(&target_bus).await?;
        buffer.send(FlushPendingSnapshots).await??;

        let revisions = snapshots
            .send(TakeSnapshots)
            .await?
            .iter()
            .map(InsertBatch::snapshot_revision)
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(replayed, 2);
        assert_eq!(revisions.len(), 2);
        assert_eq!(
            revisions[0]
                .context("first replay revision is missing")?
                .seq(),
            1
        );
        assert_eq!(
            revisions[1]
                .context("second replay revision is missing")?
                .seq(),
            2
        );
        Ok(())
    }
}
