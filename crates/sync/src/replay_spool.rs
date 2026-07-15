// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded external sort for post-snapshot EventStore replay.

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

pub(crate) const REPLAY_QUERY_PAGE_SIZE: usize = 1_024;
const REPLAY_MERGE_FAN_IN: usize = 32;
const MAX_SPOOLED_EVENT_BYTES: usize = 64 * 1024 * 1024;
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
        let mut ordered_cursors: Vec<_> = cursors.into_iter().collect();
        ordered_cursors.sort_by_key(|(aggregate_id, _)| *aggregate_id);

        let mut runs = Vec::new();
        let mut total_events = 0usize;
        let mut max_timestamp: Option<u128> = None;

        for (aggregate_id, snapshot_cursor) in ordered_cursors {
            // Event-log sequence numbers are one-based while a fresh snapshot uses zero.
            // Querying zero is supported by the legacy store API, but it still returns event
            // sequence one; normalize here so integrity validation has one unambiguous cursor.
            let mut cursor = first_replay_sequence(snapshot_cursor);
            loop {
                let mut page = query_page(eventstore, aggregate_id, cursor).await?;
                if page.is_empty() {
                    break;
                }
                if page.len() > REPLAY_QUERY_PAGE_SIZE {
                    bail!(
                        "EventStore returned {} replay events for aggregate {}, exceeding page limit {}",
                        page.len(),
                        aggregate_id,
                        REPLAY_QUERY_PAGE_SIZE
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
                    max_timestamp = Some(max_timestamp.map_or(event.ts(), |ts| ts.max(event.ts())));
                }

                cursor = expected_sequence;
                total_events = total_events
                    .checked_add(page.len())
                    .context("EventStore replay event count overflow")?;
                let page_was_full = page.len() == REPLAY_QUERY_PAGE_SIZE;
                page.sort_by_key(event_order_key);
                runs.push(write_run(page)?);

                if !page_was_full {
                    break;
                }
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

pub(crate) async fn query_page(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate_id: AggregateId,
    cursor: u64,
) -> Result<Vec<InterfoldEvent>> {
    let (addr, rx) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
    eventstore
        .send(
            EventStoreQueryBy::<SeqAgg>::new(
                CorrelationId::new(),
                std::collections::HashMap::from([(aggregate_id, cursor)]),
                addr,
            )
            .with_limit(REPLAY_QUERY_PAGE_SIZE as u64),
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

fn write_run(events: Vec<InterfoldEvent>) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new().context("failed to create EventStore replay spool file")?;
    {
        let mut writer = BufWriter::new(file.as_file_mut());
        for event in events {
            write_event(&mut writer, &event)?;
        }
        writer.flush().context("failed to flush replay spool run")?;
    }
    Ok(file)
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
    let mut bytes = vec![0u8; len];
    reader
        .read_exact(&mut bytes)
        .context("truncated replay spool event")?;
    bincode::deserialize(&bytes)
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
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{E3id, EventPublisher, Sequenced, TestEvent};

    fn event(aggregate: u64, sequence: u64, timestamp: u128) -> InterfoldEvent<Sequenced> {
        InterfoldEvent::<Sequenced>::test_event("spooled")
            .e3_id(E3id::new(sequence.to_string(), aggregate))
            .seq(sequence)
            .ts(timestamp)
            .build()
    }

    #[test]
    fn merge_orders_multiple_bounded_runs_deterministically() -> Result<()> {
        let first = write_run(vec![event(1, 2, 30), event(1, 3, 50)])?;
        let second = write_run(vec![event(2, 1, 10), event(2, 2, 40)])?;
        let third = write_run(vec![event(1, 1, 20), event(3, 1, 40)])?;
        let mut merger = RunMerger::new(&[first, second, third])?;
        let mut keys = Vec::new();
        while let Some(event) = merger.next_event()? {
            keys.push(event_order_key(&event));
        }

        assert_eq!(
            keys,
            vec![
                (10, AggregateId::new(2), 1),
                (20, AggregateId::new(1), 1),
                (30, AggregateId::new(1), 2),
                (40, AggregateId::new(2), 2),
                (40, AggregateId::new(3), 1),
                (50, AggregateId::new(1), 3),
            ]
        );
        Ok(())
    }

    #[test]
    fn fresh_snapshot_cursor_starts_at_first_one_based_log_sequence() {
        assert_eq!(first_replay_sequence(0), 1);
        assert_eq!(first_replay_sequence(7), 7);
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
        assert_eq!(spool.runs.len(), 2);
        Ok(())
    }
}
