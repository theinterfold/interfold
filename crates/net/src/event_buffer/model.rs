// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::fmt::Debug;
use std::sync::Arc;

use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use e3_events::AggregateId;
use serde::Serialize;
use tokio::time::Instant;
use tracing::{debug, info};

use crate::{
    direct_requester::{DirectRequester, WithPeer, WithoutPeer},
    domain::sync_coordinator::effective_sync_limit,
    domain::wire::{decode_sync, encode_sync, SyncMessageKind},
    events::PeerTarget,
};

/// Startup sync is a recovery aid, not an unbounded bulk-transfer protocol. These limits prevent
/// a peer from keeping a node in startup indefinitely or retaining an attacker-controlled history
/// in memory. Operators with a larger legitimate gap must use the controlled resync procedure.
const MAX_SYNC_FETCH_PAGES: usize = 512;
const MAX_SYNC_FETCH_EVENTS: usize = 50_000;
const MAX_SYNC_FETCH_BYTES: usize = 128 * 1024 * 1024;
const MAX_SYNC_FETCH_DURATION: Duration = Duration::from_secs(5 * 60);

pub(crate) struct SyncFetchBudget {
    started: Instant,
    pages: usize,
    events: usize,
    bytes: usize,
    max_pages: usize,
    max_events: usize,
    max_bytes: usize,
    max_duration: Duration,
    exhausted: bool,
    /// The latest event time that the fetch accepts now: a later one exceeds this node's
    /// clock-drift allowance, which applies again when the history is published.
    latest_ts: LatestTs,
}

/// The latest event time that the node accepts at the time of the call.
pub(crate) type LatestTs = Arc<dyn Fn() -> Result<u128> + Send + Sync>;

impl SyncFetchBudget {
    pub(crate) fn production() -> Self {
        Self::new(
            MAX_SYNC_FETCH_PAGES,
            MAX_SYNC_FETCH_EVENTS,
            MAX_SYNC_FETCH_BYTES,
        )
    }

    fn new(max_pages: usize, max_events: usize, max_bytes: usize) -> Self {
        Self {
            started: Instant::now(),
            pages: 0,
            events: 0,
            bytes: 0,
            max_pages,
            max_events,
            max_bytes,
            max_duration: MAX_SYNC_FETCH_DURATION,
            exhausted: false,
            latest_ts: Arc::new(|| Ok(u128::MAX)),
        }
    }

    /// Refuse events stamped after the time that `latest_ts` returns when a history is checked.
    pub(crate) fn with_latest_ts(mut self, latest_ts: LatestTs) -> Self {
        self.latest_ts = latest_ts;
        self
    }

    /// The latest event time that the fetch accepts now.
    pub(crate) fn latest_ts(&self) -> Result<u128> {
        (self.latest_ts)()
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// The time left, or an error that marks the budget exhausted.
    pub(crate) fn remaining(&mut self) -> Result<Duration> {
        match self.max_duration.checked_sub(self.started.elapsed()) {
            Some(remaining) => Ok(remaining),
            None => {
                self.exhausted = true;
                bail!("historical sync exceeded total deadline")
            }
        }
    }

    /// Run `work` within the time left, and mark the budget exhausted when the time runs out.
    pub(crate) async fn within<T>(
        &mut self,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let remaining = self.remaining()?;
        match tokio::time::timeout(remaining, work).await {
            Ok(result) => result,
            Err(_) => {
                self.exhausted = true;
                bail!("historical sync exceeded total deadline")
            }
        }
    }

    fn record_page(&mut self, event_count: usize, encoded_bytes: usize) -> Result<()> {
        let pages = self
            .pages
            .checked_add(1)
            .context("sync page count overflow")?;
        let events = self
            .events
            .checked_add(event_count)
            .context("sync event count overflow")?;
        let bytes = self
            .bytes
            .checked_add(encoded_bytes)
            .context("sync byte count overflow")?;

        if pages > self.max_pages {
            self.exhausted = true;
            bail!("historical sync exceeded page limit ({})", self.max_pages);
        }
        if events > self.max_events {
            self.exhausted = true;
            bail!("historical sync exceeded event limit ({})", self.max_events);
        }
        if bytes > self.max_bytes {
            self.exhausted = true;
            bail!("historical sync exceeded byte limit ({})", self.max_bytes);
        }

        self.pages = pages;
        self.events = events;
        self.bytes = bytes;
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum BatchCursor {
    Done,
    Next(u128),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EventBatch<E: Debug> {
    pub events: Vec<E>,
    pub next: BatchCursor,
    pub aggregate_id: AggregateId,
    /// Timestamp from which the responder stores this network's history live: the time when the
    /// gossip that it held during its own startup became durable. `None` while it still starts
    /// up. A responder vouches only for history at or after this time; earlier records come from
    /// its log and from its own peers.
    pub observed_from: Option<u128>,
}

impl<E: Debug> TryFrom<Vec<u8>> for EventBatch<E>
where
    E: serde::de::DeserializeOwned,
{
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        decode_sync(&value, SyncMessageKind::EventBatch).context("failed to deserialize EventBatch")
    }
}

impl<E: Debug> TryFrom<EventBatch<E>> for Vec<u8>
where
    E: serde::Serialize,
{
    type Error = anyhow::Error;

    fn try_from(value: EventBatch<E>) -> Result<Self> {
        encode_sync(SyncMessageKind::EventBatch, &value).context("failed to serialize EventBatch")
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct FetchEventsSince {
    aggregate_id: AggregateId,
    since: u128,
    limit: usize,
}

impl FetchEventsSince {
    pub fn new(aggregate_id: AggregateId, since: u128, limit: usize) -> Self {
        Self {
            aggregate_id,
            since,
            limit,
        }
    }

    pub fn aggregate_id(&self) -> AggregateId {
        self.aggregate_id
    }

    pub fn since(&self) -> u128 {
        self.since
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl TryFrom<FetchEventsSince> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(value: FetchEventsSince) -> Result<Self> {
        encode_sync(SyncMessageKind::FetchEvents, &value)
            .context("failed to serialize FetchEventsSince")
    }
}

impl TryFrom<Vec<u8>> for FetchEventsSince {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        decode_sync(&value, SyncMessageKind::FetchEvents)
            .context("failed to deserialize FetchEventsSince")
    }
}

pub async fn fetch_events_since<E>(
    requester: &DirectRequester<WithPeer>,
    request: FetchEventsSince,
) -> Result<EventBatch<E>>
where
    E: Debug + TryFrom<Vec<u8>> + Send + Sync + 'static,
    EventBatch<E>: TryFrom<Vec<u8>>,
{
    requester.request(request).await
}

/// The history that one peer served for an aggregate.
#[derive(Debug)]
pub(crate) struct PeerHistory<E> {
    pub events: Vec<E>,
    /// The responder's `observed_from`, the same on every page.
    pub observed_from: Option<u128>,
}

/// Fetch the history of `aggregate_id` after `since`, page by page. With `source_time`, the source
/// fails when it has not ended in that time, which leaves the rest of the budget to other sources.
pub(crate) async fn fetch_all_batched_events_with_budget<E>(
    requester: DirectRequester<WithoutPeer>,
    peer: PeerTarget,
    aggregate_id: AggregateId,
    since: u128,
    batch_size: usize,
    budget: &mut SyncFetchBudget,
    source_time: Option<Duration>,
) -> Result<PeerHistory<E>>
where
    E: Debug + Serialize + TryFrom<Vec<u8>> + Send + Sync + 'static,
    EventBatch<E>: TryFrom<Vec<u8>>,
{
    ensure!(batch_size > 0, "sync batch size must be greater than 0");
    let batch_size = effective_sync_limit(batch_size);
    let requester = requester.to(peer);
    let mut all_events = Vec::new();
    let mut cursor = since;
    let mut observed_from = None;
    let mut first_page = true;
    let source_deadline = source_time.map(|time| Instant::now() + time);

    loop {
        let request = FetchEventsSince::new(aggregate_id, cursor, batch_size);
        info!(
            "Fetching batch aggregate={} cursor={} batch_size={}",
            aggregate_id, cursor, batch_size
        );
        let remaining = budget.remaining()?;
        let source_left =
            source_deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let wait = source_left.map_or(remaining, |left| left.min(remaining));
        let batch = match tokio::time::timeout(wait, fetch_events_since(&requester, request)).await
        {
            Ok(result) => result?,
            Err(_) if source_left.is_some_and(|left| left < remaining) => {
                bail!("the history source used its share of the fetch deadline");
            }
            Err(_) => {
                budget.exhausted = true;
                bail!("historical sync exceeded total deadline");
            }
        };
        ensure!(
            batch.aggregate_id == aggregate_id,
            "sync peer returned aggregate {} while fetching {}",
            batch.aggregate_id,
            aggregate_id
        );
        ensure!(
            batch.events.len() <= batch_size,
            "sync peer returned {} events, exceeding requested batch size {}",
            batch.events.len(),
            batch_size
        );
        info!(
            "Batch received with {} events for aggregate={} cursor={}",
            batch.events.len(),
            aggregate_id,
            cursor
        );

        let page_bytes: usize = bincode::serialized_size(&batch.events)
            .context("failed to measure historical sync page")?
            .try_into()
            .context("historical sync page size does not fit usize")?;
        budget.record_page(batch.events.len(), page_bytes)?;
        // A responder that restarts or resets between two pages serves the rest from another log,
        // and loses the time that it had. Its pages then do not form one history, so the source
        // fails. A responder that ends its own startup during the fetch keeps its log; the source
        // keeps the time of its first page, `None`, so it vouches for nothing.
        if first_page {
            observed_from = batch.observed_from;
            first_page = false;
        } else if observed_from.is_some() {
            ensure!(
                batch.observed_from == observed_from,
                "sync peer changed its live-history time from {observed_from:?} to {:?} between \
                 pages",
                batch.observed_from
            );
        }
        all_events
            .try_reserve(batch.events.len())
            .map_err(|error| {
                anyhow::anyhow!("failed to reserve historical sync buffer: {error}")
            })?;
        all_events.extend(batch.events);

        match batch.next {
            BatchCursor::Done => break,
            BatchCursor::Next(next_cursor) => {
                ensure!(
                    next_cursor > cursor,
                    "sync peer returned non-advancing cursor {next_cursor} from {cursor}"
                );
                cursor = next_cursor;
            }
        }
    }

    debug!(
        "Historical sync fetch complete: {} events",
        all_events.len()
    );

    Ok(PeerHistory {
        events: all_events,
        observed_from,
    })
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
