// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One peer's history of one aggregate: paged, checked as it arrives, one copy of each event.

use std::collections::{HashMap, HashSet};
use std::iter::Sum;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use e3_events::{
    prelude::*, AggregateId, EventId, EventSource, InterfoldEvent, TimestampClaim, Unsequenced,
};
use tokio::time::Instant;
use tracing::debug;

use crate::{
    direct_requester::{DirectRequester, WithPeer},
    domain::history_messages::{BatchCursor, EventBatch, FetchEventsSince},
    domain::sync_coordinator::MAX_SYNC_BATCH_SIZE,
    NetworkPolicy,
};

/// Startup sync is a recovery aid, not a bulk transfer. A peer that keeps the node busy cannot
/// hold it in startup past this deadline.
const MAX_SYNC_FETCH_DURATION: Duration = Duration::from_secs(5 * 60);

/// Most history that the fetch holds in memory, over all aggregates and the source in progress.
/// Peers can serve several copies of an event; the fetch keeps one.
pub(crate) const MAX_KEPT_HISTORY: HistorySize = HistorySize {
    events: 50_000,
    bytes: 128 * 1024 * 1024,
};

/// The latest event time that the node accepts at the time of the call.
pub(crate) type LatestTs = Arc<dyn Fn() -> Result<u128> + Send + Sync>;

/// The deadline of the whole startup fetch. A fetch past it fails.
pub(crate) struct FetchDeadline {
    started: Instant,
    passed: bool,
}

impl FetchDeadline {
    pub(crate) fn production() -> Self {
        Self {
            started: Instant::now(),
            passed: false,
        }
    }

    pub(crate) fn has_passed(&self) -> bool {
        self.passed
    }

    pub(crate) fn remaining(&mut self) -> Result<Duration> {
        match MAX_SYNC_FETCH_DURATION.checked_sub(self.started.elapsed()) {
            Some(remaining) => Ok(remaining),
            None => self.pass(),
        }
    }

    pub(crate) async fn within<T>(
        &mut self,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        self.within_share(None, work).await
    }

    /// Run `work` within the time left and, with `share_end`, before that time. A source that uses
    /// its share fails, which leaves the rest of the deadline to other sources.
    pub(crate) async fn within_share<T>(
        &mut self,
        share_end: Option<Instant>,
        work: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let remaining = self.remaining()?;
        let share = share_end.map(|end| end.saturating_duration_since(Instant::now()));
        match tokio::time::timeout(share.map_or(remaining, |share| share.min(remaining)), work)
            .await
        {
            Ok(result) => result,
            Err(_) if share.is_some_and(|share| share < remaining) => {
                bail!("the history source used its share of the fetch deadline")
            }
            Err(_) => self.pass(),
        }
    }

    fn pass<T>(&mut self) -> Result<T> {
        self.passed = true;
        bail!("historical sync exceeded total deadline")
    }
}

/// The events and encoded bytes of some history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HistorySize {
    pub(crate) events: usize,
    pub(crate) bytes: usize,
}

impl HistorySize {
    fn of(event: &InterfoldEvent<Unsequenced>) -> Result<Self> {
        let bytes = bincode::serialized_size(event)
            .context("failed to measure a historical sync event")?
            .try_into()
            .context("historical sync event size does not fit usize")?;
        Ok(Self { events: 1, bytes })
    }

    pub(crate) fn plus(self, other: Self) -> Self {
        Self {
            events: self.events.saturating_add(other.events),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    pub(crate) fn minus(self, other: Self) -> Self {
        Self {
            events: self.events.saturating_sub(other.events),
            bytes: self.bytes.saturating_sub(other.bytes),
        }
    }

    fn exceeds(self, limit: Self) -> bool {
        self.events > limit.events || self.bytes > limit.bytes
    }
}

impl Sum for HistorySize {
    fn sum<I: Iterator<Item = Self>>(sizes: I) -> Self {
        sizes.fold(Self::default(), Self::plus)
    }
}

/// The history of one aggregate that the node asks for, and what a peer's events must fit there.
pub(crate) struct HistoryRange {
    pub(crate) aggregate_id: AggregateId,
    pub(crate) since: u128,
    /// The timestamps that events already hold at or after `since`: the node's stored events, and
    /// the events that startup publishes with the history. The event store holds one event at a
    /// timestamp and stops the node on a second one.
    pub(crate) stored: Arc<HashMap<u128, TimestampClaim>>,
    /// The node publishes the history at its latest event time and refuses an event beyond its
    /// clock-drift allowance then.
    pub(crate) latest_ts: LatestTs,
}

/// History events with one copy of each event ID and at most one event at each timestamp. Merging
/// gives the same result for any order of sources when each source's events arrive in timestamp
/// order.
#[derive(Default)]
pub(crate) struct MergedEvents {
    by_id: HashMap<EventId, InterfoldEvent<Unsequenced>>,
    by_ts: HashMap<u128, EventId>,
    size: HistorySize,
}

impl MergedEvents {
    /// Keep one copy of each event. Peers stamp an event with the time that it reached them, so
    /// the earliest copy wins, which makes the result independent of the order of the peers. The
    /// event ID does not fix the whole payload, so two copies with one ID must carry one payload,
    /// and two events must not share a timestamp. Otherwise the merge fails rather than drop one.
    pub(crate) fn merge(&mut self, event: InterfoldEvent<Unsequenced>) -> Result<()> {
        let id = event.id();
        let ts = event.ts();
        if let Some(kept) = self.by_id.get(&id) {
            ensure!(
                kept.get_data() == event.get_data(),
                "history peers served different payloads under event ID {id}"
            );
            if ts >= kept.ts() {
                return Ok(());
            }
        }
        if let Some(other) = self.by_ts.get(&ts) {
            ensure!(
                *other == id,
                "history peers served events {other} and {id} at the same timestamp"
            );
        }
        let size = HistorySize::of(&event)?;
        if let Some(replaced) = self.by_id.insert(id, event) {
            self.by_ts.remove(&replaced.ts());
            self.size = self.size.minus(HistorySize::of(&replaced)?);
        }
        self.by_ts.insert(ts, id);
        self.size = self.size.plus(size);
        Ok(())
    }

    /// Merge `other` in timestamp order, or change nothing when one of its events conflicts. The
    /// check reads only `other`'s events, so a failed merge copies none of the history.
    pub(crate) fn extend(&mut self, other: MergedEvents) -> Result<()> {
        let events = other.into_events();
        // The timestamps that the merge moves events to and frees, as merging in order would.
        let mut moved: HashMap<EventId, u128> = HashMap::new();
        let mut taken: HashMap<u128, EventId> = HashMap::new();
        let mut freed: HashSet<u128> = HashSet::new();
        for event in &events {
            let id = event.id();
            let ts = event.ts();
            let current = match self.by_id.get(&id) {
                Some(kept) => {
                    ensure!(
                        kept.get_data() == event.get_data(),
                        "history peers served different payloads under event ID {id}"
                    );
                    Some(moved.get(&id).copied().unwrap_or(kept.ts()))
                }
                None => None,
            };
            if current.is_some_and(|current| ts >= current) {
                continue;
            }
            let occupant = taken.get(&ts).copied().or_else(|| {
                (!freed.contains(&ts))
                    .then(|| self.by_ts.get(&ts).copied())
                    .flatten()
            });
            if let Some(other) = occupant.filter(|other| *other != id) {
                bail!("history peers served events {other} and {id} at the same timestamp");
            }
            if let Some(current) = current {
                taken.remove(&current);
                freed.insert(current);
            }
            taken.insert(ts, id);
            moved.insert(id, ts);
        }
        events.into_iter().try_for_each(|event| self.merge(event))
    }

    /// Whether `event` adds nothing: the events hold it at the same or an earlier time. Fails when
    /// they hold another payload under its ID.
    fn holds_copy(&self, event: &InterfoldEvent<Unsequenced>) -> Result<bool> {
        let Some(kept) = self.by_id.get(&event.id()) else {
            return Ok(false);
        };
        ensure!(
            kept.get_data() == event.get_data(),
            "history peers served different payloads under event ID {}",
            event.id()
        );
        Ok(kept.ts() <= event.ts())
    }

    pub(crate) fn size(&self) -> HistorySize {
        self.size
    }

    pub(crate) fn into_events(self) -> Vec<InterfoldEvent<Unsequenced>> {
        let mut events: Vec<_> = self.by_id.into_values().collect();
        events.sort_by_key(|event| event.ts());
        events
    }
}

/// One peer's history of a range, checked event by event as its pages arrive. A peer stores an
/// event again each time that the event reaches it after the peer forgot it, and serves every
/// copy. The source keeps one copy of each event that the earlier sources' `held` history lacks,
/// within `room`.
pub(crate) struct SourceHistory<'a> {
    range: &'a HistoryRange,
    held: &'a MergedEvents,
    network: &'a NetworkPolicy,
    room: HistorySize,
    last_ts: Option<u128>,
    kept: MergedEvents,
}

impl<'a> SourceHistory<'a> {
    pub(crate) fn new(
        range: &'a HistoryRange,
        held: &'a MergedEvents,
        network: &'a NetworkPolicy,
        room: HistorySize,
    ) -> Self {
        Self {
            range,
            held,
            network,
            room,
            last_ts: None,
            kept: MergedEvents::default(),
        }
    }

    /// Check one served event, and keep it unless this source or the earlier sources hold it.
    pub(crate) fn add(&mut self, event: InterfoldEvent<Unsequenced>) -> Result<()> {
        let range = self.range;
        if event.ts() < range.since {
            bail!(
                "historical sync peer returned event {} from before the requested range",
                event.id()
            );
        }
        // A peer's store holds one event at a timestamp and serves its history in timestamp order.
        if let Some(last) = self.last_ts.filter(|last| event.ts() <= *last) {
            bail!(
                "historical sync peer returned event {} at timestamp {} after timestamp {last}",
                event.id(),
                event.ts()
            );
        }
        // The same event only: the ID that a stored event carries need not be its payload's.
        if let Some(claim) = range.stored.get(&event.ts()) {
            if !claim.admits(&event)? {
                bail!(
                    "historical sync peer returned event {} at the timestamp of this node's event \
                     {}",
                    event.id(),
                    claim.id
                );
            }
        }
        // The peer supplies the context ID. The merge keeps one event per ID, so a mislabeled
        // event could hide another peer's copy of a different event.
        let payload_id = EventId::hash(event.get_data());
        if event.id() != payload_id {
            bail!(
                "historical sync peer returned event {} whose payload has ID {}",
                event.id(),
                payload_id
            );
        }
        if event.aggregate_id() != range.aggregate_id {
            bail!(
                "historical sync peer returned event for aggregate {} while fetching {}",
                event.aggregate_id(),
                range.aggregate_id
            );
        }
        self.network.validate_peer_event(&event)?;
        self.last_ts = Some(event.ts());
        if self.held.holds_copy(&event)? {
            return Ok(());
        }
        // A peer's history is the network's, whatever source the peer's store recorded.
        self.kept.merge(event.with_source(EventSource::Net))?;
        let kept = self.kept.size();
        ensure!(
            !kept.exceeds(self.room),
            "historical sync exceeded the kept-history limit: the source adds {} events and {} \
             bytes, room for {} events and {} bytes",
            kept.events,
            kept.bytes,
            self.room.events,
            self.room.bytes
        );
        Ok(())
    }

    /// The kept events of a source that served its whole history. The allowance is read at the
    /// end: a peer ahead of this node within it can store events while the node pages through
    /// its history.
    pub(crate) fn finish(self) -> Result<MergedEvents> {
        if let Some(last) = self.last_ts {
            let latest = (self.range.latest_ts)()?;
            if last > latest {
                bail!(
                    "historical sync peer returned an event at {last}, beyond this node's \
                     clock-drift allowance"
                );
            }
        }
        Ok(self.kept)
    }
}

/// Page the requester's peer's history of `source`'s range into `source`. With `source_time`, the
/// source fails when it has not ended in that time, which leaves the rest of the deadline to other
/// sources. Returns the responder's live-history time from its first page.
pub(crate) async fn fetch_source(
    requester: &DirectRequester<WithPeer>,
    source: &mut SourceHistory<'_>,
    deadline: &mut FetchDeadline,
    source_time: Option<Duration>,
) -> Result<Option<u128>> {
    let aggregate_id = source.range.aggregate_id;
    let mut cursor = source.range.since;
    let mut observed_from = None;
    let mut first_page = true;
    let source_end = source_time.map(|time| Instant::now() + time);

    loop {
        let request = FetchEventsSince::new(aggregate_id, cursor, MAX_SYNC_BATCH_SIZE);
        debug!("Fetching history page aggregate={aggregate_id} cursor={cursor}");
        let batch = deadline
            .within_share(
                source_end,
                requester.request::<EventBatch<InterfoldEvent<Unsequenced>>, _>(request),
            )
            .await?;
        ensure!(
            batch.aggregate_id == aggregate_id,
            "sync peer returned aggregate {} while fetching {}",
            batch.aggregate_id,
            aggregate_id
        );
        ensure!(
            batch.events.len() <= MAX_SYNC_BATCH_SIZE,
            "sync peer returned {} events, exceeding requested batch size {}",
            batch.events.len(),
            MAX_SYNC_BATCH_SIZE
        );
        debug!(
            "History page with {} events for aggregate={aggregate_id} cursor={cursor}",
            batch.events.len()
        );
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
        batch
            .events
            .into_iter()
            .try_for_each(|event| source.add(event))?;

        match batch.next {
            BatchCursor::Done => return Ok(observed_from),
            BatchCursor::Next(next_cursor) => {
                ensure!(
                    next_cursor > cursor,
                    "sync peer returned non-advancing cursor {next_cursor} from {cursor}"
                );
                cursor = next_cursor;
            }
        }
    }
}

#[cfg(test)]
#[path = "history_source_tests.rs"]
mod tests;
