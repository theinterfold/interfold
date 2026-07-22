// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    events::{FlushEventStores, PersistEvent},
    Event, EventContextAccessors, EventLog, EventStoreFilter, EventStoreQueryBy,
    EventStoreQueryResponse, InterfoldEvent, Seq, SequenceIndex, Sequenced, Ts, Unsequenced,
};
use actix::{Actor, AsyncContext, Handler, Recipient, WrapFuture};
use anyhow::{bail, Context as _, Result};
use tracing::{error, warn};

const INDEX_RECONCILE_PAGE_SIZE: usize = 1_024;

pub struct EventStore<I: SequenceIndex, L: EventLog> {
    index: I,
    log: L,
}

impl<I: SequenceIndex, L: EventLog> EventStore<I, L> {
    /// Attempt to store an event. Returns the sequenced event on success,
    /// `None` if the event has the same stable identity and payload as the stored event, or an
    /// error on failure. Transport context such as `Local` versus `Net` is not part of the
    /// logical event identity and may legitimately change during historical redelivery.
    pub fn store_event(
        &mut self,
        event: InterfoldEvent<Unsequenced>,
    ) -> Result<Option<InterfoldEvent<Sequenced>>> {
        let ts = event.ts();
        if let Some(indexed_seq) = self.index.get(ts)? {
            let Some((logged_seq, existing)) = self.log.read_from_bounded(indexed_seq, 1)?.next()
            else {
                bail!(
                    "event index corruption at timestamp {ts}: sequence {indexed_seq} is missing \
                     from the event log"
                );
            };
            if logged_seq != indexed_seq {
                bail!(
                    "event index corruption at timestamp {ts}: requested sequence {indexed_seq}, \
                     log returned sequence {logged_seq}"
                );
            }
            if existing.id() == event.id() && existing.get_data() == event.get_data() {
                warn!(
                    timestamp = ts,
                    sequence = indexed_seq,
                    event_id = %event.id(),
                    event_type = %event.get_data().event_type(),
                    incoming_source = ?event.source(),
                    stored_source = ?existing.source(),
                    "Ignoring duplicate logical event"
                );
                return Ok(None);
            }
            bail!(
                "event timestamp collision at {ts}, sequence {indexed_seq}: existing {} ({}) \
                 conflicts with incoming {} ({})",
                existing.id(),
                existing.get_data().event_type(),
                event.id(),
                event.get_data().event_type()
            );
        }
        let seq = self.log.append(&event)?;
        self.index.insert(ts, seq)?;
        Ok(Some(event.into_sequenced(seq)))
    }

    fn collect_events(
        &self,
        iter: Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>,
        filter: Option<EventStoreFilter>,
        limit: Option<u64>,
    ) -> Vec<InterfoldEvent<Sequenced>> {
        let iter = iter.map(|(s, e)| e.into_sequenced(s));

        match filter {
            Some(EventStoreFilter::Source(source)) => {
                let iter = iter.filter(move |e| e.get_ctx().source() == source);
                match limit {
                    Some(lim) => iter.take(lim as usize).collect(),
                    None => iter.collect(),
                }
            }
            None => match limit {
                Some(lim) => iter.take(lim as usize).collect(),
                None => iter.collect(),
            },
        }
    }

    /// Query events by timestamp. Returns events at or after the given timestamp.
    pub fn query_by_ts(
        &self,
        query: u128,
        filter: Option<EventStoreFilter>,
        limit: Option<u64>,
    ) -> Result<Vec<InterfoldEvent<Sequenced>>> {
        let Some(seq) = self.index.seek(query)? else {
            return Ok(vec![]);
        };
        // For unfiltered queries, push the limit down to the log implementation. Historical net
        // sync uses this path and must not read/materialize the complete remaining history for a
        // single remote request. A source-filtered query cannot safely apply the limit before the
        // filter without changing its semantics, so it retains the unbounded iterator path.
        let events = match (filter.as_ref(), limit) {
            (None, Some(limit)) => self
                .log
                .read_from_bounded(seq, usize::try_from(limit).unwrap_or(usize::MAX))?,
            _ => self.log.read_from(seq)?,
        };
        let result = self.collect_events(events, filter, limit);
        Ok(result)
    }

    /// Query events by sequence number. Returns events at or after the given sequence.
    pub fn query_by_seq(
        &self,
        query: u64,
        filter: Option<EventStoreFilter>,
        limit: Option<u64>,
    ) -> Result<Vec<InterfoldEvent<Sequenced>>> {
        // H7: the replay cursor must never point past the log head. The snapshot
        // cursor is committed atomically with its snapshot data, so a cursor ahead
        // of the log can only happen if the two unsynchronised flush timers
        // (Sled vs. commitlog) lost a log entry the cursor already accounted for.
        // Replaying an empty range past the gap would be silent divergence, so we
        // halt loudly. `query == head + 1` is the legitimate "fully caught up" case.
        let head = self.log.head();
        let caught_up = head
            .checked_add(1)
            .context("event-log sequence overflow while checking replay cursor")?;
        if query > caught_up {
            bail!(
                "Replay cursor seq {query} is ahead of the event-log head {head}: the snapshot \
                 cursor references events the log does not contain (lost in a crash flush window). \
                 Halting; operator recovery required."
            );
        }
        Ok(self.collect_events(self.log.read_from(query)?, filter, limit))
    }
}

impl<I: SequenceIndex, L: EventLog> EventStore<I, L> {
    pub fn new(index: I, log: L) -> Result<Self> {
        let mut store = Self { index, log };
        store.reconcile_index()?;
        Ok(store)
    }

    /// H5: the commitlog append and the ts→seq index insert are two non-atomic
    /// writes against different backing stores. A crash between them leaves the
    /// log holding an event with no index entry, so ts-keyed lookups (the net
    /// subscriber cursor) silently miss it until reconciled. On startup we walk
    /// the log (the source of truth) and backfill any missing index rows so the
    /// derived index can never lag the log across a restart.
    fn reconcile_index(&mut self) -> Result<()> {
        let head = self.log.head();
        if head == 0 {
            return Ok(());
        }
        let mut repaired = 0u64;
        let mut next_sequence = 1u64;
        while next_sequence <= head {
            let mut page_len = 0usize;
            for (seq, event) in self
                .log
                .read_from_bounded(next_sequence, INDEX_RECONCILE_PAGE_SIZE)
                .with_context(|| {
                    format!(
                        "event log integrity failure during index reconciliation at sequence \
                         {next_sequence}"
                    )
                })?
            {
                if seq != next_sequence {
                    bail!(
                        "Event log integrity failure during index reconciliation: expected sequence \
                         {next_sequence}, got {seq}. Halting; run `interfold node validate` and \
                         recover from a verified backup or controlled resync."
                    );
                }
                if seq > head {
                    bail!(
                        "Event log changed during index reconciliation: captured head {head}, but \
                         bounded read returned sequence {seq}. Halting to avoid an inconsistent \
                         derived index."
                    );
                }

                let ts = event.ts();
                match self.index.get(ts) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        self.index.insert(ts, seq).with_context(|| {
                            format!(
                                "failed to backfill event index at sequence {seq}; refusing to \
                                 serve an incomplete timestamp index"
                            )
                        })?;
                        repaired += 1;
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed to read event index at timestamp {ts}; refusing to serve \
                                 an unverified timestamp index"
                            )
                        })
                    }
                }
                next_sequence = seq.checked_add(1).with_context(|| {
                    format!("event log sequence overflow while reconciling sequence {seq}")
                })?;
                page_len += 1;
            }

            if page_len == 0 {
                bail!(
                    "Event log integrity failure during index reconciliation: log head is {head}, \
                     but no event was returned for sequence {next_sequence}. Halting; run \
                     `interfold node validate` and recover from a verified backup or controlled \
                     resync."
                );
            }
            if page_len > INDEX_RECONCILE_PAGE_SIZE {
                bail!(
                    "Event log violated bounded-read contract during index reconciliation: \
                     returned {page_len} events for limit {INDEX_RECONCILE_PAGE_SIZE}."
                );
            }
        }
        if repaired > 0 {
            warn!(
                "Reconciled event index on startup: backfilled {repaired} missing ts→seq entries"
            );
        }
        Ok(())
    }
}

impl<I: SequenceIndex, L: EventLog> Actor for EventStore<I, L> {
    type Context = actix::Context<Self>;
}

impl<I: SequenceIndex, L: EventLog> Handler<PersistEvent> for EventStore<I, L> {
    type Result = Result<Option<InterfoldEvent<Sequenced>>>;

    fn handle(&mut self, msg: PersistEvent, _: &mut Self::Context) -> Self::Result {
        let stored = self.store_event(msg.0)?;
        // Flush duplicates too: a previous attempt may have appended and
        // indexed the event but failed its durability acknowledgement.
        self.log
            .flush()
            .context("failed to durably flush accepted event")?;
        Ok(stored)
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<FlushEventStores> for EventStore<I, L> {
    type Result = Result<()>;

    fn handle(&mut self, _: FlushEventStores, _: &mut Self::Context) -> Self::Result {
        self.log.flush()
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<EventStoreQueryBy<Ts>> for EventStore<I, L> {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<Ts>, ctx: &mut Self::Context) -> Self::Result {
        let query = msg.query();
        let id = msg.id();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();
        let response =
            EventStoreQueryResponse::from_result(id, self.query_by_ts(query, filter, limit));
        ctx.wait(
            async move {
                if let Err(error) = deliver_query_response(sender, response).await {
                    error!(%error, "Event-store query recipient closed");
                }
            }
            .into_actor(self),
        );
    }
}

impl<I: SequenceIndex, L: EventLog> Handler<EventStoreQueryBy<Seq>> for EventStore<I, L> {
    type Result = ();
    fn handle(&mut self, msg: EventStoreQueryBy<Seq>, ctx: &mut Self::Context) -> Self::Result {
        let id = msg.id();
        let query = msg.query();
        let limit = msg.limit();
        let filter = msg.filter().cloned();
        let sender = msg.sender();
        let response =
            EventStoreQueryResponse::from_result(id, self.query_by_seq(query, filter, limit));
        ctx.wait(
            async move {
                if let Err(error) = deliver_query_response(sender, response).await {
                    error!(%error, "Event-store query recipient closed");
                }
            }
            .into_actor(self),
        );
    }
}

async fn deliver_query_response(
    sender: Recipient<EventStoreQueryResponse>,
    response: EventStoreQueryResponse,
) -> std::result::Result<(), actix::MailboxError> {
    sender.send(response).await
}

#[cfg(test)]
mod tests {
    use crate::{
        CorrelationId, EventConstructorWithTimestamp, EventContextSeq, EventSource, TestEvent,
    };

    use super::*;
    use anyhow::Result;
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    // ---------------------------------------------------------------------------
    // Mock SequenceIndex backed by BTreeMap
    // ---------------------------------------------------------------------------
    struct MockIndex(BTreeMap<u128, u64>);

    impl MockIndex {
        fn new() -> Self {
            Self(BTreeMap::new())
        }
    }

    impl SequenceIndex for MockIndex {
        fn insert(&mut self, key: u128, value: u64) -> Result<()> {
            self.0.insert(key, value);
            Ok(())
        }

        fn get(&self, key: u128) -> Result<Option<u64>> {
            Ok(self.0.get(&key).copied())
        }

        fn seek(&self, key: u128) -> Result<Option<u64>> {
            Ok(self.0.range(key..).next().map(|(_, &v)| v))
        }
    }

    // ---------------------------------------------------------------------------
    // Mock EventLog backed by Vec
    // ---------------------------------------------------------------------------
    struct MockLog {
        events: Vec<InterfoldEvent<Unsequenced>>,
        bounded_read_calls: Option<Arc<AtomicUsize>>,
        bounded_read_limit: Option<Arc<AtomicUsize>>,
        flushes: Option<Arc<AtomicUsize>>,
        unbounded_read_calls: Option<Arc<AtomicUsize>>,
        fail_reads: bool,
    }

    impl MockLog {
        fn new() -> Self {
            Self {
                events: Vec::new(),
                bounded_read_calls: None,
                bounded_read_limit: None,
                flushes: None,
                unbounded_read_calls: None,
                fail_reads: false,
            }
        }

        fn with_bounded_read_tracker(tracker: Arc<AtomicUsize>) -> Self {
            Self {
                events: Vec::new(),
                bounded_read_calls: None,
                bounded_read_limit: Some(tracker),
                flushes: None,
                unbounded_read_calls: None,
                fail_reads: false,
            }
        }

        fn with_flush_tracker(tracker: Arc<AtomicUsize>) -> Self {
            Self {
                events: Vec::new(),
                bounded_read_calls: None,
                bounded_read_limit: None,
                flushes: Some(tracker),
                unbounded_read_calls: None,
                fail_reads: false,
            }
        }

        fn with_reconcile_trackers(
            events: Vec<InterfoldEvent<Unsequenced>>,
            bounded_read_calls: Arc<AtomicUsize>,
            bounded_read_limit: Arc<AtomicUsize>,
            unbounded_read_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events,
                bounded_read_calls: Some(bounded_read_calls),
                bounded_read_limit: Some(bounded_read_limit),
                flushes: None,
                unbounded_read_calls: Some(unbounded_read_calls),
                fail_reads: false,
            }
        }

        fn failing_reads() -> Self {
            Self {
                fail_reads: true,
                ..Self::new()
            }
        }
    }

    impl EventLog for MockLog {
        fn append(&mut self, event: &InterfoldEvent<Unsequenced>) -> Result<u64> {
            self.events.push(event.clone());
            Ok(self.events.len() as u64)
        }

        fn flush(&mut self) -> Result<()> {
            if let Some(flushes) = &self.flushes {
                flushes.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }

        fn read_from(
            &self,
            from: u64,
        ) -> Result<Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>> {
            if self.fail_reads {
                bail!("simulated event-log integrity failure");
            }
            if let Some(calls) = &self.unbounded_read_calls {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            let items: Vec<_> = self
                .events
                .iter()
                .enumerate()
                .filter(move |(i, _)| (*i as u64 + 1) >= from)
                .map(|(i, e)| (i as u64 + 1, e.clone()))
                .collect();
            Ok(Box::new(items.into_iter()))
        }

        fn read_from_bounded(
            &self,
            from: u64,
            limit: usize,
        ) -> Result<Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>> {
            if self.fail_reads {
                bail!("simulated event-log integrity failure");
            }
            if let Some(calls) = &self.bounded_read_calls {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(tracker) = &self.bounded_read_limit {
                tracker.fetch_max(limit, Ordering::SeqCst);
            }
            let items: Vec<_> = self
                .events
                .iter()
                .enumerate()
                .filter(move |(i, _)| (*i as u64 + 1) >= from)
                .take(limit)
                .map(|(i, event)| (i as u64 + 1, event.clone()))
                .collect();
            Ok(Box::new(items.into_iter()))
        }

        fn head(&self) -> u64 {
            self.events.len() as u64
        }
    }

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------
    fn make_event(ts: u128, source: EventSource) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("test", 1).into(),
            None,
            ts,
            None,
            source,
        )
    }

    fn make_distinct_event(ts: u128, source: EventSource) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("different", 2).into(),
            None,
            ts,
            None,
            source,
        )
    }

    fn make_local_event(ts: u128) -> InterfoldEvent<Unsequenced> {
        make_event(ts, EventSource::Local)
    }

    fn make_network_event(ts: u128) -> InterfoldEvent<Unsequenced> {
        make_event(ts, EventSource::Net)
    }

    fn new_store() -> EventStore<MockIndex, MockLog> {
        EventStore::new(MockIndex::new(), MockLog::new()).unwrap()
    }

    fn populated_store(events: &[InterfoldEvent<Unsequenced>]) -> EventStore<MockIndex, MockLog> {
        let mut store = new_store();
        for event in events {
            store.store_event(event.clone()).unwrap();
        }
        store
    }

    // ===========================================================================
    // store_event
    // ===========================================================================

    #[test]
    fn store_event_returns_sequenced_event() {
        let mut store = new_store();
        let event = make_local_event(100);

        let result = store.store_event(event).unwrap().unwrap();

        assert_eq!(result.get_ctx().ts(), 100);
    }

    #[test]
    fn store_event_assigns_incrementing_sequence_numbers() {
        let mut store = new_store();

        let _a = store.store_event(make_local_event(100)).unwrap().unwrap();
        let _b = store.store_event(make_local_event(200)).unwrap().unwrap();
        let _c = store.store_event(make_local_event(300)).unwrap().unwrap();

        assert_eq!(store.index.get(100).unwrap(), Some(1));
        assert_eq!(store.index.get(200).unwrap(), Some(2));
        assert_eq!(store.index.get(300).unwrap(), Some(3));
    }

    #[test]
    fn store_event_appends_to_log() {
        let mut store = new_store();
        store.store_event(make_local_event(100)).unwrap();
        store.store_event(make_local_event(200)).unwrap();

        let logged: Vec<_> = store.log.read_from(1).unwrap().collect();
        assert_eq!(logged.len(), 2);
    }

    #[actix::test]
    async fn shutdown_flush_message_reaches_event_log() -> Result<()> {
        let flushes = Arc::new(AtomicUsize::new(0));
        let store = EventStore::new(
            MockIndex::new(),
            MockLog::with_flush_tracker(Arc::clone(&flushes)),
        )
        .unwrap()
        .start();

        store.send(FlushEventStores).await??;

        assert_eq!(flushes.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[actix::test]
    async fn persistence_acknowledgement_crosses_the_flush_boundary() -> Result<()> {
        let flushes = Arc::new(AtomicUsize::new(0));
        let store = EventStore::new(
            MockIndex::new(),
            MockLog::with_flush_tracker(Arc::clone(&flushes)),
        )?
        .start();

        let stored = store.send(PersistEvent(make_local_event(100))).await??;

        assert!(stored.is_some());
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        let duplicate = store.send(PersistEvent(make_local_event(100))).await??;
        assert!(duplicate.is_none());
        assert_eq!(flushes.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[actix::test]
    async fn query_response_waits_for_a_full_recipient_mailbox() {
        use tokio::sync::{mpsc, Notify};

        struct SaturatedResponseSink {
            block_first: bool,
            gate: Arc<Notify>,
            received: mpsc::UnboundedSender<()>,
        }

        impl Actor for SaturatedResponseSink {
            type Context = actix::Context<Self>;

            fn started(&mut self, ctx: &mut Self::Context) {
                ctx.set_mailbox_capacity(1);
            }
        }

        impl Handler<EventStoreQueryResponse> for SaturatedResponseSink {
            type Result = ();

            fn handle(
                &mut self,
                _: EventStoreQueryResponse,
                ctx: &mut Self::Context,
            ) -> Self::Result {
                self.received.send(()).unwrap();
                if self.block_first {
                    self.block_first = false;
                    let gate = Arc::clone(&self.gate);
                    ctx.wait(async move { gate.notified().await }.into_actor(self));
                }
            }
        }

        let gate = Arc::new(Notify::new());
        let (received_tx, mut received_rx) = mpsc::unbounded_channel();
        let sink = SaturatedResponseSink {
            block_first: true,
            gate: Arc::clone(&gate),
            received: received_tx,
        }
        .start();
        let recipient = sink.recipient();

        recipient.do_send(EventStoreQueryResponse::new(CorrelationId::new(), vec![]));
        received_rx.recv().await.unwrap();
        recipient
            .try_send(EventStoreQueryResponse::new(CorrelationId::new(), vec![]))
            .unwrap();

        let delivery = tokio::spawn(deliver_query_response(
            recipient,
            EventStoreQueryResponse::new(CorrelationId::new(), vec![]),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !delivery.is_finished(),
            "delivery must wait instead of dropping a full-mailbox response"
        );

        gate.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), delivery)
            .await
            .expect("response delivery should resume after mailbox capacity is available")
            .unwrap()
            .unwrap();
        received_rx.recv().await.unwrap();
        received_rx.recv().await.unwrap();
    }

    #[actix::test]
    async fn query_read_failure_is_returned_without_panicking_the_actor() {
        struct ResponseSink(Option<tokio::sync::oneshot::Sender<EventStoreQueryResponse>>);

        impl Actor for ResponseSink {
            type Context = actix::Context<Self>;
        }

        impl Handler<EventStoreQueryResponse> for ResponseSink {
            type Result = ();

            fn handle(
                &mut self,
                msg: EventStoreQueryResponse,
                _: &mut Self::Context,
            ) -> Self::Result {
                self.0.take().unwrap().send(msg).ok();
            }
        }

        let store = EventStore::new(MockIndex::new(), MockLog::failing_reads())
            .unwrap()
            .start();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sink = ResponseSink(Some(sender)).start();
        store.do_send(EventStoreQueryBy::<Seq>::new(
            CorrelationId::new(),
            1,
            sink.recipient(),
        ));

        let response = receiver.await.unwrap();
        let error = response.into_events().unwrap_err();
        assert!(error
            .to_string()
            .contains("simulated event-log integrity failure"));
        store.send(FlushEventStores).await.unwrap().unwrap();
    }

    #[test]
    fn startup_index_reconciliation_reads_log_in_bounded_pages() {
        let event_count = INDEX_RECONCILE_PAGE_SIZE * 2 + 2;
        let events = (1..=event_count)
            .map(|timestamp| make_local_event(timestamp as u128))
            .collect::<Vec<_>>();
        let bounded_calls = Arc::new(AtomicUsize::new(0));
        let max_limit = Arc::new(AtomicUsize::new(0));
        let unbounded_calls = Arc::new(AtomicUsize::new(0));
        let log = MockLog::with_reconcile_trackers(
            events,
            Arc::clone(&bounded_calls),
            Arc::clone(&max_limit),
            Arc::clone(&unbounded_calls),
        );

        let store = EventStore::new(MockIndex::new(), log).unwrap();

        assert_eq!(unbounded_calls.load(Ordering::SeqCst), 0);
        assert_eq!(bounded_calls.load(Ordering::SeqCst), 3);
        assert_eq!(max_limit.load(Ordering::SeqCst), INDEX_RECONCILE_PAGE_SIZE);
        assert_eq!(
            store.index.get(event_count as u128).unwrap(),
            Some(event_count as u64)
        );
    }

    #[test]
    fn exact_duplicate_is_indefinitely_idempotent() {
        let mut store = new_store();
        let event = make_local_event(100);
        store.store_event(event.clone()).unwrap();

        for _ in 0..100 {
            let result = store.store_event(event.clone()).unwrap();
            assert!(result.is_none());
        }

        assert_eq!(store.log.read_from(1).unwrap().count(), 1);
    }

    #[test]
    fn local_event_redelivered_from_network_is_idempotent() {
        let mut store = new_store();
        store.store_event(make_local_event(100)).unwrap();

        assert!(store
            .store_event(make_network_event(100))
            .unwrap()
            .is_none());
        let stored = store.log.read_from(1).unwrap().next().unwrap().1;
        assert_eq!(stored.source(), EventSource::Local);
        assert_eq!(store.log.read_from(1).unwrap().count(), 1);
    }

    #[test]
    fn conflicting_payload_at_same_timestamp_fails_immediately() {
        let mut store = new_store();
        store.store_event(make_local_event(100)).unwrap();

        let error = store
            .store_event(make_distinct_event(100, EventSource::Net))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("timestamp collision"), "{message}");
        assert!(message.contains("sequence 1"), "{message}");
        assert_eq!(store.log.read_from(1).unwrap().count(), 1);
    }

    // ===========================================================================
    // query_by_seq
    // ===========================================================================

    #[test]
    fn seq_query_returns_all_events() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
        ]);

        let events = store.query_by_seq(1, None, None).unwrap();

        assert_eq!(events.len(), 3);
    }

    #[test]
    fn seq_query_reads_from_given_offset() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
            make_local_event(400),
        ]);

        let events = store.query_by_seq(3, None, None).unwrap();

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn seq_query_with_source_filter() {
        let store = populated_store(&[
            make_local_event(100),
            make_network_event(200),
            make_local_event(300),
            make_network_event(400),
        ]);

        let events = store
            .query_by_seq(1, Some(EventStoreFilter::Source(EventSource::Local)), None)
            .unwrap();

        assert_eq!(events.len(), 2);
        for e in &events {
            assert_eq!(e.get_ctx().source(), EventSource::Local);
        }
    }

    #[test]
    fn seq_query_with_limit() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
            make_local_event(400),
            make_local_event(500),
        ]);

        let events = store.query_by_seq(1, None, Some(2)).unwrap();

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn seq_query_with_filter_and_limit() {
        let store = populated_store(&[
            make_local_event(100),
            make_network_event(200),
            make_local_event(300),
            make_local_event(400),
            make_network_event(500),
        ]);

        let events = store
            .query_by_seq(
                1,
                Some(EventStoreFilter::Source(EventSource::Local)),
                Some(2),
            )
            .unwrap();

        assert_eq!(events.len(), 2);
        for e in &events {
            assert_eq!(e.get_ctx().source(), EventSource::Local);
        }
    }

    #[test]
    fn seq_query_on_empty_log_returns_empty() {
        let store = new_store();

        let events = store.query_by_seq(1, None, None).unwrap();

        assert!(events.is_empty());
    }

    // ===========================================================================
    // query_by_ts
    // ===========================================================================

    #[test]
    fn ts_query_returns_events_from_exact_timestamp() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
            make_local_event(400),
        ]);

        let events = store.query_by_ts(200, None, None).unwrap();

        assert_eq!(events.len(), 3);
    }

    #[test]
    fn ts_query_seeks_to_nearest_future_timestamp() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(300),
            make_local_event(500),
        ]);

        // ts=200 has no match; seek finds ts=300 onwards
        let events = store.query_by_ts(200, None, None).unwrap();

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn ts_query_returns_empty_when_no_matching_timestamp() {
        let store = new_store();

        let events = store.query_by_ts(999, None, None).unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn ts_query_returns_empty_when_past_all_events() {
        let store = populated_store(&[make_local_event(100), make_local_event(200)]);

        let events = store.query_by_ts(999, None, None).unwrap();

        assert!(events.is_empty());
    }

    #[test]
    fn ts_query_with_filter() {
        let store = populated_store(&[
            make_local_event(100),
            make_network_event(200),
            make_local_event(300),
        ]);

        let events = store
            .query_by_ts(100, Some(EventStoreFilter::Source(EventSource::Net)), None)
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].get_ctx().source(), EventSource::Net);
    }

    #[test]
    fn ts_query_with_limit() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
            make_local_event(400),
        ]);

        let events = store.query_by_ts(100, None, Some(2)).unwrap();

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn ts_query_pushes_unfiltered_limit_into_event_log() {
        let observed_limit = Arc::new(AtomicUsize::new(0));
        let log = MockLog::with_bounded_read_tracker(observed_limit.clone());
        let mut store = EventStore::new(MockIndex::new(), log).unwrap();
        for timestamp in [100, 200, 300, 400] {
            store.store_event(make_local_event(timestamp)).unwrap();
        }

        let events = store.query_by_ts(100, None, Some(2)).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(observed_limit.load(Ordering::SeqCst), 2);
    }

    // ===========================================================================
    // Pagination / Cursor boundary tests
    // ===========================================================================

    #[test]
    fn ts_query_is_inclusive_at_boundary() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
        ]);

        let page1 = store.query_by_ts(100, None, Some(2)).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].get_ctx().ts(), 100);
        assert_eq!(page1[1].get_ctx().ts(), 200);

        let page2 = store.query_by_ts(200, None, Some(2)).unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].get_ctx().ts(), 200);
        assert_eq!(page2[1].get_ctx().ts(), 300);
    }

    #[test]
    fn ts_query_cursor_off_by_one_causes_duplicates() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
        ]);

        let page1 = store.query_by_ts(100, None, Some(2)).unwrap();
        assert_eq!(page1.len(), 2);

        let cursor_ts = page1.last().unwrap().get_ctx().ts();
        assert_eq!(cursor_ts, 200);

        let page2 = store.query_by_ts(cursor_ts, None, None).unwrap();
        assert_eq!(page2.len(), 2);

        let total: Vec<_> = page1.iter().chain(page2.iter()).collect();
        let ts_values: Vec<_> = total.iter().map(|e| e.get_ctx().ts()).collect();
        let has_duplicates = ts_values.len()
            != ts_values
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len();

        assert!(
            has_duplicates,
            "BUG: ts=200 appears in both pages (inclusive query with cursor=last_ts)"
        );
    }

    #[test]
    fn ts_query_pagination_without_duplicates() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
            make_local_event(400),
        ]);

        let page1 = store.query_by_ts(100, None, Some(2)).unwrap();
        assert_eq!(page1.len(), 2);

        let cursor_ts = page1.last().unwrap().get_ctx().ts() + 1;
        let page2 = store.query_by_ts(cursor_ts, None, Some(2)).unwrap();

        let all_ts: Vec<_> = page1
            .iter()
            .chain(page2.iter())
            .map(|e| e.get_ctx().ts())
            .collect();

        assert_eq!(all_ts.len(), 4);
        assert_eq!(all_ts, vec![100, 200, 300, 400]);
    }

    #[test]
    fn seq_query_is_inclusive_at_boundary() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
        ]);

        let page1 = store.query_by_seq(1, None, Some(2)).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].seq(), 1);
        assert_eq!(page1[1].seq(), 2);

        let page2 = store.query_by_seq(2, None, Some(2)).unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].seq(), 2);
        assert_eq!(page2[1].seq(), 3);
    }

    #[test]
    fn seq_query_cursor_off_by_one_causes_duplicates() {
        let store = populated_store(&[
            make_local_event(100),
            make_local_event(200),
            make_local_event(300),
        ]);

        let page1 = store.query_by_seq(1, None, Some(2)).unwrap();
        assert_eq!(page1.len(), 2);

        let cursor_seq = page1.last().unwrap().seq();
        assert_eq!(cursor_seq, 2);

        let page2 = store.query_by_seq(cursor_seq, None, None).unwrap();
        assert_eq!(page2.len(), 2);

        let total: Vec<_> = page1.iter().chain(page2.iter()).collect();
        let seq_values: Vec<_> = total.iter().map(|e| e.seq()).collect();
        let has_duplicates = seq_values.len()
            != seq_values
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len();

        assert!(
            has_duplicates,
            "BUG: seq=2 appears in both pages (inclusive query with cursor=last_seq)"
        );
    }
}
