// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::HashMap,
    fmt,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use e3_events::{E3id, PartyId};
use e3_utils::ArcBytes;

use crate::{backoff::backoff_delay, events::DocumentPublishedNotification, ContentHash};

/// First delay before a replicated document is announced again. Later announcements back off.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
/// First delay before a failed publication is retried. Later retries back off.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(15);
/// Longest delay between announcements, and between retries.
pub const MAX_ANNOUNCE_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Age after which a replicated document is stored on the DHT again. Peers can drop records, so
/// the publisher refreshes them, but rarely: one refresh sends the whole document to up to 20
/// peers.
pub const REPLICATION_REFRESH: Duration = Duration::from_secs(30 * 60);

/// When a pending publication next replicates the full document and when it is announced again.
///
/// A replication stores the document on the DHT. An announcement gossips a small notification
/// that names it. Only the first announcement and a refresh after [`REPLICATION_REFRESH`] upload
/// the document; other announcements send the notification only.
#[derive(Clone, Debug, Default)]
pub struct PublicationSchedule {
    replicated_at: Option<Instant>,
    announcements: u32,
    failures: u32,
}

impl PublicationSchedule {
    /// Whether the next announcement must store the full document first.
    pub fn needs_replication(&self, now: Instant) -> bool {
        self.replicated_at
            .is_none_or(|at| now.saturating_duration_since(at) >= REPLICATION_REFRESH)
    }

    /// Record a completed DHT replication.
    pub fn record_replicated(&mut self, now: Instant) {
        self.replicated_at = Some(now);
        self.announcements = 0;
    }

    /// Record a completed announcement and return the delay before the next one.
    pub fn record_announced(&mut self) -> Duration {
        self.failures = 0;
        self.announcements = self.announcements.saturating_add(1);
        backoff_delay(ANNOUNCE_INTERVAL, self.announcements, MAX_ANNOUNCE_BACKOFF)
    }

    /// Record a failed replication or announcement and return the delay before the retry.
    pub fn record_failed(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        backoff_delay(RETRY_INTERVAL, self.failures, MAX_ANNOUNCE_BACKOFF)
    }
}

/// Delay before a failed document fetch is tried again, after `failures` consecutive failures.
pub fn fetch_retry_delay(failures: u32) -> Duration {
    backoff_delay(RETRY_INTERVAL, failures, MAX_ANNOUNCE_BACKOFF)
}

/// Most party filters that a document notification can carry. Documents name no party or one.
const MAX_NOTIFICATION_FILTERS: usize = 8;
/// Longest E3 identifier in a notification: a decimal `uint256` has at most 78 digits.
const MAX_NOTIFICATION_E3_ID_LEN: usize = 78;

/// Whether a notification has a shape this node can act on: a SHA-256 content hash, a small party
/// filter, and a `uint256` E3 identifier. Peers choose every field, so the node checks the sizes
/// before it buffers or queues a notification.
pub fn notification_is_well_formed(notification: &DocumentPublishedNotification) -> bool {
    notification.key.0.len() == 32
        && notification.meta.filter.len() <= MAX_NOTIFICATION_FILTERS
        && notification.meta.e3_id.e3_id().len() <= MAX_NOTIFICATION_E3_ID_LEN
}

/// A notified document that waits for a fetch slot or for its retry time.
#[derive(Clone, Debug)]
pub struct WaitingFetch {
    pub notification: DocumentPublishedNotification,
    pub not_before: Instant,
    pub failures: u32,
}

/// Documents that wait to be fetched. It holds at most `capacity` documents, so peers cannot grow
/// it without bound by sending notifications for many documents.
#[derive(Debug)]
pub struct FetchQueue {
    capacity: usize,
    max_attempts: u32,
    waiting: HashMap<(E3id, ContentHash), WaitingFetch>,
}

impl FetchQueue {
    pub fn new(capacity: usize, max_attempts: u32) -> Self {
        Self {
            capacity,
            max_attempts,
            waiting: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn contains(&self, id: &(E3id, ContentHash)) -> bool {
        self.waiting.contains_key(id)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Queue a newly notified document. A document that is already queued keeps its retry time
    /// and takes the newest notification, so an earlier notification with wrong metadata does
    /// not decide the fetch. When the queue is full, the document with the most failed fetches
    /// makes room; if no queued document has failed, the new one is dropped and `false` is
    /// returned.
    pub fn push(
        &mut self,
        id: (E3id, ContentHash),
        notification: DocumentPublishedNotification,
        now: Instant,
    ) -> bool {
        if let Some(waiting) = self.waiting.get_mut(&id) {
            waiting.notification = notification;
            return true;
        }
        if self.waiting.len() >= self.capacity {
            let evicted = self
                .waiting
                .iter()
                .filter(|(_, waiting)| waiting.failures > 0)
                .max_by_key(|(_, waiting)| waiting.failures)
                .map(|(id, _)| id.clone());
            let Some(evicted) = evicted else {
                return false;
            };
            self.waiting.remove(&evicted);
        }
        self.waiting.insert(
            id,
            WaitingFetch {
                notification,
                not_before: now,
                failures: 0,
            },
        );
        true
    }

    /// Queue a document again after its `failures`-th failed fetch. Returns `false` when the
    /// document has used all its attempts or the queue is full; a later announcement queues it
    /// again.
    pub fn retry(
        &mut self,
        id: (E3id, ContentHash),
        notification: DocumentPublishedNotification,
        failures: u32,
        now: Instant,
    ) -> bool {
        if failures >= self.max_attempts || self.waiting.len() >= self.capacity {
            return false;
        }
        self.waiting.insert(
            id,
            WaitingFetch {
                notification,
                not_before: now + fetch_retry_delay(failures),
                failures,
            },
        );
        true
    }

    /// Remove and return the due document that has waited longest.
    pub fn pop_due(&mut self, now: Instant) -> Option<((E3id, ContentHash), WaitingFetch)> {
        let id = self
            .waiting
            .iter()
            .filter(|(_, waiting)| waiting.not_before <= now)
            .min_by_key(|(_, waiting)| waiting.not_before)
            .map(|(id, _)| id.clone())?;
        self.waiting.remove_entry(&id)
    }

    pub fn remove_e3(&mut self, e3_id: &E3id) {
        self.waiting.retain(|(id, _), _| id != e3_id);
    }
}

/// Pure decision/state service backing the `DocumentPublisher` actor.
///
/// Owns the bookkeeping that decides:
/// - which E3s this node is interested in (so it knows which published documents to fetch),
/// - which DHT content hashes belong to each E3 (so they can be pruned on completion),
/// - whether an incoming publish notification is relevant to this node.
///
/// It performs no network or actix I/O — the actor uses these decisions to drive the
/// libp2p/Kademlia interactions.
#[derive(Default)]
pub struct DocumentPublishingService {
    /// Set of E3ids we are interested in, keyed to our party id for that E3.
    ids: HashMap<E3id, PartyId>,
    /// Track DHT content hashes per E3 for cleanup on completion.
    dht_keys: HashMap<E3id, Vec<ContentHash>>,
}

impl DocumentPublishingService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_interests(ids: HashMap<E3id, PartyId>) -> Self {
        Self {
            ids,
            dht_keys: HashMap::new(),
        }
    }

    /// Register interest in an E3 (this node was selected as `party_id`).
    pub fn register_interest(&mut self, e3_id: E3id, party_id: PartyId) {
        self.ids.insert(e3_id, party_id);
    }

    /// Mark an E3 complete, returning the DHT keys that should be pruned for it.
    pub fn complete_e3(&mut self, e3_id: &E3id) -> Vec<ContentHash> {
        self.ids.remove(e3_id);
        self.dht_keys.remove(e3_id).unwrap_or_default()
    }

    /// Compute the content hash for a value being published and record it against `e3_id`
    /// so it can be pruned when the E3 completes.
    pub fn track_published_key(&mut self, e3_id: &E3id, value: &ArcBytes) -> ContentHash {
        let key = ContentHash::from_content(value);
        self.dht_keys
            .entry(e3_id.clone())
            .or_default()
            .push(key.clone());
        key
    }

    /// Return our party id for a published document if (and only if) we are interested in it.
    #[allow(dead_code)]
    pub fn interested_party(
        &self,
        notification: &DocumentPublishedNotification,
    ) -> Option<PartyId> {
        Self::interest_in(&self.ids, notification)
    }

    /// Owned snapshot of the current interest map, for handing to async network I/O tasks.
    pub fn interest_snapshot(&self) -> HashMap<E3id, PartyId> {
        self.ids.clone()
    }

    /// Pure interest check usable without owning the service (e.g. from network I/O helpers).
    pub fn interest_in(
        ids: &HashMap<E3id, PartyId>,
        notification: &DocumentPublishedNotification,
    ) -> Option<PartyId> {
        let party_id = ids.get(&notification.meta.e3_id)?;
        if notification.meta.matches(party_id) {
            Some(*party_id)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentExpiryError {
    AlreadyExpired,
    OutOfRange,
}

impl fmt::Display for DocumentExpiryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExpired => formatter.write_str("document expiry is not in the future"),
            Self::OutOfRange => formatter.write_str("document expiry is outside Instant range"),
        }
    }
}

impl std::error::Error for DocumentExpiryError {}

/// Convert a future UTC datetime into a monotonic [`Instant`] relative to now.
pub fn datetime_to_instant_from_now(target: DateTime<Utc>) -> Result<Instant, DocumentExpiryError> {
    let now_datetime = Utc::now();
    let now_instant = Instant::now();

    if target <= now_datetime {
        return Err(DocumentExpiryError::AlreadyExpired);
    }

    let duration = target.signed_duration_since(now_datetime);
    let std_duration = duration
        .to_std()
        .map_err(|_| DocumentExpiryError::OutOfRange)?;
    now_instant
        .checked_add(std_duration)
        .ok_or(DocumentExpiryError::OutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{DocumentKind, DocumentMeta, Filter, PartyId};

    fn notification(e3: &str, filters: Vec<Filter<PartyId>>) -> DocumentPublishedNotification {
        DocumentPublishedNotification::new(
            DocumentMeta::new(E3id::new(e3, 1), DocumentKind::TrBFV, filters, None),
            ContentHash::from_content(b"doc"),
            0,
        )
    }

    #[test]
    fn not_interested_when_unregistered() {
        let svc = DocumentPublishingService::new();
        assert!(svc.interested_party(&notification("1", vec![])).is_none());
    }

    #[test]
    fn live_and_recovered_interests_match() {
        let mut live = DocumentPublishingService::new();
        live.register_interest(E3id::new("1", 1), 2);
        let recovered =
            DocumentPublishingService::with_interests(HashMap::from([(E3id::new("1", 1), 2)]));

        assert_eq!(live.interested_party(&notification("1", vec![])), Some(2));
        assert_eq!(
            recovered.interested_party(&notification("1", vec![])),
            Some(2)
        );
    }

    #[test]
    fn filtered_to_other_party_is_not_interesting() {
        let mut svc = DocumentPublishingService::new();
        svc.register_interest(E3id::new("1", 1), 2);
        // Document targeted only at party 5 — we are party 2.
        let n = notification("1", vec![Filter::Item(5)]);
        assert!(svc.interested_party(&n).is_none());
    }

    #[test]
    fn filtered_to_our_party_is_interesting() {
        let mut svc = DocumentPublishingService::new();
        svc.register_interest(E3id::new("1", 1), 2);
        let n = notification("1", vec![Filter::Item(2)]);
        assert_eq!(svc.interested_party(&n), Some(2));
    }

    #[test]
    fn track_and_prune_keys_round_trip() {
        let mut svc = DocumentPublishingService::new();
        let e3 = E3id::new("1", 1);
        let k1 = svc.track_published_key(&e3, &ArcBytes::from_bytes(b"one"));
        let k2 = svc.track_published_key(&e3, &ArcBytes::from_bytes(b"two"));
        let pruned = svc.complete_e3(&e3);
        assert_eq!(pruned, vec![k1, k2]);
        // After completion the E3 is forgotten and yields nothing further.
        assert!(svc.complete_e3(&e3).is_empty());
        assert!(svc.interested_party(&notification("1", vec![])).is_none());
    }

    fn within(delay: Duration, expected: Duration) -> bool {
        delay >= expected && delay <= expected.mul_f64(1.1)
    }

    #[test]
    fn replication_happens_once_then_on_refresh() {
        let start = Instant::now();
        let mut schedule = PublicationSchedule::default();
        assert!(schedule.needs_replication(start));
        schedule.record_replicated(start);
        assert!(!schedule.needs_replication(start + REPLICATION_REFRESH / 2));
        assert!(schedule.needs_replication(start + REPLICATION_REFRESH));
    }

    #[test]
    fn announcements_back_off_and_failures_retry_sooner() {
        let mut schedule = PublicationSchedule::default();
        schedule.record_replicated(Instant::now());
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL * 2));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL * 4));
        for _ in 0..10 {
            schedule.record_announced();
        }
        assert!(within(schedule.record_announced(), MAX_ANNOUNCE_BACKOFF));

        assert!(within(schedule.record_failed(), RETRY_INTERVAL));
        assert!(within(schedule.record_failed(), RETRY_INTERVAL * 2));
        assert!(within(schedule.record_announced(), MAX_ANNOUNCE_BACKOFF));
    }

    #[test]
    fn a_refresh_restarts_the_announcement_backoff() {
        let start = Instant::now();
        let mut schedule = PublicationSchedule::default();
        schedule.record_replicated(start);
        for _ in 0..5 {
            schedule.record_announced();
        }
        schedule.record_replicated(start + REPLICATION_REFRESH);
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL));
    }

    fn document(e3: &str, content: &[u8]) -> ((E3id, ContentHash), DocumentPublishedNotification) {
        let notification = notification(e3, vec![]);
        let key = ContentHash::from_content(content);
        let notification = DocumentPublishedNotification {
            key: key.clone(),
            ..notification
        };
        ((E3id::new(e3, 1), key), notification)
    }

    #[test]
    fn fetch_queue_is_bounded_and_prefers_fresh_documents() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(2, 6);
        let (a, a_note) = document("1", b"a");
        let (b, b_note) = document("1", b"b");
        let (c, c_note) = document("1", b"c");
        assert!(queue.push(a.clone(), a_note.clone(), now));
        assert!(queue.push(b.clone(), b_note, now));
        assert!(
            !queue.push(c.clone(), c_note.clone(), now),
            "full of fresh documents"
        );
        assert_eq!(queue.len(), 2);

        let (id, waiting) = queue.pop_due(now).unwrap();
        assert!(queue.retry(id.clone(), waiting.notification, 1, now));
        assert!(
            queue.push(c.clone(), c_note, now),
            "a failed document makes room"
        );
        assert!(!queue.contains(&id));
        assert!(queue.contains(&c));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn a_repeated_notification_keeps_the_retry_time_and_replaces_the_metadata() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4, 6);
        let (a, a_note) = document("1", b"a");
        assert!(queue.retry(a.clone(), a_note.clone(), 2, now));
        let newer = DocumentPublishedNotification {
            meta: DocumentMeta::new(
                E3id::new("1", 1),
                DocumentKind::TrBFV,
                vec![Filter::Item(3)],
                None,
            ),
            ..a_note
        };
        assert!(queue.push(a.clone(), newer.clone(), now));
        assert!(queue.pop_due(now).is_none());
        let (_, waiting) = queue.pop_due(now + MAX_ANNOUNCE_BACKOFF * 2).unwrap();
        assert_eq!(waiting.notification.meta.filter, newer.meta.filter);
        assert_eq!(waiting.failures, 2);
    }

    #[test]
    fn oversized_notifications_are_not_well_formed() {
        let (_, good) = document("1", b"a");
        assert!(notification_is_well_formed(&good));
        let long_key = DocumentPublishedNotification {
            key: ContentHash(vec![7; 33]),
            ..good.clone()
        };
        assert!(!notification_is_well_formed(&long_key));
        let many_filters = notification("1", vec![Filter::Item(1); MAX_NOTIFICATION_FILTERS + 1]);
        assert!(!notification_is_well_formed(&many_filters));
        let long_e3 = notification(&"9".repeat(MAX_NOTIFICATION_E3_ID_LEN + 1), vec![]);
        assert!(!notification_is_well_formed(&long_e3));
    }

    #[test]
    fn fetch_retries_stop_after_the_attempt_limit() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4, 3);
        let (a, a_note) = document("1", b"a");
        assert!(queue.retry(a.clone(), a_note.clone(), 2, now));
        queue.pop_due(now + MAX_ANNOUNCE_BACKOFF * 2).unwrap();
        assert!(!queue.retry(a.clone(), a_note, 3, now));
        assert!(queue.is_empty());
    }

    #[test]
    fn due_documents_leave_oldest_first_and_closed_e3s_are_dropped() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4, 6);
        let (a, a_note) = document("1", b"a");
        let (b, b_note) = document("2", b"b");
        assert!(queue.push(b.clone(), b_note, now + Duration::from_secs(1)));
        assert!(queue.push(a.clone(), a_note, now));
        assert_eq!(queue.pop_due(now + Duration::from_secs(1)).unwrap().0, a);
        queue.remove_e3(&E3id::new("2", 1));
        assert!(queue.is_empty());
    }

    #[test]
    fn fetch_retries_back_off() {
        assert!(within(fetch_retry_delay(1), RETRY_INTERVAL));
        assert!(within(fetch_retry_delay(3), RETRY_INTERVAL * 4));
        assert!(within(fetch_retry_delay(40), MAX_ANNOUNCE_BACKOFF));
    }

    #[test]
    fn datetime_helper_rejects_past_expiry() {
        assert_eq!(
            datetime_to_instant_from_now(Utc::now() - chrono::Duration::days(1)),
            Err(DocumentExpiryError::AlreadyExpired)
        );
    }

    #[test]
    fn datetime_helper_accepts_future_expiry() {
        assert!(datetime_to_instant_from_now(Utc::now() + chrono::Duration::days(1)).is_ok());
    }
}
