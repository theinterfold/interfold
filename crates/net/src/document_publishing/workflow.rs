// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use e3_events::{DocumentReceived, E3id, PartyId};
use e3_utils::ArcBytes;
use libp2p::PeerId;

use crate::{
    backoff::backoff_delay,
    events::{DocumentPublishedNotification, NetCommand},
    ContentHash,
};

/// First delay before a document is announced again. Later announcements back off.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
/// First delay before a failed announcement or replication is retried. Later retries back off.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(15);
/// Longest delay between announcements, and between retries.
pub const MAX_ANNOUNCE_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Age after which a replicated document is stored on the DHT again. Peers can drop records, so
/// the publisher refreshes them, but rarely: one refresh sends the whole document to up to 20
/// peers.
pub const REPLICATION_REFRESH: Duration = Duration::from_secs(30 * 60);

/// When a pending publication is next announced and next replicated.
///
/// An announcement stores the document in this node's own DHT store, so that a peer whose lookup
/// reaches this node can fetch it from here, and then gossips a small notification that names it.
/// A replication uploads the full document to the DHT peers closest to its key, so that peers can
/// also fetch it from them, and while this node is away. The two have separate schedules: a
/// failing replication never delays an announcement. The document is uploaded once, and again
/// every [`REPLICATION_REFRESH`].
#[derive(Clone, Debug, Default)]
pub struct PublicationSchedule {
    replicated_at: Option<Instant>,
    replication_failures: u32,
    announcements: u32,
    announcement_failures: u32,
}

impl PublicationSchedule {
    /// Whether the document must be uploaded now: it never was, or the last upload is older than
    /// [`REPLICATION_REFRESH`].
    pub fn needs_replication(&self, now: Instant) -> bool {
        self.replication_due_in(now).is_zero()
    }

    /// Time until the next upload is due; zero when it is due now.
    pub fn replication_due_in(&self, now: Instant) -> Duration {
        self.replicated_at.map_or(Duration::ZERO, |at| {
            REPLICATION_REFRESH.saturating_sub(now.saturating_duration_since(at))
        })
    }

    /// Record a completed upload and return the delay before the next one. A refresh also
    /// restarts the announcement backoff.
    pub fn record_replicated(&mut self, now: Instant) -> Duration {
        self.replicated_at = Some(now);
        self.replication_failures = 0;
        self.announcements = 0;
        REPLICATION_REFRESH
    }

    /// Record a failed upload and return the delay before the next attempt.
    pub fn record_replication_failed(&mut self) -> Duration {
        self.replication_failures = self.replication_failures.saturating_add(1);
        backoff_delay(
            RETRY_INTERVAL,
            self.replication_failures,
            MAX_ANNOUNCE_BACKOFF,
        )
    }

    /// Record a completed announcement and return the delay before the next one.
    pub fn record_announced(&mut self) -> Duration {
        self.announcement_failures = 0;
        self.announcements = self.announcements.saturating_add(1);
        backoff_delay(ANNOUNCE_INTERVAL, self.announcements, MAX_ANNOUNCE_BACKOFF)
    }

    /// Record a failed announcement and return the delay before the retry.
    pub fn record_announcement_failed(&mut self) -> Duration {
        self.announcement_failures = self.announcement_failures.saturating_add(1);
        backoff_delay(
            RETRY_INTERVAL,
            self.announcement_failures,
            MAX_ANNOUNCE_BACKOFF,
        )
    }
}

/// Delay before a failed document fetch is tried again, after `failures` consecutive failures.
pub fn fetch_retry_delay(failures: u32) -> Duration {
    backoff_delay(RETRY_INTERVAL, failures, MAX_ANNOUNCE_BACKOFF)
}

/// Most notifications kept for one waiting document, distinct by metadata. Peers choose the
/// metadata, and only the fetched payload shows which metadata is right. So the queue keeps the
/// first notification it saw and the newest others, and the fetch accepts the document under the
/// first one that matches it. A peer cannot replace a correct notification with a wrong one.
pub const MAX_NOTIFICATION_CANDIDATES: usize = 4;
/// Keep the first announcer and the most recent others when peer identities churn.
pub const MAX_FETCH_ANNOUNCERS: usize = 128;

/// A notified document that waits for a fetch slot or for its retry time.
#[derive(Clone, Debug)]
pub struct WaitingFetch {
    /// The peer charged for this queue entry or active read.
    pub peer: Option<PeerId>,
    announcers: Vec<Option<PeerId>>,
    /// Notifications that name this document, first seen first, distinct by metadata.
    pub notifications: Vec<DocumentPublishedNotification>,
    pub not_before: Instant,
    pub failures: u32,
}

impl WaitingFetch {
    fn new(
        peer: Option<PeerId>,
        notifications: Vec<DocumentPublishedNotification>,
        not_before: Instant,
        failures: u32,
    ) -> Self {
        Self {
            peer,
            announcers: vec![peer],
            notifications,
            not_before,
            failures,
        }
    }

    /// Add a notification. A copy with the same metadata replaces the older copy. When the list is
    /// full, the oldest notification after the first one makes room.
    pub fn add(&mut self, peer: Option<PeerId>, notification: DocumentPublishedNotification) {
        add_candidate(&mut self.notifications, notification);
        if !self.announcers.contains(&peer) {
            if self.announcers.len() >= MAX_FETCH_ANNOUNCERS {
                self.announcers.remove(1);
            }
            self.announcers.push(peer);
        }
    }
}

/// Add `notification` to `candidates` under the rules of [`WaitingFetch::add`].
///
/// Only the party filter decides whether a notification can match the payload (the E3 and the
/// content hash are the queue key), so the list keeps one notification per filter, the one that
/// expires last, which a copy cannot shorten. A well-formed notification that is relevant to this
/// node has one of two filters, `[]` or `[Item(own party)]`, so forged copies cannot push a correct
/// notification out of the list.
pub fn add_candidate(
    candidates: &mut Vec<DocumentPublishedNotification>,
    notification: DocumentPublishedNotification,
) {
    if let Some(existing) = candidates
        .iter_mut()
        .find(|existing| existing.meta.filter == notification.meta.filter)
    {
        if notification.meta.expires_at > existing.meta.expires_at {
            *existing = notification;
        }
        return;
    }
    if candidates.len() >= MAX_NOTIFICATION_CANDIDATES {
        candidates.remove(1);
    }
    candidates.push(notification);
}

/// Documents that wait to be fetched. It holds at most `capacity` documents, so peers cannot grow
/// it without bound by sending notifications for many documents.
///
/// A failed fetch is retried with a backoff that reaches [`MAX_ANNOUNCE_BACKOFF`] and stays there,
/// until the document arrives, its E3 closes, or its notifications expire. A document whose
/// publisher went offline is therefore still fetched when a replica becomes reachable.
#[derive(Debug)]
pub struct FetchQueue {
    capacity: usize,
    waiting: HashMap<(E3id, ContentHash), WaitingFetch>,
    peers: VecDeque<Option<PeerId>>,
}

impl FetchQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            waiting: HashMap::new(),
            peers: VecDeque::new(),
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
    /// and adds the notification to its candidates. When the queue is full, the largest owner
    /// makes room for a peer below its share. Otherwise, only a document with
    /// more failed fetches from the same peer makes room.
    pub fn push(
        &mut self,
        id: (E3id, ContentHash),
        peer: Option<PeerId>,
        notification: DocumentPublishedNotification,
        now: Instant,
    ) -> bool {
        if let Some(waiting) = self.waiting.get_mut(&id) {
            waiting.add(peer, notification);
            let mut counts = self.peer_counts();
            let waiting = self.waiting.get_mut(&id).unwrap();
            *counts.get_mut(&waiting.peer).unwrap() -= 1;
            waiting.peer = *waiting
                .announcers
                .iter()
                .min_by_key(|peer| counts.get(peer).copied().unwrap_or(0))
                .unwrap();
            self.add_peer(peer);
            self.prune_peers();
            return true;
        }
        if !self.make_room(peer, 0) {
            return false;
        }
        self.add_peer(peer);
        self.waiting
            .insert(id, WaitingFetch::new(peer, vec![notification], now, 0));
        true
    }

    /// Queue a failed fetch under the announcer with the least queued work that can admit it.
    /// A later announcement can restore a document that cannot reclaim space in a full queue.
    pub fn retry(
        &mut self,
        id: (E3id, ContentHash),
        mut waiting: WaitingFetch,
        now: Instant,
    ) -> bool {
        if waiting.notifications.is_empty() {
            return false;
        }
        let counts = self.peer_counts();
        let mut announcers = waiting.announcers.clone();
        announcers.sort_by_key(|peer| counts.get(peer).copied().unwrap_or(0));
        let Some(peer) = announcers
            .into_iter()
            .find(|peer| self.make_room(*peer, waiting.failures))
        else {
            return false;
        };
        waiting.peer = peer;
        waiting.not_before = now + fetch_retry_delay(waiting.failures);
        for peer in &waiting.announcers {
            self.add_peer(*peer);
        }
        self.waiting.insert(id, waiting);
        true
    }

    fn add_peer(&mut self, peer: Option<PeerId>) {
        if !self.peers.contains(&peer) {
            self.peers.push_back(peer);
        }
    }

    fn prune_peers(&mut self) {
        let peers: HashSet<_> = self
            .waiting
            .values()
            .flat_map(|item| item.announcers.iter().copied())
            .collect();
        self.peers.retain(|peer| peers.contains(peer));
    }

    fn peer_counts(&self) -> HashMap<Option<PeerId>, usize> {
        let mut counts = HashMap::new();
        for item in self.waiting.values() {
            *counts.entry(item.peer).or_insert(0) += 1;
        }
        counts
    }

    /// Unused capacity belongs to any peer. At capacity, a new or smaller owner can reclaim
    /// space from the largest owner; otherwise only less promising work of its own makes room.
    /// Shared work moves to a less loaded announcer before it can be dropped.
    fn make_room(&mut self, peer: Option<PeerId>, failures: u32) -> bool {
        if self.waiting.len() < self.capacity {
            return true;
        }
        let mut counts = self.peer_counts();
        let mut reassigned = HashSet::new();
        loop {
            let owner = crate::ingress_limits::eviction_owner(
                peer,
                counts.iter().map(|(peer, count)| (*peer, *count)),
                self.capacity,
            );
            let evicted = self
                .waiting
                .iter()
                .filter(|(id, item)| {
                    item.peer == owner
                        && (owner != peer || item.failures > failures)
                        && !reassigned.contains(*id)
                })
                .max_by_key(|(_, item)| (item.failures, std::cmp::Reverse(item.not_before)))
                .map(|(id, _)| id.clone());
            let Some(evicted) = evicted else { return false };
            let item = self.waiting.get_mut(&evicted).unwrap();
            let alternative = item
                .announcers
                .iter()
                .copied()
                .min_by_key(|peer| counts.get(peer).copied().unwrap_or(0));
            if let Some(alternative) = alternative.filter(|alternative| {
                counts.get(alternative).copied().unwrap_or(0) < counts[&owner]
            }) {
                item.peer = alternative;
                *counts.get_mut(&owner).unwrap() -= 1;
                if counts[&owner] == 0 {
                    counts.remove(&owner);
                }
                *counts.entry(alternative).or_insert(0) += 1;
                // Reconsider the donor after each move, without moving the same work back.
                reassigned.insert(evicted);
                continue;
            }
            self.waiting.remove(&evicted);
            self.prune_peers();
            return true;
        }
    }

    /// Serve the peer with the fewest active reads, rotating ties. A lone peer can use all slots.
    pub fn pop_due(
        &mut self,
        now: Instant,
        in_flight: &HashMap<Option<PeerId>, usize>,
    ) -> Option<((E3id, ContentHash), WaitingFetch)> {
        let due: HashSet<_> = self
            .waiting
            .values()
            .filter(|item| item.not_before <= now)
            .flat_map(|item| item.announcers.iter().copied())
            .collect();
        let peer = self
            .peers
            .iter()
            .filter(|peer| due.contains(peer))
            .min_by_key(|peer| in_flight.get(peer).copied().unwrap_or(0))
            .copied()?;
        while self.peers.front() != Some(&peer) {
            self.peers.rotate_left(1);
        }
        self.peers.rotate_left(1);
        let id = self
            .waiting
            .iter()
            .filter(|(_, item)| item.announcers.contains(&peer) && item.not_before <= now)
            .min_by_key(|(_, item)| item.not_before)
            .map(|(id, _)| id.clone())?;
        let (id, mut waiting) = self.waiting.remove_entry(&id)?;
        waiting.peer = peer;
        self.prune_peers();
        Some((id, waiting))
    }

    pub fn remove_e3(&mut self, e3_id: &E3id) {
        self.waiting.retain(|(id, _), _| id != e3_id);
        self.prune_peers();
    }
}

/// Network cleanup of one DHT key that has no reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cleanup {
    /// End the Kademlia query of a stopped publication's upload.
    CancelPut(ContentHash),
    /// Remove a record from this node's DHT store.
    RemoveRecord(ContentHash),
}

/// Cleanup that waits for room in the network command queue, oldest first. It holds at most
/// `limit` keys, so its bytes are bounded too. A full queue drops its oldest entry: the record
/// still expires and the query still times out on its own.
pub struct CleanupQueue {
    entries: VecDeque<Cleanup>,
    limit: usize,
}

impl CleanupQueue {
    pub fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            limit,
        }
    }

    /// Queue `cleanup`. Returns whether the oldest entry was dropped to make room.
    pub fn push(&mut self, cleanup: Cleanup) -> bool {
        let full = self.entries.len() >= self.limit;
        if full {
            self.entries.pop_front();
        }
        self.entries.push_back(cleanup);
        full
    }

    /// The next command to send. Removals that follow each other go out as one command.
    pub fn next_command(&mut self) -> Option<NetCommand> {
        match self.entries.pop_front()? {
            Cleanup::CancelPut(key) => Some(NetCommand::DhtCancelPut { key }),
            Cleanup::RemoveRecord(key) => {
                let mut keys = vec![key];
                while let Some(Cleanup::RemoveRecord(_)) = self.entries.front() {
                    if let Some(Cleanup::RemoveRecord(key)) = self.entries.pop_front() {
                        keys.push(key);
                    }
                }
                Some(NetCommand::DhtRemoveRecords { keys })
            }
        }
    }

    /// Drop every entry. Returns how many were dropped.
    pub fn clear(&mut self) -> usize {
        let dropped = self.entries.len();
        self.entries.clear();
        dropped
    }
}

/// Most received documents that a restart stores in this node's DHT store again. The store holds
/// at most 1024 records, and this node's own publications need room too.
pub const MAX_RESTORED_DOCUMENTS: usize = 512;
/// Most bytes of received documents that a restart stores in this node's DHT store again.
pub const MAX_RESTORED_DOCUMENT_BYTES: usize = 128 * 1024 * 1024;

/// Received documents to store in this node's DHT store again after a restart. The DHT store is in
/// memory, so without them the node stops serving the documents that it received, also to peers
/// whose dealer is offline.
///
/// It keeps the documents received last, in event-log order, within a count and a byte limit, and
/// drops the documents that expired and the documents of E3s that closed. The limits apply while
/// recovery reads the log, before the chain history closes the E3s that ended while the node was
/// offline, so those documents can take the place of older documents of open E3s.
#[derive(Debug)]
pub struct RestorableDocuments {
    max_documents: usize,
    max_bytes: usize,
    documents: VecDeque<DocumentReceived>,
    bytes: usize,
}

impl Default for RestorableDocuments {
    fn default() -> Self {
        Self::with_limits(MAX_RESTORED_DOCUMENTS, MAX_RESTORED_DOCUMENT_BYTES)
    }
}

impl RestorableDocuments {
    pub fn with_limits(max_documents: usize, max_bytes: usize) -> Self {
        Self {
            max_documents,
            max_bytes,
            documents: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Keep a received broadcast document after the ones kept before. The oldest documents make
    /// room for it. A document with a party filter is not kept: this node received it because the
    /// filter names this node, and no other peer fetches it, so a restored copy would only take
    /// the place of a broadcast document. An expired document, or one larger than the byte limit,
    /// is not kept either.
    pub fn push(&mut self, document: DocumentReceived, now: DateTime<Utc>) {
        let size = document.value.size();
        if !document.meta.filter.is_empty()
            || document.meta.expires_at <= now
            || size > self.max_bytes
        {
            return;
        }
        self.documents.push_back(document);
        self.bytes += size;
        while self.documents.len() > self.max_documents || self.bytes > self.max_bytes {
            self.pop_oldest();
        }
    }

    /// Remove and return the oldest document that has not expired at `now`.
    pub fn pop(&mut self, now: DateTime<Utc>) -> Option<DocumentReceived> {
        while let Some(document) = self.pop_oldest() {
            if document.meta.expires_at > now {
                return Some(document);
            }
        }
        None
    }

    pub fn remove_e3(&mut self, e3_id: &E3id) {
        self.documents
            .retain(|document| &document.meta.e3_id != e3_id);
        self.bytes = self
            .documents
            .iter()
            .map(|document| document.value.size())
            .sum();
    }

    fn pop_oldest(&mut self) -> Option<DocumentReceived> {
        let document = self.documents.pop_front()?;
        self.bytes -= document.value.size();
        Some(document)
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
        assert_eq!(schedule.record_replicated(start), REPLICATION_REFRESH);
        assert!(!schedule.needs_replication(start + REPLICATION_REFRESH / 2));
        assert_eq!(
            schedule.replication_due_in(start + REPLICATION_REFRESH / 2),
            REPLICATION_REFRESH / 2
        );
        assert!(schedule.needs_replication(start + REPLICATION_REFRESH));
    }

    #[test]
    fn announcements_back_off_and_failures_retry_sooner() {
        let mut schedule = PublicationSchedule::default();
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL * 2));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL * 4));
        for _ in 0..10 {
            schedule.record_announced();
        }
        assert!(within(schedule.record_announced(), MAX_ANNOUNCE_BACKOFF));

        assert!(within(
            schedule.record_announcement_failed(),
            RETRY_INTERVAL
        ));
        assert!(within(
            schedule.record_announcement_failed(),
            RETRY_INTERVAL * 2
        ));
        assert!(within(schedule.record_announced(), MAX_ANNOUNCE_BACKOFF));
    }

    #[test]
    fn failed_uploads_back_off_without_slowing_announcements() {
        let start = Instant::now();
        let mut schedule = PublicationSchedule::default();
        assert!(within(schedule.record_replication_failed(), RETRY_INTERVAL));
        assert!(within(
            schedule.record_replication_failed(),
            RETRY_INTERVAL * 2
        ));
        assert!(schedule.needs_replication(start));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL));

        schedule.record_replicated(start);
        assert!(within(schedule.record_replication_failed(), RETRY_INTERVAL));
    }

    #[test]
    fn announcement_outcomes_and_upload_failures_keep_separate_backoffs() {
        let mut schedule = PublicationSchedule::default();
        assert!(within(schedule.record_replication_failed(), RETRY_INTERVAL));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL));
        assert!(within(
            schedule.record_announcement_failed(),
            RETRY_INTERVAL
        ));
        // Neither announcement outcome resets or advances the upload backoff,
        assert!(within(
            schedule.record_replication_failed(),
            RETRY_INTERVAL * 2
        ));
        // and upload failures do not advance the announcement backoff.
        assert!(within(
            schedule.record_announcement_failed(),
            RETRY_INTERVAL * 2
        ));
        assert!(within(schedule.record_announced(), ANNOUNCE_INTERVAL * 2));
        assert!(within(
            schedule.record_replication_failed(),
            RETRY_INTERVAL * 4
        ));
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
        let mut queue = FetchQueue::new(2);
        let (a, a_note) = document("1", b"a");
        let (b, b_note) = document("1", b"b");
        let (c, c_note) = document("1", b"c");
        assert!(queue.push(a.clone(), None, a_note.clone(), now));
        assert!(queue.push(b.clone(), None, b_note, now));
        assert!(
            !queue.push(c.clone(), None, c_note.clone(), now),
            "full of fresh documents"
        );
        assert_eq!(queue.len(), 2);

        let (id, mut waiting) = queue.pop_due(now, &HashMap::new()).unwrap();
        waiting.failures = 1;
        assert!(queue.retry(id.clone(), waiting, now));
        assert!(
            queue.push(c.clone(), None, c_note, now),
            "a failed document makes room"
        );
        assert!(!queue.contains(&id));
        assert!(queue.contains(&c));
        assert_eq!(queue.len(), 2);
    }

    fn with_filter(
        note: &DocumentPublishedNotification,
        filter: Vec<Filter<u64>>,
    ) -> DocumentPublishedNotification {
        DocumentPublishedNotification {
            meta: DocumentMeta::new(note.meta.e3_id.clone(), DocumentKind::TrBFV, filter, None),
            ..note.clone()
        }
    }

    #[test]
    fn announcer_churn_is_bounded_and_keeps_recent_peers_eligible() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(2);
        let (id, note) = document("1", b"shared");
        let mut in_flight = HashMap::new();
        let mut latest = None;
        for index in 0..MAX_FETCH_ANNOUNCERS * 2 {
            let peer = Some(PeerId::random());
            assert!(queue.push(id.clone(), peer, note.clone(), now));
            assert!(queue.peers.len() <= MAX_FETCH_ANNOUNCERS);
            assert!(queue.waiting[&id].announcers.len() <= MAX_FETCH_ANNOUNCERS);
            assert_eq!(queue.len(), 1);
            if index < MAX_FETCH_ANNOUNCERS * 2 - 1 {
                in_flight.insert(peer, 1);
            }
            latest = peer;
        }
        let (fetched, waiting) = queue.pop_due(now, &in_flight).unwrap();
        assert_eq!(fetched, id);
        assert_eq!(waiting.peer, latest);
        assert_eq!(waiting.notifications, vec![note]);
        assert!(queue.pop_due(now, &in_flight).is_none());
        assert!(queue.peers.is_empty());
    }

    #[test]
    fn a_repeated_notification_keeps_the_retry_time_and_adds_a_candidate() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, a_note) = document("1", b"a");
        assert!(queue.retry(
            a.clone(),
            WaitingFetch::new(None, vec![a_note.clone()], now, 2),
            now
        ));
        let newer = with_filter(&a_note, vec![Filter::Item(3)]);
        assert!(queue.push(a.clone(), None, newer.clone(), now));
        assert!(queue.pop_due(now, &HashMap::new()).is_none());
        let (_, waiting) = queue
            .pop_due(now + MAX_ANNOUNCE_BACKOFF * 2, &HashMap::new())
            .unwrap();
        assert_eq!(waiting.notifications, vec![a_note, newer]);
        assert_eq!(waiting.failures, 2);
    }

    /// Copies with the same filter do not take extra places, and a copy cannot shorten the expiry,
    /// so a forged-first sequence cannot push the correct notification out of the list.
    #[test]
    fn candidates_are_one_per_filter_and_keep_the_latest_expiry() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, genuine) = document("1", b"a");
        let genuine = with_filter(&genuine, vec![Filter::Item(3)]);
        let forged = |filter: Vec<Filter<u64>>, minutes: i64| DocumentPublishedNotification {
            meta: DocumentMeta::new(
                genuine.meta.e3_id.clone(),
                DocumentKind::TrBFV,
                filter,
                Some(chrono::Utc::now() + chrono::Duration::minutes(minutes)),
            ),
            ..genuine.clone()
        };
        assert!(queue.push(a.clone(), None, forged(vec![], 60), now));
        assert!(queue.push(a.clone(), None, genuine.clone(), now));
        for minutes in 1..10 {
            assert!(queue.push(a.clone(), None, forged(vec![], minutes), now));
            assert!(queue.push(a.clone(), None, forged(vec![Filter::Item(3)], minutes), now));
        }
        let (_, waiting) = queue.pop_due(now, &HashMap::new()).unwrap();
        assert_eq!(waiting.notifications.len(), 2);
        assert!(waiting.notifications.contains(&genuine));
    }

    /// A peer that sends notifications with other filters cannot push out the first one, and the
    /// newest ones are kept.
    #[test]
    fn candidates_keep_the_first_notification_and_the_newest_others() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, genuine) = document("1", b"a");
        assert!(queue.push(a.clone(), None, genuine.clone(), now));
        let forged: Vec<_> = (0..MAX_NOTIFICATION_CANDIDATES as u64 + 2)
            .map(|party| with_filter(&genuine, vec![Filter::Item(party + 10)]))
            .collect();
        for note in &forged {
            assert!(queue.push(a.clone(), None, note.clone(), now));
        }
        let (_, waiting) = queue.pop_due(now, &HashMap::new()).unwrap();
        assert_eq!(waiting.notifications.len(), MAX_NOTIFICATION_CANDIDATES);
        assert_eq!(waiting.notifications[0], genuine);
        assert_eq!(
            waiting.notifications[1..],
            forged[forged.len() - (MAX_NOTIFICATION_CANDIDATES - 1)..]
        );
    }

    /// A correct notification that arrives after a wrong one is still a candidate.
    #[test]
    fn a_later_correct_notification_is_kept_beside_an_earlier_wrong_one() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, genuine) = document("1", b"a");
        let forged = with_filter(&genuine, vec![Filter::Range(None, None)]);
        assert!(queue.push(a.clone(), None, forged.clone(), now));
        assert!(queue.push(a.clone(), None, genuine.clone(), now));
        let (_, waiting) = queue.pop_due(now, &HashMap::new()).unwrap();
        assert_eq!(waiting.notifications, vec![forged, genuine]);
    }

    /// A document whose publisher left must still be fetched once a replica answers, so failed
    /// fetches keep retrying at the longest backoff instead of being dropped.
    #[test]
    fn fetch_retries_continue_at_the_longest_backoff() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, a_note) = document("1", b"a");
        for failures in 1..40 {
            assert!(queue.retry(
                a.clone(),
                WaitingFetch::new(None, vec![a_note.clone()], now, failures),
                now
            ));
            let (_, waiting) = queue
                .pop_due(now + MAX_ANNOUNCE_BACKOFF * 2, &HashMap::new())
                .unwrap();
            assert_eq!(waiting.failures, failures);
            assert!(waiting.not_before <= now + MAX_ANNOUNCE_BACKOFF * 2);
        }
    }

    /// A full queue keeps the documents that failed least, so a document that keeps failing does
    /// not hold a slot against fresh ones.
    #[test]
    fn a_full_queue_retries_only_documents_that_failed_less() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(2);
        let (a, a_note) = document("1", b"a");
        let (b, b_note) = document("1", b"b");
        let (c, c_note) = document("1", b"c");
        assert!(queue.retry(
            a.clone(),
            WaitingFetch::new(None, vec![a_note], now, 5),
            now
        ));
        assert!(queue.retry(
            b.clone(),
            WaitingFetch::new(None, vec![b_note], now, 1),
            now
        ));
        assert!(!queue.retry(
            c.clone(),
            WaitingFetch::new(None, vec![c_note.clone()], now, 7),
            now
        ));
        assert!(queue.retry(
            c.clone(),
            WaitingFetch::new(None, vec![c_note], now, 2),
            now
        ));
        assert!(!queue.contains(&a));
        assert!(queue.contains(&b) && queue.contains(&c));
    }

    #[test]
    fn due_documents_leave_oldest_first_and_closed_e3s_are_dropped() {
        let now = Instant::now();
        let mut queue = FetchQueue::new(4);
        let (a, a_note) = document("1", b"a");
        let (b, b_note) = document("2", b"b");
        assert!(queue.push(b.clone(), None, b_note, now + Duration::from_secs(1)));
        assert!(queue.push(a.clone(), None, a_note, now));
        assert_eq!(
            queue
                .pop_due(now + Duration::from_secs(1), &HashMap::new())
                .unwrap()
                .0,
            a
        );
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

    #[test]
    fn a_full_cleanup_queue_drops_its_oldest_entry() {
        let key = |n: u8| ContentHash::from_content(&[n]);
        let mut queue = CleanupQueue::new(3);
        assert!(!queue.push(Cleanup::RemoveRecord(key(1))));
        assert!(!queue.push(Cleanup::CancelPut(key(2))));
        assert!(!queue.push(Cleanup::RemoveRecord(key(3))));
        assert!(queue.push(Cleanup::RemoveRecord(key(4))));

        assert!(matches!(
            queue.next_command(),
            Some(NetCommand::DhtCancelPut { key: cancelled }) if cancelled == key(2)
        ));
        assert!(matches!(
            queue.next_command(),
            Some(NetCommand::DhtRemoveRecords { keys }) if keys == vec![key(3), key(4)]
        ));
        assert!(queue.next_command().is_none());
    }

    fn received(e3: &str, bytes: usize) -> DocumentReceived {
        DocumentReceived {
            meta: DocumentMeta::new(
                E3id::new(e3, 1),
                DocumentKind::TrBFV,
                vec![],
                Some(Utc::now() + chrono::Duration::hours(1)),
            ),
            value: ArcBytes::from_bytes(&vec![0; bytes]),
        }
    }

    fn restore_order(restorable: &mut RestorableDocuments) -> Vec<String> {
        std::iter::from_fn(|| restorable.pop(Utc::now()))
            .map(|document| document.meta.e3_id.e3_id().to_string())
            .collect()
    }

    #[test]
    fn restorable_documents_keep_at_most_their_count_limit() {
        let mut restorable = RestorableDocuments::with_limits(3, 1_000);
        for e3 in ["a", "b", "c", "d"] {
            restorable.push(received(e3, 2), Utc::now());
        }
        assert_eq!(restore_order(&mut restorable), ["b", "c", "d"]);
    }

    #[test]
    fn restorable_documents_keep_at_most_their_byte_limit() {
        let mut restorable = RestorableDocuments::with_limits(100, 10);
        for (e3, bytes) in [("a", 4), ("b", 4), ("c", 4), ("d", 6)] {
            restorable.push(received(e3, bytes), Utc::now());
        }
        assert_eq!(restore_order(&mut restorable), ["c", "d"]);
    }

    fn expiring(e3: &str, bytes: usize, expires_in: i64, now: DateTime<Utc>) -> DocumentReceived {
        DocumentReceived {
            meta: DocumentMeta::new(
                E3id::new(e3, 1),
                DocumentKind::TrBFV,
                vec![],
                Some(now + chrono::Duration::seconds(expires_in)),
            ),
            value: ArcBytes::from_bytes(&vec![0; bytes]),
        }
    }

    #[test]
    fn an_expired_document_is_not_kept() {
        let now = Utc::now();
        let mut restorable = RestorableDocuments::with_limits(1, 100);
        restorable.push(received("a", 2), now);
        // Kept, it would push out "a".
        restorable.push(expiring("expired", 2, -1, now), now);
        assert_eq!(restore_order(&mut restorable), ["a"]);
    }

    #[test]
    fn a_document_larger_than_the_byte_limit_is_not_kept() {
        let mut restorable = RestorableDocuments::with_limits(10, 10);
        restorable.push(received("a", 4), Utc::now());
        // Kept, it would push out "a" and then itself.
        restorable.push(received("too large", 11), Utc::now());
        assert_eq!(restore_order(&mut restorable), ["a"]);
    }

    #[test]
    fn a_document_for_one_party_is_not_kept() {
        let mut restorable = RestorableDocuments::with_limits(1, 100);
        restorable.push(received("broadcast", 2), Utc::now());
        let mut share = received("share", 2);
        share.meta = DocumentMeta::new(
            E3id::new("share", 1),
            DocumentKind::TrBFV,
            vec![Filter::Item(3)],
            Some(Utc::now() + chrono::Duration::hours(1)),
        );
        // Kept, it would push out the broadcast document.
        restorable.push(share, Utc::now());
        assert_eq!(restore_order(&mut restorable), ["broadcast"]);
    }

    #[test]
    fn a_document_that_expires_while_kept_is_not_restored() {
        let now = Utc::now();
        let mut restorable = RestorableDocuments::with_limits(10, 100);
        restorable.push(expiring("f", 1, 1, now), now);
        restorable.push(expiring("g", 1, 60, now), now);
        let later = now + chrono::Duration::seconds(2);
        let next = |restorable: &mut RestorableDocuments| {
            restorable.pop(later).map(|document| document.meta.e3_id)
        };
        assert_eq!(next(&mut restorable), Some(E3id::new("g", 1)));
        assert_eq!(next(&mut restorable), None);
    }

    #[test]
    fn removing_an_e3_frees_its_bytes() {
        let mut restorable = RestorableDocuments::with_limits(10, 10);
        restorable.push(received("a", 4), Utc::now());
        restorable.push(received("e", 6), Utc::now());
        restorable.remove_e3(&E3id::new("e", 1));
        // Fits only when the bytes of "e" are free again.
        restorable.push(received("b", 6), Utc::now());
        assert_eq!(restore_order(&mut restorable), ["a", "b"]);
    }
}
