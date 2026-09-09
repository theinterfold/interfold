// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::HashMap, fmt, time::Instant};

use chrono::{DateTime, Utc};
use e3_events::{E3id, PartyId};
use e3_utils::ArcBytes;

use crate::{events::DocumentPublishedNotification, ContentHash};

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
    /// The notifications this node has gossiped, per E3, so they can be re-announced.
    ///
    /// A `DocumentPublishedNotification` is gossiped exactly once, when the DHT put
    /// succeeds. A peer that is not subscribed at that instant — restarting, or still
    /// dialing — never learns the content hash and cannot fetch the record, even though the
    /// record itself stays in the DHT for days. Historical peer sync does not cover these
    /// notifications either. Keeping the pointer lets the publisher re-announce it when a
    /// peer (re)joins the topic; receivers dedup by content, so re-sends are harmless.
    announced: HashMap<E3id, Vec<DocumentPublishedNotification>>,
}

impl DocumentPublishingService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_interests(ids: HashMap<E3id, PartyId>) -> Self {
        Self {
            ids,
            dht_keys: HashMap::new(),
            announced: HashMap::new(),
        }
    }

    /// Register interest in an E3 (this node was selected as `party_id`).
    pub fn register_interest(&mut self, e3_id: E3id, party_id: PartyId) {
        self.ids.insert(e3_id, party_id);
    }

    /// Mark an E3 complete, returning the DHT keys that should be pruned for it.
    pub fn complete_e3(&mut self, e3_id: &E3id) -> Vec<ContentHash> {
        self.ids.remove(e3_id);
        self.announced.remove(e3_id);
        self.dht_keys.remove(e3_id).unwrap_or_default()
    }

    /// Remember a notification that was gossiped so it can be re-announced later.
    pub fn track_announced(&mut self, notification: DocumentPublishedNotification) {
        self.announced
            .entry(notification.meta.e3_id.clone())
            .or_default()
            .push(notification);
    }

    /// Every notification this node has gossiped for an E3 that is still in flight.
    pub fn announcements_to_repeat(&self) -> Vec<DocumentPublishedNotification> {
        self.announced.values().flatten().cloned().collect()
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
