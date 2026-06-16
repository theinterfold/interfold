// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::HashMap, time::Instant};

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
}

impl DocumentPublishingService {
    pub fn new() -> Self {
        Self::default()
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

/// Convert a future UTC datetime into a monotonic [`Instant`] relative to now.
///
/// Returns `None` if the target has already passed.
pub fn datetime_to_instant_from_now(target: DateTime<Utc>) -> Option<Instant> {
    let now_datetime = Utc::now();
    let now_instant = Instant::now();

    if target <= now_datetime {
        return None; // Already expired
    }

    let duration = target.signed_duration_since(now_datetime);
    let std_duration = duration.to_std().ok()?;
    now_instant.checked_add(std_duration)
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
    fn interested_when_registered_and_unfiltered() {
        let mut svc = DocumentPublishingService::new();
        svc.register_interest(E3id::new("1", 1), 2);
        assert_eq!(svc.interested_party(&notification("1", vec![])), Some(2));
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
    fn datetime_helper_is_none_for_past() {
        assert!(datetime_to_instant_from_now(Utc::now() - chrono::Duration::days(1)).is_none());
    }

    #[test]
    fn datetime_helper_is_some_for_future() {
        assert!(datetime_to_instant_from_now(Utc::now() + chrono::Duration::days(1)).is_some());
    }
}
