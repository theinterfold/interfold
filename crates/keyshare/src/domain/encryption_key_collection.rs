// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure tally logic for collecting BFV encryption keys from the committee.
//!
//! No actix/timer/bus dependencies — plain synchronous state plus tracing.
//! The actor wrapper owns the mailbox, timeout timer and parent address and
//! merely reacts to the [`CollectOutcome`] returned by these methods.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use e3_events::{E3id, EncryptionKey, PartyId};
use tracing::info;

/// Lifecycle of a collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionPhase {
    Collecting,
    Finished,
    TimedOut,
}

/// Result of feeding an input into the collection.
#[derive(Debug)]
pub(crate) enum CollectOutcome {
    /// Nothing actionable happened (not collecting, unexpected/duplicate party,
    /// or an already-delivered expelled party was scrubbed).
    Ignored,
    /// Input accepted, still waiting on more parties.
    Pending,
    /// All expected keys are now present, sorted by `party_id`.
    Completed(Vec<Arc<EncryptionKey>>),
}

/// Pure tally for the encryption-key collection phase.
pub(crate) struct EncryptionKeyCollection {
    e3_id: E3id,
    todo: HashSet<PartyId>,
    keys: HashMap<PartyId, Arc<EncryptionKey>>,
    phase: CollectionPhase,
}

impl EncryptionKeyCollection {
    /// Expect keys from parties `0..total`.
    pub fn new(e3_id: E3id, total: u64) -> Self {
        Self {
            e3_id,
            todo: (0..total).collect(),
            keys: HashMap::new(),
            phase: CollectionPhase::Collecting,
        }
    }

    pub fn is_collecting(&self) -> bool {
        matches!(self.phase, CollectionPhase::Collecting)
    }

    /// Record a received encryption key.
    pub fn receive(&mut self, key: Arc<EncryptionKey>) -> CollectOutcome {
        if !self.is_collecting() {
            info!(
                e3_id = %self.e3_id,
                "EncryptionKeyCollection is not collecting, ignoring"
            );
            return CollectOutcome::Ignored;
        }

        let pid = key.party_id;
        if self.todo.take(&pid).is_none() {
            info!(
                e3_id = %self.e3_id,
                "Error: {} was not in encryption key collector's ID list",
                pid
            );
            return CollectOutcome::Ignored;
        }

        info!(
            e3_id = %self.e3_id,
            "Inserting encryption key... waiting on: {}",
            self.todo.len()
        );
        self.keys.insert(pid, key);
        self.finish_if_done()
    }

    /// Remove an expelled party from the expected set so the DKG can complete
    /// with N-1 keys. If the party already delivered, scrub their key.
    pub fn expel(&mut self, party_id: PartyId) -> CollectOutcome {
        if !self.is_collecting() {
            return CollectOutcome::Ignored;
        }

        if !self.todo.remove(&party_id) {
            if self.keys.remove(&party_id).is_some() {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} already delivered key — removed from collected keys",
                    party_id
                );
            } else {
                info!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Expelled party {} was not in todo set and had no collected key",
                    party_id
                );
            }
            return CollectOutcome::Ignored;
        }

        info!(
            e3_id = %self.e3_id,
            party_id,
            remaining = self.todo.len(),
            "Removed expelled party {} from encryption key collection, {} remaining",
            party_id,
            self.todo.len()
        );
        self.finish_if_done()
    }

    /// Mark the collection as timed out, returning the missing parties if it
    /// was still collecting (otherwise `None`).
    pub fn timeout(&mut self) -> Option<Vec<PartyId>> {
        if !self.is_collecting() {
            return None;
        }
        self.phase = CollectionPhase::TimedOut;
        Some(self.todo.iter().copied().collect())
    }

    fn finish_if_done(&mut self) -> CollectOutcome {
        if self.todo.is_empty() {
            info!(e3_id = %self.e3_id, "All encryption keys collected!");
            self.phase = CollectionPhase::Finished;
            CollectOutcome::Completed(self.sorted_keys())
        } else {
            CollectOutcome::Pending
        }
    }

    fn sorted_keys(&self) -> Vec<Arc<EncryptionKey>> {
        let mut keys: Vec<_> = self.keys.values().cloned().collect();
        keys.sort_by_key(|k| k.party_id);
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(party_id: u64) -> Arc<EncryptionKey> {
        Arc::new(EncryptionKey::new(
            party_id,
            e3_utils::utility_types::ArcBytes::from_bytes(&[]),
        ))
    }

    fn collection() -> EncryptionKeyCollection {
        EncryptionKeyCollection::new(E3id::new("1", 1), 3)
    }

    #[test]
    fn collects_all_keys_in_party_order() {
        let mut c = collection();
        assert!(matches!(c.receive(key(2)), CollectOutcome::Pending));
        assert!(matches!(c.receive(key(0)), CollectOutcome::Pending));
        match c.receive(key(1)) {
            CollectOutcome::Completed(keys) => {
                let ids: Vec<_> = keys.iter().map(|k| k.party_id).collect();
                assert_eq!(ids, vec![0, 1, 2]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(!c.is_collecting());
    }

    #[test]
    fn unexpected_party_is_ignored() {
        let mut c = collection();
        assert!(matches!(c.receive(key(9)), CollectOutcome::Ignored));
    }

    #[test]
    fn receive_after_finished_is_ignored() {
        let mut c = collection();
        c.receive(key(0));
        c.receive(key(1));
        c.receive(key(2));
        assert!(matches!(c.receive(key(0)), CollectOutcome::Ignored));
    }

    #[test]
    fn expel_reduces_todo_and_can_complete() {
        let mut c = collection();
        c.receive(key(0));
        c.receive(key(1));
        // party 2 never delivers; expelling it completes with N-1 keys.
        match c.expel(2) {
            CollectOutcome::Completed(keys) => {
                let ids: Vec<_> = keys.iter().map(|k| k.party_id).collect();
                assert_eq!(ids, vec![0, 1]);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn expel_after_delivery_scrubs_key_without_completing() {
        let mut c = collection();
        c.receive(key(0));
        c.receive(key(1));
        // party 1 already delivered; expelling scrubs the key and does not complete.
        assert!(matches!(c.expel(1), CollectOutcome::Ignored));
        // still collecting (party 2 outstanding, party 1 scrubbed)
        assert!(c.is_collecting());
        match c.expel(2) {
            CollectOutcome::Completed(keys) => {
                let ids: Vec<_> = keys.iter().map(|k| k.party_id).collect();
                assert_eq!(ids, vec![0], "scrubbed party 1 must not reappear");
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn timeout_reports_missing_then_is_inert() {
        let mut c = collection();
        c.receive(key(0));
        let mut missing = c.timeout().expect("missing parties");
        missing.sort();
        assert_eq!(missing, vec![1, 2]);
        assert!(!c.is_collecting());
        assert!(c.timeout().is_none(), "second timeout is a no-op");
    }
}
