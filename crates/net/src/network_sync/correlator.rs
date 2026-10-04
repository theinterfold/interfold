// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::CorrelationId;
use libp2p::kad;
use libp2p::request_response;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Maximum time a correlation entry is kept before being considered stale
const CORRELATOR_TTL: Duration = Duration::from_secs(120);

/// This correlates query_id and correlation_id.
/// Entries are automatically cleaned up after CORRELATOR_TTL to prevent memory leaks
/// from responses that never arrive.
#[derive(Clone)]
pub(crate) struct Correlator {
    inner: HashMap<CorrelatorKey, (CorrelationId, Instant)>,
    /// Tracked queries that this node cancelled. Always a subset of `inner`.
    cancelled: HashSet<CorrelatorKey>,
}

/// Typed key for the correlator, avoiding string formatting
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) enum CorrelatorKey {
    Kademlia(kad::QueryId),
    RequestResponse(request_response::OutboundRequestId),
}

impl From<kad::QueryId> for CorrelatorKey {
    fn from(id: kad::QueryId) -> Self {
        CorrelatorKey::Kademlia(id)
    }
}

impl From<request_response::OutboundRequestId> for CorrelatorKey {
    fn from(id: request_response::OutboundRequestId) -> Self {
        CorrelatorKey::RequestResponse(id)
    }
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            cancelled: HashSet::new(),
        }
    }

    /// Add a pairing between query_id and correlation_id
    pub fn track(&mut self, query_id: impl Into<CorrelatorKey>, correlation_id: CorrelationId) {
        self.cleanup_stale();
        self.inner
            .insert(query_id.into(), (correlation_id, Instant::now()));
    }

    /// Remove the pairing and return the correlation_id
    pub fn expire(&mut self, query_id: impl Into<CorrelatorKey>) -> Result<CorrelationId> {
        Ok(self.expire_cancellable(query_id)?.0)
    }

    /// Note that this node cancelled a tracked query, so that its result is not reported as a
    /// failure.
    pub fn mark_cancelled(&mut self, query_id: impl Into<CorrelatorKey>) {
        let key = query_id.into();
        if self.inner.contains_key(&key) {
            self.cancelled.insert(key);
        }
    }

    /// Remove the pairing and return the correlation_id, and whether this node cancelled the
    /// query.
    pub fn expire_cancellable(
        &mut self,
        query_id: impl Into<CorrelatorKey>,
    ) -> Result<(CorrelationId, bool)> {
        let key = query_id.into();
        let cancelled = self.cancelled.remove(&key);
        self.inner
            .remove(&key)
            .map(|(cid, _)| (cid, cancelled))
            .ok_or_else(|| anyhow::anyhow!("Failed to correlate query_id"))
    }

    /// Remove entries older than CORRELATOR_TTL to prevent unbounded growth
    fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.inner
            .retain(|_, (_, created)| now.duration_since(*created) < CORRELATOR_TTL);
        let inner = &self.inner;
        self.cancelled.retain(|key| inner.contains_key(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cancelled_query_is_reported_as_cancelled_once() -> Result<()> {
        let local = libp2p::PeerId::random();
        let mut kademlia = kad::Behaviour::new(local, kad::store::MemoryStore::new(local));
        let mut query = || kademlia.get_closest_peers(libp2p::PeerId::random());
        let (cancelled, finished, untracked) = (query(), query(), query());
        let mut correlator = Correlator::new();
        correlator.track(cancelled, CorrelationId::new());
        correlator.track(finished, CorrelationId::new());
        correlator.mark_cancelled(cancelled);
        // An untracked query is not remembered.
        correlator.mark_cancelled(untracked);

        assert!(correlator.expire_cancellable(cancelled)?.1);
        assert!(!correlator.expire_cancellable(finished)?.1);
        assert!(correlator.cancelled.is_empty());
        Ok(())
    }
}
