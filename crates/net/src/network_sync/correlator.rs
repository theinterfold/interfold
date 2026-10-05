// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_events::CorrelationId;
use libp2p::kad;
use libp2p::request_response;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum time a correlation entry is kept before being considered stale
const CORRELATOR_TTL: Duration = Duration::from_secs(120);

/// This correlates query_id and correlation_id.
/// Entries are automatically cleaned up after CORRELATOR_TTL to prevent memory leaks
/// from responses that never arrive.
#[derive(Clone)]
pub(crate) struct Correlator {
    inner: HashMap<CorrelatorKey, (CorrelationId, Instant)>,
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
        self.inner
            .remove(&query_id.into())
            .map(|(cid, _)| cid)
            .ok_or_else(|| anyhow::anyhow!("Failed to correlate query_id"))
    }

    /// Remove entries older than CORRELATOR_TTL to prevent unbounded growth
    fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.inner
            .retain(|_, (_, created)| now.duration_since(*created) < CORRELATOR_TTL);
    }
}
