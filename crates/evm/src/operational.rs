// SPDX-License-Identifier: LGPL-3.0-only

//! Read-only operational probes for required EVM readers and writers.
//!
//! These snapshots are observability state, not protocol authority. Protocol state remains in the
//! event log, repositories, and contracts; readiness only uses these probes to fail closed when a
//! required runtime boundary is no longer making progress.

use actix::{Message, Recipient};
use anyhow::Context;
use serde::Serialize;
use std::{
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EvmIngestionSnapshot {
    pub chain_name: String,
    pub expected_chain_id: u64,
    pub connected_chain_id: Option<u64>,
    pub confirmations: u64,
    pub raw_head: Option<u64>,
    pub confirmed_head: Option<u64>,
    pub cursor: Option<u64>,
    pub head_timestamp_secs: Option<u64>,
    pub last_success_at_ms: Option<u64>,
    pub last_error_at_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct EvmIngestionState {
    snapshot: EvmIngestionSnapshot,
}

/// Cheaply cloneable progress handle shared by the chain reader and readiness server.
#[derive(Clone, Default)]
pub struct EvmIngestionStatus(Arc<RwLock<EvmIngestionState>>);

impl std::fmt::Debug for EvmIngestionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmIngestionStatus")
            .field("snapshot", &self.snapshot())
            .finish()
    }
}

impl EvmIngestionStatus {
    pub fn new(chain_name: impl Into<String>, expected_chain_id: u64) -> Self {
        Self(Arc::new(RwLock::new(EvmIngestionState {
            snapshot: EvmIngestionSnapshot {
                chain_name: chain_name.into(),
                expected_chain_id,
                ..EvmIngestionSnapshot::default()
            },
        })))
    }

    pub fn configure(&self, connected_chain_id: u64, confirmations: u64) {
        if let Ok(mut state) = self.0.write() {
            state.snapshot.connected_chain_id = Some(connected_chain_id);
            state.snapshot.confirmations = confirmations;
        }
    }

    pub fn record_progress(
        &self,
        connected_chain_id: u64,
        confirmations: u64,
        raw_head: u64,
        cursor: u64,
        head_timestamp_secs: u64,
    ) {
        if let Ok(mut state) = self.0.write() {
            state.snapshot.connected_chain_id = Some(connected_chain_id);
            state.snapshot.confirmations = confirmations;
            state.snapshot.raw_head = Some(raw_head);
            state.snapshot.confirmed_head = Some(raw_head.saturating_sub(confirmations));
            state.snapshot.cursor = Some(cursor);
            state.snapshot.head_timestamp_secs = Some(head_timestamp_secs);
            state.snapshot.last_success_at_ms = Some(now_ms());
            state.snapshot.last_error = None;
            state.snapshot.last_error_at_ms = None;
        }
    }

    pub fn record_error(&self, error: impl Into<String>) {
        if let Ok(mut state) = self.0.write() {
            state.snapshot.last_error = Some(error.into());
            state.snapshot.last_error_at_ms = Some(now_ms());
        }
    }

    pub fn snapshot(&self) -> EvmIngestionSnapshot {
        self.0
            .read()
            .map(|state| state.snapshot.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvmWriterHealth {
    pub writer: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub effects_enabled: bool,
    pub pending_effects: usize,
    pub oldest_pending_age_ms: Option<u64>,
    pub in_flight_effects: usize,
}

#[derive(Message, Clone, Copy, Debug)]
#[rtype(result = "EvmWriterHealth")]
pub struct GetEvmWriterHealth {
    pub now_ms: u64,
}

impl GetEvmWriterHealth {
    pub fn now() -> Self {
        Self { now_ms: now_ms() }
    }
}

/// Type-erased handle for probing any required EVM writer actor.
#[derive(Clone)]
pub struct EvmWriterProbe {
    recipient: Recipient<GetEvmWriterHealth>,
}

impl std::fmt::Debug for EvmWriterProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmWriterProbe").finish_non_exhaustive()
    }
}

impl EvmWriterProbe {
    pub fn new(recipient: Recipient<GetEvmWriterHealth>) -> Self {
        Self { recipient }
    }

    pub async fn snapshot(&self) -> anyhow::Result<EvmWriterHealth> {
        self.recipient
            .send(GetEvmWriterHealth::now())
            .await
            .context("required EVM writer actor is unavailable")
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_clears_transient_error_and_tracks_confirmed_cursor() {
        let status = EvmIngestionStatus::new("test", 31337);
        status.record_error("rpc unavailable");
        status.record_progress(31337, 12, 120, 108, 1_700_000_000);

        let snapshot = status.snapshot();
        assert_eq!(snapshot.expected_chain_id, 31337);
        assert_eq!(snapshot.connected_chain_id, Some(31337));
        assert_eq!(snapshot.confirmed_head, Some(108));
        assert_eq!(snapshot.cursor, Some(108));
        assert!(snapshot.last_error.is_none());
        assert!(snapshot.last_success_at_ms.is_some());
    }
}
