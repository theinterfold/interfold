// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Machine-readable timing for the CKKS DKG, relin ceremony, and
//! decryption-share path.
//!
//! Every mark writes ONE `tracing` event with target `ckks_timing`, the
//! literal message `ckks_timing`, and `key=value` fields only — so a
//! script can grep a node log for `ckks_timing` and tabulate it
//! (`scripts/ckks-timing-report.sh`). Fields:
//!
//! - `e3`: the E3 id (`chain:id`)
//! - `party`: this node's 0-based on-chain committee slot
//! - `phase`: dotted phase name (`dkg.*`, `ceremony.*`, `decrypt.*`)
//! - `t_ms`: milliseconds since the timeline origin (`CiphernodeSelected`,
//!   or the restart when the timeline was rebuilt on recovery)
//! - `dt_ms`: milliseconds since the previous mark on this timeline
//! - `dur_ms` (spans only): wall time of the measured computation
//! - `level`, `bytes`, `count`: optional per-phase detail
//! - `origin`: `selected` or `restart`
//!
//! Field names deliberately avoid the operator log's sensitive-name
//! filter (`seed`, `keyshare`, `secret`, ...), which would redact them.
//!
//! Process-local by design: `Instant`s do not survive a restart, so a
//! recovered node starts a fresh timeline with `origin=restart` rather
//! than pretending to know the pre-crash clock.

use std::time::Instant;

/// Log target every timing event carries.
pub const CKKS_TIMING_TARGET: &str = "ckks_timing";

/// One node's timing marks for one CKKS E3.
#[derive(Debug, Clone)]
pub struct CkksTimeline {
    e3: String,
    party_id_chain: u64,
    origin: Instant,
    origin_kind: &'static str,
    last: Instant,
}

/// Optional per-mark detail.
#[derive(Debug, Clone, Copy, Default)]
pub struct Detail {
    /// Ceremony level the mark is about.
    pub level: Option<usize>,
    /// Payload size the mark is about.
    pub bytes: Option<usize>,
    /// Item count the mark is about (chunks, keys, shares).
    pub count: Option<usize>,
}

impl Detail {
    /// Detail for one ceremony level.
    pub fn level(level: usize) -> Self {
        Self {
            level: Some(level),
            ..Self::default()
        }
    }

    /// Detail for one ceremony level plus a payload size.
    pub fn level_bytes(level: usize, bytes: usize) -> Self {
        Self {
            level: Some(level),
            bytes: Some(bytes),
            count: None,
        }
    }

    /// Detail carrying a count.
    pub fn count(count: usize) -> Self {
        Self {
            count: Some(count),
            ..Self::default()
        }
    }

    /// Detail carrying a payload size only (hybrid ceremony shares have
    /// no level).
    pub fn bytes(bytes: usize) -> Self {
        Self {
            bytes: Some(bytes),
            ..Self::default()
        }
    }
}

impl CkksTimeline {
    /// Start a timeline now. `origin_kind` is `"selected"` for a fresh E3
    /// and `"restart"` when rebuilt on recovery.
    pub fn start(e3: impl Into<String>, party_id_chain: u64, origin_kind: &'static str) -> Self {
        let now = Instant::now();
        Self {
            e3: e3.into(),
            party_id_chain,
            origin: now,
            origin_kind,
            last: now,
        }
    }

    fn ms(d: std::time::Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    /// Record that `phase` happened now.
    pub fn mark(&mut self, phase: &'static str) {
        self.mark_with(phase, Detail::default());
    }

    /// Record that `phase` happened now, with detail.
    pub fn mark_with(&mut self, phase: &'static str, detail: Detail) {
        let now = Instant::now();
        let t_ms = Self::ms(now.duration_since(self.origin));
        let dt_ms = Self::ms(now.duration_since(self.last));
        self.last = now;
        tracing::info!(
            target: "ckks_timing",
            e3 = %self.e3,
            party = self.party_id_chain,
            phase = phase,
            level = detail.level,
            bytes = detail.bytes,
            count = detail.count,
            t_ms,
            dt_ms,
            origin = self.origin_kind,
            "ckks_timing"
        );
    }

    /// Time a synchronous computation and record it as `phase` with its
    /// wall duration in `dur_ms`.
    pub fn span<T>(&mut self, phase: &'static str, detail: Detail, f: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let out = f();
        self.record_span(phase, detail, started.elapsed());
        out
    }

    /// Record an already-measured computation as `phase` with `dur_ms`
    /// (for callers that cannot wrap the computation in a closure because
    /// the borrow checker needs the timeline free while it runs).
    pub fn record_span(&mut self, phase: &'static str, detail: Detail, dur: std::time::Duration) {
        let now = Instant::now();
        let dur_ms = Self::ms(dur);
        let t_ms = Self::ms(now.duration_since(self.origin));
        let dt_ms = Self::ms(now.duration_since(self.last));
        self.last = now;
        tracing::info!(
            target: "ckks_timing",
            e3 = %self.e3,
            party = self.party_id_chain,
            phase = phase,
            level = detail.level,
            bytes = detail.bytes,
            count = detail.count,
            t_ms,
            dt_ms,
            dur_ms,
            origin = self.origin_kind,
            "ckks_timing"
        );
    }
}
