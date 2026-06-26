// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{
    fmt,
    fmt::Debug,
    fmt::Display,
    fmt::Formatter,
    sync::atomic::{AtomicUsize, Ordering},
};

use serde::{Deserialize, Serialize};

static NEXT_CORRELATION_ID: AtomicUsize = AtomicUsize::new(1);

/// CorrelationId provides a way to correlate commands and the events they create.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId {
    id: usize,
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationId {
    pub fn new() -> Self {
        let id = NEXT_CORRELATION_ID.fetch_add(1, Ordering::SeqCst);
        Self { id }
    }

    /// Derive a deterministic correlation id from arbitrary content bytes.
    ///
    /// Used for `ComputeRequest`s so a request/response pair can be matched across a process
    /// restart: `CorrelationId::new()` is a per-process counter that resets on restart, so a
    /// regenerated compute would get a different id and its response would be dropped by the
    /// dispatching actor. A content hash is stable across restart and identical for a replayed vs.
    /// regenerated request (given deterministic inputs). Uses SHA-256 (stable across toolchain
    /// versions, unlike `std`'s `DefaultHasher`); 64 bits of digest make collisions negligible.
    pub fn from_seed(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&digest[..8]);
        Self {
            id: u64::from_le_bytes(id_bytes) as usize,
        }
    }
}

impl Display for CorrelationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Debug for CorrelationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
