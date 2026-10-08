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
    sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

/// The next ID of this process. IDs persist in the event log, and a restarted node replays them
/// next to the IDs it issues again, so each boot starts above every ID that an earlier boot can
/// have issued: at the current time in microseconds, which no boot outruns one ID at a time.
fn next_correlation_id() -> &'static AtomicUsize {
    static NEXT: OnceLock<AtomicUsize> = OnceLock::new();
    NEXT.get_or_init(|| {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_micros())
            .unwrap_or_default();
        AtomicUsize::new(usize::try_from(micros).unwrap_or(usize::MAX / 2).max(1))
    })
}

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
        let id = next_correlation_id().fetch_add(1, Ordering::SeqCst);
        Self { id }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// IDs of a new boot start at the boot time, above the IDs that an earlier boot issued.
    #[test]
    fn ids_start_above_the_ids_of_earlier_boots() {
        let earlier_boot_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as usize
            - 1_000_000;
        let first = CorrelationId::new();
        let second = CorrelationId::new();
        assert!(first.id > earlier_boot_start);
        assert!(second.id > first.id);
    }
}
