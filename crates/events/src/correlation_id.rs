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
    fs, io,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// IDs that one boot of a node reserves. A boot that issues more could repeat some of them in the
/// next boot; at any realistic rate that takes years.
const CORRELATION_ID_RESERVATION: usize = 1 << 32;

/// The next ID of this process. IDs persist in the event log, and a restarted node replays them
/// next to the IDs it issues again. Each boot starts at the current time in microseconds, which no
/// boot outruns one ID at a time, and a node then raises it above the reservation of its earlier
/// boot (`reserve_correlation_ids`), which also holds after a clock rollback.
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

/// Keep this process's correlation IDs above every ID that an earlier boot of the node issued:
/// raise the next ID to the reservation recorded at `path`, then durably record a reservation above
/// the IDs that this boot can issue. A node without the file, such as one that starts from reset
/// state, keeps the clock seed. A file that is not a number stops the start: guessing could repeat
/// IDs that the event log replays.
pub fn reserve_correlation_ids(path: &Path) -> anyhow::Result<()> {
    let recorded = match fs::read_to_string(path) {
        Ok(text) => text.trim().parse::<usize>().with_context(|| {
            format!(
                "{} does not hold a correlation ID reservation; restore it, or remove it together \
                 with the event log by resetting the node state",
                path.display()
            )
        })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    };
    let next = next_correlation_id()
        .fetch_max(recorded, Ordering::SeqCst)
        .max(recorded);
    let reservation = next.saturating_add(CORRELATION_ID_RESERVATION);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let staged = path.with_extension("staged");
    fs::write(&staged, reservation.to_string())
        .with_context(|| format!("failed to write {}", staged.display()))?;
    fs::File::open(&staged)?.sync_all()?;
    fs::rename(&staged, path).with_context(|| format!("failed to replace {}", path.display()))?;
    // The rename is durable only once the directory entry is.
    #[cfg(unix)]
    fs::File::open(parent)?
        .sync_all()
        .with_context(|| format!("failed to sync {}", parent.display()))?;
    Ok(())
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

    /// An earlier boot reserved IDs above this boot's clock seed, as after a clock rollback: the
    /// IDs of this boot start above that reservation, and the next boot's reservation is higher.
    #[test]
    fn a_restart_issues_ids_above_the_earlier_reservation() {
        let path = std::env::temp_dir().join(format!(
            "correlation-ids-{}-{}",
            std::process::id(),
            CorrelationId::new().id
        ));
        let reserved = CorrelationId::new().id + (1usize << 40);
        fs::write(&path, reserved.to_string()).unwrap();

        reserve_correlation_ids(&path).unwrap();

        assert!(CorrelationId::new().id >= reserved);
        let recorded: usize = fs::read_to_string(&path).unwrap().trim().parse().unwrap();
        assert!(recorded >= reserved + CORRELATION_ID_RESERVATION);
        fs::remove_file(&path).unwrap();
    }

    /// A fresh node writes its first reservation into a folder that does not exist yet, and a
    /// reservation that is not a number stops the start instead of being ignored.
    #[test]
    fn a_fresh_folder_gets_a_reservation_and_a_broken_one_stops_the_start() {
        let dir = std::env::temp_dir().join(format!(
            "correlation-ids-{}-{}",
            std::process::id(),
            CorrelationId::new().id
        ));
        let path = dir.join("node").join("correlation-ids");

        reserve_correlation_ids(&path).unwrap();
        let recorded: usize = fs::read_to_string(&path).unwrap().trim().parse().unwrap();
        assert!(recorded > CorrelationId::new().id);

        fs::write(&path, "not a number").unwrap();
        assert!(reserve_correlation_ids(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
