// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain reader's progress signal for a local health check.
//!
//! A reader that cannot reach its provider logs errors and retries, but nothing outside the
//! process can see that its ingestion stopped. The reader therefore reports every successful read
//! of the chain head, with its cursor, to a sink. The file sink below writes one small file per
//! chain, which `dappnode/healthcheck.sh` reads: a file that stops changing means a stalled reader,
//! and a head and cursor that both stop moving mean a provider that stopped following the chain,
//! or a sync that stopped advancing.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// What a chain reader learned from its provider in one successful read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngestionProgress {
    pub chain_id: u64,
    /// The provider's chain head at the read.
    pub head: u64,
    /// The last block whose logs the reader delivered.
    pub cursor: u64,
}

/// Receives each successful head read of a chain reader.
pub type IngestionProgressSink = Arc<dyn Fn(IngestionProgress) + Send + Sync>;

/// Name of the heartbeat file of one chain under the heartbeat directory.
pub fn heartbeat_file_name(chain_id: u64) -> String {
    format!("chain-{chain_id}.heartbeat")
}

struct ChainHeartbeat {
    head: u64,
    cursor: u64,
    progressed_at: u64,
    last_error: Option<String>,
}

/// A sink that writes one heartbeat file per chain under `dir`.
///
/// Each file holds `key=value` lines: `chain_id`, `head`, `cursor`, `polled_at` (Unix seconds of
/// the read) and `progressed_at` (Unix seconds of the last read at which `head` or `cursor`
/// changed). The cursor counts as progress because a long historical sync reads toward one head
/// for minutes while its cursor advances. The format is for a shell health check, which needs no
/// JSON parser. Each write replaces the file atomically, so a reader never sees a partial file.
///
/// The directory is created and probed for writes first, so a node whose heartbeat can never be
/// written fails at startup instead of passing a health check that finds no heartbeat. Files of an
/// earlier run are removed, so a health check that runs during a long startup finds no heartbeat
/// instead of a stale one.
pub fn ingestion_heartbeat_files(dir: PathBuf) -> io::Result<IngestionProgressSink> {
    ingestion_heartbeat_files_with_clock(dir, Arc::new(unix_now))
}

/// [`ingestion_heartbeat_files`] with the clock as a parameter, for tests.
pub fn ingestion_heartbeat_files_with_clock(
    dir: PathBuf,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
) -> io::Result<IngestionProgressSink> {
    fs::create_dir_all(&dir)?;
    clear_heartbeats(&dir)?;
    let probe = dir.join(".write-probe");
    fs::write(&probe, b"")?;
    fs::remove_file(&probe)?;

    let chains: Mutex<HashMap<u64, ChainHeartbeat>> = Mutex::new(HashMap::new());
    Ok(Arc::new(move |progress: IngestionProgress| {
        let mut chains = chains
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = clock();
        let entry = chains
            .entry(progress.chain_id)
            .or_insert_with(|| ChainHeartbeat {
                head: progress.head,
                cursor: progress.cursor,
                progressed_at: now,
                last_error: None,
            });
        if entry.head != progress.head || entry.cursor != progress.cursor {
            entry.head = progress.head;
            entry.cursor = progress.cursor;
            entry.progressed_at = now;
        }
        let result = write_heartbeat(&dir, progress, now, entry.progressed_at);
        // Log a write failure once, and the recovery once, not on every poll.
        match result {
            Ok(()) => {
                if entry.last_error.take().is_some() {
                    info!(
                        chain_id = progress.chain_id,
                        "Ingestion heartbeat writes recovered"
                    );
                }
            }
            Err(error) => {
                let message = error.to_string();
                if entry.last_error.as_deref() != Some(message.as_str()) {
                    warn!(
                        chain_id = progress.chain_id,
                        dir = %dir.display(),
                        error = %message,
                        "Could not write the ingestion heartbeat"
                    );
                    entry.last_error = Some(message);
                }
            }
        }
    }))
}

/// Name of the file under the heartbeat directory that states how many chain readers the node
/// starts, and when it started.
pub const INGESTION_EXPECTATION_FILE: &str = "expected";

/// Record, before the node builds anything, that it starts `chains` chain readers now: `chains`
/// and `started_at` (Unix seconds) as `key=value` lines, written atomically. After a startup grace,
/// the health check requires a heartbeat for every one of them, so a reader that never reaches its
/// first successful read fails the check instead of passing as a node that is still starting.
pub fn write_ingestion_expectation(dir: &Path, chains: usize) -> io::Result<()> {
    write_ingestion_expectation_at(dir, chains, unix_now())
}

/// [`write_ingestion_expectation`] at `started_at`, for tests.
pub fn write_ingestion_expectation_at(
    dir: &Path,
    chains: usize,
    started_at: u64,
) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(INGESTION_EXPECTATION_FILE);
    let tmp = dir.join(format!("{INGESTION_EXPECTATION_FILE}.tmp"));
    fs::write(
        &tmp,
        format!(
            "chains={chains}
started_at={started_at}
"
        ),
    )?;
    fs::rename(&tmp, &path)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn clear_heartbeats(dir: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        let is_heartbeat = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("chain-") && name.ends_with(".heartbeat"));
        if is_heartbeat {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn write_heartbeat(
    dir: &Path,
    progress: IngestionProgress,
    polled_at: u64,
    progressed_at: u64,
) -> io::Result<()> {
    let content = format!(
        "chain_id={}\nhead={}\ncursor={}\npolled_at={}\nprogressed_at={}\n",
        progress.chain_id, progress.head, progress.cursor, polled_at, progressed_at
    );
    let path = dir.join(heartbeat_file_name(progress.chain_id));
    let tmp = dir.join(format!("{}.tmp", heartbeat_file_name(progress.chain_id)));
    fs::write(&tmp, content)?;
    fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The expectation names the chain readers and the start time, and the heartbeat sink, which
    /// removes the heartbeats of an earlier run, keeps it.
    #[test]
    fn the_expectation_survives_the_heartbeat_reset() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(heartbeat_file_name(1)), b"chain_id=1\n").unwrap();
        write_ingestion_expectation_at(dir.path(), 2, 1_000).unwrap();
        let _sink = ingestion_heartbeat_files(dir.path().to_path_buf()).unwrap();

        assert_eq!(
            fs::read_to_string(dir.path().join(INGESTION_EXPECTATION_FILE)).unwrap(),
            "chains=2\nstarted_at=1000\n"
        );
        assert!(!dir.path().join(heartbeat_file_name(1)).exists());
    }

    fn read_fields(dir: &Path, chain_id: u64) -> HashMap<String, String> {
        fs::read_to_string(dir.join(heartbeat_file_name(chain_id)))
            .expect("heartbeat file")
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    /// A sink whose clock the test moves.
    fn sink_with_clock(dir: &Path) -> (IngestionProgressSink, Arc<std::sync::atomic::AtomicU64>) {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let clock = now.clone();
        let sink = ingestion_heartbeat_files_with_clock(
            dir.to_path_buf(),
            Arc::new(move || clock.load(std::sync::atomic::Ordering::SeqCst)),
        )
        .unwrap();
        (sink, now)
    }

    #[test]
    fn a_heartbeat_file_records_the_read_and_when_the_reader_last_progressed() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let (sink, now) = sink_with_clock(dir.path());

        sink(IngestionProgress {
            chain_id: 1,
            head: 100,
            cursor: 99,
        });
        let first = read_fields(dir.path(), 1);
        assert_eq!(first["chain_id"], "1");
        assert_eq!(first["head"], "100");
        assert_eq!(first["cursor"], "99");
        assert_eq!(first["polled_at"], "1000");
        assert_eq!(first["progressed_at"], "1000");
        assert!(!dir.path().join("chain-1.heartbeat.tmp").exists());

        // Ten seconds later, the same head and cursor: the poll is fresh, nothing progressed.
        now.store(1_010, Ordering::SeqCst);
        sink(IngestionProgress {
            chain_id: 1,
            head: 100,
            cursor: 99,
        });
        let second = read_fields(dir.path(), 1);
        assert_eq!(second["polled_at"], "1010");
        assert_eq!(second["progressed_at"], "1000");

        // The cursor moves while the head stays: a historical sync toward one head progresses.
        now.store(1_020, Ordering::SeqCst);
        sink(IngestionProgress {
            chain_id: 1,
            head: 100,
            cursor: 100,
        });
        let third = read_fields(dir.path(), 1);
        assert_eq!(third["cursor"], "100");
        assert_eq!(third["progressed_at"], "1020");

        // A new head with the same cursor progresses too.
        now.store(1_030, Ordering::SeqCst);
        sink(IngestionProgress {
            chain_id: 1,
            head: 101,
            cursor: 100,
        });
        let fourth = read_fields(dir.path(), 1);
        assert_eq!(fourth["head"], "101");
        assert_eq!(fourth["progressed_at"], "1030");
    }

    #[test]
    fn an_unwritable_heartbeat_directory_fails_at_startup() {
        // A node whose heartbeat can never be written must not pass a health check that treats a
        // missing heartbeat as a starting node.
        let dir = tempfile::tempdir().unwrap();
        let file_in_the_way = dir.path().join("ingestion");
        fs::write(&file_in_the_way, b"not a directory").unwrap();

        assert!(ingestion_heartbeat_files(file_in_the_way).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_denies_writes_fails_the_startup_probe() {
        use std::os::unix::fs::PermissionsExt;

        // The directory exists and is empty, so creation and cleanup succeed; only the probe
        // write can report that heartbeats will never be written.
        let dir = tempfile::tempdir().unwrap();
        let read_only = dir.path().join("ingestion");
        fs::create_dir(&read_only).unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o555)).unwrap();
        let can_write = fs::write(read_only.join("check"), b"").is_ok();

        let result = ingestion_heartbeat_files(read_only.clone());

        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o755)).unwrap();
        if can_write {
            // Running as root: permissions do not deny the write, so the probe cannot fail here.
            return;
        }
        assert!(result.is_err());
    }

    #[test]
    fn each_chain_has_its_own_file() {
        let dir = tempfile::tempdir().unwrap();
        let sink = ingestion_heartbeat_files(dir.path().to_path_buf()).unwrap();
        sink(IngestionProgress {
            chain_id: 1,
            head: 10,
            cursor: 10,
        });
        sink(IngestionProgress {
            chain_id: 11155111,
            head: 20,
            cursor: 19,
        });
        assert_eq!(read_fields(dir.path(), 1)["head"], "10");
        assert_eq!(read_fields(dir.path(), 11155111)["cursor"], "19");
    }

    #[test]
    fn the_files_of_an_earlier_run_are_removed_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("chain-1.heartbeat"), "polled_at=1\n").unwrap();
        fs::write(dir.path().join("notes.txt"), "keep").unwrap();

        // A health check between process start and the first read must find no heartbeat, not
        // the stale one of the previous run.
        let _sink = ingestion_heartbeat_files(dir.path().to_path_buf()).unwrap();

        assert!(!dir.path().join("chain-1.heartbeat").exists());
        assert!(dir.path().join("notes.txt").exists());
    }
}
