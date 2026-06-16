// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Cross-host fencing: a process-lifetime advisory lock that guarantees at most
//! one active instance per node data directory.
//!
//! Two copies of the same ciphernode running against the same data directory
//! would double-sign, race on the commitlog, and corrupt derived state. `sled`
//! already takes an OS lock on its own directory, but its error surfaces late
//! and cryptically, and other on-disk state (the key file, snapshots) is not
//! covered. This fence is acquired *before* any store is opened so the second
//! instance fails fast with a clear, actionable message.
//!
//! The lock is an exclusive advisory lock (`flock`-style, via stable
//! [`std::fs::File::try_lock`]) on a dedicated `interfold.lock` file in the node's
//! data directory. The OS releases the lock automatically when the holding
//! process exits (gracefully, by crash, or by kill), so there is no stale-lock
//! recovery problem: a crashed node's lock is immediately reacquirable.
//!
//! Hold the returned [`ProcessFence`] for the lifetime of the process; dropping
//! it releases the lock.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::info;

/// The lock-file name placed in the node's data directory.
const LOCK_FILE_NAME: &str = "interfold.lock";

/// A held cross-host fence. While this value is alive the process holds an
/// exclusive advisory lock on the node's data directory. Dropping it (on exit)
/// releases the lock.
#[derive(Debug)]
pub struct ProcessFence {
    /// Keeps the OS lock alive for the lifetime of this guard.
    _file: File,
    path: PathBuf,
}

impl ProcessFence {
    /// The path to the lock file being held.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Acquire the fence for the data directory derived from `db_path` (the
    /// directory passed to the store, e.g. `config.db_file()`).
    ///
    /// The lock file is created alongside the database directory and tagged with
    /// the holder's pid and `node_name` for diagnostics. Returns an error if
    /// another live process already holds the fence.
    pub fn acquire(db_path: &Path, node_name: &str) -> Result<Self> {
        let lock_path = lock_path_for(db_path);
        Self::acquire_at(&lock_path, node_name)
    }

    /// Acquire the fence at an explicit lock-file path. Exposed for tests and
    /// callers that know the precise lock location.
    pub fn acquire_at(lock_path: &Path, node_name: &str) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create data directory for fence at {parent:?}")
            })?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("failed to open fence lock file at {lock_path:?}"))?;

        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                bail!(
                    "another interfold instance is already running for node '{node_name}' \
                     against this data directory (lock held at {lock_path:?}). Refusing to \
                     start a second instance, which would double-sign and corrupt state. \
                     Stop the other instance first."
                );
            }
            Err(std::fs::TryLockError::Error(err)) => {
                return Err(err)
                    .with_context(|| format!("failed to acquire fence lock at {lock_path:?}"));
            }
        }

        // Best-effort diagnostics: record who holds the lock. Failure to write
        // does not affect correctness (the OS lock is already held).
        let pid = std::process::id();
        let _ = (|| -> std::io::Result<()> {
            file.set_len(0)?;
            write!(file, "node={node_name}\npid={pid}\n")?;
            file.flush()
        })();

        info!("Acquired process fence for node '{node_name}' (pid {pid}) at {lock_path:?}");

        Ok(Self {
            _file: file,
            path: lock_path.to_path_buf(),
        })
    }
}

/// Compute the lock-file path for a given database path. The lock lives in the
/// database directory's parent (the node data directory) so it covers all of
/// the node's on-disk state, not just the sled DB.
fn lock_path_for(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(LOCK_FILE_NAME),
        _ => db_path.with_extension("lock"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn lock_path_is_sibling_of_db_dir() {
        let p = lock_path_for(Path::new("/data/node1/db"));
        assert_eq!(p, PathBuf::from("/data/node1/interfold.lock"));
    }

    #[test]
    fn second_acquire_on_same_dir_fails() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("db");
        let first = ProcessFence::acquire(&db, "node1").expect("first acquire");

        let err = ProcessFence::acquire(&db, "node1")
            .expect_err("second acquire must fail while first is held");
        assert!(
            err.to_string().contains("already running"),
            "unexpected error: {err}"
        );

        drop(first);
        // After releasing, a fresh acquire succeeds again.
        let _again = ProcessFence::acquire(&db, "node1").expect("reacquire after drop");
    }

    #[test]
    fn different_data_dirs_do_not_conflict() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let _a = ProcessFence::acquire(&dir_a.path().join("db"), "a").unwrap();
        let _b = ProcessFence::acquire(&dir_b.path().join("db"), "b").unwrap();
    }

    #[test]
    fn lock_file_records_pid() {
        let dir = tempdir().unwrap();
        let fence = ProcessFence::acquire(&dir.path().join("db"), "diag").unwrap();
        let contents = std::fs::read_to_string(fence.path()).unwrap();
        assert!(contents.contains("node=diag"));
        assert!(contents.contains(&format!("pid={}", std::process::id())));
    }
}
