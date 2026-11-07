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
pub const LOCK_FILE_NAME: &str = "interfold.lock";

/// The error when another live process holds the fence.
#[derive(Debug)]
pub struct FenceHeld {
    node_name: String,
    lock_path: PathBuf,
}

impl std::fmt::Display for FenceHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "another interfold instance is already running for node '{}' against this data \
             directory (lock held at {:?}). Refusing to start a second instance, which would \
             double-sign and corrupt state. Stop the other instance first.",
            self.node_name, self.lock_path
        )
    }
}

impl std::error::Error for FenceHeld {}

/// A held cross-host fence. While this value is alive the process holds an
/// exclusive advisory lock on the node's data directory. Dropping it (on exit)
/// releases the lock.
#[derive(Debug)]
pub struct ProcessFence {
    /// Keeps the OS lock alive for the lifetime of this guard.
    _file: File,
    path: PathBuf,
}

impl Drop for ProcessFence {
    fn drop(&mut self) {
        // Closing normally releases the lock, but an overlapping process spawn can
        // briefly inherit the open file description between fork and exec. Unlock
        // it explicitly so shutdown makes the fence immediately reacquirable.
        let _ = self._file.unlock();
    }
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
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        let mut file = lock(&mut options, lock_path, node_name)?;

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

    /// Hold the fence of an existing lock file without writing to it: a purge fences the nodes it
    /// finds on disk this way, whatever their files' permissions.
    pub fn hold_existing(lock_path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        let file = lock(&mut options, lock_path, &lock_path.display().to_string())?;
        Ok(Self {
            _file: file,
            path: lock_path.to_path_buf(),
        })
    }
}

/// Opens `lock_path` and takes its exclusive lock. The open follows no link, since the fence may
/// rewrite the file and through a link that would be another file, and does not wait, since a FIFO
/// would hold a read-only open until a writer comes; what it opens must be a plain file.
fn lock(options: &mut OpenOptions, lock_path: &Path, node_name: &str) -> Result<File> {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(lock_path).with_context(|| {
        format!("failed to open fence lock file at {lock_path:?}; it must be a plain file")
    })?;
    if !file.metadata()?.is_file() {
        bail!("the fence lock at {lock_path:?} is not a plain file; remove it, then try again");
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(FenceHeld {
            node_name: node_name.to_string(),
            lock_path: lock_path.to_path_buf(),
        }
        .into()),
        Err(std::fs::TryLockError::Error(err)) => {
            Err(err).with_context(|| format!("failed to acquire fence lock at {lock_path:?}"))
        }
    }
}

/// Compute the lock-file path for a given database path. The lock lives in the
/// database directory's parent (the node data directory) so it covers all of
/// the node's on-disk state, not just the sled DB.
pub(crate) fn lock_path_for(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(LOCK_FILE_NAME),
        _ => db_path.with_extension("lock"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A read-only lock file can be held without writing to it, and a held one blocks a second
    /// holder.
    #[cfg(unix)]
    #[test]
    fn an_existing_lock_is_held_without_being_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let lock = dir.path().join(LOCK_FILE_NAME);
        std::fs::write(&lock, b"someone's bytes").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o400)).unwrap();
        let held = ProcessFence::hold_existing(&lock).unwrap();
        assert!(ProcessFence::hold_existing(&lock).is_err());
        drop(held);
        assert_eq!(std::fs::read(&lock).unwrap(), b"someone's bytes");
    }

    /// A FIFO in the lock file's place is refused at once, not waited on.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_the_lock_s_place_is_refused_at_once() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join(LOCK_FILE_NAME);
        let made = std::process::Command::new("mkfifo")
            .arg(&lock)
            .status()
            .unwrap();
        assert!(made.success());
        let error = ProcessFence::hold_existing(&lock).unwrap_err();
        assert!(error.to_string().contains("plain file"), "{error:#}");
    }

    /// A lock file that links elsewhere is refused before the fence writes to it.
    #[cfg(unix)]
    #[test]
    fn a_lock_file_that_is_a_link_is_refused_and_its_target_kept() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("key backup");
        std::fs::write(&target, b"key bytes").unwrap();
        let lock = dir.path().join("node").join(LOCK_FILE_NAME);
        std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        let error = ProcessFence::acquire_at(&lock, "node").unwrap_err();
        assert!(error.to_string().contains("plain file"), "{error:#}");
        assert_eq!(std::fs::read(&target).unwrap(), b"key bytes");
    }

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
            err.is::<FenceHeld>() && err.to_string().contains("already running"),
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
