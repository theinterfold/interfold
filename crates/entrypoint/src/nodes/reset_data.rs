// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Clear durable round state while keeping the operator identity.
//!
//! A release that changes the durable schema refuses to load an older data directory. The
//! operator must discard the old state, but the wallet key and the libp2p keypair live in the
//! same store as that state, so deleting the directory also destroys the identity that holds
//! the bond. This command removes everything except that identity pair.
//!
//! The identity is copied out as ciphertext. The password is never required, so the key material
//! is not decrypted here.
//!
//! The command refuses to delete key-share state for an active E3, that is, an E3 that is not
//! complete or failed. The chain cannot restore a key share.

use anyhow::{bail, Context, Result};
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_config::AppConfig;
use e3_data::{DataStore, Repositories, RepositoriesFactory, SledDb};
use e3_events::{E3Stage, E3id, Get};
use e3_evm::EthPrivateKeyRepositoryFactory;
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_net::NetRepositoryFactory;
use e3_request::E3LifecycleRepositoryFactory;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{info, warn};

use crate::fence::ProcessFence;
use crate::helpers::datastore::setup_datastore;

/// The encrypted identity pair, held while the store is rebuilt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreservedIdentity {
    /// Ciphertext of the operator Ethereum private key.
    pub eth_private_key: Option<Vec<u8>>,
    /// Ciphertext of the libp2p keypair.
    pub libp2p_keypair: Option<Vec<u8>>,
}

impl PreservedIdentity {
    fn is_complete(&self) -> bool {
        self.eth_private_key.is_some() && self.libp2p_keypair.is_some()
    }

    fn is_empty(&self) -> bool {
        self.eth_private_key.is_none() && self.libp2p_keypair.is_none()
    }
}

/// What the reset did, so the caller can report it without re-reading the store.
#[derive(Debug, Clone)]
pub struct ResetOutcome {
    pub identity_restored: bool,
    pub backup_file: PathBuf,
    pub db_file: PathBuf,
    /// Every event-log path removed. Enumerated per aggregate, so this is normally `log.0`,
    /// `log.1`, and one more per configured chain rather than a single `log`.
    pub log_paths: Vec<PathBuf>,
}

/// Read the encrypted identity pair without decrypting it.
async fn read_identity(repositories: &Repositories) -> Result<PreservedIdentity> {
    Ok(PreservedIdentity {
        eth_private_key: repositories
            .eth_private_key()
            .read()
            .await
            .context("failed to read the stored operator key")?,
        libp2p_keypair: repositories
            .libp2p_keypair()
            .read()
            .await
            .context("failed to read the stored libp2p keypair")?,
    })
}

/// An E3 that this node has not seen complete, and for which it holds key-share state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveE3 {
    e3_id: E3id,
    stage: E3Stage,
}

/// Find each E3 that is not terminal and for which this node holds key-share state.
///
/// The lifecycle stage map (`//e3_lifecycle`) names every E3 that the node observed. The
/// `//threshold_keyshare/{e3_id}` record exists only on a node that the committee selected, and it
/// holds the key share of that node.
///
/// The check reads only whether the key-share record exists. It does not decode the record,
/// because a store that an older release wrote can hold an older layout, and a decode failure
/// must not hide a key share.
async fn active_e3s_with_key_shares(repositories: &Repositories) -> Result<Vec<ActiveE3>> {
    let stages = repositories
        .e3_lifecycle()
        .read()
        .await
        .context("failed to read the E3 lifecycle stage map")?
        .unwrap_or_default();
    let mut active = Vec::new();
    for (e3_id, stage) in stages {
        // Only `Complete` shows that the E3 is over. The node records `Failed` also for its own
        // local failures, such as a DKG timeout, while the E3 can continue on chain.
        if stage == E3Stage::Complete {
            continue;
        }
        if has_record(&repositories.threshold_keyshare(&e3_id).into()).await? {
            active.push(ActiveE3 { e3_id, stage });
        }
    }
    active.sort_by_cached_key(|e3| e3.e3_id.to_string());
    Ok(active)
}

/// Whether `store` holds any value at its scope. The value is not decoded.
async fn has_record(store: &DataStore) -> Result<bool> {
    let value = store
        .get_recipient()
        .send(Get::new(store.scope_bytes().to_vec()))
        .await
        .context("the data store stopped before it answered a read")?;
    Ok(value.is_some())
}

/// Refuse the reset when it would delete a key share that an active E3 needs.
///
/// `allow_active_e3s` overrides the refusal, and also a failed check, so that an operator can
/// still clear a store that this binary cannot read.
fn guard_active_e3s(active_e3s: Result<Vec<ActiveE3>>, allow_active_e3s: bool) -> Result<()> {
    let active = match active_e3s {
        Ok(active) => active,
        Err(error) if allow_active_e3s => {
            warn!(
                "Could not check for active E3s. Continuing because --allow-active-e3s is set: \
                 {error:#}"
            );
            return Ok(());
        }
        // The CLI prints only the top-level message, so the cause goes into the message itself.
        Err(error) => bail!(
            "Refusing to reset, because the command cannot show that no active E3 needs a key \
             share from this node: {error:#}. The command deleted nothing. To delete the state \
             anyway, add --allow-active-e3s."
        ),
    };
    if active.is_empty() {
        return Ok(());
    }

    let list = active
        .iter()
        .map(|e3| format!("  - E3 {} at stage {:?}", e3.e3_id, e3.stage))
        .collect::<Vec<_>>()
        .join("\n");
    if allow_active_e3s {
        warn!(
            "--allow-active-e3s is set. The reset deletes this node's key share for these E3s, \
             which this node has not seen complete:\n{list}"
        );
        return Ok(());
    }
    bail!(
        "Refusing to reset. This node holds key-share state for these E3s, which this node has not \
         seen complete:\n{list}\nThe command deleted nothing. A reset permanently deletes this \
         node's key share for each listed E3, and the chain cannot restore it. A `Failed` stage can \
         be a local failure while the E3 continues on chain. Keep this state until each listed E3 \
         is complete or failed on chain, then run this command again with --allow-active-e3s."
    )
}

/// Write the ciphertext backup before anything is deleted, so a failed reset is recoverable.
async fn write_backup(path: &Path, identity: &PreservedIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(identity).context("failed to encode the backup")?;
    fs::write(path, encoded)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    restrict_permissions(path).await
}

#[cfg(unix)]
async fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("failed to restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
async fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Every path the event log occupies for this node.
///
/// The event system does not write to `log_file()` itself. `EventSystem::persisted` hands that
/// path to `enumerate_path`, which inserts a per-aggregate index *before the extension*, so the
/// real logs are `log.0`, `log.1`, and one more per configured chain. Removing only the bare
/// `log_file()` leaves those behind, and the next start halts with `no schema marker` because the
/// key/value store was cleared while the event log still holds events.
///
/// The index is not always a trailing suffix: `log_file` is configurable per node
/// (`AppConfig::log_file`), so `events.log` enumerates to `events.0.log`. The split below mirrors
/// `enumerate_path` exactly; `matches_enumeration_of` is pinned to it by test.
async fn event_log_paths(log_file: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    // The un-enumerated path is included for older layouts that wrote to it directly.
    if fs::try_exists(log_file)
        .await
        .with_context(|| format!("failed to inspect {}", log_file.display()))?
    {
        paths.push(log_file.to_path_buf());
    }

    let Some(parent) = log_file.parent() else {
        return Ok(paths);
    };
    let Some(file_name) = log_file.file_name().and_then(|name| name.to_str()) else {
        return Ok(paths);
    };

    // A missing parent means the node never wrote state, which is not an error. Any other failure
    // is: treating an unreadable directory as empty would delete nothing, report success, and
    // leave the event log beside a cleared key/value store — the exact state this command exists
    // to avoid.
    let mut dir = match fs::read_dir(parent).await {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", parent.display()));
        }
    };
    while let Some(entry) = dir
        .next_entry()
        .await
        .with_context(|| format!("failed to read an entry in {}", parent.display()))?
    {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if matches_enumeration_of(file_name, name) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

/// Whether `candidate` is `base` with an index inserted the way `enumerate_path` inserts one.
///
/// Splits `base` at the same position `enumerate_path` splits it, then requires the candidate to
/// be `<stem>.<index><extension>`, where `<index>` is exactly how `usize` renders itself. A
/// sibling such as `log-backup`, `logs.txt`, `log.old` or `log.2.bak` therefore never matches, and
/// neither does a padded form such as `log.00`: `enumerate_path` formats a `usize`, which never
/// emits a leading zero, so a padded name is some other file and must not be removed.
fn matches_enumeration_of(base: &str, candidate: &str) -> bool {
    let (stem, extension) = match base.rfind('.') {
        Some(dot) => base.split_at(dot),
        None => (base, ""),
    };
    let Some(rest) = candidate.strip_prefix(stem) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix('.') else {
        return false;
    };
    let Some(index) = rest.strip_suffix(extension) else {
        return false;
    };
    // Round-trip through the same type `enumerate_path` formats, so the accepted set is exactly
    // the set it can produce. This also rejects an index too large to be a real aggregate.
    index
        .parse::<usize>()
        .is_ok_and(|parsed| parsed.to_string() == index)
}

async fn remove_if_present(path: &Path) -> Result<()> {
    if !fs::try_exists(path)
        .await
        .with_context(|| format!("failed to inspect {}", path.display()))?
    {
        return Ok(());
    }
    let metadata = fs::metadata(path)
        .await
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path).await
    } else {
        fs::remove_file(path).await
    }
    .with_context(|| format!("failed to remove {}", path.display()))
}

/// Clear durable state for one node and put the identity back.
///
/// `backup_file` is written first and is left in place afterwards: it is the only copy of the
/// identity between the delete and the restore.
///
/// The reset refuses, before it deletes anything, when this node holds key-share state for an E3
/// that it has not seen complete. `allow_active_e3s` overrides that refusal.
pub async fn execute(config: &AppConfig, allow_active_e3s: bool) -> Result<ResetOutcome> {
    let db_file = config.db_file();
    let log_file = config.log_file();

    // Refuse while the node is running. The fence is the same advisory lock `start` holds, so a
    // live process makes this fail instead of deleting state from under it. Held for the whole
    // reset, which also stops two resets from racing each other.
    let _fence = ProcessFence::acquire(&db_file, &config.name()).context(
        "could not acquire the node fence. The node is probably still running: stop it first, \
         then re-run this command",
    )?;

    let (identity, active_e3s) = {
        let bus = get_interfold_bus_handle()?;
        let store = setup_datastore(config, &bus)?;
        let repositories = store.repositories();
        let identity = read_identity(&repositories).await;
        let active_e3s = active_e3s_with_key_shares(&repositories).await;
        repositories.store.shutdown().await.ok();
        (identity, active_e3s)
    };
    // Release the sled handle before the directory is removed; a live handle would recreate it.
    SledDb::close_all_connections();
    let identity = identity?;
    guard_active_e3s(active_e3s, allow_active_e3s)?;

    if identity.is_empty() {
        warn!(
            "No operator identity found in {}. Nothing to preserve.",
            db_file.display()
        );
    } else if !identity.is_complete() {
        bail!(
            "The stored identity is incomplete: operator key {}, libp2p keypair {}. Refusing to \
             reset, because the missing half cannot be restored. Back up {} and investigate \
             before retrying.",
            present(&identity.eth_private_key),
            present(&identity.libp2p_keypair),
            db_file.display()
        );
    }

    let backup_file = backup_path(config);
    write_backup(&backup_file, &identity).await?;
    info!(
        "Wrote the encrypted identity backup to {}",
        backup_file.display()
    );

    remove_if_present(&db_file).await?;
    let log_paths = event_log_paths(&log_file).await?;
    for path in &log_paths {
        remove_if_present(path).await?;
    }

    let identity_restored = if identity.is_empty() {
        false
    } else {
        restore_identity(config, &identity).await?;
        true
    };

    // Verify the delete actually happened, after the identity is back in the store so a failure
    // here leaves a recoverable node rather than an empty one. The first version of this command
    // removed a path that never exists in production (`log`, not `log.0`), reported success, and
    // left the event log populated: the node then halted on the next start with `no schema
    // marker`. A post-condition turns that class of mistake into a loud failure here instead of a
    // confusing halt later.
    let survivors = event_log_paths(&log_file).await?;
    if !survivors.is_empty() {
        bail!(
            "reset removed the key/value store but {} event-log path(s) remain: {}. The node would \
             halt on the next start. The identity is restored and backed up at {}; remove the \
             listed path(s) before starting the node.",
            survivors.len(),
            survivors
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            backup_file.display()
        );
    }

    info!(
        "Removed {} and {} event-log path(s)",
        db_file.display(),
        log_paths.len()
    );

    Ok(ResetOutcome {
        identity_restored,
        backup_file,
        db_file,
        log_paths,
    })
}

/// Write the identity into the rebuilt store and read it back before reporting success.
async fn restore_identity(config: &AppConfig, identity: &PreservedIdentity) -> Result<()> {
    let bus = get_interfold_bus_handle()?;
    let store = setup_datastore(config, &bus)?;
    let repositories = store.repositories();

    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(2);
    if let Some(key) = identity.eth_private_key.clone() {
        entries.push((e3_events::StoreKeys::eth_private_key(), key));
    }
    if let Some(keypair) = identity.libp2p_keypair.clone() {
        entries.push((e3_events::StoreKeys::libp2p_keypair(), keypair));
    }
    repositories
        .store
        .write_batch_sync(entries)
        .await
        .context("failed to restore the operator identity")?;

    let restored = read_identity(&repositories).await?;
    repositories.store.shutdown().await.ok();
    SledDb::close_all_connections();

    if restored.eth_private_key != identity.eth_private_key
        || restored.libp2p_keypair != identity.libp2p_keypair
    {
        bail!(
            "The restored identity does not match what was read before the reset. The backup is \
             intact; do not start the node."
        );
    }
    Ok(())
}

fn present(value: &Option<Vec<u8>>) -> &'static str {
    if value.is_some() {
        "present"
    } else {
        "missing"
    }
}

fn backup_path(config: &AppConfig) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let name = format!("identity-backup-{}-{stamp}.json", config.name());
    config
        .db_file()
        .parent()
        .map(|dir| dir.join(&name))
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::{
        active_e3s_with_key_shares, event_log_paths, guard_active_e3s, matches_enumeration_of,
        ActiveE3,
    };
    use e3_data::{DataStore, Repositories};
    use e3_events::{E3Stage, E3id};
    use e3_keyshare::ThresholdKeyshareRepositoryFactory;
    use e3_request::E3LifecycleRepositoryFactory;
    use e3_utils::enumerate_path;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    /// Every E3 that is not `Complete` and has a key-share record blocks the reset, including a
    /// `Failed` one, because the node also records its own local failures as `Failed`. The
    /// records here do not decode as the current layout, as in a store that an older release
    /// wrote, so the check must find them by presence alone.
    #[actix::test]
    async fn finds_key_shares_of_e3s_that_are_not_complete() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        let key_published = E3id::new("1", 1);
        let ciphertext_ready = E3id::new("2", 1);
        let requested_without_share = E3id::new("3", 1);
        let complete = E3id::new("4", 1);
        let failed = E3id::new("5", 1);
        repositories
            .e3_lifecycle()
            .write_sync(&HashMap::from([
                (key_published.clone(), E3Stage::KeyPublished),
                (ciphertext_ready.clone(), E3Stage::CiphertextReady),
                (requested_without_share.clone(), E3Stage::Requested),
                (complete.clone(), E3Stage::Complete),
                (failed.clone(), E3Stage::Failed),
            ]))
            .await?;
        for e3_id in [&key_published, &ciphertext_ready, &complete, &failed] {
            DataStore::from(repositories.threshold_keyshare(e3_id))
                .write_sync(vec![0xde_u8, 0xad, 0xbe, 0xef])
                .await?;
        }
        assert!(
            repositories
                .threshold_keyshare(&key_published)
                .read()
                .await
                .is_err(),
            "the fixture must not decode as the current key-share layout"
        );

        let active = active_e3s_with_key_shares(&repositories).await?;

        assert_eq!(
            active,
            vec![
                ActiveE3 {
                    e3_id: key_published,
                    stage: E3Stage::KeyPublished,
                },
                ActiveE3 {
                    e3_id: ciphertext_ready,
                    stage: E3Stage::CiphertextReady,
                },
                ActiveE3 {
                    e3_id: failed,
                    stage: E3Stage::Failed,
                },
            ]
        );
        Ok(())
    }

    /// A stage map that this binary cannot read blocks the reset, because the reset cannot show
    /// that no active E3 needs a key share. The override still lets an operator clear the store.
    #[actix::test]
    async fn an_unreadable_stage_map_blocks_the_reset_unless_overridden() -> anyhow::Result<()> {
        let repositories = Repositories::in_mem();
        DataStore::from(repositories.e3_lifecycle())
            .write_sync(vec![0xff_u8; 3])
            .await?;

        let error = guard_active_e3s(active_e3s_with_key_shares(&repositories).await, false)
            .expect_err("an unreadable stage map must block the reset");
        // The CLI prints only the top-level message, so it must carry the cause and the override.
        let message = error.to_string();
        assert!(
            message.contains("failed to read the E3 lifecycle stage map"),
            "the refusal must name the cause, got: {message}"
        );
        assert!(
            message.contains("--allow-active-e3s"),
            "the refusal must name the override, got: {message}"
        );

        guard_active_e3s(active_e3s_with_key_shares(&repositories).await, true)?;
        Ok(())
    }

    /// Pin the matcher to the real generator. Whatever `enumerate_path` produces must be matched,
    /// for every log-file name an operator can configure. Hand-written fixtures are what let the
    /// original bug through, so the expected names here come from the production function.
    #[test]
    fn matches_every_name_enumerate_path_can_produce() {
        for base in [
            "log",
            "events.log",
            "node.events.log",
            "log.0",
            ".hidden",
            "a.b.c.d",
        ] {
            for index in [0usize, 1, 7, 42, 100] {
                let produced = enumerate_path(&PathBuf::from(format!("/data/{base}")), index);
                let produced = produced.file_name().unwrap().to_str().unwrap();
                assert!(
                    matches_enumeration_of(base, produced),
                    "base {base:?} index {index}: enumerate_path produced {produced:?}, \
                     which the matcher failed to recognise"
                );
            }
        }
    }

    /// The matcher must not remove anything `enumerate_path` could not have produced.
    #[test]
    fn rejects_names_that_merely_look_similar() {
        for (base, candidate) in [
            ("log", "log"),          // the un-enumerated path, handled separately
            ("log", "log-backup"),   // different file
            ("log", "logs.txt"),     // different file
            ("log", "log.old"),      // not an index
            ("log", "log.2.bak"),    // index plus a foreign extension
            ("log", "log."),         // empty index
            ("log", "log.1x"),       // not all digits
            ("log", "log.00"),       // padded: `usize` never formats a leading zero
            ("log", "log.007"),      // padded
            ("log", "prefix-log.1"), // different stem
            ("events.log", "events.log"),
            ("events.log", "events.01.log"), // padded
            ("events.log", "events.log.0"),  // index appended, not inserted
            ("events.log", "events.0.txt"),  // wrong extension
            ("events.log", "events.old.log"),
        ] {
            assert!(
                !matches_enumeration_of(base, candidate),
                "base {base:?} must not match {candidate:?}"
            );
        }
    }

    /// The whole-directory scan, against the layout the event system actually writes.
    #[tokio::test]
    async fn collects_enumerated_logs_and_leaves_similar_names_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let log_file = dir.join("log");

        for index in 0..3 {
            let seg = enumerate_path(&log_file, index);
            fs::create_dir_all(seg.join("blobs")).expect("create segment");
            fs::write(seg.join("0.log"), b"events").expect("write segment");
        }
        fs::create_dir_all(dir.join("log-backup")).expect("create decoy dir");
        fs::write(dir.join("logs.txt"), b"keep").expect("write decoy");
        fs::write(dir.join("log.old"), b"keep").expect("write decoy");
        fs::write(dir.join("log.2.bak"), b"keep").expect("write decoy");

        let found = event_log_paths(&log_file).await.expect("collect paths");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["log.0", "log.1", "log.2"]);
    }

    /// A node configured with an extension'd log name enumerates to `events.0.log`, so a matcher
    /// that only looked for a trailing `.<digits>` would silently remove nothing.
    #[tokio::test]
    async fn collects_logs_for_a_configured_log_file_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        let log_file = dir.join("events.log");

        for index in 0..2 {
            let seg = enumerate_path(&log_file, index);
            fs::create_dir_all(&seg).expect("create segment");
            fs::write(seg.join("0.log"), b"events").expect("write segment");
        }
        fs::write(dir.join("events.log"), b"keep-not-enumerated").expect("write base");

        let found = event_log_paths(&log_file).await.expect("collect paths");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // The base path exists here, so it is collected too: both must go.
        assert_eq!(names, vec!["events.0.log", "events.1.log", "events.log"]);
    }

    /// A store that never ran the event system has no logs at all, and that is not an error.
    #[tokio::test]
    async fn reports_no_paths_when_the_log_was_never_written() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let found = event_log_paths(&tmp.path().join("log"))
            .await
            .expect("collect paths");
        assert!(found.is_empty(), "expected no paths, got {found:?}");
    }

    /// An unreadable data directory must fail, not read as empty. Reporting "no logs" here would
    /// let the reset clear the key/value store, skip the event log, and exit 0 — leaving the node
    /// in the unmarked state the command exists to prevent.
    ///
    /// The directory is listable but not readable (`--x`), so `try_exists` on the log path
    /// succeeds and the failure lands on `read_dir`. A `0o000` directory would fail at
    /// `try_exists` instead and never exercise the enumeration path.
    #[cfg(unix)]
    #[tokio::test]
    async fn fails_when_the_data_directory_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("data");
        std::fs::create_dir(&dir).expect("create dir");
        std::fs::create_dir(dir.join("log.0")).expect("create log");

        // Execute without read: paths inside can be resolved, but the directory cannot be listed.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o111))
            .expect("drop read permission");

        let result = event_log_paths(&dir.join("log")).await;

        // Restore before asserting so the tempdir can always clean itself up.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("restore permissions");

        let error = result.expect_err("an unlistable directory must not read as empty");
        assert!(
            error.to_string().contains("failed to read"),
            "error should name the failed directory read, got: {error}"
        );
    }

    /// The decisive check: let the production event system create the layout, then require the
    /// reset to find every path it wrote. Hand-built fixtures encode an assumption about the
    /// layout, and a wrong assumption is what shipped the original bug. This asserts against the
    /// real writer instead, so a future change to how logs are named fails here rather than in an
    /// operator's data directory.
    #[actix::test]
    async fn finds_every_log_the_real_event_system_creates() {
        use e3_ciphernode_builder::EventSystem;

        let tmp = tempfile::tempdir().expect("tempdir");
        let log_path = tmp.path().join("log");

        let system = EventSystem::persisted(log_path.clone(), tmp.path().join("sled"));
        // Initializing the reader is what materializes one commit log per aggregate.
        let _reader = system.eventstore_reader().expect("eventstore reader");

        let created: Vec<String> = std::fs::read_dir(tmp.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "sled")
            .collect();
        assert!(
            !created.is_empty(),
            "the event system created no log files, so this test proves nothing"
        );

        let found = event_log_paths(&log_path).await.expect("collect paths");
        let found_names: std::collections::BTreeSet<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let created_names: std::collections::BTreeSet<String> = created.into_iter().collect();

        assert_eq!(
            found_names, created_names,
            "reset must remove exactly the logs the event system created"
        );
    }
}
