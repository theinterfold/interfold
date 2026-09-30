// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The purge's side effects: it holds the planned locks, checks the planned stores, and deletes
//! the targets.

use anyhow::{anyhow, bail, Result};
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_data::{RepositoriesFactory, SledDb};
use e3_events::StoreKeys;
use std::path::{Path, PathBuf};
use tokio::fs;

use super::facts::{entries, marked};
use super::plan::{Plan, PlannedLock, PlannedStore};
use super::{locate, resolve, PurgeTargets, MARKER_FILE_NAME, MARKER_TEXT};
use crate::fence::{FenceHeld, ProcessFence, LOCK_FILE_NAME};
use crate::helpers::datastore::get_sled_store;
use crate::nodes::state_guard::{active_e3s_with_key_shares, check_active_e3s, ActiveE3, Deletion};

/// Takes the planned locks whose folders exist.
pub(super) fn hold_existing(plan: &Plan) -> Result<Vec<ProcessFence>> {
    plan.locks
        .iter()
        .filter(|lock| !lock.create)
        .map(hold)
        .collect()
}

/// Creates the planned node folders that do not exist yet in the data folder, and takes their
/// locks.
///
/// The purge checked no store for these nodes, because they had no folder. A node that started and
/// stopped while the purge checked the others can have created one since, so each folder must hold
/// only its lock file now.
pub(super) fn hold_created(plan: &Plan) -> Result<Vec<ProcessFence>> {
    let mut fences = Vec::new();
    for lock in plan.locks.iter().filter(|lock| lock.create) {
        fences.push(hold(lock)?);
        let folder = lock.path.parent().unwrap_or(Path::new("."));
        let entries = std::fs::read_dir(folder)
            .map_err(|error| anyhow!("failed to read {}: {error}", folder.display()))?;
        for entry in entries {
            let entry = entry?;
            if entry.file_name() != LOCK_FILE_NAME {
                bail!(
                    "Node `{}` created {} while the purge checked the other nodes. The command \
                     deleted nothing. Run it again.",
                    lock.nodes.join("` or `"),
                    entry.path().display()
                );
            }
        }
    }
    Ok(fences)
}

fn hold(lock: &PlannedLock) -> Result<ProcessFence> {
    let nodes = lock
        .nodes
        .iter()
        .map(|node| format!("`{node}`"))
        .collect::<Vec<_>>()
        .join(" or ");
    match ProcessFence::acquire_at(&lock.path, &lock.nodes.join(",")) {
        Ok(fence) => Ok(fence),
        Err(error) if error.is::<FenceHeld>() => bail!(
            "Node {nodes} is running, or another command holds its lock at {}. Stop it. Then run \
             this command again. The command deleted nothing.",
            lock.path.display()
        ),
        // The CLI prints only the top-level message, so the cause goes into it.
        Err(error) => bail!(
            "Could not lock node {nodes} at {}: {error:#}. The command deleted nothing.",
            lock.path.display()
        ),
    }
}

/// A refusal for a node that the purge sees running. No flag overrides it.
#[derive(Debug)]
struct Running(String);

impl std::fmt::Display for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Running {}

/// Checks each planned store, then each piece of state that the purge cannot check. Returns the
/// warnings that `allow_active_e3s` produces.
///
/// The purge reports every refusal at once. `--allow-active-e3s` overrides all of them, so the
/// operator sees the full scope of the flag before using it. A running node stops the check at
/// once.
pub(super) async fn check(plan: &Plan, allow_active_e3s: bool) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    let mut refusals = Vec::new();
    for store in &plan.stores {
        record(
            check_store(store, allow_active_e3s).await,
            &mut warnings,
            &mut refusals,
        )?;
    }
    for unchecked in &plan.unchecked {
        record(
            refuse_unchecked(
                &unchecked.node,
                &unchecked.reason.to_string(),
                allow_active_e3s,
            ),
            &mut warnings,
            &mut refusals,
        )?;
    }
    match refusals.as_slice() {
        [] => Ok(warnings),
        [refusal] => bail!("{refusal}"),
        refusals => bail!(
            "Refusing to purge, for {} reasons. The command deleted nothing. --allow-active-e3s \
             overrides all of them at once.\n\n{}",
            refusals.len(),
            refusals.join("\n\n")
        ),
    }
}

/// Sorts a check's outcome into the warnings and the refusals. A running node ends the check.
fn record(
    outcome: Result<Option<String>>,
    warnings: &mut Vec<String>,
    refusals: &mut Vec<String>,
) -> Result<()> {
    match outcome {
        Ok(warning) => warnings.extend(warning),
        Err(error) if error.is::<Running>() => return Err(error),
        Err(error) => refusals.push(error.to_string()),
    }
    Ok(())
}

async fn check_store(store: &PlannedStore, allow_active_e3s: bool) -> Result<Option<String>> {
    let deletion = Deletion {
        verb: "purge",
        node: Some(&store.node),
    };
    let contents = match read_store(&store.db_file).await {
        Ok(contents) => contents,
        Err(error) if store_in_use(&error) => {
            return Err(Running(format!(
                "Node `{}` is running: another process has its store at {} open. Stop it. Then \
                 run this command again. The command deleted nothing.",
                store.node,
                store.db_file.display()
            ))
            .into())
        }
        Err(error) => return check_active_e3s(Err(error), allow_active_e3s, &deletion),
    };
    if store.needs_identity && !contents.has_identity {
        let reason = format!(
            "the store at {} holds no operator key, so it is not the store that the node's key \
             file protects",
            store.db_file.display()
        );
        return refuse_unchecked(&store.node, &reason, allow_active_e3s);
    }
    check_active_e3s(contents.active, allow_active_e3s, &deletion)
}

/// The refusal for a node that the purge cannot check, or the warning when `allow_active_e3s`
/// overrides it.
fn refuse_unchecked(node: &str, reason: &str, allow_active_e3s: bool) -> Result<Option<String>> {
    if allow_active_e3s {
        return Ok(Some(format!(
            "The purge cannot check node `{node}`: {reason}. It continues because \
             --allow-active-e3s is set."
        )));
    }
    bail!(
        "Refusing to purge, because the purge cannot check node `{node}`: {reason}. The command \
         deleted nothing. The purge cannot see a node that runs with another E3_DATA_DIR, \
         data_dir, or working directory. Make sure that the node is stopped. Make sure that it \
         holds no key share for an E3 that it has not seen complete. Then run this command again \
         with --allow-active-e3s."
    )
}

struct StoreContents {
    /// The E3s with key-share state that the node has not seen complete, or the read error.
    active: Result<Vec<ActiveE3>>,
    /// The store holds the encrypted operator key.
    has_identity: bool,
}

/// Opens the store and reads what the checks need. Fails only when the store does not open.
async fn read_store(db_file: &Path) -> Result<StoreContents> {
    let bus = get_interfold_bus_handle()?;
    let repositories = get_sled_store(&bus, &db_file.to_path_buf())?.repositories();
    let active = active_e3s_with_key_shares(&repositories).await;
    // A read error counts as no identity, so the check fails closed.
    let has_identity = repositories
        .store
        .keys_with_prefix(&StoreKeys::eth_private_key())
        .await
        .is_ok_and(|keys| !keys.is_empty());
    repositories.store.shutdown().await.ok();
    // Release the sled handle before the purge removes the folder. A live handle would recreate it.
    SledDb::close_all_connections();
    Ok(StoreContents {
        active,
        has_identity,
    })
}

/// sled refuses to open a store that another process has open.
fn store_in_use(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("could not acquire lock"))
}

/// Deletes the targets while the purge holds every lock.
///
/// The purge first writes a marker into each locked node folder in the data folder. A later purge
/// can then tell a folder that this purge started to empty from an empty folder that no purge
/// checked. It then empties those folders and keeps their locks and markers. It deletes the
/// configuration folder with the key files, and last the data folder with the markers and the lock
/// files. The locks stay until that last step, so no node starts while the purge deletes. After a
/// failure part of the way, a node can find its key file without its store. A second run of the
/// purge finishes the deletion.
pub(super) async fn delete(targets: &PurgeTargets, fences: &[ProcessFence]) -> Result<()> {
    let folders = node_folders(targets, fences)?;
    mark(&folders).await?;
    let locks = fences
        .iter()
        .map(|fence| resolve(fence.path()))
        .collect::<Result<Vec<_>>>()?;
    let mut deleted = false;
    delete_in_order(targets, &folders, &locks, &mut deleted)
        .await
        .map_err(|error| {
            if deleted {
                anyhow!(
                    "The purge stopped while it deleted the state: {error:#}. Part of the state can \
                     be gone. Fix the cause. Then run the command again to finish the purge."
                )
            } else {
                anyhow!(
                    "The purge could not delete the state: {error:#}. The command deleted nothing."
                )
            }
        })
}

/// The locked node folders in the data folder, which the purge empties.
fn node_folders(targets: &PurgeTargets, fences: &[ProcessFence]) -> Result<Vec<PathBuf>> {
    let mut folders = Vec::new();
    for fence in fences {
        let Some(folder) = fence.path().parent() else {
            continue;
        };
        if resolve(folder)?.starts_with(&targets.data) {
            folders.push(folder.to_path_buf());
        }
    }
    Ok(folders)
}

/// Writes the purge marker into each folder. After a failure, it removes the markers that it
/// wrote, so that no folder looks like the leftover of a purge that deleted nothing. That includes
/// a marker that the failed write left part of the way, and an incomplete marker that it replaced.
async fn mark(folders: &[PathBuf]) -> Result<()> {
    let mut created = Vec::new();
    for folder in folders {
        let marker = folder.join(MARKER_FILE_NAME);
        // Record the marker before the write: a write that fails can still create the file. Only
        // a complete marker that an earlier purge left stays after a failure.
        if !marked(folder).await {
            created.push(marker.clone());
        }
        if let Err(error) = fs::write(&marker, MARKER_TEXT).await {
            let mut left = Vec::new();
            for marker in created {
                match fs::remove_file(&marker).await {
                    Ok(()) => {}
                    Err(remove) if remove.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => left.push(marker.display().to_string()),
                }
            }
            let left = if left.is_empty() {
                String::new()
            } else {
                format!(
                    " Remove these markers by hand, or a later purge treats their folders as \
                     its leftovers: {}.",
                    left.join(", ")
                )
            };
            bail!(
                "The purge could not write its marker into {}: {error}. The command deleted \
                 nothing.{left}",
                folder.display()
            );
        }
    }
    Ok(())
}

async fn delete_in_order(
    targets: &PurgeTargets,
    folders: &[PathBuf],
    locks: &[PathBuf],
    deleted: &mut bool,
) -> Result<()> {
    for folder in folders {
        empty_node_folder(folder, locks, deleted).await?;
    }
    remove_if_present(&targets.config, deleted).await?;
    remove_if_present(&targets.data, deleted).await
}

/// Removes everything in `folder` except the lock file, the purge marker, and any entry that holds
/// another lock of the purge. Those go with the data folder at the end, so that the purge deletes
/// no lock file that it still needs. `locks` are resolved, and each entry is compared by location,
/// so a lock that a node names through a link still counts.
async fn empty_node_folder(folder: &Path, locks: &[PathBuf], deleted: &mut bool) -> Result<()> {
    for entry in entries(folder).await? {
        let path = entry.path();
        let name = entry.file_name();
        let located = locate(&path)?;
        let keep = name == LOCK_FILE_NAME
            || name == MARKER_FILE_NAME
            || locks.iter().any(|lock| lock.starts_with(&located));
        if !keep {
            remove_if_present(&path, deleted).await?;
        }
    }
    Ok(())
}

/// Removes a file, a folder, or a symbolic link. For a link, it removes the link and keeps the
/// state that the link points to.
async fn remove_if_present(path: &Path, deleted: &mut bool) -> Result<()> {
    let metadata = match fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(anyhow!("failed to inspect {}: {error}", path.display())),
    };
    // A removal that fails can still delete part of a folder.
    *deleted = true;
    if metadata.is_dir() {
        fs::remove_dir_all(path).await
    } else {
        fs::remove_file(path).await
    }
    .map_err(|error| anyhow!("failed to remove {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::purge::plan::{Plan, PlannedLock};

    /// A node folder that the purge must create was missing when it gathered the facts. If a node
    /// created it with state since, the purge refuses instead of deleting unchecked state.
    #[test]
    fn a_created_folder_that_gained_state_is_refused() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let folder = dir.path().join("late");
        std::fs::create_dir_all(folder.join("db")).expect("store folder");
        let plan = Plan {
            locks: vec![PlannedLock {
                path: folder.join(LOCK_FILE_NAME),
                nodes: vec!["late".to_string()],
                create: true,
            }],
            ..Plan::default()
        };
        let error = hold_created(&plan).expect_err("the purge must refuse");
        assert!(
            error
                .to_string()
                .contains("while the purge checked the other nodes"),
            "{error}"
        );
    }
}
