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
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::fs;

use super::facts::{entries, marker, Marker};
use super::plan::{Plan, PlannedLock, PlannedStore};
use super::{locate, resolve, PurgeTargets, MARKER_FILE_NAME, MARKER_TEXT};
use crate::fence::{FenceHeld, ProcessFence, LOCK_FILE_NAME};
use crate::helpers::datastore::get_sled_store;
use crate::nodes::state_guard::{
    active_e3s_with_key_shares, check_active_e3s, check_deletion, pending_slash_reports, ActiveE3,
    Deletion, PendingSlashReports,
};

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
    check_deletion(
        contents.active,
        contents.slash_reports,
        allow_active_e3s,
        &deletion,
    )
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
         data_dir, or working directory. Make sure that the node is stopped. Make sure that each \
         E3 that the node served is complete or failed on chain, and that one day has passed \
         after its lifecycle deadline. Then run this command again with --allow-active-e3s."
    )
}

struct StoreContents {
    /// The E3s with key-share state that the node has not seen complete, or the read error.
    active: Result<Vec<ActiveE3>>,
    /// The chains with slash reports that the node has not submitted, or the read error.
    slash_reports: Result<Vec<PendingSlashReports>>,
    /// The store holds the encrypted operator key.
    has_identity: bool,
}

/// Opens the store and reads what the checks need. Fails only when the store does not open.
async fn read_store(db_file: &Path) -> Result<StoreContents> {
    let bus = get_interfold_bus_handle()?;
    let repositories = get_sled_store(&bus, &db_file.to_path_buf())?.repositories();
    let active = active_e3s_with_key_shares(&repositories).await;
    let slash_reports = pending_slash_reports(&repositories).await;
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
        slash_reports,
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
/// purge finishes the deletion. A failure before the first deletion removes the markers again.
pub(super) async fn delete(targets: &PurgeTargets, fences: &[ProcessFence]) -> Result<()> {
    let folders = node_folders(targets, fences)?;
    let kept = Kept::new(fences)?;
    let written = mark(&folders).await?;
    let mut deleted = false;
    match delete_in_order(targets, &folders, &kept, &mut deleted).await {
        Ok(()) => Ok(()),
        Err(error) if deleted => Err(anyhow!(
            "The purge stopped while it deleted the state: {error:#}. Part of the state can be \
             gone. Fix the cause. Then run the command again to finish the purge."
        )),
        Err(error) => {
            // Nothing is gone, so no folder may look like the leftover of a purge.
            let left = unmark(&written).await;
            Err(anyhow!(
                "The purge could not delete the state: {error:#}. The command deleted nothing.{left}"
            ))
        }
    }
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

/// Writes the purge marker into each folder, and returns the markers that it wrote. It writes over
/// an incomplete marker, and it keeps a complete one that an earlier purge left. Anything else at
/// the marker path stops the purge, so that the purge never replaces or removes a file that is not
/// its own. After a failure, it removes the markers that it wrote, so that no folder looks like
/// the leftover of a purge that deleted nothing.
async fn mark(folders: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    for folder in folders {
        let path = folder.join(MARKER_FILE_NAME);
        let result = match marker(folder).await {
            Ok(Marker::Complete) => Ok(()),
            Ok(Marker::Missing | Marker::Incomplete) => {
                // Record the marker before the write: a write that fails can still create the file.
                written.push(path.clone());
                fs::write(&path, MARKER_TEXT).await.map_err(|error| {
                    anyhow!(
                        "The purge could not write its marker into {}: {error}.",
                        folder.display()
                    )
                })
            }
            Ok(Marker::Other) => Err(anyhow!(
                "{} is not a purge marker. Move it out of the node folder. Then run this command \
                 again.",
                path.display()
            )),
            Err(error) => Err(anyhow!("The purge could not check its marker: {error:#}.")),
        };
        if let Err(error) = result {
            let left = unmark(&written).await;
            bail!("{error} The command deleted nothing.{left}");
        }
    }
    Ok(written)
}

/// Removes the markers that this run wrote. A marker that it cannot remove, it empties, because a
/// later purge does not trust an incomplete marker. It empties only a regular file with the complete
/// text, so that it never writes through a link. Returns a note that names each marker that stays
/// complete, or that it cannot read.
async fn unmark(written: &[PathBuf]) -> String {
    let mut left = Vec::new();
    for path in written {
        match fs::remove_file(path).await {
            Ok(()) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {}
        }
        let folder = path.parent().unwrap_or(Path::new("."));
        if marker(folder).await.ok() == Some(Marker::Complete) {
            let _ = fs::write(path, b"").await;
        }
        if matches!(marker(folder).await, Ok(Marker::Complete) | Err(_)) {
            left.push(path.display().to_string());
        }
    }
    if left.is_empty() {
        String::new()
    } else {
        format!(
            " Remove these markers by hand, or a later purge treats their folders as its \
             leftovers: {}.",
            left.join(", ")
        )
    }
}

/// What emptying a node folder keeps besides the lock file and the marker, found before the purge
/// deletes anything. These stay until the data folder goes, so that no node can create a new lock
/// on the way to its lock while the purge runs:
/// - each folder and link on a path through which the purge took a lock (`ways`, located);
/// - each entry that holds a held lock, and each link that resolves to a folder that holds one
///   (`locks`, resolved), whichever path the purge took the lock through. A link that does not
///   resolve, such as one that points to itself, leads to no lock.
struct Kept {
    locks: Vec<PathBuf>,
    ways: HashSet<PathBuf>,
}

impl Kept {
    fn new(fences: &[ProcessFence]) -> Result<Self> {
        let mut locks = Vec::new();
        let mut ways = HashSet::new();
        for fence in fences {
            let path = fence.path();
            locks.push(resolve(path)?);
            for way in path
                .ancestors()
                .skip(1)
                .filter(|way| !way.as_os_str().is_empty())
            {
                ways.insert(locate(way)?);
            }
        }
        Ok(Self { locks, ways })
    }

    fn keeps(&self, entry: &Path) -> Result<bool> {
        let located = locate(entry)?;
        if self.ways.contains(&located) || self.holds(&located) {
            return Ok(true);
        }
        // `located` leaves a link at the entry itself unresolved.
        let link = std::fs::symlink_metadata(entry).is_ok_and(|metadata| metadata.is_symlink());
        Ok(link
            && entry
                .canonicalize()
                .is_ok_and(|resolved| self.holds(&resolved)))
    }

    /// A held lock is at `path` or inside it.
    fn holds(&self, path: &Path) -> bool {
        self.locks.iter().any(|lock| lock.starts_with(path))
    }
}

async fn delete_in_order(
    targets: &PurgeTargets,
    folders: &[PathBuf],
    kept: &Kept,
    deleted: &mut bool,
) -> Result<()> {
    for folder in folders {
        empty_node_folder(folder, kept, deleted).await?;
    }
    remove_if_present(&targets.config, deleted).await?;
    remove_if_present(&targets.data, deleted).await
}

/// Removes everything in `folder` except the lock file, the purge marker, and any entry that holds
/// another lock of the purge or leads to one. Those go with the data folder at the end, so that the
/// purge deletes no lock file that it still needs.
async fn empty_node_folder(folder: &Path, kept: &Kept, deleted: &mut bool) -> Result<()> {
    for entry in entries(folder).await? {
        let path = entry.path();
        let name = entry.file_name();
        let keep = name == LOCK_FILE_NAME || name == MARKER_FILE_NAME || kept.keeps(&path)?;
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

    /// A failure after the markers and before the first deletion removes the markers, so that no
    /// folder looks like the leftover of a purge that deleted nothing.
    #[tokio::test]
    async fn a_failure_before_the_first_deletion_removes_the_markers() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temporary folder");
        let targets = PurgeTargets::in_dir(dir.path())
            .resolved()
            .expect("targets");
        let folder = targets.data.join("cn1");
        std::fs::create_dir_all(folder.join("db")).expect("node folder");
        let fence = ProcessFence::acquire_at(&folder.join(LOCK_FILE_NAME), "cn1").expect("lock");
        // The purge can write its marker into the folder, but it cannot list the folder.
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o333)).expect("mode");
        let result = delete(&targets, &[fence]).await;
        let marker_left = folder.join(MARKER_FILE_NAME).exists();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).expect("mode");

        let error = result.expect_err("the purge must stop");
        assert!(error.to_string().contains("deleted nothing"), "{error}");
        assert!(!marker_left);
        assert!(folder.join("db").exists());
    }

    /// A link in the folder of node `outer` leads to the folder of node `inner`. Emptying `outer`
    /// keeps the link, so that no node that names its lock through the link can start with a new
    /// lock there while the purge runs. That holds whether the purge took the lock of `inner`
    /// through the link or directly, as when two profiles share the lock.
    #[tokio::test]
    async fn a_link_to_a_folder_with_a_held_lock_is_kept() {
        for through_link in [true, false] {
            let dir = tempfile::tempdir().expect("temporary folder");
            let data = resolve(dir.path()).expect("resolved").join("data");
            let outer = data.join("outer");
            let inner = data.join("inner");
            std::fs::create_dir_all(&outer).expect("outer folder");
            std::fs::create_dir_all(&inner).expect("inner folder");
            std::os::unix::fs::symlink(&inner, outer.join("alias")).expect("link");
            std::fs::write(outer.join("state"), b"").expect("state");
            let inner_lock = if through_link {
                outer.join("alias").join(LOCK_FILE_NAME)
            } else {
                inner.join(LOCK_FILE_NAME)
            };
            let fences = [
                ProcessFence::acquire_at(&outer.join(LOCK_FILE_NAME), "outer").expect("lock"),
                ProcessFence::acquire_at(&inner_lock, "inner").expect("lock"),
            ];
            let kept = Kept::new(&fences).expect("kept");
            let mut deleted = false;
            empty_node_folder(&outer, &kept, &mut deleted)
                .await
                .expect("emptied");
            assert!(
                std::fs::symlink_metadata(outer.join("alias")).is_ok(),
                "through_link={through_link}"
            );
            assert!(!outer.join("state").exists());
        }
    }

    /// Node `inner` has its folder inside the folder of node `outer`, and its lock file is a link to
    /// a file outside. Emptying `outer` keeps the folder of `inner`: it is on the path through which
    /// the purge took the lock, so `inner` cannot create a new lock there.
    #[tokio::test]
    async fn a_folder_on_the_way_to_a_held_lock_is_kept() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let data = resolve(dir.path()).expect("resolved").join("data");
        let outer = data.join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).expect("inner folder");
        let outside = dir.path().join("outside.lock");
        std::fs::write(&outside, b"").expect("outside lock");
        std::os::unix::fs::symlink(&outside, inner.join(LOCK_FILE_NAME)).expect("link");
        std::fs::write(outer.join("state"), b"").expect("state");
        let fences = [
            ProcessFence::acquire_at(&outer.join(LOCK_FILE_NAME), "outer").expect("lock"),
            ProcessFence::acquire_at(&inner.join(LOCK_FILE_NAME), "inner").expect("lock"),
        ];
        let kept = Kept::new(&fences).expect("kept");
        let mut deleted = false;
        empty_node_folder(&outer, &kept, &mut deleted)
            .await
            .expect("emptied");
        assert!(std::fs::symlink_metadata(inner.join(LOCK_FILE_NAME)).is_ok());
        assert!(!outer.join("state").exists());
    }

    /// A link that does not resolve, here one that points to itself, leads to no lock. Emptying the
    /// folder removes it, so that the purge can finish.
    #[tokio::test]
    async fn a_link_that_does_not_resolve_is_removed() {
        let dir = tempfile::tempdir().expect("temporary folder");
        let data = resolve(dir.path()).expect("resolved").join("data");
        let outer = data.join("outer");
        std::fs::create_dir_all(&outer).expect("outer folder");
        std::os::unix::fs::symlink("loop", outer.join("loop")).expect("link");
        let fences =
            [ProcessFence::acquire_at(&outer.join(LOCK_FILE_NAME), "outer").expect("lock")];
        let kept = Kept::new(&fences).expect("kept");
        let mut deleted = false;
        empty_node_folder(&outer, &kept, &mut deleted)
            .await
            .expect("emptied");
        assert!(std::fs::symlink_metadata(outer.join("loop")).is_err());
    }

    /// A marker that the purge cannot remove is emptied if it is still a regular file with the
    /// complete text, and named only when it stays complete, because a later purge trusts only a
    /// complete marker. A link at the marker path is never written through.
    #[tokio::test]
    async fn unmark_names_only_markers_that_stay_complete() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temporary folder");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"keep").expect("outside file");
        // Each folder refuses the removal. (name, marker content or None for a link, file mode,
        // named in the note)
        let cases = [
            ("writable", Some(MARKER_TEXT), 0o644, false),
            ("stuck", Some(MARKER_TEXT), 0o444, true),
            ("partial", Some(""), 0o444, false),
            ("link", None, 0o644, false),
        ];
        let mut written = Vec::new();
        for (name, content, mode, _) in cases {
            let folder = dir.path().join(name);
            std::fs::create_dir_all(&folder).expect("folder");
            let marker = folder.join(MARKER_FILE_NAME);
            match content {
                Some(content) => {
                    std::fs::write(&marker, content).expect("marker");
                    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(mode))
                        .expect("mode");
                }
                None => std::os::unix::fs::symlink(&outside, &marker).expect("link"),
            }
            std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555))
                .expect("mode");
            written.push(marker);
        }
        let note = unmark(&written).await;
        for (name, ..) in cases {
            std::fs::set_permissions(
                dir.path().join(name),
                std::fs::Permissions::from_mode(0o755),
            )
            .expect("mode");
        }

        for (name, _, _, named) in cases {
            let path = dir.path().join(name).join(MARKER_FILE_NAME);
            assert_eq!(
                note.contains(&path.display().to_string()),
                named,
                "{name}: {note}"
            );
        }
        let writable = dir.path().join("writable").join(MARKER_FILE_NAME);
        assert!(std::fs::read(writable).expect("marker").is_empty());
        assert_eq!(std::fs::read(&outside).expect("outside file"), b"keep");
    }

    /// Node `inner` names its folder through a link elsewhere in the data folder, but the folder
    /// sits inside the folder of node `outer`. Emptying `outer` keeps it, because it holds a lock
    /// of the purge. Every path goes through the link `alias`, so only resolved paths match.
    #[tokio::test]
    async fn a_folder_that_holds_a_lock_taken_through_another_link_is_kept() {
        let dir = tempfile::tempdir().expect("temporary folder");
        std::fs::create_dir_all(dir.path().join("real")).expect("real folder");
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("alias"))
            .expect("alias");
        let data = dir.path().join("alias/data");
        let outer = data.join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).expect("inner folder");
        std::os::unix::fs::symlink(&inner, data.join("link")).expect("link");
        let fences = [
            ProcessFence::acquire_at(&outer.join(LOCK_FILE_NAME), "outer").expect("lock"),
            ProcessFence::acquire_at(&data.join("link").join(LOCK_FILE_NAME), "inner")
                .expect("lock"),
        ];
        let kept = Kept::new(&fences).expect("kept");
        let mut deleted = false;
        empty_node_folder(&outer, &kept, &mut deleted)
            .await
            .expect("emptied");
        assert!(inner.join(LOCK_FILE_NAME).exists());
    }
}
