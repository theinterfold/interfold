// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::node_state::{self, Plan};
use anyhow::{anyhow, bail, Result};
use e3_ciphernode_config::NodeConfig;
use e3_cli::app_config::load_config;
use e3_console::Console;
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use e3_node::dir::{NodeDir, Recorded, State};
use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};

/// What a purge deletes, relative to the folder it runs in. Node state goes before the keys.
const DELETED: [&str; 2] = [".interfold/data", ".interfold/config"];

/// Delete the data and configuration of the local node set.
pub async fn execute(
    out: Console,
    config: &NodeConfig,
    config_file: Option<String>,
    yes: bool,
    allow_active_e3s: bool,
) -> Result<()> {
    let dir = env::current_dir()?;
    require_confirmation(
        yes,
        &format!(".interfold/data and .interfold/config in {}", dir.display()),
    )?;
    purge(&out, config, config_file, &dir, allow_active_e3s).await
}

/// Refuses unless `--yes` confirms the deletion of `folders`.
pub(crate) fn require_confirmation(yes: bool, folders: &str) -> Result<()> {
    if !yes {
        bail!(
            "The command deletes {folders}, including each node's operator key and libp2p key. \
             Nothing can restore them. To clear a node's state and keep its identity, use \
             `interfold node reset-data`. Stop the nodes, then run this command again with --yes."
        );
    }
    Ok(())
}

/// Deletes the `.interfold` data and configuration folders in `dir` once no node runs and none
/// holds an E3 that has not ended. It works out what it would delete and what stands in the way
/// before it writes anything, then checks again under every node's lock.
pub(crate) async fn purge(
    out: &Console,
    config: &NodeConfig,
    config_file: Option<String>,
    dir: &Path,
    allow_active_e3s: bool,
) -> Result<()> {
    let nodes = node_configs(config, config_file)?;
    let mut existing = Vec::new();
    survey(&nodes, dir, &mut existing)?.settle(out, allow_active_e3s)?;
    let mut fences = existing;
    for node in &nodes {
        let lock = node_lock(node);
        if !fences.iter().any(|fence| fence.path() == lock) {
            fences.push(ProcessFence::acquire(&node.db_file(), &node.name())?);
        }
    }
    // A node may have started between the survey and the locks.
    survey(&nodes, dir, &mut fences)?.settle(out, allow_active_e3s)?;
    for root in DELETED {
        let root = dir.join(root);
        if root.exists() {
            delete_keeping_locks(&root)?;
        }
    }
    // The locks go last, so a node that starts now finds no half-deleted state.
    for root in DELETED {
        let root = dir.join(root);
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
    }
    drop(fences);
    Ok(())
}

fn node_lock(node: &NodeConfig) -> PathBuf {
    node.db_file().parent().map_or_else(
        || PathBuf::from(LOCK_FILE_NAME),
        |dir| dir.join(LOCK_FILE_NAME),
    )
}

/// Everything that stands in the way of deleting `dir`'s `.interfold` folders. It only reads, and
/// holds the lock of each node it finds, so a running node stops it first.
fn survey(nodes: &[NodeConfig], dir: &Path, fences: &mut Vec<ProcessFence>) -> Result<Plan> {
    let mut plan = Plan::default();
    if is_link(&dir.join(".interfold")) {
        plan.refusals.push(format!(
            "{} is a link: what it points to may be another project's state; run the command \
             where the state really is",
            dir.join(".interfold").display()
        ));
    }
    // Everything under both folders goes: a profile's `data_dir` can put a node anywhere in them,
    // and a profile removed from the configuration leaves its folder, and its key's list, behind.
    let named: Vec<PathBuf> = nodes.iter().map(NodeConfig::node_data_dir).collect();
    let own: BTreeSet<PathBuf> = nodes
        .iter()
        .map(|node| node_state::canonical(node_state::inventory(node).path()))
        .collect();
    let (mut unchecked, mut left_behind) = (Vec::new(), Vec::new());
    for root in DELETED {
        let found = node_state::guard(&dir.join(root), &named, fences)?;
        unchecked.extend(found.unchecked);
        left_behind.extend(
            found
                .inventories
                .into_iter()
                .filter(|list| !own.contains(&node_state::canonical(list.path()))),
        );
    }
    for node in nodes {
        let current = node_state::dir(node);
        plan.check(&node.name(), &current);
        let recorded = node_state::inventory(node).read();
        if !recorded.complete && (node.db_file().exists() || node.key_file().exists()) {
            plan.blockers.push(no_full_record(&node.name()));
        }
        check_recorded(&mut plan, &node.name(), recorded, Some(current.path()));
    }
    for list in left_behind {
        let owner = format!("the key beside {}", list.path().display());
        let recorded = list.read();
        if !recorded.complete {
            plan.blockers.push(no_full_record(&owner));
        }
        check_recorded(&mut plan, &owner, recorded, None);
    }
    plan.blockers.extend(unchecked.iter().map(|folder| {
        format!(
            "{} holds the journal of a node that no profile in the configuration names, so its \
             E3s cannot be checked (add the profile back to check them)",
            folder.display()
        )
    }));
    Ok(plan)
}

fn no_full_record(owner: &str) -> String {
    format!("{owner} has keys but no full record of where it ran, so its E3s elsewhere cannot be checked")
}

/// Adds the folders a key's list names; `checked` is one already looked at. A folder that holds no
/// node now, gone or empty, may be a data volume that is not mounted.
fn check_recorded(plan: &mut Plan, owner: &str, recorded: Recorded, checked: Option<&Path>) {
    for folder in recorded.folders {
        let dir = NodeDir::new(&folder);
        match dir.state(None) {
            State::Absent => plan.blockers.push(format!(
                "{owner} ran in {}, which holds nothing now (is its volume mounted?), so its E3s \
                 cannot be checked",
                folder.display()
            )),
            _ if Some(folder.as_path()) == checked => {}
            _ => plan.check(&format!("{owner}'s folder at {}", folder.display()), &dir),
        }
    }
}

fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_symlink())
}

/// Deletes everything under `root` except the node locks, following no link.
fn delete_keeping_locks(root: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let (path, kind) = (entry.path(), entry.file_type()?);
        if entry.file_name() == LOCK_FILE_NAME {
            continue;
        }
        match kind.is_dir() {
            true => delete_keeping_locks(&path)?,
            false => std::fs::remove_file(&path)?,
        }
    }
    Ok(())
}

/// The configuration of each node profile, including `_default` and the active one, loaded the
/// way `nodes up` starts them.
fn node_configs(config: &NodeConfig, config_file: Option<String>) -> Result<Vec<NodeConfig>> {
    let mut names: Vec<&String> = config.nodes().keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            load_config(name, config_file.clone(), None)
                .map(|config| config.node)
                .map_err(|error| {
                    anyhow!(
                        "Could not load node profile `{name}`: {error:#}. The command deleted nothing."
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{node_configs, purge as run_purge};
    use anyhow::Result;
    use e3_ciphernode_config::NodeConfig;
    use e3_cli::app_config::load_config;
    use e3_console::Console;
    use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
    use std::path::Path;

    async fn purge(
        config: &NodeConfig,
        config_file: Option<String>,
        dir: &Path,
        allow_active_e3s: bool,
    ) -> Result<()> {
        let (out, _messages) = Console::channel();
        run_purge(&out, config, config_file, dir, allow_active_e3s).await
    }

    /// The purge checks every node profile, not only the one the command runs as.
    #[test]
    fn node_configs_loads_every_profile() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n  cn2:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let config = e3_cli::app_config::load_config("cn1", config_file.clone(), None)?.node;

        let names: Vec<String> = node_configs(&config, config_file)?
            .iter()
            .map(|node| node.name())
            .collect();
        assert_eq!(names, ["_default", "cn1", "cn2"]);
        Ok(())
    }

    /// A node folder that no profile names may hold an E3's key share, which the purge cannot
    /// check without that profile's keys, at any depth below the data folder: the purge refuses
    /// and deletes nothing, unless told to. A node that runs below it stops the purge either way.
    #[tokio::test]
    async fn a_node_folder_that_no_profile_names_stops_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let config = load_config("cn1", config_file.clone(), None)?.node;
        let data = config.node_data_dir().parent().unwrap().to_path_buf();
        assert_eq!(data, dir.path().join(".interfold/data"));
        let journal = data.join("group/cn2/v2/journal.redb");
        std::fs::create_dir_all(journal.parent().unwrap())?;
        std::fs::write(&journal, b"")?;

        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn2"), "{error:#}");
        assert!(journal.exists());

        // The configuration folder goes too, so a node whose `data_dir` is in it counts.
        let in_config = dir.path().join(".interfold/config/cn8/v2/journal.redb");
        std::fs::create_dir_all(in_config.parent().unwrap())?;
        std::fs::write(&in_config, b"")?;
        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn8"), "{error:#}");
        assert!(in_config.exists());
        std::fs::remove_dir_all(dir.path().join(".interfold/config/cn8"))?;

        let running = ProcessFence::acquire(&data.join("group/cn3/db"), "cn3")?;
        purge(&config, config_file.clone(), dir.path(), true)
            .await
            .unwrap_err();
        assert!(journal.exists());

        drop(running);
        purge(&config, config_file, dir.path(), true).await?;
        assert!(!data.exists());
        Ok(())
    }

    fn one_node(dir: &Path) -> Result<(NodeConfig, Option<String>)> {
        let config_file = dir.join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let config = load_config("cn1", config_file.clone(), None)?.node;
        Ok((config, config_file))
    }

    /// A data volume that is not mounted looks like an empty node, and the purge would delete the
    /// keys. The list beside the key says the node ran there.
    #[tokio::test]
    async fn a_folder_the_key_ran_in_that_is_gone_stops_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        std::fs::create_dir_all(config.key_file().parent().unwrap())?;
        std::fs::write(config.key_file(), b"key")?;
        crate::node_state::inventory(&config).record(&dir.path().join("volume/cn1/v2"))?;

        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("holds nothing now"), "{error:#}");
        assert!(config.key_file().exists());

        purge(&config, config_file, dir.path(), true).await?;
        assert!(!config.key_file().exists());
        Ok(())
    }

    /// An empty mount point is there, and looks like a node that holds nothing.
    #[tokio::test]
    async fn an_empty_folder_the_key_ran_in_stops_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        crate::node_state::inventory(&config).create()?;
        let current = crate::node_state::dir(&config);
        crate::node_state::inventory(&config).record(current.path())?;
        std::fs::create_dir_all(current.path())?;

        let error = purge(&config, config_file, dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("holds nothing now"), "{error:#}");
        Ok(())
    }

    /// Removing a profile leaves its key and list behind, and the state the list names elsewhere.
    #[tokio::test]
    async fn the_list_of_a_removed_profile_still_counts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        let key = dir.path().join(".interfold/config/removed/key");
        let list = e3_node::dir::Inventory::beside(&key);
        list.create()?;
        list.record(&dir.path().join("volume/removed/v2"))?;

        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("volume/removed"), "{error:#}");
        assert!(list.path().exists());

        purge(&config, config_file, dir.path(), true).await?;
        assert!(!list.path().exists());
        Ok(())
    }

    /// A removed profile's key with no list beside it: nothing says where it ran.
    #[tokio::test]
    async fn the_key_of_a_removed_profile_with_no_list_stops_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        let key = dir.path().join(".interfold/config/removed/key");
        std::fs::create_dir_all(key.parent().unwrap())?;
        std::fs::write(&key, b"key")?;
        let error = purge(&config, config_file, dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no full record"), "{error:#}");
        assert!(key.exists());
        Ok(())
    }

    /// A list that lost its history must not let the purge delete the key.
    #[tokio::test]
    async fn keys_whose_list_is_not_whole_stop_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        std::fs::create_dir_all(config.key_file().parent().unwrap())?;
        std::fs::write(config.key_file(), b"key")?;
        let current = crate::node_state::dir(&config);
        crate::node_state::inventory(&config).record(current.path())?;
        std::fs::create_dir_all(current.path())?;
        let error = purge(&config, config_file, dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no full record"), "{error:#}");
        assert!(config.key_file().exists());
        Ok(())
    }

    #[tokio::test]
    async fn keys_with_no_record_of_where_they_ran_stop_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        std::fs::create_dir_all(config.key_file().parent().unwrap())?;
        std::fs::write(config.key_file(), b"key")?;
        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no full record"), "{error:#}");

        crate::node_state::inventory(&config).create()?;
        purge(&config, config_file, dir.path(), false).await?;
        assert!(!config.key_file().exists());
        Ok(())
    }

    /// A purge that is refused writes nothing: not even a lock file for a node that never ran.
    #[tokio::test]
    async fn a_refused_purge_leaves_nothing_behind() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (config, config_file) = one_node(dir.path())?;
        crate::node_state::inventory(&config).record(&dir.path().join("volume/cn1/v2"))?;
        purge(&config, config_file, dir.path(), false)
            .await
            .unwrap_err();
        assert!(!config
            .db_file()
            .parent()
            .unwrap()
            .join(LOCK_FILE_NAME)
            .exists());
        Ok(())
    }

    /// A node that starts while the purge deletes must find the same lock file held.
    #[test]
    fn deleting_keeps_the_locks_until_the_end() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let node = dir.path().join("cn1/v2");
        std::fs::create_dir_all(&node)?;
        std::fs::write(node.join("journal.redb"), b"")?;
        let lock = dir.path().join("cn1").join(LOCK_FILE_NAME);
        std::fs::write(&lock, b"")?;
        super::delete_keeping_locks(dir.path())?;
        assert!(lock.exists());
        assert!(!node.join("journal.redb").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_root_stops_the_purge_even_with_the_override() -> Result<()> {
        let (dir, other) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let (config, config_file) = one_node(dir.path())?;
        std::os::unix::fs::symlink(other.path(), dir.path().join(".interfold"))?;
        std::fs::create_dir_all(other.path().join("data"))?;
        let error = purge(&config, config_file, dir.path(), true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("is a link"), "{error:#}");
        assert!(other.path().join("data").exists());
        Ok(())
    }

    /// A node folder inside another node's folder, or one whose state or whole folder is a link
    /// to storage elsewhere, counts too.
    #[cfg(unix)]
    #[tokio::test]
    async fn node_folders_inside_another_or_behind_a_link_stop_the_purge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let config = load_config("cn1", config_file.clone(), None)?.node;
        let data = config.node_data_dir().parent().unwrap().to_path_buf();

        for node in ["cn2", "cn2/v2/cn4"] {
            let journal = data.join(node).join("v2/journal.redb");
            std::fs::create_dir_all(journal.parent().unwrap())?;
            std::fs::write(&journal, b"")?;
        }
        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn4"), "{error:#}");
        std::fs::remove_dir_all(data.join("cn2"))?;

        let elsewhere = tempfile::tempdir()?;
        std::fs::write(elsewhere.path().join("journal.redb"), b"")?;
        std::fs::create_dir_all(data.join("cn3"))?;
        std::os::unix::fs::symlink(elsewhere.path(), data.join("cn3/v2"))?;
        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn3"), "{error:#}");
        std::fs::remove_dir_all(data.join("cn3"))?;

        // The whole node folder behind a link, with a link back up beside it.
        let moved = tempfile::tempdir()?;
        let journal = moved.path().join("v2/journal.redb");
        std::fs::create_dir_all(journal.parent().unwrap())?;
        std::fs::write(&journal, b"")?;
        std::os::unix::fs::symlink(moved.path(), data.join("cn5"))?;
        std::os::unix::fs::symlink(&data, data.join("loop"))?;
        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn5"), "{error:#}");
        assert!(journal.exists());
        std::fs::remove_file(data.join("cn5"))?;

        // A lock file that links elsewhere, a configured node's included, is refused before the
        // fence writes through it.
        let outside = moved.path().join("key backup");
        std::fs::write(&outside, b"key bytes")?;
        for node in ["cn6", "cn1"] {
            let lock = data.join(node).join(LOCK_FILE_NAME);
            std::fs::create_dir_all(lock.parent().unwrap())?;
            // An earlier purge took the configured node's fence, which left its plain lock file.
            let _ = std::fs::remove_file(&lock);
            std::os::unix::fs::symlink(&outside, &lock)?;
            let error = purge(&config, config_file.clone(), dir.path(), true)
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains("plain file"), "{error:#}");
            assert_eq!(std::fs::read(&outside)?, b"key bytes");
            std::fs::remove_file(&lock)?;
        }

        // A link the purge cannot follow stops it: what is behind may be a node.
        use std::os::unix::fs::PermissionsExt;
        let sealed = moved.path().join("sealed");
        std::fs::create_dir_all(sealed.join("node"))?;
        std::os::unix::fs::symlink(sealed.join("node"), data.join("cn7"))?;
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000))?;
        let result = purge(&config, config_file, dir.path(), true).await;
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755))?;
        assert!(result.is_err());
        assert!(data.join("cn7").exists());
        Ok(())
    }
}
