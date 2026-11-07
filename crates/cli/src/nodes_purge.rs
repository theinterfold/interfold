// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::node_state;
use anyhow::{anyhow, bail, Result};
use e3_ciphernode_config::NodeConfig;
use e3_cli::app_config::load_config;
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use std::collections::BTreeSet;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Delete the data and configuration of the local node set.
pub async fn execute(
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
    purge(config, config_file, &dir, allow_active_e3s).await
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
/// holds an E3 that has not ended.
pub(crate) async fn purge(
    config: &NodeConfig,
    config_file: Option<String>,
    dir: &Path,
    allow_active_e3s: bool,
) -> Result<()> {
    let nodes = node_configs(config, config_file)?;
    let mut fences = Vec::new();
    let mut refusals = Vec::new();
    for node in &nodes {
        fences.push(ProcessFence::acquire(&node.db_file(), &node.name())?);
        if allow_active_e3s {
            continue;
        }
        let held = node_state::held_e3s(node).await?;
        if !held.is_empty() {
            let held: Vec<String> = held.iter().map(ToString::to_string).collect();
            refusals.push(format!("{} holds E3(s) {}", node.name(), held.join(", ")));
        }
    }
    // Everything under the data folder goes, so every node there is fenced and every journal there
    // checked, at any depth: a profile's `data_dir` can nest a node, and a profile removed from the
    // configuration leaves its folder behind.
    let mut contents = Contents::default();
    scan(
        &dir.join(".interfold/data"),
        &mut BTreeSet::new(),
        &mut contents,
    )?;
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let held: BTreeSet<PathBuf> = fences.iter().map(|fence| canonical(fence.path())).collect();
    for lock in &contents.locks {
        if !held.contains(&canonical(lock)) {
            fences.push(ProcessFence::acquire_at(lock, &lock.display().to_string())?);
        }
    }
    let named: BTreeSet<PathBuf> = nodes
        .iter()
        .map(|node| canonical(&node.node_data_dir()))
        .collect();
    for folder in &contents.nodes {
        if !allow_active_e3s && !named.contains(&canonical(folder)) {
            refusals.push(format!(
                "{} holds the journal of a node that no profile in the configuration names, so \
                 its E3s cannot be checked (add the profile back to check them)",
                folder.display()
            ));
        }
    }
    if !refusals.is_empty() {
        bail!(
            "Deleted nothing: {}. Wait for those E3s to end, or rerun with --allow-active-e3s \
             after checking each on chain.",
            refusals.join("; ")
        );
    }
    for folder in [".interfold/data", ".interfold/config"] {
        let folder = dir.join(folder);
        if folder.exists() {
            std::fs::remove_dir_all(&folder)?;
        }
    }
    Ok(())
}

/// What a folder holds at any depth: the node folders, each with its journal at
/// `v2/journal.redb`, and the lock files of the nodes that use them.
#[derive(Default)]
struct Contents {
    nodes: Vec<PathBuf>,
    locks: Vec<PathBuf>,
}

/// Every folder counts as a node folder when its journal exists, also inside another node's
/// folder. The walk follows links to folders, since a node's state may live elsewhere behind one,
/// and visits each folder once, since a link may point back up. The deletion follows no link.
fn scan(dir: &Path, visited: &mut BTreeSet<PathBuf>, contents: &mut Contents) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !visited.insert(std::fs::canonicalize(dir)?) {
        return Ok(());
    }
    if node_state::journal_in(dir).exists() {
        contents.nodes.push(dir.to_path_buf());
    }
    for entry in entries {
        let entry = entry?;
        let (path, kind) = (entry.path(), entry.file_type()?);
        if entry.file_name() == LOCK_FILE_NAME {
            // Taking the fence writes to its file, which through a link would be another file.
            if !kind.is_file() {
                bail!(
                    "Deleted nothing: {} is not a plain file, so the purge cannot fence the node \
                     that uses it. Remove it, then run the purge again.",
                    path.display()
                );
            }
            contents.locks.push(path);
        } else if kind.is_dir() || (kind.is_symlink() && path.is_dir()) {
            scan(&path, visited, contents)?;
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
    use super::{node_configs, purge};
    use anyhow::Result;
    use e3_cli::app_config::load_config;
    use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};

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
        let journal = crate::node_state::journal_in(&data.join("group/cn2"));
        std::fs::create_dir_all(journal.parent().unwrap())?;
        std::fs::write(&journal, b"")?;

        let error = purge(&config, config_file.clone(), dir.path(), false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cn2"), "{error:#}");
        assert!(journal.exists());

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
            let journal = crate::node_state::journal_in(&data.join(node));
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
        let journal = crate::node_state::journal_in(moved.path());
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

        // A lock file that links elsewhere is refused before the fence writes through it.
        let outside = moved.path().join("key backup");
        std::fs::write(&outside, b"key bytes")?;
        std::fs::create_dir_all(data.join("cn6"))?;
        std::os::unix::fs::symlink(&outside, data.join("cn6").join(LOCK_FILE_NAME))?;
        let error = purge(&config, config_file, dir.path(), true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not a plain file"), "{error:#}");
        assert_eq!(std::fs::read(&outside)?, b"key bytes");
        Ok(())
    }
}
