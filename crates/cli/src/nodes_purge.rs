// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::node_state;
use anyhow::{anyhow, bail, Result};
use e3_ciphernode_config::NodeConfig;
use e3_cli::app_config::load_config;
use e3_console::{log, Console};

/// Delete the data of every node in the configuration.
pub fn execute(
    out: &Console,
    config: &NodeConfig,
    config_file: Option<String>,
    yes: bool,
    allow_active_e3s: bool,
) -> Result<()> {
    require_confirmation(yes, "the data of every node in the configuration")?;
    purge(out, config, config_file, allow_active_e3s)
}

/// Refuses unless `--yes` confirms the deletion of `what`.
pub(crate) fn require_confirmation(yes: bool, what: &str) -> Result<()> {
    if !yes {
        bail!(
            "This deletes {what}. The operator and network keys stay. Stop the nodes, then run \
             this command again with --yes."
        );
    }
    Ok(())
}

/// Clears every node the configuration names. A folder that no profile names any more is not
/// this command's to delete.
pub(crate) fn purge(
    out: &Console,
    config: &NodeConfig,
    config_file: Option<String>,
    allow_active_e3s: bool,
) -> Result<()> {
    let nodes = node_configs(config, config_file)?;
    node_state::clear(out, &nodes, allow_active_e3s)?;
    log!(out, "The operator and network keys stay.");
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
    use crate::node_state;
    use alloy::primitives::Address;
    use anyhow::Result;
    use e3_ciphernode_config::NodeConfig;
    use e3_cli::app_config::load_config;
    use e3_console::Console;
    use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
    use e3_node::dir::Identity;
    use std::path::{Path, PathBuf};

    fn purge(config: &NodeConfig, config_file: Option<String>, override_: bool) -> Result<()> {
        let (out, _messages) = Console::channel();
        run_purge(&out, config, config_file, override_)
    }

    /// Nodes `cn1` and `cn2` of one configuration, as the first of them sees it.
    fn two_nodes(dir: &Path) -> Result<(Vec<NodeConfig>, Option<String>)> {
        let config_file = dir.join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n  cn2:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let nodes = ["cn1", "cn2"]
            .map(|name| load_config(name, config_file.clone(), None).map(|config| config.node));
        let [first, second] = nodes;
        Ok((vec![first?, second?], config_file))
    }

    /// Gives `node` a key, a wallet store and a folder a node ran in; returns that folder.
    fn with_state(node: &NodeConfig) -> Result<PathBuf> {
        for credential in [node.key_file(), node.db_file()] {
            std::fs::create_dir_all(credential.parent().unwrap())?;
            std::fs::write(credential, b"keep me")?;
        }
        let dir = node_state::dir(node);
        dir.open(&Identity {
            chain_id: 1,
            interfold: Address::repeat_byte(1),
            operator: Address::repeat_byte(2),
        })?;
        drop(e3_journal::Journal::open(dir.journal())?);
        Ok(dir.path().to_path_buf())
    }

    /// The purge checks every node profile, not only the one the command runs as.
    #[test]
    fn node_configs_loads_every_profile() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        let names: Vec<String> = node_configs(&nodes[0], config_file)?
            .iter()
            .map(|node| node.name())
            .collect();
        assert_eq!(names, ["_default", "cn1", "cn2"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_purge_deletes_every_node_s_data_and_keeps_every_key() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        let folders = [with_state(&nodes[0])?, with_state(&nodes[1])?];

        purge(&nodes[0], config_file, false)?;

        assert!(folders.iter().all(|folder| !folder.exists()));
        for node in &nodes {
            assert_eq!(std::fs::read(node.key_file())?, b"keep me");
            assert_eq!(std::fs::read(node.db_file())?, b"keep me");
        }
        Ok(())
    }

    /// Data this binary cannot read may hold an E3 that has not ended: nothing is deleted, in any
    /// node, unless the operator says so.
    #[tokio::test]
    async fn a_node_that_cannot_be_checked_stops_the_purge_of_every_node() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        let folders = [with_state(&nodes[0])?, with_state(&nodes[1])?];
        std::fs::write(folders[1].join("manifest.json"), b"not json")?;

        let error = purge(&nodes[0], config_file.clone(), false).unwrap_err();
        assert!(error.to_string().contains("cn2"), "{error:#}");
        assert!(folders.iter().all(|folder| folder.exists()));

        purge(&nodes[0], config_file, true)?;
        assert!(folders.iter().all(|folder| !folder.exists()));
        Ok(())
    }

    /// Nothing overrides a node that runs.
    #[tokio::test]
    async fn a_running_node_stops_the_purge_even_with_the_override() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        let folders = [with_state(&nodes[0])?, with_state(&nodes[1])?];
        let running = ProcessFence::acquire(&nodes[1].db_file(), "cn2")?;

        purge(&nodes[0], config_file.clone(), true).unwrap_err();
        assert!(folders.iter().all(|folder| folder.exists()));

        drop(running);
        purge(&nodes[0], config_file, false)?;
        assert!(folders.iter().all(|folder| !folder.exists()));
        Ok(())
    }

    /// A node that never ran has nothing to lose, and is left as it was: not even a lock file.
    #[tokio::test]
    async fn a_node_with_no_data_is_left_as_it_was() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        purge(&nodes[0], config_file, false)?;
        assert!(!nodes[0]
            .db_file()
            .parent()
            .unwrap()
            .join(LOCK_FILE_NAME)
            .exists());
        Ok(())
    }

    /// A folder that no profile names may be another project's: the purge does not touch it.
    #[tokio::test]
    async fn a_folder_no_profile_names_stays() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (nodes, config_file) = two_nodes(dir.path())?;
        let data = nodes[0].node_data_dir().parent().unwrap().to_path_buf();
        let journal = data.join("removed/v2/journal.redb");
        std::fs::create_dir_all(journal.parent().unwrap())?;
        std::fs::write(&journal, b"")?;

        purge(&nodes[0], config_file, false)?;
        assert!(journal.exists());
        Ok(())
    }
}
