// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{keystore, node_state};
use anyhow::{bail, Result};
use clap::Subcommand;
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use e3_crypto::Cipher;
use e3_entrypoint::fence::ProcessFence;

#[derive(Subcommand, Clone, Debug)]
pub enum NodeCommands {
    /// Check a stopped node: its password and keys, the layout of its data, and the E3s it holds.
    /// Exits non-zero on failure and changes no file.
    Validate,

    /// Delete the node's data but keep its operator and network keys.
    ///
    /// Use this when a release changes the layout of the node's data and the node refuses to start
    /// on it. The keys live in the keystore, apart from the data, so they stay.
    ///
    /// Refuses while the node runs, and while it holds an E3 that has not ended: the chain cannot
    /// restore a deleted key share. Refuses too where it cannot tell: data in an older layout,
    /// which this binary cannot read, and another node's journal inside the folder.
    ResetData {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,

        /// Delete the data even when the node holds an E3 that has not ended. The node loses its
        /// key share for that E3. Check first that each listed E3 is complete or failed on chain.
        #[arg(long)]
        allow_active_e3s: bool,

        /// Reset only when the data uses an older layout than this binary writes. Otherwise change
        /// nothing and exit with success. A package can run this before every start.
        #[arg(long)]
        if_schema_older: bool,
    },
}

pub async fn execute(out: Console, command: NodeCommands, config: &NodeConfig) -> Result<()> {
    match command {
        NodeCommands::Validate => validate(out, config).await,
        NodeCommands::ResetData {
            yes,
            allow_active_e3s,
            if_schema_older,
        } => reset_data(out, config, yes, allow_active_e3s, if_schema_older).await,
    }
}

async fn validate(out: Console, config: &NodeConfig) -> Result<()> {
    let _fence = ProcessFence::acquire(&config.db_file(), &config.name())?;
    let cipher = Cipher::from_file(config.key_file()).await?;
    match keystore::read(&config.db_file(), &cipher)? {
        Some(keys) => log!(
            out,
            "keys: operator {}, peer {}",
            keys.address(),
            keys.peer_id()?
        ),
        None => log!(out, "keys: no wallet is set"),
    }
    if node_state::layout_is_older(config)? {
        bail!(
            "data: {} uses an older layout; reset it with `interfold node reset-data`",
            node_state::folder(config).display()
        );
    }
    let held = node_state::held_e3s(config).await?;
    log!(out, "data: readable; the node holds {} E3(s)", held.len());
    for e3 in held {
        log!(out, "  E3 {e3}");
    }
    Ok(())
}

async fn reset_data(
    out: Console,
    config: &NodeConfig,
    yes: bool,
    allow_active_e3s: bool,
    if_schema_older: bool,
) -> Result<()> {
    let folder = node_state::folder(config);
    if !yes {
        bail!(
            "This deletes the data of node '{}' at {}. The operator and network keys stay. Stop \
             the node, then run this command again with --yes.",
            config.name(),
            folder.display()
        );
    }
    let older = node_state::layout_is_older(config)?;
    if if_schema_older && !older {
        log!(
            out,
            "The data does not use an older layout. Nothing to reset."
        );
        return Ok(());
    }
    let mut fences = vec![ProcessFence::acquire(&config.db_file(), &config.name())?];
    if !folder.exists() {
        log!(out, "The node has no data. Nothing to reset.");
        return Ok(());
    }
    // Another node's `data_dir` may sit inside this folder: it is fenced, and its journal checked.
    let others = node_state::guard(&folder, &[config.node_data_dir()], &mut fences)?;
    if !allow_active_e3s {
        if let Some(other) = others.first() {
            bail!(
                "{} holds the journal of another node, whose E3s this command cannot check. \
                 Move it out, or rerun with --allow-active-e3s after checking its E3s on chain.",
                other.display()
            );
        }
        // This binary cannot read data of an older layout, so it cannot list its E3s.
        if older && node_state::journal_in(&config.node_data_dir()).exists() {
            bail!(
                "The data uses an older layout that this binary cannot read, so it cannot check \
                 for E3s that have not ended. Check on chain that none of this node's E3s still \
                 runs, then rerun with --allow-active-e3s."
            );
        }
        let held = node_state::held_e3s(config).await?;
        if !held.is_empty() {
            let held: Vec<String> = held.iter().map(ToString::to_string).collect();
            bail!(
                "The node holds E3(s) that have not ended: {}. Wait for them to end, or rerun \
                 with --allow-active-e3s after checking each on chain.",
                held.join(", ")
            );
        }
    }
    std::fs::remove_dir_all(&folder)?;
    log!(out, "Removed {}", folder.display());
    log!(
        out,
        "The operator and network keys stay. Verify with: interfold wallet get --name {}",
        config.name()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reset_data;
    use crate::node_state;
    use anyhow::Result;
    use e3_ciphernode_config::NodeConfig;
    use e3_cli::app_config::load_config;
    use e3_console::Console;

    fn node(dir: &std::path::Path) -> Result<NodeConfig> {
        let config_file = dir.join("config.yaml");
        std::fs::write(&config_file, "node:\n  network: local\n")?;
        Ok(load_config(
            "_default",
            Some(config_file.to_string_lossy().into_owned()),
            None,
        )?
        .node)
    }

    async fn reset(config: &NodeConfig, allow_active_e3s: bool) -> Result<()> {
        let (out, _messages) = Console::channel();
        reset_data(out, config, true, allow_active_e3s, true).await
    }

    /// A journal in an older layout, which this binary cannot read, may hold E3s that have not
    /// ended: the reset refuses unless told to go ahead.
    #[tokio::test]
    async fn a_journal_in_an_older_layout_is_kept_unless_the_reset_is_told() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = node_state::folder(&config);
        std::fs::create_dir_all(&folder)?;
        std::fs::write(folder.join("LAYOUT"), "0")?;
        std::fs::write(node_state::journal_in(&config.node_data_dir()), b"")?;

        let error = reset(&config, false).await.unwrap_err();
        assert!(error.to_string().contains("older layout"), "{error:#}");
        assert!(folder.exists());

        reset(&config, true).await?;
        assert!(!folder.exists());
        Ok(())
    }

    /// Another node whose data folder sits inside this one's is not this command's to delete.
    #[tokio::test]
    async fn another_node_inside_the_folder_stops_the_reset() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = node_state::folder(&config);
        std::fs::create_dir_all(&folder)?;
        std::fs::write(folder.join("LAYOUT"), "0")?;
        let other = node_state::journal_in(&folder.join("other"));
        std::fs::create_dir_all(other.parent().unwrap())?;
        std::fs::write(&other, b"")?;

        let error = reset(&config, false).await.unwrap_err();
        assert!(error.to_string().contains("other"), "{error:#}");
        assert!(other.exists());
        Ok(())
    }
}
