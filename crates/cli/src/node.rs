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
    /// restore a deleted key share.
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
    let _fence = ProcessFence::acquire(&config.db_file(), &config.name())?;
    if !folder.exists() {
        log!(out, "The node has no data. Nothing to reset.");
        return Ok(());
    }
    // This binary cannot read data of an older layout, so it cannot list its E3s; the release
    // that changed the layout is the one that reset it.
    if !allow_active_e3s && !older {
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
