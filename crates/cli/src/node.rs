// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_entrypoint::validate::validate_node;

#[derive(Subcommand, Clone, Debug)]
pub enum NodeCommands {
    /// Validate the on-disk state of a single node without starting it.
    ///
    /// Opens the node's persisted stores read-only and checks that the schema
    /// is loadable by this binary, the event log is intact, the snapshot cursor
    /// is consistent, and there are no orphaned committee tickets ("loose
    /// ends"). Safe to run while the node is stopped; intended as the
    /// pre-upgrade and post-crash health check. Exits non-zero on failure.
    Validate,
}

pub async fn execute(out: Console, command: NodeCommands, config: &AppConfig) -> Result<()> {
    match command {
        NodeCommands::Validate => {
            // Offline-only contract: hold the same cross-host fence `start` uses so the
            // validator cannot read state out from under a live node or race a concurrent
            // `interfold start`. Released when this scope ends.
            let _fence =
                e3_entrypoint::fence::ProcessFence::acquire(&config.db_file(), &config.name())?;
            let report = validate_node(config).await?;
            log!(out, "{}", report.render());
            if report.has_failure() {
                bail!("node validation failed");
            }
        }
    }
    Ok(())
}
