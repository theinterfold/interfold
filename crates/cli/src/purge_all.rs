// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::nodes_purge::{purge, require_confirmation};
use anyhow::Result;
use e3_ciphernode_config::NodeConfig;
use e3_console::Console;
use std::env;

/// Delete the data of every node in the configuration, then the program cache.
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
        "the data of every node in the configuration, and the program cache",
    )?;
    purge(&out, config, config_file, allow_active_e3s)?;
    // A missing cache folder is nothing to delete.
    if dir.join(".interfold/caches").exists() {
        crate::program_support::cache_purge().await?;
    }
    Ok(())
}
