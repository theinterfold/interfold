// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::nodes_purge::{purge, require_confirmation};
use anyhow::Result;
use e3_config::AppConfig;
use std::env;

/// Delete the local node set's data and configuration, then the program cache.
pub async fn execute(
    config: &AppConfig,
    config_file: Option<String>,
    yes: bool,
    allow_active_e3s: bool,
) -> Result<()> {
    let dir = env::current_dir()?;
    require_confirmation(
        yes,
        &format!(
            ".interfold/data, .interfold/config and .interfold/caches in {}",
            dir.display()
        ),
    )?;
    purge(config, config_file, &dir, allow_active_e3s).await?;
    // A missing cache folder is nothing to delete. The node state is already gone at this point.
    if dir.join(".interfold/caches").exists() {
        e3_support_scripts::program_cache_purge().await?;
    }
    Ok(())
}
