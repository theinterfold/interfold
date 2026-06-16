// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::env;
use tokio::fs;

/// Purge all ciphernode data
pub async fn execute() -> Result<()> {
    let cwd = env::current_dir()?;
    let data_folder = cwd.join(".interfold/data");
    if fs::try_exists(&data_folder).await? {
        fs::remove_dir_all(data_folder).await?;
    }
    let config_folder = cwd.join(".interfold/config");
    if fs::try_exists(&config_folder).await? {
        fs::remove_dir_all(config_folder).await?;
    }
    Ok(())
}
