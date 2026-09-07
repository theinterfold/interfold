// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use e3_config::AppConfig;
use tracing::instrument;

use super::client;

#[instrument(skip_all)]
pub async fn execute(config: &AppConfig) -> Result<()> {
    if !client::is_ready().await? {
        // not running!
        return Ok(());
    }
    client::ensure_same_swarm(&config.config_file()).await?;

    client::terminate().await?;

    Ok(())
}
