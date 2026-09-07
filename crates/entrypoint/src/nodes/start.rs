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
pub async fn execute(config: &AppConfig, id: &str) -> Result<()> {
    if !client::is_ready().await? {
        bail!("Swarm client is not ready. Did you forget to call `interfold nodes up`?");
    }
    client::ensure_same_swarm(&config.config_file()).await?;

    client::start(id).await?;

    Ok(())
}
