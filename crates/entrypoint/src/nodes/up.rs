// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::nodes::daemon;
use anyhow::*;
use e3_config::AppConfig;
use tracing::instrument;

use super::client;

#[instrument(skip_all)]
pub async fn execute(
    config: &AppConfig,
    detach: bool, // TBI
    exclude: Vec<String>,
    verbose: u8,
    maybe_config_string: Option<String>,
    maybe_otel: Option<String>,
) -> Result<()> {
    if client::is_ready().await? {
        // Name the other swarm so the operator does not assume it is theirs.
        client::ensure_same_swarm(&config.config_file()).await?;
        bail!("Swarm is already running!");
    }

    if detach {
        client::start_daemon(verbose, &maybe_config_string, &exclude).await?;
        return Ok(());
    }

    //  run the swarm_daemon process locally forwarding args
    daemon::execute(config, exclude, verbose, maybe_config_string, maybe_otel).await?;

    Ok(())
}
