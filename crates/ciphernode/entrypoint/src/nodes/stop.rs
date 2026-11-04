// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use tracing::instrument;

use super::client;

#[instrument(skip_all)]
pub async fn execute(id: &str) -> Result<()> {
    if !client::is_ready().await? {
        bail!("Swarm client is not ready. Did you forget to call `interfold nodes up`?");
    }

    client::stop(id).await?;

    Ok(())
}
