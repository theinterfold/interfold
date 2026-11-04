// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use tracing::instrument;

use super::client;

#[instrument(skip_all)]
pub async fn execute() -> Result<()> {
    if !client::is_ready().await? {
        // not running!
        return Ok(());
    }

    client::terminate().await?;

    Ok(())
}
