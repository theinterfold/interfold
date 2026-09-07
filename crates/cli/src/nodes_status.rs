// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use e3_config::AppConfig;
use e3_entrypoint::nodes::status;

pub async fn execute(config: &AppConfig, id: &str) -> Result<()> {
    status::execute(config, id).await?;
    Ok(())
}
