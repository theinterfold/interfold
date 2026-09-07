// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use e3_config::AppConfig;
use e3_entrypoint::nodes::down;

pub async fn execute(config: &AppConfig) -> Result<()> {
    down::execute(config).await?;
    Ok(())
}
