// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use e3_ciphernode_config::NodeConfig;
use e3_entrypoint::nodes::daemon;

pub async fn execute(
    config: &NodeConfig,
    exclude: Vec<String>,
    verbose: u8,
    config_string: Option<String>,
    otel: Option<String>,
) -> Result<()> {
    daemon::execute(config, exclude, verbose, config_string, otel).await
}
