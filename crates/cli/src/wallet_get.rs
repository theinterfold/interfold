// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};

pub async fn execute(out: Console, config: &NodeConfig) -> Result<()> {
    let address = e3_entrypoint::wallet::get::execute(config).await?;
    log!(out, "{}", address);

    Ok(())
}
