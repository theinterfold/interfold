// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::keystore;
use anyhow::{Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use e3_crypto::Cipher;

pub async fn execute(out: Console, config: &NodeConfig) -> Result<()> {
    let cipher = Cipher::from_file(config.key_file()).await?;
    let keys = keystore::read(&config.db_file(), &cipher)?.context("No wallet has been set.")?;
    log!(out, "{}", keys.address());

    Ok(())
}
