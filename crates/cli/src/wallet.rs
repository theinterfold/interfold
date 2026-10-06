// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::Console;

use crate::{helpers::read_secret_line, wallet_get, wallet_set};

#[derive(Subcommand, Clone, Debug)]
pub enum WalletCommands {
    /// Set wallet private key
    Set {
        /// Read the private key from one line on stdin
        #[arg(long)]
        private_key_stdin: bool,
    },
    /// Get your wallet address
    Get,
}

pub async fn execute(out: Console, command: WalletCommands, config: AppConfig) -> Result<()> {
    match command {
        WalletCommands::Set { private_key_stdin } => {
            let private_key = if private_key_stdin {
                Some(read_secret_line(
                    &mut std::io::stdin().lock(),
                    "private key",
                )?)
            } else {
                None
            };
            wallet_set::execute(out, &config, private_key).await?
        }
        WalletCommands::Get => wallet_get::execute(out, &config).await?,
    };

    Ok(())
}
