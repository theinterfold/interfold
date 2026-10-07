// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::Console;

use crate::{helpers::read_secret_line, password_delete, password_set};

#[derive(Subcommand, Clone, Debug)]
pub enum PasswordCommands {
    /// Set the password when none is set. Refuses when the key file exists; `password delete`
    /// removes it first
    Set {
        /// Read the new password from one line on stdin
        #[arg(long)]
        password_stdin: bool,
    },

    /// Delete the current password
    Delete,
}

pub async fn execute(out: Console, command: PasswordCommands, config: &AppConfig) -> Result<()> {
    match command {
        PasswordCommands::Set { password_stdin } => {
            let password = if password_stdin {
                Some(read_secret_line(&mut std::io::stdin().lock(), "password")?)
            } else {
                None
            };
            password_set::execute(out, config, password).await?
        }
        PasswordCommands::Delete => password_delete::execute(&out, config).await?,
    };

    Ok(())
}
