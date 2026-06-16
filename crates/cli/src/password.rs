// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::Console;
use zeroize::Zeroizing;

use crate::{helpers::parse_zeroizing, password_delete, password_set};

#[derive(Subcommand, Clone, Debug)]
pub enum PasswordCommands {
    /// Set (or overwrite) a password
    Set {
        /// The new password
        #[arg(short, long, value_parser = parse_zeroizing)]
        password: Option<Zeroizing<String>>,
    },

    /// Delete the current password
    Delete,
}

pub async fn execute(out: Console, command: PasswordCommands, config: &AppConfig) -> Result<()> {
    match command {
        PasswordCommands::Set { password } => password_set::execute(out, config, password).await?,
        PasswordCommands::Delete => password_delete::execute(&out, config).await?,
    };

    Ok(())
}
