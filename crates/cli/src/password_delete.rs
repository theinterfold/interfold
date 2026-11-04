// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::helpers::prompt_password::prompt_password;
use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Confirm};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use zeroize::Zeroize;

pub async fn prompt_delete(out: Console, config: &NodeConfig) -> Result<bool> {
    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to delete the key? This action cannot be undone.")
        .default(false)
        .interact()?
    {
        return Ok(false);
    }

    let Ok(mut cur_pw) = e3_entrypoint::password::delete::get_current_password(config).await else {
        log!(out, "Password is not set. Nothing to do.");
        return Ok(false);
    };

    let mut pw_str = prompt_password("Please enter the current password")?;
    if pw_str != *cur_pw {
        // Clean up sensitive data
        pw_str.zeroize();
        cur_pw.zeroize();
        return Err(anyhow::anyhow!("Incorrect password"));
    }

    Ok(true)
}

pub async fn execute(out: &Console, config: &NodeConfig) -> Result<()> {
    if prompt_delete(out.clone(), config).await? {
        e3_entrypoint::password::delete::execute(config).await?;
        log!(out, "Password successfully deleted.");
    } else {
        log!(out, "Operation cancelled.");
    }
    Ok(())
}
