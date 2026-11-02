// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use zeroize::{Zeroize, Zeroizing};

use crate::helpers::prompt_password::prompt_password;

pub fn ask_for_password(input: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    if let Some(pw_str) = input {
        if pw_str.trim().is_empty() {
            bail!("Password must not be blank")
        }
        return Ok(pw_str);
    }

    // First password entry
    let mut pw_str = prompt_password("Please enter a new password")?;
    if pw_str.trim().is_empty() {
        bail!("Password must not be blank")
    }

    // Second password entry for confirmation
    let mut confirm_pw_str = prompt_password("Please confirm your password")?;

    // Check if passwords match
    if pw_str.trim() != confirm_pw_str.trim() {
        // Clean up sensitive data
        pw_str.zeroize();
        confirm_pw_str.zeroize();
        bail!("Passwords do not match")
    }

    // Clean up sensitive data
    confirm_pw_str.zeroize();
    let trimmed = Zeroizing::new(pw_str.trim().to_owned());
    pw_str.zeroize();

    Ok(trimmed)
}

pub async fn execute(
    out: Console,
    config: &NodeConfig,
    input: Option<Zeroizing<String>>,
) -> Result<()> {
    log!(out, "Setting password...");
    e3_entrypoint::password::set::preflight(config).await?;

    let pw = ask_for_password(input)?;

    e3_entrypoint::password::set::execute(config, pw).await?;

    log!(out, "Password successfully set.");

    Ok(())
}
