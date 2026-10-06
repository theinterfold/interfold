// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use e3_config::AppConfig;
use e3_crypto::{FilePasswordManager, PasswordManager};
use zeroize::Zeroizing;

use crate::helpers::rand::generate_random_bytes;

/// Checks if the Keyfile already exists and fail with a constructive error
pub async fn preflight(config: &AppConfig) -> Result<()> {
    let key_file = config.key_file();
    let pm = FilePasswordManager::new(key_file);

    if pm.is_set() {
        bail!(
            "The key file {} already exists, and `interfold password set` does not replace a \
             password. To set another one, run `interfold password delete` first. The stored \
             wallet key and libp2p key are encrypted with the current password: keep a copy of \
             the wallet private key, and run `interfold wallet set` again after you set the new \
             password.",
            config.key_file().display()
        )
    }

    Ok(())
}

pub async fn execute(config: &AppConfig, input: Zeroizing<String>) -> Result<()> {
    let pw = Zeroizing::new(input.as_bytes().to_owned());

    execute_bytes(config, pw).await?;

    Ok(())
}

pub async fn execute_bytes(config: &AppConfig, input: Zeroizing<Vec<u8>>) -> Result<()> {
    let key_file = config.key_file();
    let mut pm = FilePasswordManager::new(key_file);

    // If a password exists, delete it first
    if pm.is_set() {
        pm.delete_key().await?;
    }

    pm.set_key(input).await?;
    Ok(())
}

pub async fn autopassword(config: &AppConfig) -> Result<()> {
    let key_file = config.key_file();
    let pm = FilePasswordManager::new(key_file);
    if !pm.is_set() {
        let pw = generate_random_bytes(128);
        execute_bytes(config, pw.into()).await?;
    }
    Ok(())
}
