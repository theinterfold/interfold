// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{hex::FromHex, primitives::FixedBytes, signers::local::PrivateKeySigner};
use anyhow::{anyhow, Result};
use dialoguer::{theme::ColorfulTheme, Password};
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use e3_crypto::Cipher;
use zeroize::Zeroizing;

fn validate_private_key(input: &String) -> Result<()> {
    let bytes =
        FixedBytes::<32>::from_hex(input).map_err(|e| anyhow!("Invalid private key: {}", e))?;
    PrivateKeySigner::from_bytes(&bytes).map_err(|e| anyhow!("Invalid private key: {}", e))?;
    Ok(())
}

pub fn ask_for_private_key(given_key: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    let key = if let Some(given_key) = given_key {
        validate_private_key(&given_key)?;
        given_key
    } else {
        Zeroizing::new(
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter your Ethereum private key (0x...)")
                .validate_with(validate_private_key)
                .interact()?
                .trim()
                .to_string(),
        )
    };

    Ok(key)
}

pub async fn execute(
    out: Console,
    config: &NodeConfig,
    private_key: Option<Zeroizing<String>>,
) -> Result<()> {
    let input = ask_for_private_key(private_key)?;
    let key = Zeroizing::new(FixedBytes::<32>::from_hex(&*input)?.0);
    let cipher = Cipher::from_file(config.key_file()).await?;
    crate::keystore::write(&config.db_file(), &cipher, &key)?;
    log!(
        out,
        "Wallet key has been successfully stored and encrypted."
    );

    Ok(())
}
