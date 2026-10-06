// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::config_setup as setup;
use alloy::primitives::Address;
use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input};
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_utils::{colorize, Color};
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing::instrument;

use crate::helpers::read_secret_line;
use crate::password_set::ask_for_password;
use crate::wallet_set::ask_for_private_key;

#[instrument(name = "app", skip_all)]
pub async fn execute(
    out: Console,
    network: String,
    rpc_url: Option<String>,
    config_dir: Option<PathBuf>,
    password_stdin: bool,
    private_key_stdin: bool,
) -> Result<()> {
    // Refuse a network that setup cannot write before anything is read.
    crate::config_setup::network_chain(&network)?;
    // A prompt needs a terminal. Without one, every value must come from a flag or stdin, which
    // the command checks before it reads stdin.
    if !std::io::stdin().is_terminal() {
        let missing: Vec<&str> = [
            (rpc_url.is_none(), "--rpc-url"),
            (config_dir.is_none(), "--config-dir"),
            (!password_stdin, "--password-stdin"),
            (!private_key_stdin, "--private-key-stdin"),
        ]
        .into_iter()
        .filter_map(|(missing, flag)| missing.then_some(flag))
        .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "`interfold ciphernode setup` runs without a terminal, so it cannot prompt. Pass {}.",
                missing.join(", ")
            );
        }
    }
    let mut password = None;
    let mut private_key = None;
    if password_stdin || private_key_stdin {
        let mut stdin = std::io::stdin().lock();
        if password_stdin {
            password = Some(read_secret_line(&mut stdin, "password")?);
        }
        if private_key_stdin {
            private_key = Some(read_secret_line(&mut stdin, "private key")?);
        }
    }
    let pw = ask_for_password(password)?;
    let rpc_url = match rpc_url {
        Some(url) => {
            setup::validate_rpc_url(&url)?;
            url
        }
        None => {
            let theme = ColorfulTheme::default();
            let prompt = Input::<String>::with_theme(&theme).with_prompt("Enter WebSocket RPC URL");
            let prompt = match default_rpc_url(&network) {
                Some(default) => prompt.default(default.to_string()),
                None => prompt,
            };
            prompt
                .validate_with(|url: &String| setup::validate_rpc_url(url))
                .interact_text()?
        }
    };

    let private_key = ask_for_private_key(private_key)?;
    let default_config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
        .join("interfold");

    let config_dir: PathBuf = match config_dir {
        Some(dir) => {
            if dir.as_os_str().is_empty() || dir.is_file() {
                anyhow::bail!("--config-dir {} is not a directory", dir.display());
            }
            dir
        }
        None => Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter config directory")
            .default(default_config_dir.display().to_string())
            .validate_with(|input: &String| -> Result<(), &str> {
                let path = PathBuf::from(input);
                if input.is_empty() {
                    Err("Path cannot be empty")
                } else if path.is_file() {
                    Err("Path is a file, not a directory")
                } else {
                    Ok(())
                }
            })
            .interact_text()?
            .into(),
    };

    // Derive the node address from the private key so it can be written into
    // the generated config (the loader reads it from `node.address`).
    let node_address = setup::derive_address(&private_key)?;

    // Execute
    let config = setup::execute(&rpc_url, &node_address, &config_dir, &network)?;

    e3_entrypoint::password::set::preflight(&config).await?;
    e3_entrypoint::password::set::execute(&config, pw).await?;

    let (address, peer_id) = e3_entrypoint::wallet::set::execute(&config, private_key).await?;
    print_info(out, &config, address, &peer_id.to_string(), &rpc_url)?;
    Ok(())
}

fn default_rpc_url(network: &str) -> Option<&'static str> {
    match network.to_ascii_lowercase().as_str() {
        "local" | "localhost" | "hardhat" | "devnet" => Some("ws://127.0.0.1:8545"),
        "mainnet" => Some("wss://ethereum-rpc.publicnode.com"),
        "sepolia" => Some("wss://ethereum-sepolia-rpc.publicnode.com"),
        _ => None,
    }
}

fn print_info(
    out: Console,
    config: &AppConfig,
    address: Address,
    peer_id: &str,
    rpc_url: &str,
) -> Result<()> {
    let abs_config = config.config_file().canonicalize()?;

    log!(out, "\nInterfold configuration successfully created!");
    log!(
        out,
        "Editable configuration has been written to:\n\n {}",
        colorize(abs_config.to_string_lossy(), Color::Yellow)
    );
    log!(out, "");
    log!(out, "Data written:");
    log!(out, " address: {}", colorize(address, Color::Cyan));
    log!(out, " peer_id: {}", colorize(peer_id, Color::Cyan));
    log!(out, " rpc_url: {}", colorize(rpc_url, Color::Cyan));
    log!(
        out,
        " network: {}",
        colorize(config.network().name(), Color::Cyan)
    );
    log!(out, "");
    if config.using_custom_config() {
        log!(
            out,
            "Run future commands from within this directory tree, or pass\n {}\n",
            colorize(
                format!("--config {}", abs_config.to_string_lossy()),
                Color::Yellow
            )
        );
    }
    log!(
        out,
        "You can start your node using:\n `{}`\n",
        colorize("interfold start", Color::Yellow)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_setup_defaults_to_the_local_rpc() {
        assert_eq!(default_rpc_url("local"), Some("ws://127.0.0.1:8545"));
    }

    #[test]
    fn sepolia_setup_keeps_the_public_rpc_default() {
        assert!(default_rpc_url("sepolia").unwrap().contains("sepolia"));
    }

    #[test]
    fn mainnet_setup_does_not_default_to_sepolia() {
        assert_eq!(
            default_rpc_url("mainnet"),
            Some("wss://ethereum-rpc.publicnode.com")
        );
    }

    #[test]
    fn custom_network_setup_requires_an_explicit_rpc() {
        assert_eq!(default_rpc_url("private-network"), None);
    }
}
