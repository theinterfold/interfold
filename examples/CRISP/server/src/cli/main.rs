// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod approve;
mod commands;

use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input};
use reqwest::Client;

use commands::{default_registry_hint, default_voting_token_hint, initialize_crisp_round};
use crisp::logger::init_logger;
use log::info;

use clap::{Parser, Subcommand};
use once_cell::sync::Lazy;
use sled::Db;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::commands::check_committee_key_published;

pub static CLI_DB: Lazy<Arc<RwLock<Db>>> = Lazy::new(|| {
    let pathdb = std::env::current_dir().unwrap().join("database/cli");
    Arc::new(RwLock::new(sled::open(pathdb).unwrap()))
});

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optional environment selection (default: 0)
    #[arg(short, long, default_value_t = 0)]
    environment: usize,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize new E3 round
    Init {
        /// Voting eligibility token (`MockVotingToken` on localhost). Omit or `0x0` to use deploy
        /// JSON / `CRISP_VOTING_TOKEN` in `.env`. With `--onchain`, this is the registry or votes
        /// token eligibility is read from, defaulting to the deployed `SelfRegistry`.
        #[arg(short, long, default_value = "")]
        token_address: String,
        /// Minimum balance to vote. Defaults per mode: 1e18 for a token census, 1 for `--onchain`
        /// (a registered `SelfRegistry` account reports exactly 1).
        #[arg(short, long)]
        balance_threshold: Option<String>,
        /// Request an open-registration round: eligibility is read on-chain per input instead of
        /// from a census snapshot, so anyone can register during the input window and vote.
        #[arg(long, default_value_t = false)]
        onchain: bool,
    },
    CheckE3Ready {
        #[arg(short, long)]
        e3id: String,
    },
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_logger();

    let _client = Client::new();
    let cli = Cli::parse();

    if cli.environment != 0 {
        info!("Check back soon!");
        return Ok(());
    }

    match cli.command {
        Some(Commands::Init {
            token_address,
            balance_threshold,
            onchain,
        }) => {
            let balance_threshold =
                balance_threshold.unwrap_or_else(|| default_balance_threshold(onchain));
            let e3_id = initialize_crisp_round(&token_address, &balance_threshold, onchain).await?;
            println!("{}", e3_id);
        }
        Some(Commands::CheckE3Ready { e3id }) => {
            let is_ready = check_committee_key_published(&e3id).await?;
            println!("{}", is_ready);
        }
        None => {
            // Fall back to interactive mode if no command was specified
            let action = select_action()?;
            match action {
                0 => {
                    let onchain = select_census()? == 1;
                    let token_address = if onchain {
                        get_registry_address()?
                    } else {
                        get_token_address()?
                    };
                    let balance_threshold = get_balance_threshold(onchain)?;
                    let e3_id =
                        initialize_crisp_round(&token_address, &balance_threshold, onchain).await?;
                    println!("E3 ID: {}", e3_id);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
fn select_environment() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let selections = &["CRISP: Voting Protocol (ETH)", "More Coming Soon!"];
    Ok(FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Interfold (EEEE): Please choose the private execution environment you would like to run!")
        .default(0)
        .items(&selections[..])
        .interact()?)
}

fn select_action() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let selections = &[
        "Initialize new E3 round.",
        // "Participate in an E3 round.",
        // "Activate an E3 round.",
        // "Decrypt Ciphertext & Publish Results",
    ];
    Ok(FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Create a new CRISP round or participate in an existing round.")
        .default(0)
        .items(&selections[..])
        .interact()?)
}

fn select_census() -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let selections = &[
        "Token census — holders of a token at a snapshot may vote.",
        "Open registration — anyone can register on-chain during the round and vote.",
    ];
    Ok(FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Who may vote in this round?")
        .default(0)
        .items(&selections[..])
        .interact()?)
}

fn get_token_address() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the token contract address for the voting round")
        .default(default_voting_token_hint())
        .interact_text()?)
}

fn get_registry_address() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the registry (or votes token) eligibility is read from")
        .default(default_registry_hint())
        .interact_text()?)
}

/// The floor a slot must clear to vote, in the token's raw units. A registered `SelfRegistry`
/// account reports exactly 1, so an open-registration round defaults to that; a token round keeps
/// the one-full-token default this CLI always had.
fn default_balance_threshold(onchain: bool) -> String {
    if onchain {
        "1".to_string()
    } else {
        "1000000000000000000".to_string()
    }
}

fn get_balance_threshold(
    onchain: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the balance threshold for the voting round")
        .default(default_balance_threshold(onchain))
        .interact_text()?)
}
