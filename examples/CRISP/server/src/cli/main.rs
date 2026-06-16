// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod approve;
mod commands;

use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input};
use reqwest::Client;

use commands::{default_voting_token_hint, initialize_crisp_round};
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
        /// Voting eligibility token (`MockVotingToken` on localhost). Omit or `0x0` to use deploy JSON / `CRISP_VOTING_TOKEN` in `.env`.
        #[arg(short, long, default_value = "")]
        token_address: String,
        #[arg(short, long, default_value = "1000000000000000000")]
        balance_threshold: String,
    },
    CheckE3Ready {
        #[arg(short, long)]
        e3id: u64,
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
        }) => {
            let e3_id = initialize_crisp_round(&token_address, &balance_threshold).await?;
            println!("{}", e3_id);
        }
        Some(Commands::CheckE3Ready { e3id }) => {
            let is_ready = check_committee_key_published(e3id).await?;
            println!("{}", is_ready);
        }
        None => {
            // Fall back to interactive mode if no command was specified
            let action = select_action()?;
            match action {
                0 => {
                    let token_address = get_token_address()?;
                    let balance_threshold = get_balance_threshold()?;
                    let e3_id = initialize_crisp_round(&token_address, &balance_threshold).await?;
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

fn get_token_address() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the token contract address for the voting round")
        .default(default_voting_token_hint())
        .interact_text()?)
}

fn get_balance_threshold() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the balance threshold for the voting round")
        .default("1000000000000000000".to_string())
        .interact_text()?)
}
