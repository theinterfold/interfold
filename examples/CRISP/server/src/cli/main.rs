// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod approve;
mod commands;

use clap::{Parser, Subcommand};
use commands::{check_committee_key_published, default_hint, initialize_crisp_round};
use crisp::logger::init_logger;
use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input};
use eyre::Result;
use log::info;

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
pub async fn main() -> Result<()> {
    init_logger();

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
                balance_threshold.unwrap_or_else(|| default_balance_threshold(onchain).to_owned());
            let e3_id = initialize_crisp_round(&token_address, &balance_threshold, onchain).await?;
            println!("{e3_id}");
        }
        Some(Commands::CheckE3Ready { e3id }) => {
            println!("{}", check_committee_key_published(&e3id).await?);
        }
        None => {
            // Without a command, ask for the round settings.
            select(
                "Create a new CRISP round or participate in an existing round.",
                &["Initialize new E3 round."],
            )?;
            let onchain = select(
                "Who may vote in this round?",
                &[
                    "Token census — holders of a token at a snapshot may vote.",
                    "Open registration — anyone can register on-chain during the round and vote.",
                ],
            )? == 1;
            let token_address = if onchain {
                prompt(
                    "Enter the registry (or votes token) eligibility is read from",
                    default_hint("SelfRegistry"),
                )?
            } else {
                prompt(
                    "Enter the token contract address for the voting round",
                    default_hint("MockVotingToken"),
                )?
            };
            let balance_threshold = prompt(
                "Enter the balance threshold for the voting round",
                default_balance_threshold(onchain).to_owned(),
            )?;
            let e3_id = initialize_crisp_round(&token_address, &balance_threshold, onchain).await?;
            println!("E3 ID: {e3_id}");
        }
    }

    Ok(())
}

fn select(prompt: &str, items: &[&str]) -> Result<usize> {
    Ok(FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(0)
        .items(items)
        .interact()?)
}

fn prompt(text: &str, default: String) -> Result<String> {
    Ok(Input::with_theme(&ColorfulTheme::default())
        .with_prompt(text)
        .default(default)
        .interact_text()?)
}

/// The floor a slot must clear to vote, in the token's raw units. A registered `SelfRegistry`
/// account reports exactly 1, so an open-registration round defaults to that; a token round
/// defaults to one full token.
fn default_balance_threshold(onchain: bool) -> &'static str {
    if onchain {
        "1"
    } else {
        "1000000000000000000"
    }
}
