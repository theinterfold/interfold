// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use e3_config::AppConfig;

mod context;
mod license;
mod lifecycle;
pub mod setup;
mod tickets;
mod utils;

use context::ChainContext;
use e3_console::Console;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::helpers::{ensure_hex_zeroizing, parse_zeroizing};

#[derive(Debug, Args, Clone, Default, Serialize, Deserialize)]
pub struct ChainArgs {
    /// Chain name as defined in the interfold config (defaults to the first entry)
    #[arg(long = "chain")]
    pub chain: Option<String>,
}

impl ChainArgs {
    fn selection(&self) -> Option<&str> {
        self.chain.as_deref()
    }
}

#[derive(Subcommand, Clone, Debug)]
pub enum CiphernodeCommands {
    /// Setup local ciphernode configuration
    Setup {
        /// An rpc url for interfold to connect to
        #[arg(long = "rpc-url", short = 'r')]
        rpc_url: Option<String>,

        /// The password
        #[arg(short='p', long, value_parser = parse_zeroizing)]
        password: Option<Zeroizing<String>>,

        /// Wallet Private Key
        #[arg(short='k', long, value_parser = ensure_hex_zeroizing)]
        private_key: Option<Zeroizing<String>>,
    },
    /// Manage FOLD license tokens and bonding state
    License {
        #[command(subcommand)]
        command: LicenseCommands,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Manage collateral tickets backed by the stable token
    Tickets {
        #[command(subcommand)]
        command: TicketCommands,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Register the current operator in the bonding registry
    Register {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Request deregistration from the bonding registry
    Deregister {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Force the registry to recompute activation for the node
    Activate {
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Intentionally deactivate by withdrawing tickets and/or license stake
    Deactivate {
        #[arg(long = "tickets", value_name = "AMOUNT")]
        ticket_amount: Option<String>,
        #[arg(long = "license", value_name = "AMOUNT")]
        license_amount: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Display the current on-chain status for this operator
    Status {
        #[command(flatten)]
        chain: ChainArgs,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum LicenseCommands {
    /// Bond FOLD into the bonding registry
    Bond {
        #[arg(long = "amount")]
        amount: String,
    },
    /// Unbond FOLD (moves stake to the exit queue)
    Unbond {
        #[arg(long = "amount")]
        amount: String,
    },
    /// Claim any unlocked exits
    Claim {
        #[arg(long = "max-ticket")]
        max_ticket: Option<String>,
        #[arg(long = "max-license")]
        max_license: Option<String>,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum TicketCommands {
    /// Deposit stablecoins to mint tickets
    Buy {
        #[arg(long = "amount")]
        amount: String,
    },
    /// Burn tickets by withdrawing the underlying stablecoin
    Burn {
        #[arg(long = "amount")]
        amount: String,
    },
}

pub async fn execute(out: Console, command: CiphernodeCommands, config: &AppConfig) -> Result<()> {
    match command {
        CiphernodeCommands::License { chain, command } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            license::execute(out, &ctx, command).await?
        }
        CiphernodeCommands::Tickets { chain, command } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            tickets::execute(out, &ctx, command).await?
        }
        CiphernodeCommands::Register { chain } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::register(out, &ctx).await?
        }
        CiphernodeCommands::Deregister { chain } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::deregister(out, &ctx).await?
        }
        CiphernodeCommands::Activate { chain } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::activate(out, &ctx).await?
        }
        CiphernodeCommands::Deactivate {
            chain,
            ticket_amount,
            license_amount,
        } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::deactivate(out, &ctx, ticket_amount, license_amount).await?
        }
        CiphernodeCommands::Status { chain } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::status(out, &ctx).await?
        }
        CiphernodeCommands::Setup { .. } => {
            bail!(
                "Cannot run `interfold ciphernode setup` when a configuration already exists: {:?}",
                config.config_file()
            );
        }
    }

    Ok(())
}
