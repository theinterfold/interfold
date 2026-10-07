// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use e3_config::AppConfig;

mod bond;
mod context;
mod lifecycle;
pub mod setup;
mod tickets;
mod utils;

use context::ChainContext;
use e3_console::Console;
use serde::{Deserialize, Serialize};

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
        /// P2P network profile and chain for this configuration. The command writes the Sepolia
        /// deployment that is built into the binary.
        #[arg(
            long,
            default_value = "sepolia",
            value_parser = clap::builder::PossibleValuesParser::new([
                clap::builder::PossibleValue::new("sepolia"),
                // Earlier releases accepted `local`. The command refuses it and names the template.
                clap::builder::PossibleValue::new("local").hide(true),
            ])
        )]
        network: String,

        /// An rpc url for interfold to connect to
        #[arg(long = "rpc-url", short = 'r')]
        rpc_url: Option<String>,

        /// The folder for the configuration file. Without it, the command prompts for one.
        #[arg(long = "config-dir", value_name = "PATH")]
        config_dir: Option<std::path::PathBuf>,

        /// Read the password from the first requested line on stdin
        #[arg(long)]
        password_stdin: bool,

        /// Read the private key from the next requested line on stdin
        #[arg(long)]
        private_key_stdin: bool,
    },
    /// Authorize the initial wallet that will own this node's collateral
    SetBondOwner {
        /// Wallet or Safe that controls the bond; a separate cold owner is recommended
        #[arg(long = "owner", value_name = "ADDRESS")]
        owner: String,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Propose transferring an operator position to a new bond owner
    ProposeBondOwner {
        /// Operator position to transfer
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: String,
        /// Wallet or Safe that may accept ownership
        #[arg(long = "new-owner", value_name = "ADDRESS")]
        new_owner: String,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Accept a proposed bond-owner transfer
    AcceptBondOwner {
        /// Operator position being accepted
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: String,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Manage FOLD ciphernode bonding for an operator
    Bond {
        #[command(subcommand)]
        command: BondCommands,
        /// Target operator; defaults to the configured signer for self-owned positions
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Manage stablecoin-backed tickets for an operator
    Tickets {
        #[command(subcommand)]
        command: TicketCommands,
        /// Target operator; defaults to the configured signer for self-owned positions
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Register an operator using the configured bond-owner signer
    Register {
        /// Target operator; defaults to the configured signer for self-owned positions
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Request deregistration as the bond owner or operator emergency key
    Deregister {
        /// Target operator; defaults to the configured signer
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Recompute the activation state of a registered operator
    Activate {
        /// Target operator; defaults to the configured signer for self-owned positions
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Intentionally deactivate by withdrawing tickets and/or ciphernode bond
    Deactivate {
        /// Ticket-token amount to withdraw, not a ticket count.
        #[arg(long = "tickets", value_name = "AMOUNT")]
        ticket_amount: Option<String>,
        #[arg(long = "bond", value_name = "AMOUNT")]
        ciphernode_bond_amount: Option<String>,
        /// Target operator; defaults to the configured signer for self-owned positions
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
    /// Display the current on-chain status for this operator
    Status {
        /// Target operator; defaults to the configured signer
        #[arg(long = "operator", value_name = "ADDRESS")]
        operator: Option<String>,
        #[command(flatten)]
        chain: ChainArgs,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum BondCommands {
    /// Bond FOLD into an operator position
    Bond {
        #[arg(long = "amount")]
        amount: String,
    },
    /// Queue FOLD from an operator position for exit
    Unbond {
        #[arg(long = "amount")]
        amount: String,
    },
    /// Claim unlocked ticket and ciphernode bond exits
    Claim {
        #[arg(long = "max-ticket")]
        max_ticket: Option<String>,
        #[arg(long = "max-bond")]
        max_bond: Option<String>,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum TicketCommands {
    /// Deposit stablecoins to mint tickets for an operator
    Buy {
        /// Stablecoin amount to deposit, not a ticket count. Available tickets
        /// are floor(total collateral balance / ticket price).
        #[arg(long = "amount")]
        amount: String,
    },
    /// Burn an operator's tickets and queue the stablecoins for exit
    Burn {
        /// Ticket-token amount to burn, not a ticket count.
        #[arg(long = "amount")]
        amount: String,
    },
}

pub async fn execute(out: Console, command: CiphernodeCommands, config: &AppConfig) -> Result<()> {
    match command {
        CiphernodeCommands::SetBondOwner { chain, owner } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::set_bond_owner(out, &ctx, &owner).await?
        }
        CiphernodeCommands::ProposeBondOwner {
            chain,
            operator,
            new_owner,
        } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::propose_bond_owner(out, &ctx, &operator, &new_owner).await?
        }
        CiphernodeCommands::AcceptBondOwner { chain, operator } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            lifecycle::accept_bond_owner(out, &ctx, &operator).await?
        }
        CiphernodeCommands::Bond {
            chain,
            operator,
            command,
        } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            bond::execute(out, &ctx, operator, command).await?
        }
        CiphernodeCommands::Tickets {
            chain,
            operator,
            command,
        } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            tickets::execute(out, &ctx, operator, command).await?
        }
        CiphernodeCommands::Register { chain, operator } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            lifecycle::register(out, &ctx, operator).await?
        }
        CiphernodeCommands::Deregister { chain, operator } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            lifecycle::deregister(out, &ctx, operator).await?
        }
        CiphernodeCommands::Activate { chain, operator } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            lifecycle::activate(out, &ctx, operator).await?
        }
        CiphernodeCommands::Deactivate {
            chain,
            operator,
            ticket_amount,
            ciphernode_bond_amount,
        } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            lifecycle::deactivate(out, &ctx, operator, ticket_amount, ciphernode_bond_amount)
                .await?
        }
        CiphernodeCommands::Status { chain, operator } => {
            let ctx = ChainContext::new(config, chain.selection()).await?;
            let operator = ctx.resolve_operator(operator.as_deref())?;
            lifecycle::status(out, &ctx, operator).await?
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
