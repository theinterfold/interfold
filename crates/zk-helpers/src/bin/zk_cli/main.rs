// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit generation, verification-key hashing, and parity matrix generation.

mod generate;
mod parity_matrices;
mod vk_hash;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "zk-cli", about = "Generate ZK circuit artifacts.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List supported circuits and their parameter types.
    List,
    /// Sample circuit data and generate configs.nr, with optional Prover.toml.
    Generate(generate::Args),
    /// Combine canonical 32-byte VK hashes with SAFE, in input order.
    VkHash(vk_hash::Args),
    /// Generate both parity matrix files for a committee.
    ParityMatrices(parity_matrices::Args),
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::List => {
            generate::list();
            Ok(())
        }
        Command::Generate(args) => generate::run(args),
        Command::VkHash(args) => vk_hash::run(args),
        Command::ParityMatrices(args) => parity_matrices::run(args),
    }
}
