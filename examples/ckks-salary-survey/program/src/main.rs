// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `ckks-salary-program` CLI: the survey policy as a standalone binary
//! (the server's evaluator calls the same library).
//!
//! ```text
//! ckks-salary-program evaluate --inputs a.bin,b.bin --rlk-dir <dir> \
//!     --output stats.bin --commitment-output c.bin
//! ckks-salary-program decode --plaintext-hex 0x... --count 3 --cap 500000
//! ckks-salary-program params
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "CKKS salary-survey E3 program (packed statistics policy)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the serialized ParamSet-3 CKKS parameters as hex.
    Params,
    /// Evaluate the packed statistics over salary ciphertexts.
    Evaluate {
        /// Comma-separated ciphertext files (each a verified submission).
        #[arg(long, value_delimiter = ',')]
        inputs: Vec<PathBuf>,
        /// Directory holding the ceremony's `rlk_level_0.bin`.
        #[arg(long)]
        rlk_dir: PathBuf,
        /// Output ciphertext file.
        #[arg(long)]
        output: PathBuf,
        /// Optional keccak commitment output file.
        #[arg(long)]
        commitment_output: Option<PathBuf>,
    },
    /// Decode a published fixed-point plaintext into statistics.
    Decode {
        #[arg(long)]
        plaintext_hex: String,
        #[arg(long)]
        count: u64,
        #[arg(long)]
        cap: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Params => {
            println!("{}", hex::encode(ckks_salary_program::params_bytes()?));
        }
        Command::Evaluate {
            inputs,
            rlk_dir,
            output,
            commitment_output,
        } => {
            let cts = inputs
                .iter()
                .map(std::fs::read)
                .collect::<std::io::Result<Vec<_>>>()?;
            let rlk = ckks_salary_program::load_relin_key(&rlk_dir)?;
            let eval = ckks_salary_program::evaluate(&cts, &rlk)?;
            std::fs::write(&output, &eval.ciphertext)?;
            println!("Created {}", output.display());
            if let Some(c) = commitment_output {
                std::fs::write(&c, eval.commitment)?;
                println!("Created {}", c.display());
            }
            println!("commitment 0x{}", hex::encode(eval.commitment));
        }
        Command::Decode {
            plaintext_hex,
            count,
            cap,
        } => {
            let bytes = hex::decode(plaintext_hex.trim_start_matches("0x"))?;
            let stats = ckks_salary_program::decode_statistics(&bytes, count, cap)?;
            println!("{stats:#?}");
        }
    }
    Ok(())
}
