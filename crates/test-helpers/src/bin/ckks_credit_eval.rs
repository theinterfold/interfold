// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate the credit-scoring v2 SIGMOID policy over REAL applicant
//! ciphertexts — the E3 "program" role for the CKKS private-credit-
//! scoring demo. Takes the applicants' `(ct_z, ct_m)` ciphertext PAIRS in
//! applicant order (applicant `i` holds slot `i`: `ct_z` its slot-encoded
//! logit under the round's public model, `ct_m` its output mask) plus the
//! committee's per-level relinearization keys (`rlk_level_1.bin`,
//! `rlk_level_2.bin` — the ParamSet-4 ceremony plan), and writes the ONE
//! evaluated ciphertext the committee threshold-decrypts: slot `i` =
//! `σ_cubic(z_i) + m_i`. The committee never sees a logit; each applicant
//! subtracts its own mask (`e3_trckks::policy::credit_v2_unmask`).
//!
//! Usage:
//!   ckks_credit_eval --params <hex> --inputs z0.bin,m0.bin,z1.bin,m1.bin,... \
//!       --rlk-dir <dir with rlk_level_1.bin + rlk_level_2.bin> \
//!       --output scores.bin [--commitment-output c.bin]

use clap::Parser;
use e3_fhe_params::ckks_presets::CREDIT_RELIN_LEVELS;
use e3_trckks::policy::{credit_sigmoid_policy, RelinKeys};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
struct HexBytes(pub Vec<u8>);

fn parse_hex(s: &str) -> Result<HexBytes, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s)
        .map(HexBytes)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Serialized CKKS parameters (hex; protobuf encoding).
    #[arg(long, value_parser = parse_hex)]
    params: HexBytes,

    /// Comma-separated applicant ciphertext files as `(z, m)` PAIRS in
    /// applicant order: `z0,m0,z1,m1,...` (applicant `i` holds slot `i`).
    #[arg(long, value_delimiter = ',')]
    inputs: Vec<String>,

    /// The ceremony key directory holding `rlk_level_1.bin` and
    /// `rlk_level_2.bin` (the levels `credit_sigmoid_policy` multiplies at).
    #[arg(long)]
    rlk_dir: String,

    /// Output path for the evaluated scores ciphertext.
    #[arg(long)]
    output: String,

    /// Optional output path for the keccak256 ciphertext commitment.
    #[arg(long)]
    commitment_output: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.inputs.is_empty() || args.inputs.len() % 2 != 0 {
        return Err(format!(
            "--inputs must hold (z, m) pairs, got {} files",
            args.inputs.len()
        )
        .into());
    }

    let inputs: Vec<ArcBytes> = args
        .inputs
        .iter()
        .map(|p| Ok(ArcBytes::from_bytes(&fs::read(p)?)))
        .collect::<Result<_, std::io::Error>>()?;
    let applicants = inputs.len() / 2;

    // Committee shape is irrelevant to policy evaluation; params only.
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&args.params.0), applicants as u64, 1);
    let params = config.params()?;
    let rlks = RelinKeys::load_from_dir(Path::new(&args.rlk_dir), &params, &CREDIT_RELIN_LEVELS)?;

    println!(
        "Evaluating credit v2 (σ_cubic on the encrypted logit, output mask) over {applicants} \
         applicants with per-level relin keys at {CREDIT_RELIN_LEVELS:?}"
    );
    let out = credit_sigmoid_policy(&config, &inputs, &rlks)?;

    fs::write(&args.output, &out[..])?;
    println!("Created {}", args.output);
    if let Some(commitment_output) = args.commitment_output {
        let commitment = alloy::primitives::keccak256(&out[..]);
        fs::write(&commitment_output, commitment.as_slice())?;
        println!("Created {}", commitment_output);
    }
    Ok(())
}
