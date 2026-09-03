// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate the PACKED statistics policy over REAL salary ciphertexts —
//! the E3 "program" role for the CKKS salary-survey demo. Takes the
//! participants' ciphertexts (each a slot-replicated CKKS encryption of
//! `salary / cap` under the committee's aggregated pk) and writes the ONE
//! evaluated ciphertext the committee threshold-decrypts: `sum/cap` in
//! slot 0 and `sum_of_squares/cap^2` in slot 1 (genuine relinearized
//! ct×ct multiplication). Individual salaries are NEVER decrypted.
//!
//! Needs the committee's joint level-0 relin-ceremony key
//! (`rlk_level_0.bin`, written by the ciphernodes under
//! `$CKKS_RELIN_KEY_DIR/<chain>:<e3_id>/`).
//!
//! Usage:
//!   ckks_stats_eval --params <hex> --inputs s0.bin,s1.bin,... \
//!       --rlk-dir /tmp/ckks-relin-keys/<chain:e3_id> \
//!       --output stats.bin --commitment-output c.bin

use clap::Parser;
use e3_trckks::policy::statistics_packed_policy;
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksRelinearizationKey;
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

    /// Comma-separated salary ciphertext files, in participant order.
    #[arg(long, value_delimiter = ',')]
    inputs: Vec<String>,

    /// Directory holding the committee's joint relin-ceremony key
    /// (`rlk_level_0.bin`, as written by the ciphernodes under
    /// `$CKKS_RELIN_KEY_DIR/<chain>:<e3_id>/`).
    #[arg(long)]
    rlk_dir: String,

    /// Output path for the evaluated statistics ciphertext.
    #[arg(long)]
    output: String,

    /// Optional output path for the keccak256 ciphertext commitment.
    #[arg(long)]
    commitment_output: Option<String>,

    /// Public output scale S: opened slots carry `S*sum/cap` and
    /// `S*sumsq/cap^2`, so the canonical 2-decimal on-chain fixed-point
    /// encoding retains 6+ significant digits. Must match the demo
    /// server's decode step.
    #[arg(long, default_value_t = 10_000.0)]
    output_scale: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.inputs.is_empty() {
        return Err("need at least one salary ciphertext".into());
    }

    let inputs: Vec<ArcBytes> = args
        .inputs
        .iter()
        .map(|p| Ok(ArcBytes::from_bytes(&fs::read(p)?)))
        .collect::<Result<_, std::io::Error>>()?;

    // Committee shape is irrelevant to policy evaluation; params only.
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&args.params.0), inputs.len() as u64, 1);
    let params = config.params()?;

    // The packed statistics policy squares (and relinearizes) at level 0.
    let rlk_path = Path::new(&args.rlk_dir).join("rlk_level_0.bin");
    let rlk_bytes = fs::read(&rlk_path)
        .map_err(|e| format!("missing ceremony key {}: {e}", rlk_path.display()))?;
    let rlk = CkksRelinearizationKey::from_bytes(&rlk_bytes, &params)?;
    if rlk.level() != 0 {
        return Err(format!(
            "{} holds a level-{} key, expected level 0",
            rlk_path.display(),
            rlk.level()
        )
        .into());
    }

    println!(
        "Evaluating statistics over {} inputs: sum (slot 0) + relinearized sum-of-squares (slot 1)",
        inputs.len()
    );
    let out = statistics_packed_policy(&config, &inputs, &rlk, args.output_scale)?;

    fs::write(&args.output, &out[..])?;
    println!("Created {}", args.output);
    if let Some(commitment_output) = args.commitment_output {
        let commitment = alloy::primitives::keccak256(&out[..]);
        fs::write(&commitment_output, commitment.as_slice())?;
        println!("Created {}", commitment_output);
    }
    Ok(())
}
