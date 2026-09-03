// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate one slot-batched auction round over REAL bid ciphertexts —
//! the E3 "program" role for the CKKS auction integration test. Takes the
//! bidders' ciphertexts (each a slot-replicated CKKS encryption of a bid
//! under the committee's aggregated pk) and writes the single evaluated
//! ciphertext the committee threshold-decrypts. Losing bids are NEVER
//! decrypted.
//!
//! Modes:
//! - `bracket` / `all-pairs`: masked pairwise differences
//!   (`auction_round_policy`) — sign reveals order, mask blinds magnitude,
//!   but the opened values still carry masked bid-difference magnitudes.
//! - `winner`: leak-free ITERATED SIGN EXTRACTION
//!   (`sign_extraction_policy`) — every i<j pair slot is driven to exactly
//!   ±1, so the opening reveals the comparison BITS and nothing else.
//!   Needs the joint relin-ceremony key(s) (`--rlk-dir`) produced by the
//!   ciphernodes — `rlk_hybrid.bin` (ONE hybrid key for every level; what
//!   ParamSet 2 runs) or `rlk_level_{L}.bin` per sign-map multiplication
//!   level for per-level parameters — and a `--bound`
//!   ≥ the maximum bid (pair differences are normalized by `1/bound`
//!   before the cubic sign map; gaps ≥ ~2% of the bound binarize with the
//!   default 12 iterations).
//!
//! Usage:
//!   ckks_auction_eval --params <hex> --bids b0.bin,b1.bin,b2.bin \
//!       --output round.bin --commitment-output c.bin \
//!       --mode winner --rlk-dir /tmp/ckks-relin-keys/<e3_id> --bound 1000

use clap::Parser;
use e3_trckks::policy::{sign_extraction_policy, RelinKeys};
use e3_trckks::program::{auction_round_policy, AuctionBracket, AuctionRound};
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

    /// Comma-separated bid ciphertext files, in bidder order.
    #[arg(long, value_delimiter = ',')]
    bids: Vec<String>,

    /// Output path for the evaluated round ciphertext.
    #[arg(long)]
    output: String,

    /// Optional output path for the keccak256 ciphertext commitment.
    #[arg(long)]
    commitment_output: Option<String>,

    /// Evaluation mode: "bracket" (first bracket round, pairwise),
    /// "all-pairs" (every i<j masked comparison in ONE ciphertext), or
    /// "winner" (leak-free all-pairs sign extraction; needs --rlk-dir).
    #[arg(long, default_value = "bracket")]
    mode: String,

    /// Directory holding the committee's joint relin-ceremony key(s)
    /// (`rlk_hybrid.bin`, or `rlk_level_{level}.bin` per level, as
    /// written by the ciphernodes under `<data_dir>/<node>/ckks/relin-keys/<e3_id>/`).
    /// Required for --mode winner.
    #[arg(long)]
    rlk_dir: Option<String>,

    /// Sign-map iterations (winner mode). 12 binarizes gaps down to ~2%
    /// of --bound.
    #[arg(long, default_value_t = 12)]
    iterations: usize,

    /// Bid bound B for winner mode: pair differences are normalized by
    /// 1/B, so B must be ≥ the maximum possible bid (the demo passes its
    /// bid cap).
    #[arg(long, default_value_t = 1000.0)]
    bound: f64,
}

/// The multiplication levels of `sign_extraction_policy`: iteration `i`
/// multiplies at levels `1+3i` (squaring) and `3+3i` (update).
fn winner_mult_levels(iterations: usize) -> Vec<usize> {
    let mut levels = Vec::with_capacity(2 * iterations);
    for i in 0..iterations {
        levels.push(1 + 3 * i);
        levels.push(3 + 3 * i);
    }
    levels
}

/// Load the ceremony key(s): the ONE hybrid key when the params carry
/// special primes, else one per sign-map multiplication level.
fn load_winner_rlks(
    dir: &Path,
    iterations: usize,
    params: &std::sync::Arc<fhe::ckks::CkksParameters>,
) -> Result<RelinKeys, Box<dyn std::error::Error>> {
    Ok(RelinKeys::load_from_dir(
        dir,
        params,
        &winner_mult_levels(iterations),
    )?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.bids.len() < 2 {
        return Err("need at least two bids".into());
    }

    let bids: Vec<ArcBytes> = args
        .bids
        .iter()
        .map(|p| Ok(ArcBytes::from_bytes(&fs::read(p)?)))
        .collect::<Result<_, std::io::Error>>()?;

    // Committee shape is irrelevant to policy evaluation; params only.
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&args.params.0), bids.len() as u64, 1);

    let out = match args.mode.as_str() {
        "winner" => {
            let rlk_dir = args
                .rlk_dir
                .as_deref()
                .ok_or("--mode winner requires --rlk-dir (the ceremony key directory)")?;
            let params = config.params()?;
            let rlks = load_winner_rlks(Path::new(rlk_dir), args.iterations, &params)?;
            let pairs = AuctionRound::all_pairs(bids.len()).pairs;
            println!(
                "Evaluating auction (winner): sign extraction over pairs {:?}, bound {}, {} iterations, {} relin key",
                pairs,
                args.bound,
                args.iterations,
                match &rlks {
                    RelinKeys::Hybrid(_) => "ONE hybrid",
                    RelinKeys::PerLevel(_) => "per-level",
                }
            );
            sign_extraction_policy(&config, &bids, &pairs, args.bound, args.iterations, &rlks)?
        }
        mode @ ("all-pairs" | "bracket") => {
            let round = match mode {
                "all-pairs" => AuctionRound::all_pairs(bids.len()),
                _ => AuctionBracket::new(bids.len())
                    .next_round()
                    .ok_or("auction with <2 bidders has no round")?,
            };
            println!("Evaluating auction round ({mode}): pairs {:?}", round.pairs);
            auction_round_policy(&config, &bids, &round, &mut rand::rng())?
        }
        other => {
            return Err(format!("unknown mode: {other} (bracket | all-pairs | winner)").into())
        }
    };

    fs::write(&args.output, &out[..])?;
    println!("Created {}", args.output);
    if let Some(commitment_output) = args.commitment_output {
        let commitment = alloy::primitives::keccak256(&out[..]);
        fs::write(&commitment_output, commitment.as_slice())?;
        println!("Created {}", commitment_output);
    }
    Ok(())
}
