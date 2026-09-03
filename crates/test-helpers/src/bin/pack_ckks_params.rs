// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Encode CKKS parameters for an on-chain E3 request (protobuf bytes,
//! hex-printed). The CKKS analogue of `pack_e3_params`.
//!
//! Two ways to select parameters:
//! - `--param-set <u8>`: the canonical on-chain preset
//!   (`ckks_params_for_on_chain_param_set`) — byte-identical to what every
//!   ciphernode derives for that ParamSet (0 = insecure-512, 2 =
//!   sign-extraction ladder).
//! - explicit `--moduli/--degree/--scale-bits` (legacy/manual).
//!
//! DKG transport constraint: every modulus must be ≤ the DKG transport
//! preset's plaintext modulus (see `threshold_keyshare_ckks::encrypted_dkg`).

use clap::{command, Parser};
use fhe::ckks::CkksParametersBuilder;
use fhe_traits::Serialize as FheSerialize;
use std::{error::Error, num::ParseIntError, process};

fn parse_hex(arg: &str) -> Result<u64, ParseIntError> {
    let without_prefix = arg.trim_start_matches("0x");
    u64::from_str_radix(without_prefix, 16)
}

#[derive(Parser, Debug)]
#[command(author, version, about="Encodes CKKS parameters for a CKKS E3 request", long_about = None)]
struct Args {
    /// Canonical on-chain ParamSet value (0 = insecure-512, 2 =
    /// sign-extraction ladder). Overrides the manual options.
    #[arg(long = "param-set")]
    param_set: Option<u8>,

    #[arg(short, long, value_parser = parse_hex, value_delimiter = ',')]
    moduli: Vec<u64>,

    #[arg(short, long, default_value_t = 512)]
    degree: u64,

    /// log2 of the encoding scale (e.g. 26 for scale 2^26).
    #[arg(short, long = "scale-bits", default_value_t = 26)]
    scale_bits: i32,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let params = if let Some(param_set) = args.param_set {
        e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(param_set)?
    } else {
        if args.moduli.is_empty() {
            println!("Provide `--param-set` or `--moduli` with at least one value");
            process::exit(1);
        }
        CkksParametersBuilder::new()
            .set_degree(args.degree as usize)
            .set_moduli(&args.moduli)
            .set_scale(2f64.powi(args.scale_bits))
            .build_arc()?
    };

    for byte in params.to_bytes() {
        print!("{:02x}", byte);
    }

    Ok(())
}
