// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use clap::{command, Parser};
use e3_fhe_params::{build_bfv_params_arc, encode_bfv_params};
use std::{error::Error, num::ParseIntError, process};

fn parse_hex(arg: &str) -> Result<u64, ParseIntError> {
    let without_prefix = arg.trim_start_matches("0x");
    u64::from_str_radix(without_prefix, 16)
}

#[derive(Parser, Debug)]
#[command(author, version, about="Encodes BFV parameters whilst generating a random CRP", long_about = None)]
struct Args {
    #[arg(short, long, required = true, value_parser = parse_hex,value_delimiter = ',')]
    moduli: Vec<u64>,

    #[arg(short, long)]
    degree: u64,

    #[arg(short, long = "plaintext-modulus")]
    plaintext_modulus: u64,

    #[arg(short, long = "error1-variance")]
    error1_variance: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let params: std::sync::Arc<fhe::bfv::BfvParameters>;

    if args.moduli.is_empty() {
        println!("Parameter `--moduli` must include at least one value");
        process::exit(1);
    }

    if let Some(error1_variance) = args.error1_variance {
        params = build_bfv_params_arc(
            args.degree as usize,
            args.plaintext_modulus,
            &args.moduli,
            Some(&error1_variance),
        );
    } else {
        params = build_bfv_params_arc(
            args.degree as usize,
            args.plaintext_modulus,
            &args.moduli,
            None,
        );
    }

    let encoded = encode_bfv_params(&params);

    for byte in encoded {
        print!("{:02x}", byte);
    }

    Ok(())
}
