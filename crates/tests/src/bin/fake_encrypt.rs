// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// This is a test script designed to encrypt some fixed data to a fhe public key
use clap::Parser;
use e3_bfv_client::compute_ct_commitment;
use e3_fhe_params::DEFAULT_BFV_PRESET;
use e3_fhe_params::{build_bfv_params_from_set_arc, decode_bfv_params_arc};
use fhe::bfv::{Encoding, Plaintext, PublicKey};
use fhe_traits::{DeserializeParametrized, FheEncoder, FheEncrypter, Serialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs;

#[derive(Debug, Clone)]
struct HexBytes(pub Vec<u8>);

fn parse_hex(s: &str) -> Result<HexBytes, String> {
    // Remove "0x" or "0X" prefix if present
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    // Decode hex string to bytes
    hex::decode(s)
        .map(HexBytes)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    output: String,

    #[arg(long)]
    commitment_output: Option<String>,

    #[arg(short, long, value_delimiter = ',')]
    plaintext: Vec<u64>,

    #[arg(long, value_parser = parse_hex)]
    params: Option<HexBytes>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Read the base64 encoded string from the input file
    println!("Loading public key from {}", args.input);
    let bytes = fs::read(&args.input)?;
    let params = if let Some(params_bytes) = args.params {
        decode_bfv_params_arc(&params_bytes.0).expect("Failed to decode BFV params")
    } else {
        build_bfv_params_from_set_arc(DEFAULT_BFV_PRESET.into())
    };
    let pubkey = PublicKey::from_bytes(&bytes, &params)?;
    let raw_plaintext = args.plaintext;

    println!("Encrypting plaintext: {:?}", raw_plaintext);

    let pt = Plaintext::try_encode(&raw_plaintext, Encoding::poly(), &params)?;
    let ciphertext = pubkey.try_encrypt(&pt, &mut ChaCha20Rng::seed_from_u64(42))?;
    let ciphertext_bytes = ciphertext.clone().to_bytes();

    fs::write(&args.output, &ciphertext_bytes)?;
    if let Some(commitment_output) = args.commitment_output {
        let commitment = compute_ct_commitment(
            ciphertext_bytes.clone(),
            params.degree(),
            params.plaintext(),
            params.moduli().to_vec(),
        )?;
        fs::write(&commitment_output, commitment)?;
        println!("Created {}", commitment_output);
    }
    println!("Created {}", args.output);

    Ok(())
}
