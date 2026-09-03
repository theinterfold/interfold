// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Encrypt real values under a committee's aggregated CKKS public key —
//! the integration-test bidder. Unlike `fake_encrypt` (BFV, fixed test
//! data), this is a REAL client encryption: the value is slot-replicated
//! (the auction bracket's requirement — one-hot masks pick a slot, so
//! every slot must carry the bid) and encrypted with fresh randomness.
//!
//! Usage:
//!   ckks_encrypt --pubkey pubkey.bin --params <hex> --value 42.5 \
//!       --output bid.bin [--commitment-output c.bin] \
//!       [--circuit-inputs inputs.json]
//!
//! With `--circuit-inputs`, encryption runs through the Greco-style
//! verifiable path: the encryption randomness is witnessed and the
//! written JSON carries the private inputs for BOTH proof legs
//! (`user_data_encryption_ckks_ct0` / `..._ct1`), bound by the shared
//! `u` commitment. The ciphertext written to `--output` is the one the
//! witnesses attest to.

use clap::Parser;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParameters, CkksPublicKey};
use fhe_traits::{
    Deserialize as FheDeserialize, DeserializeParametrized, Serialize as FheSerialize,
};
use std::fs;
use std::sync::Arc;

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
    /// Path to the committee's aggregated CKKS public key.
    #[arg(long)]
    pubkey: String,

    /// Serialized CKKS parameters (hex; protobuf encoding).
    #[arg(long, value_parser = parse_hex)]
    params: HexBytes,

    /// The real value to encrypt (e.g. an auction bid).
    #[arg(long)]
    value: f64,

    /// Output path for the ciphertext.
    #[arg(long)]
    output: String,

    /// Optional output path for the keccak256 ciphertext commitment.
    #[arg(long)]
    commitment_output: Option<String>,

    /// Optional output path for Greco-style circuit inputs (JSON). When
    /// set, encryption runs through the verifiable path and the witnessed
    /// ciphertext is written to `--output`.
    #[arg(long)]
    circuit_inputs: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let params = Arc::new(CkksParameters::try_deserialize(&args.params.0)?);
    let pk_bytes = fs::read(&args.pubkey)?;
    let pk = CkksPublicKey::from_bytes(&pk_bytes, &params)?;

    // Slot-replicate: the slot-batched auction bracket extracts pair
    // results with one-hot masks, so the bid must live in EVERY slot.
    let slots = params.degree() / 2;
    let values = vec![args.value; slots];

    let ct_bytes = if let Some(circuit_inputs_path) = &args.circuit_inputs {
        // Verifiable path: witness the encryption randomness and emit
        // Greco-style circuit inputs alongside the ciphertext.
        let result = e3_bfv_client::ckks_verifiable_encrypt(
            values,
            pk_bytes.clone(),
            params.degree(),
            params.moduli().to_vec(),
        )?;
        fs::write(circuit_inputs_path, &result.circuit_inputs)?;
        println!("Created {circuit_inputs_path}");
        result.encrypted_data
    } else {
        let encoder = CkksEncoder::new(&params);
        let pt = encoder.encode(&values, 0)?;
        let ct: CkksCiphertext = pk.try_encrypt(&pt, &mut rand::rng())?;
        ct.to_bytes()
    };

    fs::write(&args.output, &ct_bytes)?;
    println!("Encrypted {} into {}", args.value, args.output);

    if let Some(commitment_output) = args.commitment_output {
        let commitment = alloy::primitives::keccak256(&ct_bytes);
        fs::write(&commitment_output, commitment.as_slice())?;
        println!("Created {}", commitment_output);
    }

    Ok(())
}
