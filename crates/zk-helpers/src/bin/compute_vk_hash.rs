// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Combine any number of Barretenberg `vk_hash` blobs (32 bytes each, big-endian field) with the
//! same SAFE sponge as Noir `lib::math::commitments::compute_vk_hash` (`DS_VK_HASH`).
//!
//! Input order is preserved — e.g. CRISP fold uses:
//! `user_data_encryption`, `crisp`, `ct0`, `ct1`.

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use clap::Parser;
use e3_zk_helpers::compute_vk_hash;
use num_bigint::BigUint;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "compute-vk-hash")]
#[command(about = "Hash N vk_hash files with compute_vk_hash (SAFE / DS_VK_HASH), order preserved")]
struct Args {
    /// Paths to 32-byte `vk_hash` files from `bb write_vk ... -o <dir>` (use one dir per circuit).
    #[arg(required = true)]
    vk_hash_files: Vec<PathBuf>,
}

fn field_from_vk_hash_file(path: &std::path::Path) -> Result<Fr> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("{}: expected 32 bytes, got {}", path.display(), bytes.len());
    }
    let n = BigUint::from_bytes_be(&bytes);
    let mut limbs = n.to_u64_digits();
    limbs.resize(4, 0);
    let bigint = ark_ff::BigInt::new([limbs[0], limbs[1], limbs[2], limbs[3]]);
    Fr::from_bigint(bigint).ok_or_else(|| {
        anyhow::anyhow!(
            "{}: vk_hash is not in the canonical range [0, p)",
            path.display()
        )
    })
}

fn field_to_padded_be_hex(fr: Fr) -> String {
    let repr = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(repr.len());
    out[start..].copy_from_slice(&repr);
    format!("0x{}", hex::encode(out))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut fields = Vec::with_capacity(args.vk_hash_files.len());
    for path in &args.vk_hash_files {
        fields.push(field_from_vk_hash_file(path).with_context(|| path.display().to_string())?);
    }
    let combined = compute_vk_hash(fields);
    println!("{}", field_to_padded_be_hex(combined));
    Ok(())
}
