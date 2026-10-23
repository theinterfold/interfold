// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Hashes verification-key hashes in order, as the Noir `compute_vk_hash` does.
//!
//! `scripts/compile_circuits.sh` uses it to compute the VK anchor of the auction. Each argument
//! is a file with one field element as 32 big-endian bytes (the `vk_hash` file that `bb write_vk`
//! writes). The output is the 0x-prefixed hash.
//!
//! ```text
//! cargo run --release -p e3-user-program --example vk_hash -- <file>...
//! ```

use anyhow::{Context, Result, bail, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use e3_zk_witness::compute_vk_hash;

fn main() -> Result<()> {
    let files: Vec<String> = std::env::args().skip(1).collect();
    ensure!(!files.is_empty(), "usage: vk_hash <file>...");
    let hashes = files
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
            if bytes.len() != 32 {
                bail!("{path}: expected 32 bytes, got {}", bytes.len());
            }
            Ok(Fr::from_be_bytes_mod_order(&bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    let hash = compute_vk_hash(hashes);
    println!("0x{}", hex::encode(hash.into_bigint().to_bytes_be()));
    Ok(())
}
