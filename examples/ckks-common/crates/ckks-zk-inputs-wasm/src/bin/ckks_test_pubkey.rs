// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generate a throwaway CKKS keypair for a Greco param set (test fixture
//! for the browser/node smoke test).
//!
//! Usage: `ckks_test_pubkey <param_set> <out_dir> [seed_u64]`
//! Writes `<out_dir>/pubkey_ps<set>.bin` and `<out_dir>/seckey_ps<set>.bin`.

use rand::SeedableRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let param_set: u8 = std::env::args()
        .nth(1)
        .ok_or("pass the on-chain ParamSet value")?
        .parse()?;
    let out_dir = std::env::args().nth(2).ok_or("pass the output dir")?;
    let seed: u64 = std::env::args()
        .nth(3)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(0);
    let mut rng = if seed == 0 {
        rand_chacha::ChaCha20Rng::from_rng(&mut rand::rng())
    } else {
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    };
    let (sk, pk) = ckks_zk_inputs_wasm::generate_keypair(param_set, &mut rng)?;
    std::fs::create_dir_all(&out_dir)?;
    let pk_path = format!("{out_dir}/pubkey_ps{param_set}.bin");
    let sk_path = format!("{out_dir}/seckey_ps{param_set}.bin");
    std::fs::write(&pk_path, pk)?;
    std::fs::write(&sk_path, sk)?;
    println!("written {pk_path} and {sk_path}");
    Ok(())
}
