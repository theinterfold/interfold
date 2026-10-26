// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Writes a local l-BFV committee key for the insecure SIMD preset, as the version-3 key envelope
//! the SDK takes as `committeeKey`. Two parties contribute, as in the unit tests of
//! `e3-bfv-client`. The proof benchmark and the SDK tests use it, so they need no key generation.
//!
//! ```text
//! cargo run --release --manifest-path circuits/tools/Cargo.toml --bin lbfv_key -- <output file>
//! ```

use anyhow::{Context, Result, ensure};
use e3_bfv_client::encode_lbfv_key_envelope;
use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{LBFVPublicKey, PublicKeyShare, RelinKeyShare, aggregate_relinearization_key};
use fhe_traits::Serialize;

const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

fn main() -> Result<()> {
    let output = std::env::args()
        .nth(1)
        .context("usage: lbfv_key <output file>")?;
    let (params, _) = build_pair_for_preset(PRESET)?;
    let crs =
        CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).context("no CRS seed")?)?;
    let urs =
        CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).context("no URS seed")?)?;
    let mut rng = rand::rng();
    let secret_keys = (0..2)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect::<Vec<_>>();
    let public_key_shares = secret_keys
        .iter()
        .map(|secret_key| PublicKeyShare::contribute_with_crp(secret_key, &crs, &mut rng))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let rlk_shares = secret_keys
        .iter()
        .map(|secret_key| {
            RelinKeyShare::contribution_with_crp(secret_key, &urs, &crs, 0, 0, &mut rng)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let public_key: LBFVPublicKey = public_key_shares.iter().cloned().aggregate()?;
    let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
    let envelope = encode_lbfv_key_envelope(&public_key.to_bytes(), &rlk.to_bytes(), PRESET)?;
    ensure!(!envelope.is_empty(), "empty envelope");
    std::fs::write(&output, &envelope).with_context(|| format!("write {output}"))?;
    println!("wrote {} bytes to {output}", envelope.len());
    Ok(())
}
