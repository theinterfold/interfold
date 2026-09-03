// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The salary-survey E3 program: the PACKED statistics policy.
//!
//! Given verified salary ciphertexts (each a slot-replicated CKKS encryption
//! of `salary / cap`), the policy computes ONE output ciphertext holding
//!
//! * slot 0: `S * sum_i (salary_i / cap)`
//! * slot 1: `S * sum_i (salary_i / cap)^2` (relinearized ct×ct product with
//!   the committee's joint level-0 relin key)
//!
//! where `S` is a public output scale that keeps 6+ significant digits in
//! the canonical 2-decimal fixed-point on-chain plaintext. One threshold
//! opening reveals ONLY those two aggregates; the count `n` is public
//! (submissions are on-chain events), and mean / variance / stddev are
//! derived from `(n, sum, sumsq)` by anyone.
//!
//! This is plain Rust (no RISC Zero guest): the same code the ciphernodes'
//! `e3-trckks` crate ships, wrapped with the survey's fixed parameters. It
//! is shared by the server's evaluation job and the `ckks-salary-program`
//! CLI so both compute byte-identical outputs.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use e3_trckks::policy::statistics_packed_policy;
use e3_trckks::program::decode_fixed_point_output;
use e3_trckks::TrCkksConfig;
use e3_utils::ArcBytes;
use fhe::ckks::{CkksParameters, CkksRelinearizationKey};
use fhe_traits::Serialize as FheSerialize;

/// On-chain ParamSet the survey runs on: 3 × 36-bit transport-fit moduli,
/// Δ = 2^40, one genuine multiplication level.
pub const PARAM_SET: u8 = 3;
/// Output scale `S` (see module docs).
pub const OUTPUT_SCALE: f64 = 10_000.0;
/// Decimal places of the canonical on-chain fixed-point plaintext
/// (`e3_aggregator::plaintext_aggregation::ckks::CKKS_OUTPUT_DECIMALS`).
pub const OUTPUT_DECIMALS: u32 = 2;
/// File name of the level-0 joint relin key written by every ciphernode
/// after the relin ceremony.
pub const RLK_LEVEL_0_FILE: &str = "rlk_level_0.bin";

/// The CKKS parameters every party (nodes, client, server) derives for
/// [`PARAM_SET`] — byte-identical to the ciphernodes' runtime params.
pub fn params() -> Result<Arc<CkksParameters>> {
    e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(PARAM_SET)
}

/// Serialized [`params`] (the `--params` hex the CLIs take).
pub fn params_bytes() -> Result<Vec<u8>> {
    Ok(params()?.to_bytes())
}

/// Load the level-0 joint relin key from a ceremony directory
/// (`<dir>/rlk_level_0.bin`).
pub fn load_relin_key(rlk_dir: &Path) -> Result<CkksRelinearizationKey> {
    let path = rlk_dir.join(RLK_LEVEL_0_FILE);
    let bytes =
        std::fs::read(&path).with_context(|| format!("missing ceremony key {}", path.display()))?;
    let rlk = CkksRelinearizationKey::from_bytes(&bytes, &params()?)?;
    if rlk.level() != 0 {
        bail!(
            "{} holds a level-{} key, expected level 0",
            path.display(),
            rlk.level()
        );
    }
    Ok(rlk)
}

/// The evaluated output ciphertext plus its keccak commitment.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub ciphertext: Vec<u8>,
    pub commitment: [u8; 32],
}

/// Run the packed statistics policy over serialized salary ciphertexts.
pub fn evaluate(inputs: &[Vec<u8>], rlk: &CkksRelinearizationKey) -> Result<Evaluation> {
    if inputs.is_empty() {
        bail!("need at least one salary ciphertext");
    }
    let inputs: Vec<ArcBytes> = inputs.iter().map(|b| ArcBytes::from_bytes(b)).collect();
    // Committee shape is irrelevant to policy evaluation; params only.
    let config = TrCkksConfig::new(
        ArcBytes::from_bytes(&params_bytes()?),
        inputs.len() as u64,
        1,
    );
    let out = statistics_packed_policy(&config, &inputs, rlk, OUTPUT_SCALE)?;
    let ciphertext = out.extract_bytes();
    let commitment = alloy_primitives::keccak256(&ciphertext).0;
    Ok(Evaluation {
        ciphertext,
        commitment,
    })
}

/// Statistics derived from the opened aggregates.
#[derive(Debug, Clone, PartialEq)]
pub struct Statistics {
    pub count: u64,
    pub sum: f64,
    pub sum_of_squares: f64,
    pub mean: f64,
    pub variance: f64,
    pub stddev: f64,
}

/// Decode the canonical fixed-point plaintext into its raw opened slots.
pub fn decode_fixed_point(plaintext: &[u8]) -> Result<Vec<f64>> {
    decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)
}

/// Decode the canonical on-chain plaintext (`int128[]` at 2 decimals):
/// slot 0 = `S*sum/cap`, slot 1 = `S*sumsq/cap^2`.
pub fn decode_statistics(plaintext: &[u8], count: u64, cap: u64) -> Result<Statistics> {
    let values = decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)?;
    if values.len() < 2 {
        bail!("plaintext carries {} slots, expected >= 2", values.len());
    }
    if count == 0 {
        bail!("count must be nonzero");
    }
    let cap = cap as f64;
    let n = count as f64;
    let sum = values[0] / OUTPUT_SCALE * cap;
    let sum_of_squares = values[1] / OUTPUT_SCALE * cap * cap;
    let mean = sum / n;
    let variance = (sum_of_squares / n - mean * mean).max(0.0);
    Ok(Statistics {
        count,
        sum,
        sum_of_squares,
        mean,
        variance,
        stddev: variance.sqrt(),
    })
}

/// Population mean/variance of cleartext salaries — what the homomorphic
/// result must match (used by tests and the e2e harness).
pub fn expected_statistics(salaries: &[u64]) -> Statistics {
    let n = salaries.len() as f64;
    let sum: f64 = salaries.iter().map(|&s| s as f64).sum();
    let sum_of_squares: f64 = salaries.iter().map(|&s| (s as f64).powi(2)).sum();
    let mean = sum / n;
    let variance = (sum_of_squares / n - mean * mean).max(0.0);
    Statistics {
        count: salaries.len() as u64,
        sum,
        sum_of_squares,
        mean,
        variance,
        stddev: variance.sqrt(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decode_round_trips_the_packed_layout() {
        let salaries = [50_000u64, 60_000, 70_000];
        let cap = 500_000u64;
        let expected = expected_statistics(&salaries);
        let slot0 = OUTPUT_SCALE * expected.sum / cap as f64;
        let slot1 = OUTPUT_SCALE * expected.sum_of_squares / (cap as f64).powi(2);
        let bytes = encode_fixed_point_output(&[slot0, slot1], OUTPUT_DECIMALS).unwrap();
        let got = decode_statistics(&bytes, 3, cap).unwrap();
        assert!(
            (got.mean - expected.mean).abs() < 1.0,
            "{got:?} vs {expected:?}"
        );
        assert!(
            (got.variance - expected.variance).abs() / expected.variance < 0.01,
            "{got:?} vs {expected:?}"
        );
    }

    #[test]
    fn params_are_the_statistics_preset() {
        let p = params().unwrap();
        assert_eq!(p.degree(), 512);
        assert_eq!(p.moduli().len(), 3);
    }
}
