// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS treasury-risk program (the E3 "policy").
//!
//! The computation the committee's ciphertext output carries is
//! [`e3_trckks::policy::treasury_risk_policy`]: DAO `i` submits THREE
//! COEFFICIENT-encoded ciphertexts — `forward(x_i)` (its private exposure
//! vector over [`ASSETS`] public assets, cap-normalised to `[0, 1]`),
//! `reversed(w ∘ x_i)` (the same vector weighted by the round's PUBLIC
//! risk weights `w`, proven by the `ckks_treasury_validity_ps5` leg) and a
//! cross-term `mask(m_i)` — and the network sums `F = Σ f_i`, `R = Σ r_i`,
//! `M = Σ m_i`, does ONE ciphertext × ciphertext product `F · R`
//! relinearised under the committee's level-0 key (`rlk_level_0.bin`, the
//! ParamSet-5 ceremony plan `PerLevel([0])`), rescales once and adds `M`.
//! Coefficient 0 of the opened output is `−Σ_a w_a (Σ_i x_{i,a})²` — the
//! weighted concentration risk of the COMBINED book. Coefficients `1..`
//! are cross terms hidden by the masks. No DAO's book, and not even the
//! aggregate book, is ever opened: only the one scalar.
//!
//! The committee runs NO app logic: this crate is the plain-Rust wrapper
//! the coordination server calls (CRISP's `program/` is a RISC Zero
//! guest; the CKKS demos run the policy natively — the ciphertext output
//! is published with a mock proof, see the Readme's honest-scope section).

use anyhow::{bail, Context, Result};
use e3_fhe_params::ckks_presets::{
    ckks_opening_level_for_param_set, ckks_params_for_on_chain_param_set,
    relin_ceremony_plan_for_param_set, RelinCeremonyPlan,
};
use e3_trckks::policy::{
    treasury_risk_policy, RelinKeys, COEFFICIENT_MASK_BOUND, COEFFICIENT_MASK_WIDTH,
};
use e3_trckks::program::{
    decode_fixed_point_output, COEFFICIENT_OUTPUT_COUNT, COEFFICIENT_OUTPUT_DECIMALS,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksParameters, CkksRelinearizationKey};
use fhe_traits::Serialize as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// On-chain ParamSet of the coefficient-encoded preset (N=512, 3 limbs, Δ=2^40).
pub const PARAM_SET: u8 = 5;
/// Number of public assets per exposure vector.
pub const ASSETS: usize = 4;
/// Cross-term mask: `MASK_WIDTH` integers uniform in `[0, MASK_BOUND)`.
pub const MASK_WIDTH: usize = COEFFICIENT_MASK_WIDTH;
pub const MASK_BOUND: f64 = COEFFICIENT_MASK_BOUND;
/// Fixed-point bits of exposures and weights the circuit takes (`×2^16`).
pub const FRAC_BITS: u32 = 16;
/// `|w_a| ≤ WEIGHT_BOUND`, `0 ≤ x_a ≤ EXPOSURE_BOUND`.
pub const WEIGHT_BOUND: f64 = 1.0;
pub const EXPOSURE_BOUND: f64 = 1.0;
/// The published output: the first 64 coefficients at 4 decimals.
pub const OUTPUT_COUNT: usize = COEFFICIENT_OUTPUT_COUNT;
pub const OUTPUT_DECIMALS: u32 = COEFFICIENT_OUTPUT_DECIMALS;
/// The level the policy relinearises at (the ceremony's key file).
pub const RELIN_LEVELS: [usize; 1] = [0];
/// Minimum number of DAOs before a round may be evaluated: with one DAO
/// the "aggregate" risk is that DAO's own risk.
pub const MIN_DAOS: usize = 2;

/// The round's public risk weights (real values; the fixed point the
/// circuit and the contract take is [`Weights::fixed_point`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct Weights(pub [f64; ASSETS]);

/// The weights in the circuit's fixed point (`×2^16`, rounded), the shape
/// registered on-chain (negatives are emitted as `p − |w|` words there).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct FixedPointWeights(pub [i32; ASSETS]);

impl Weights {
    pub fn validate(&self) -> Result<()> {
        for (a, w) in self.0.iter().enumerate() {
            if !w.is_finite() || w.abs() > WEIGHT_BOUND {
                bail!("weight {a} = {w} outside [-{WEIGHT_BOUND}, {WEIGHT_BOUND}]");
            }
        }
        Ok(())
    }

    pub fn fixed_point(&self) -> FixedPointWeights {
        let scale = (1u64 << FRAC_BITS) as f64;
        FixedPointWeights(std::array::from_fn(|a| (self.0[a] * scale).round() as i32))
    }
}

impl FixedPointWeights {
    pub fn to_f64(&self) -> Weights {
        let scale = (1u64 << FRAC_BITS) as f64;
        Weights(std::array::from_fn(|a| self.0[a] as f64 / scale))
    }
}

/// Canonical serialized ParamSet-5 parameters (byte-identical to every node's).
pub fn params() -> Result<Arc<CkksParameters>> {
    ckks_params_for_on_chain_param_set(PARAM_SET).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn params_bytes() -> Result<Vec<u8>> {
    Ok(params()?.to_bytes())
}

/// Level the output is opened at (1: one rescale).
pub fn opening_level() -> usize {
    ckks_opening_level_for_param_set(PARAM_SET).unwrap_or(0)
}

/// Ceremony keys a complete DKG writes for this set: ONE (`rlk_level_0.bin`).
pub fn expected_ceremony_keys() -> usize {
    relin_ceremony_plan_for_param_set(PARAM_SET)
        .map(|p| p.key_count())
        .unwrap_or(0)
}

/// The ceremony's key file names the evaluator waits for.
pub fn ceremony_key_files() -> Vec<String> {
    match relin_ceremony_plan_for_param_set(PARAM_SET) {
        Ok(RelinCeremonyPlan::PerLevel(levels)) => levels
            .iter()
            .map(|l| RelinKeys::level_key_file(*l))
            .collect(),
        Ok(RelinCeremonyPlan::Hybrid) => vec![RelinKeys::HYBRID_KEY_FILE.to_string()],
        _ => vec![],
    }
}

/// Loads the joint level-0 key from a ceremony key directory
/// (`<node data dir>/<node>/ckks/relin-keys/<chain>:<e3_id>/`).
pub fn load_ceremony_keys(dir: &Path, params: &Arc<CkksParameters>) -> Result<RelinKeys> {
    RelinKeys::load_from_dir(dir, params, &RELIN_LEVELS)
        .with_context(|| format!("loading ceremony keys from {}", dir.display()))
}

/// The level-0 relinearization key the policy multiplies under
/// (`treasury_risk_policy` takes the ONE per-level key, not the bundle).
pub fn level_0_key(keys: &RelinKeys) -> Result<&CkksRelinearizationKey> {
    match keys {
        RelinKeys::PerLevel(levels) => levels
            .iter()
            .find(|k| k.level() == 0)
            .context("ceremony bundle has no level-0 relin key (rlk_level_0.bin)"),
        RelinKeys::Hybrid(_) => bail!(
            "ParamSet {PARAM_SET} uses the PerLevel([0]) ceremony plan; got a hybrid key bundle"
        ),
    }
}

/// One DAO's three accepted ciphertexts: `(forward, reversed, mask)`.
pub type DaoInputs = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Evaluate the round: returns the ciphertext output bytes to publish
/// on-chain. `inputs` are the accepted `(forward, reversed, mask)` triples
/// (order does not matter — the policy sums before it multiplies).
/// Refuses fewer than [`MIN_DAOS`] submissions.
pub fn evaluate(inputs: &[DaoInputs], rlk_dir: &Path) -> Result<Vec<u8>> {
    if inputs.len() < MIN_DAOS {
        bail!(
            "treasury risk needs at least {MIN_DAOS} DAOs (one DAO's aggregate is its own book); got {}",
            inputs.len()
        );
    }
    let params = params()?;
    let rlk = load_ceremony_keys(rlk_dir, &params)?;
    let mut flat: Vec<ArcBytes> = Vec::with_capacity(3 * inputs.len());
    for (f, r, m) in inputs {
        flat.push(ArcBytes::from_bytes(f));
        flat.push(ArcBytes::from_bytes(r));
        flat.push(ArcBytes::from_bytes(m));
    }
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 1, 1);
    let out =
        treasury_risk_policy(&config, &flat, level_0_key(&rlk)?).context("treasury risk policy")?;
    Ok(out.to_vec())
}

/// The opened coefficients of an on-chain plaintext (64 values at 4 decimals).
pub fn decode_opened(plaintext: &[u8]) -> Result<Vec<f64>> {
    let values = decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)?;
    if values.len() != OUTPUT_COUNT {
        bail!(
            "plaintext has {} coefficients, expected {OUTPUT_COUNT}",
            values.len()
        );
    }
    Ok(values)
}

/// The weighted concentration risk of the combined book: `−opened[0]`
/// (the `t^N ≡ −1` wrap of `forward · reversed`).
pub fn risk_from_opened(opened: &[f64]) -> Result<f64> {
    opened
        .first()
        .map(|c0| -c0)
        .context("opened output has no coefficient 0")
}

/// The value the network computes for the given books (oracle; test/e2e
/// use — needs the plaintext books).
pub fn expected_risk(books: &[[f64; ASSETS]], weights: &Weights) -> f64 {
    let w = weights.fixed_point().to_f64();
    let mut agg = [0.0f64; ASSETS];
    for x in books {
        for a in 0..ASSETS {
            agg[a] += x[a];
        }
    }
    (0..ASSETS).map(|a| w.0[a] * agg[a] * agg[a]).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decodes_opened_coefficients_and_negates_the_risk() {
        let mut values = vec![0.0f64; OUTPUT_COUNT];
        values[0] = -0.2478;
        values[1] = 517.75;
        let bytes = encode_fixed_point_output(&values, OUTPUT_DECIMALS).unwrap();
        let opened = decode_opened(&bytes).unwrap();
        assert_eq!(opened.len(), OUTPUT_COUNT);
        assert!((opened[0] + 0.2478).abs() < 1e-9);
        assert!((risk_from_opened(&opened).unwrap() - 0.2478).abs() < 1e-9);
        let short = encode_fixed_point_output(&[1.0, 2.0], OUTPUT_DECIMALS).unwrap();
        assert!(decode_opened(&short).is_err());
    }

    #[test]
    fn weights_bounds_fixed_point_and_ceremony_shape() {
        let w = Weights([0.5, -0.25, 1.0, 0.125]);
        w.validate().unwrap();
        assert_eq!(
            w.fixed_point(),
            FixedPointWeights([32768, -16384, 65536, 8192])
        );
        assert_eq!(w.fixed_point().to_f64(), w);
        assert!(Weights([1.5, 0.0, 0.0, 0.0]).validate().is_err());
        assert!(Weights([f64::NAN, 0.0, 0.0, 0.0]).validate().is_err());
        assert_eq!(expected_ceremony_keys(), 1);
        assert_eq!(ceremony_key_files(), vec!["rlk_level_0.bin".to_string()]);
        assert_eq!(opening_level(), 1);
        assert_eq!(params().unwrap().degree(), 512);
        assert_eq!(params().unwrap().moduli().len(), 3);
    }

    #[test]
    fn expected_risk_squares_the_aggregate() {
        let w = Weights([0.30, 0.10, 0.45, 0.15]);
        let books = [[0.1, 0.2, 0.3, 0.4], [0.2, 0.1, 0.0, 0.1]];
        let agg = [0.3, 0.3, 0.3, 0.5];
        let want: f64 = (0..4)
            .map(|a| w.fixed_point().to_f64().0[a] * agg[a] * agg[a])
            .sum();
        assert!((expected_risk(&books, &w) - want).abs() < 1e-12);
    }

    #[test]
    fn refuses_fewer_than_two_daos() {
        let dir = std::env::temp_dir();
        let one = vec![(vec![0u8], vec![0u8], vec![0u8])];
        let err = evaluate(&one, &dir).unwrap_err();
        assert!(err.to_string().contains("at least 2 DAOs"), "{err}");
        assert!(evaluate(&[], &dir).is_err());
    }
}
