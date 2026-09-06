// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private federated-averaging program (the E3 "policy").
//!
//! The computation the committee's ciphertext output carries is
//! [`e3_trckks::policy::federated_average_policy`]: client `i` submits TWO
//! coefficient-encoded ciphertexts — its model update `g_i` as
//! `gradient_block(g_i)` (`g_{i,j}` on coefficient `j + 1`, the constant
//! `1.0` on coefficient `d + 1`) and its PRIVATE sample count `n_i` as
//! `constant(n_i)` (coefficient 0) — proven by the
//! `ckks_fedavg_validity_ps5` leg. The network multiplies each pair
//! (ONE ciphertext × ciphertext product per client under the committee's
//! level-0 relin key: scalar × vector, so no cross terms and no masks),
//! sums, rescales once and opens ONE ciphertext at level 1:
//!
//! ```text
//! opened[j + 1] = Σ_i n_i · g_{i,j}   (j < d)
//! opened[d + 1] = Σ_i n_i
//! ```
//!
//! The sample-weighted mean update is `opened[j + 1] / opened[d + 1]`.
//! Neither any client's update nor its sample size is revealed — the
//! network weights by the private counts homomorphically. The aggregate
//! itself IS public (the usual FedAvg leakage), which is why a round
//! carries a public minimum client count the server enforces before it
//! evaluates.
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
use e3_trckks::policy::{federated_average_policy, RelinKeys};
use e3_trckks::program::{
    decode_fixed_point_output, COEFFICIENT_OUTPUT_COUNT, COEFFICIENT_OUTPUT_DECIMALS,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksParameters;
use fhe_traits::Serialize as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// On-chain ParamSet of the coefficient-transport preset (N=512, 3 limbs, Δ=2^40).
pub const PARAM_SET: u8 = 5;
/// Model-update dimension compiled into the validity circuit.
pub const D: usize = 8;
/// Largest `d` the output window admits (`d + 2 ≤ 64`).
pub const MAX_D: usize = COEFFICIENT_OUTPUT_COUNT - 2;
/// Every update entry is in `[-ENTRY_BOUND, ENTRY_BOUND]`.
pub const ENTRY_BOUND: f64 = 1.0;
/// Fractional bits of the fixed-point entries the circuit takes (`× 2^16`).
pub const WEIGHT_FRAC_BITS: u32 = 16;
/// Fractional bits of the on-chain squared-norm bound (`× 2^32`).
pub const NORM_FRAC_BITS: u32 = 32;
/// Exclusive upper bound of a client's sample count.
pub const COUNT_BOUND: u32 = 1024;
/// Decimals of the canonical on-chain fixed-point output for this layout.
pub const OUTPUT_DECIMALS: u32 = COEFFICIENT_OUTPUT_DECIMALS;
/// Number of coefficients the output publishes.
pub const OUTPUT_COUNT: usize = COEFFICIENT_OUTPUT_COUNT;
/// The level the policy relinearizes at (the ceremony's key file).
pub const RELIN_LEVELS: [usize; 1] = [0];

/// A round's public parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundParams {
    /// Update dimension (`≤ MAX_D`; the circuit is compiled for [`D`]).
    pub d: usize,
    /// Squared-norm bound `B`: every update proves `Σ_j g_j² ≤ B`.
    pub norm_bound: f64,
    /// Minimum accepted updates before the round is evaluated.
    pub min_clients: usize,
}

impl RoundParams {
    pub fn validate(&self) -> Result<()> {
        if self.d != D {
            bail!(
                "d = {} but the validity circuit is compiled for d = {D}",
                self.d
            );
        }
        if self.d > MAX_D {
            bail!("d = {} exceeds the output window ({MAX_D})", self.d);
        }
        if !self.norm_bound.is_finite() || self.norm_bound <= 0.0 {
            bail!("norm bound {} must be positive", self.norm_bound);
        }
        if self.norm_bound > self.d as f64 * ENTRY_BOUND * ENTRY_BOUND {
            bail!(
                "norm bound {} exceeds the largest possible squared norm {}",
                self.norm_bound,
                self.d as f64
            );
        }
        if self.min_clients == 0 {
            bail!("min_clients must be at least 1");
        }
        Ok(())
    }

    /// The bound in the circuit's `2^32` fixed point (rounded down).
    pub fn norm_bound_fixed_point(&self) -> u64 {
        (self.norm_bound * 2f64.powi(NORM_FRAC_BITS as i32)).floor() as u64
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

/// Loads the level-0 joint key from a ceremony key directory
/// (`<node data dir>/<node>/ckks/relin-keys/<chain>:<e3_id>/`).
pub fn load_ceremony_keys(dir: &Path, params: &Arc<CkksParameters>) -> Result<RelinKeys> {
    RelinKeys::load_from_dir(dir, params, &RELIN_LEVELS)
        .with_context(|| format!("loading ceremony keys from {}", dir.display()))
}

/// Evaluate the round: returns the ciphertext output bytes to publish
/// on-chain. `inputs` are the accepted `(gradient ct, count ct)` pairs (any
/// order — the policy sums). The caller enforces the round's minimum
/// client count before calling.
pub fn evaluate(inputs: &[(Vec<u8>, Vec<u8>)], rlk_dir: &Path) -> Result<Vec<u8>> {
    if inputs.is_empty() {
        bail!("need at least one update");
    }
    let params = params()?;
    let rlks = load_ceremony_keys(rlk_dir, &params)?;
    // The policy multiplies at level 0 under a per-level key (ParamSet 5
    // has no special primes, so the ceremony is never hybrid).
    let rlk = match &rlks {
        RelinKeys::PerLevel(keys) => keys
            .first()
            .context("ceremony key directory has no level-0 key")?,
        RelinKeys::Hybrid(_) => bail!("ParamSet 5 uses a per-level ceremony, got a hybrid key"),
    };
    let mut flat: Vec<ArcBytes> = Vec::with_capacity(2 * inputs.len());
    for (g, c) in inputs {
        flat.push(ArcBytes::from_bytes(g));
        flat.push(ArcBytes::from_bytes(c));
    }
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 1, 1);
    let out = federated_average_policy(&config, &flat, rlk).context("federated average policy")?;
    Ok(out.to_vec())
}

/// The opened coefficients of an on-chain plaintext (all [`OUTPUT_COUNT`]).
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

/// The sample-weighted mean update and the total sample count from the
/// opened coefficients: `mean[j] = opened[j+1] / opened[d+1]`,
/// `total = opened[d+1]`.
pub fn weighted_mean(opened: &[f64], d: usize) -> Result<(Vec<f64>, f64)> {
    if opened.len() < d + 2 {
        bail!(
            "opened output has {} coefficients, need {}",
            opened.len(),
            d + 2
        );
    }
    let total = opened[d + 1];
    if !(total > 0.5) {
        bail!("total sample count {total} is not positive");
    }
    let mean = opened[1..=d].iter().map(|v| v / total).collect();
    Ok((mean, total))
}

/// Oracle: the exact weighted mean of plaintext updates (test / e2e use).
pub fn expected_weighted_mean(updates: &[(Vec<f64>, u32)]) -> (Vec<f64>, f64) {
    let d = updates.first().map(|(g, _)| g.len()).unwrap_or(0);
    let total: f64 = updates.iter().map(|(_, n)| *n as f64).sum();
    let mut mean = vec![0.0; d];
    for (g, n) in updates {
        for (j, v) in g.iter().enumerate() {
            mean[j] += *n as f64 * v;
        }
    }
    for m in &mut mean {
        *m /= total;
    }
    (mean, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decodes_and_averages_an_opened_output() {
        let mut coeffs = vec![0.0; OUTPUT_COUNT];
        // Two clients: n = [137, 63], g_0 = [0.5, -0.25], g_1 = [1.0, 1.0].
        coeffs[1] = 137.0 * 0.5 - 63.0 * 0.25;
        coeffs[2] = 200.0;
        coeffs[D + 1] = 200.0;
        let bytes = encode_fixed_point_output(&coeffs, OUTPUT_DECIMALS).unwrap();
        let opened = decode_opened(&bytes).unwrap();
        assert_eq!(opened.len(), OUTPUT_COUNT);
        let (mean, total) = weighted_mean(&opened, D).unwrap();
        assert_eq!(total, 200.0);
        assert!((mean[0] - 0.26375).abs() < 1e-4);
        assert!((mean[1] - 1.0).abs() < 1e-9);
        assert_eq!(mean.len(), D);
        assert!(decode_opened(&bytes[..bytes.len() - 16]).is_err());
        assert!(weighted_mean(&vec![0.0; OUTPUT_COUNT], D).is_err());
        let (oracle, t) = expected_weighted_mean(&[
            (vec![0.5, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 137),
            (vec![-0.25, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 63),
        ]);
        assert_eq!(t, 200.0);
        assert!((oracle[0] - mean[0]).abs() < 1e-4);
    }

    #[test]
    fn round_params_and_preset_shape() {
        let p = RoundParams {
            d: D,
            norm_bound: 2.5,
            min_clients: 3,
        };
        p.validate().unwrap();
        assert_eq!(p.norm_bound_fixed_point(), (2.5 * 4294967296.0) as u64);
        assert!(RoundParams { d: 9, ..p.clone() }.validate().is_err());
        assert!(RoundParams {
            norm_bound: 0.0,
            ..p.clone()
        }
        .validate()
        .is_err());
        assert!(RoundParams {
            norm_bound: 9.0,
            ..p.clone()
        }
        .validate()
        .is_err());
        assert!(RoundParams {
            min_clients: 0,
            ..p.clone()
        }
        .validate()
        .is_err());
        assert_eq!(expected_ceremony_keys(), 1);
        assert_eq!(ceremony_key_files(), vec!["rlk_level_0.bin".to_string()]);
        assert_eq!(opening_level(), 1);
        let params = params().unwrap();
        assert_eq!(params.degree(), 512);
        assert_eq!(params.moduli().len(), 3);
        assert_eq!(params.scale(), 2f64.powi(40));
    }

    #[test]
    fn evaluate_refuses_an_empty_round() {
        let err = evaluate(&[], Path::new("/nonexistent")).unwrap_err();
        assert!(err.to_string().contains("at least one"));
    }
}
