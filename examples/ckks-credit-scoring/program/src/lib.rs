// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private credit-scoring v2 program (the E3 "policy").
//!
//! The computation the committee's ciphertext output carries is
//! [`e3_trckks::policy::credit_sigmoid_policy`]: applicant `i` submits
//! TWO slot-encoded ciphertexts at slot `i` — the PUBLIC model's logit
//! `z_i = ⟨w, x_i⟩/cap + b` over its Merkle-attested features (proven by
//! the `ckks_credit_validity_ps4` leg) and an OUTPUT mask `m_i` — and the
//! network computes `σ_cubic(z_i) + m_i` in slot `i` of ONE output. The
//! sigmoid needs two ciphertext × ciphertext products (`z²`, then `z³`),
//! relinearized under the committee's per-level keys at levels 1 and 2
//! (`rlk_level_1.bin`, `rlk_level_2.bin` — the ParamSet-4 ceremony plan)
//! and opened at level 3. That ct×ct depth is why this app is CKKS with a
//! ceremony rather than BFV or the ceremony-free linear v1
//! (`credit_linear_logit_policy`). The threshold decryption reveals only
//! masked probabilities; only applicant `i` (holding `m_i`) can subtract
//! it and read `σ(z_i)`.
//!
//! The committee runs NO app logic: this crate is the plain-Rust wrapper
//! the coordination server calls (CRISP's `program/` is a RISC Zero
//! guest; the CKKS demos run the policy natively — the ciphertext output
//! is published with a mock proof, see the Readme's honest-scope section).

use anyhow::{bail, Context, Result};
use e3_fhe_params::ckks_presets::{
    ckks_opening_level_for_param_set, ckks_params_for_on_chain_param_set,
    relin_ceremony_plan_for_param_set, RelinCeremonyPlan, CREDIT_RELIN_LEVELS,
};
use e3_trckks::policy::{
    credit_sigmoid_policy, credit_v2_max_applicants, credit_v2_unmask, sigmoid_cubic, RelinKeys,
    CREDIT_FEATURES, CREDIT_LOGIT_BOUND, CREDIT_OUTPUT_MASK_BOUND,
};
use e3_trckks::program::{decode_fixed_point_output, CREDIT_OUTPUT_DECIMALS};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksParameters;
use fhe_traits::Serialize as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// On-chain ParamSet of the credit-scoring preset (N=512, 5 limbs, Δ=2^40).
pub const PARAM_SET: u8 = 4;
/// Number of features per applicant.
pub const FEATURES: usize = CREDIT_FEATURES;
/// Exclusive upper bound of the applicant's OUTPUT mask value `m`.
pub const MASK_BOUND: f64 = CREDIT_OUTPUT_MASK_BOUND;
/// Fractional bits of the mask numerator the circuit takes (`m = mask / 2^10`).
pub const MASK_FRAC_BITS: u32 = 10;
/// Sup-norm bound on weights and bias (the circuit's `|w| ≤ 8`).
pub const WEIGHT_BOUND: f64 = 8.0;
/// Fractional bits of the fixed-point model the circuit takes (`×2^16`).
pub const WEIGHT_FRAC_BITS: u32 = 16;
/// Bound on every logit the policy evaluates (`|z| ≤ 8·8 + 8`).
pub const LOGIT_BOUND: f64 = CREDIT_LOGIT_BOUND;
/// Decimals of the canonical on-chain fixed-point output for this layout.
pub const OUTPUT_DECIMALS: u32 = CREDIT_OUTPUT_DECIMALS;
/// The levels the policy relinearizes at (the ceremony's key files).
pub const RELIN_LEVELS: [usize; 2] = CREDIT_RELIN_LEVELS;

/// The public model a round is scored with (real weights; the fixed
/// point the circuit and the contract take is [`Model::fixed_point`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Model {
    pub weights: [f64; FEATURES],
    pub bias: f64,
}

/// The model in the circuit's fixed point (`×2^16`, rounded), the shape
/// registered on-chain (negatives are emitted as `p − |w|` words there).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FixedPointModel {
    pub weights: [i32; FEATURES],
    pub bias: i32,
}

impl Model {
    pub fn validate(&self) -> Result<()> {
        for (j, w) in self.weights.iter().enumerate() {
            if !w.is_finite() || w.abs() > WEIGHT_BOUND {
                bail!("weight {j} = {w} outside [-{WEIGHT_BOUND}, {WEIGHT_BOUND}]");
            }
        }
        if !self.bias.is_finite() || self.bias.abs() > WEIGHT_BOUND {
            bail!(
                "bias {} outside [-{WEIGHT_BOUND}, {WEIGHT_BOUND}]",
                self.bias
            );
        }
        Ok(())
    }

    /// The fixed-point model (what the circuit proves against and the
    /// contract stores).
    pub fn fixed_point(&self) -> FixedPointModel {
        let scale = (1u64 << WEIGHT_FRAC_BITS) as f64;
        FixedPointModel {
            weights: std::array::from_fn(|j| (self.weights[j] * scale).round() as i32),
            bias: (self.bias * scale).round() as i32,
        }
    }

    /// The logit the applicant encrypts, computed EXACTLY as the circuit
    /// pins it: the fixed-point numerator over `2^16 · cap` (oracle use).
    pub fn logit(&self, features: &[u32; FEATURES], cap: u32) -> f64 {
        let fp = self.fixed_point();
        let mut acc: i128 = 0;
        for j in 0..FEATURES {
            acc += fp.weights[j] as i128 * features[j] as i128;
        }
        acc += fp.bias as i128 * cap as i128;
        acc as f64 / ((1u64 << WEIGHT_FRAC_BITS) as f64 * cap as f64)
    }
}

/// Canonical serialized ParamSet-4 parameters (byte-identical to every node's).
pub fn params() -> Result<Arc<CkksParameters>> {
    ckks_params_for_on_chain_param_set(PARAM_SET).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn params_bytes() -> Result<Vec<u8>> {
    Ok(params()?.to_bytes())
}

/// Maximum applicants one round can score (one slot each: `N / 2 = 256`).
pub fn max_applicants() -> Result<usize> {
    Ok(credit_v2_max_applicants(params()?.as_ref()))
}

/// Level the output is opened at (3: three rescales).
pub fn opening_level() -> usize {
    ckks_opening_level_for_param_set(PARAM_SET).unwrap_or(0)
}

/// Ceremony keys a complete DKG writes for this set: TWO
/// (`rlk_level_1.bin`, `rlk_level_2.bin`).
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

/// Loads the two joint keys from a ceremony key directory
/// (`<node data dir>/<node>/ckks/relin-keys/<chain>:<e3_id>/`).
pub fn load_ceremony_keys(dir: &Path, params: &Arc<CkksParameters>) -> Result<RelinKeys> {
    RelinKeys::load_from_dir(dir, params, &RELIN_LEVELS)
        .with_context(|| format!("loading ceremony keys from {}", dir.display()))
}

/// Evaluate the round: returns the ciphertext output bytes to publish
/// on-chain. `applications` are the accepted `(logit ct, mask ct)` pairs
/// in slot order (application at index `i` opens in slot `i`; the
/// on-chain `index` of each accepted application IS its position here,
/// and a registered applicant that never applied leaves its slot empty —
/// pass its pair as `None`).
pub fn evaluate(
    applications: &[Option<(Vec<u8>, Vec<u8>)>],
    ceremony_dir: &Path,
) -> Result<Vec<u8>> {
    let last = applications
        .iter()
        .rposition(Option::is_some)
        .context("need at least one application")?;
    let params = params()?;
    let rlks = load_ceremony_keys(ceremony_dir, &params)?;
    // Slots up to the last applicant; empty ones carry zero ciphertexts
    // (encryptions of 0 under no key are not needed: the policy sums the
    // pairs it is given, so gaps are filled by skipping — but slot
    // positions must be preserved, so an empty slot is an all-zero
    // ciphertext pair which the policy treats as `σ(0) + 0`).
    let mut inputs: Vec<ArcBytes> = Vec::with_capacity(2 * (last + 1));
    let zero = zero_ciphertext(&params)?;
    for slot in applications.iter().take(last + 1) {
        match slot {
            Some((z, m)) => {
                inputs.push(ArcBytes::from_bytes(z));
                inputs.push(ArcBytes::from_bytes(m));
            }
            None => {
                inputs.push(ArcBytes::from_bytes(&zero));
                inputs.push(ArcBytes::from_bytes(&zero));
            }
        }
    }
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 1, 1);
    let out = credit_sigmoid_policy(&config, &inputs, &rlks).context("credit sigmoid policy")?;
    Ok(out.to_vec())
}

/// A trivial (all-zero components) level-0 ciphertext: an encryption of
/// 0 under EVERY key, used to hold an empty slot's position.
fn zero_ciphertext(params: &Arc<CkksParameters>) -> Result<Vec<u8>> {
    use fhe_math::rq::{Ntt, Poly};
    let ctx = params.context_at_level(0)?;
    let zero = Poly::<Ntt>::zero(ctx);
    let ct = fhe::ckks::CkksCiphertext::new(vec![zero.clone(), zero], params.scale(), 0, params)?;
    Ok(ct.to_bytes())
}

/// The opened raw slot values of an on-chain plaintext, one per slot in
/// slot order: `out[i] = σ_cubic(z_i) + m_i` (0.5 for an empty slot).
pub fn decode_opened_slots(plaintext: &[u8], slots: usize) -> Result<Vec<f64>> {
    let values = decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)?;
    if values.len() < slots {
        bail!(
            "plaintext has {} slots but {slots} were requested",
            values.len()
        );
    }
    Ok(values[..slots].to_vec())
}

/// The applicant's own recovery: `σ(z) = opened − m` (CLIENT side in the
/// app; here for the oracle/test path).
pub fn recover_score(opened: f64, mask_value: f64) -> f64 {
    credit_v2_unmask(opened, mask_value)
}

/// The value the network computes for logit `z` (oracle).
pub fn expected_score(z: f64) -> f64 {
    sigmoid_cubic(z)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decodes_opened_slots() {
        let bytes = encode_fixed_point_output(&[517.75, 0.5, 300.1234], OUTPUT_DECIMALS).unwrap();
        assert_eq!(
            decode_opened_slots(&bytes, 3).unwrap(),
            vec![517.75, 0.5, 300.1234]
        );
        assert!(decode_opened_slots(&bytes, 4).is_err());
    }

    #[test]
    fn model_bounds_fixed_point_and_recovery() {
        let model = Model {
            weights: [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2],
            bias: -0.8,
        };
        model.validate().unwrap();
        let fp = model.fixed_point();
        assert_eq!(
            fp.weights,
            [111411, -150733, 58982, 26214, -72090, 170394, -32768, 78643]
        );
        assert_eq!(fp.bias, -52429);
        let z = model.logit(&[520, 130, 350, 999, 0, 1, 777, 42], 1000);
        assert!((z - 10753580.0 / (65536.0 * 1000.0)).abs() < 1e-12);
        let opened = expected_score(z) + 517.25;
        assert!((recover_score(opened, 517.25) - expected_score(z)).abs() < 1e-12);
        let bad = Model {
            weights: [9.0; FEATURES],
            bias: 0.0,
        };
        assert!(bad.validate().is_err());
        assert_eq!(expected_ceremony_keys(), 2);
        assert_eq!(
            ceremony_key_files(),
            vec!["rlk_level_1.bin".to_string(), "rlk_level_2.bin".to_string()]
        );
        assert_eq!(max_applicants().unwrap(), 256);
        assert_eq!(opening_level(), 3);
    }

    #[test]
    fn zero_ciphertext_round_trips() {
        let params = params().unwrap();
        let bytes = zero_ciphertext(&params).unwrap();
        let ct = <fhe::ckks::CkksCiphertext as fhe_traits::DeserializeParametrized>::from_bytes(
            &bytes, &params,
        )
        .unwrap();
        assert_eq!(ct.level, 0);
        assert_eq!(ct.len(), 2);
    }
}
