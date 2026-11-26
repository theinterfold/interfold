// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared smudging-noise helpers for the BFV parameter presets.

use crate::BfvPreset;
use fhe::bfv::BfvParameters;
use fhe::trbfv::{FreshNoiseModel, Lambda, SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use fhe_math::rq::sample_uniform_coefficients_bigint;
use num_bigint::BigInt;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// The fresh-encryption noise model the preset's smudging bound is sized for.
///
/// Inputs encrypted under an l-BFV public key carry a larger fresh-noise term than a BFV public
/// key's, so fhe.rs requires [`FreshNoiseModel::LbfvPublicKey`] for them. Every preset whose
/// circuits are the l-BFV circuits uses it: the l-BFV presets, and `InsecureThreshold`, which
/// shares their parameters and generates the `insecure_lbfv` circuit configuration. All other
/// presets, trBFV included, keep [`FreshNoiseModel::BfvPublicKey`]. A DKG preset follows its
/// threshold counterpart.
pub fn fresh_noise_model(preset: BfvPreset) -> FreshNoiseModel {
    let threshold = preset.threshold_counterpart().unwrap_or(preset);
    if threshold.lbfv_label().is_some() {
        FreshNoiseModel::LbfvPublicKey
    } else {
        FreshNoiseModel::BfvPublicKey
    }
}

/// The fhe.rs bound-calculator configuration for one threshold-BFV operation on `preset`.
///
/// `mult_depth` is the number of multiplicative levels applied after the `num_ciphertexts`
/// additions; 0 is the summation-only (trBFV) bound. The noise model follows
/// [`fresh_noise_model`], so every caller of a preset agrees on the bound.
pub fn smudging_bound_config(
    preset: BfvPreset,
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: Lambda,
) -> Result<SmudgingBoundCalculatorConfig, fhe::Error> {
    SmudgingBoundCalculatorConfig::new_with_fresh_noise_model(
        params,
        n,
        num_ciphertexts,
        mult_depth,
        lambda,
        fresh_noise_model(preset),
    )
}

/// Calculate the smudging bound for one threshold-BFV operation on `preset`.
pub fn calculate_smudging_bound(
    preset: BfvPreset,
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: Lambda,
) -> Result<BigUint, fhe::Error> {
    calculate_smudging_bound_with_model(
        fresh_noise_model(preset),
        params,
        n,
        num_ciphertexts,
        mult_depth,
        lambda,
    )
}

/// Calculate the smudging bound for an explicit fresh-noise model. A trBFV request carries no
/// preset, so its executor names the BFV model and depth 0, which is the bound that trBFV E3s
/// have always used.
pub fn calculate_smudging_bound_with_model(
    model: FreshNoiseModel,
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: Lambda,
) -> Result<BigUint, fhe::Error> {
    let config = SmudgingBoundCalculatorConfig::new_with_fresh_noise_model(
        params,
        n,
        num_ciphertexts,
        mult_depth,
        lambda,
        model,
    )?;
    SmudgingBoundCalculator::new(config).calculate_sm_bound()
}

/// Generate centered smudging coefficients for one threshold-BFV operation.
///
/// The circuit witness path needs the coefficient form, so this helper samples with the validated
/// bound and canonical uniform sampler before the polynomial is dealt into shares.
pub fn generate_smudging_error<R: RngCore + CryptoRng>(
    preset: BfvPreset,
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: Lambda,
    rng: &mut R,
) -> Result<Vec<BigInt>, fhe::Error> {
    let bound = BigInt::from(calculate_smudging_bound(
        preset,
        params.clone(),
        n,
        num_ciphertexts,
        mult_depth,
        lambda,
    )?);
    Ok(sample_uniform_coefficients_bigint(
        &bound,
        params.degree(),
        rng,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BfvParamSet;
    use e3_committee::CiphernodesCommitteeSize::{self, Large, Micro, Minimum, Small};

    /// trBFV E3 error sizes as main computes them (`e3_trbfv::helpers::calculate_error_size` on
    /// fhe.rs v0.6.0, with `(n, threshold)` of each committee). l-BFV must not move them: they are
    /// every trBFV E3's on-chain error size and its circuits' smudging constants.
    const MAIN_TRBFV_BOUNDS: [(BfvPreset, CiphernodesCommitteeSize, &str); 8] = [
        (BfvPreset::InsecureThreshold64, Minimum, "2691203584"),
        (BfvPreset::InsecureThreshold64, Micro, "10796271616"),
        (BfvPreset::InsecureThreshold64, Small, "24409575936"),
        (BfvPreset::InsecureThreshold64, Large, "60417584128"),
        (
            BfvPreset::SecureThreshold8192,
            Minimum,
            "299076299051614234752268452445514891264",
        ),
        (
            BfvPreset::SecureThreshold8192,
            Micro,
            "1196305196206461472480897364641464713216",
        ),
        (
            BfvPreset::SecureThreshold8192,
            Small,
            "2691686691464555313601357401166064910336",
        ),
        (
            BfvPreset::SecureThreshold8192,
            Large,
            "6579678579135687703215112815888425811968",
        ),
    ];

    #[test]
    fn trbfv_smudging_bounds_are_mains() {
        for (preset, committee, expected) in MAIN_TRBFV_BOUNDS {
            let values = committee.values();
            let bound = calculate_smudging_bound(
                preset,
                BfvParamSet::from(preset).build_arc(),
                values.n,
                values.threshold,
                preset.search_defaults().unwrap().mult_depth,
                preset.lambda().unwrap(),
            )
            .unwrap();
            assert_eq!(bound.to_string(), expected, "{preset:?} {committee:?}");
        }
    }

    /// l-BFV presets are sized with fhe.rs's l-BFV noise model (a larger `u` bound), and every
    /// other preset with the BFV model; the two models give different bounds.
    #[test]
    fn lbfv_presets_use_the_lbfv_noise_model() {
        for preset in [
            BfvPreset::InsecureThresholdLbfv,
            BfvPreset::InsecureDkgLbfv,
            BfvPreset::SecureThreshold16384,
            BfvPreset::SecureDkg16384,
        ] {
            assert_eq!(
                fresh_noise_model(preset),
                FreshNoiseModel::LbfvPublicKey,
                "{preset:?}"
            );
        }
        for preset in [
            BfvPreset::InsecureThreshold64,
            BfvPreset::InsecureDkg64,
            BfvPreset::SecureThreshold8192,
            BfvPreset::SecureDkg8192,
        ] {
            assert_eq!(
                fresh_noise_model(preset),
                FreshNoiseModel::BfvPublicKey,
                "{preset:?}"
            );
        }

        for preset in [
            BfvPreset::InsecureThresholdLbfv,
            BfvPreset::SecureThreshold16384,
        ] {
            let defaults = preset.search_defaults().unwrap();
            let params = BfvParamSet::from(preset).build_arc();
            let lambda = preset.lambda().unwrap();
            for committee in [Minimum, Micro, Small] {
                let n = committee.values().n;
                let bound = |model| {
                    let config = SmudgingBoundCalculatorConfig::new_with_fresh_noise_model(
                        params.clone(),
                        n,
                        defaults.z as usize,
                        defaults.mult_depth,
                        lambda,
                        model,
                    )
                    .unwrap();
                    SmudgingBoundCalculator::new(config)
                        .calculate_sm_bound()
                        .unwrap()
                };
                let lbfv = bound(FreshNoiseModel::LbfvPublicKey);
                assert_eq!(
                    calculate_smudging_bound(
                        preset,
                        params.clone(),
                        n,
                        defaults.z as usize,
                        defaults.mult_depth,
                        lambda,
                    )
                    .unwrap(),
                    lbfv,
                    "{preset:?} {committee:?}"
                );
                assert_ne!(
                    lbfv,
                    bound(FreshNoiseModel::BfvPublicKey),
                    "{preset:?} {committee:?}"
                );
            }
        }
    }
}
