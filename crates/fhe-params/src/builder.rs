// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::constants::{
    insecure, insecure_64, insecure_simd, secure_16384, secure_16384_simd, secure_16384_simd_d6,
    secure_8192,
};
use crate::presets::{BfvParamSet, BfvPreset, PresetError};
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use num_bigint::BigUint;
use std::sync::Arc;

pub fn build_pair_for_preset(
    preset: BfvPreset,
) -> Result<(Arc<BfvParameters>, Arc<BfvParameters>), PresetError> {
    match preset {
        BfvPreset::InsecureThreshold64 => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(insecure_64::DEGREE)
                .set_plaintext_modulus(insecure_64::threshold::PLAINTEXT_MODULUS)
                .set_moduli(insecure_64::threshold::MODULI)
                .set_error1_variance(BigUint::from(
                    insecure_64::threshold::ERROR1_VARIANCE_BIGUINT,
                ))
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(insecure_64::DEGREE)
                .set_plaintext_modulus(insecure_64::dkg::PLAINTEXT_MODULUS)
                .set_moduli(insecure_64::dkg::MODULI)
                .set_variance(insecure_64::dkg::VARIANCE as usize)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::InsecureThresholdLbfv => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(insecure::DEGREE)
                .set_plaintext_modulus(insecure::threshold::PLAINTEXT_MODULUS)
                .set_moduli(insecure::threshold::MODULI)
                .set_error1_variance_str(insecure::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(insecure::DEGREE)
                .set_plaintext_modulus(insecure::dkg::PLAINTEXT_MODULUS)
                .set_moduli(insecure::dkg::MODULI)
                .set_variance(insecure::dkg::VARIANCE as usize)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::InsecureThresholdSimd => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(insecure_simd::DEGREE)
                .set_plaintext_modulus(insecure_simd::threshold::PLAINTEXT_MODULUS)
                .set_moduli(insecure_simd::threshold::MODULI)
                .set_error1_variance_str(insecure_simd::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(insecure_simd::DEGREE)
                .set_plaintext_modulus(insecure_simd::dkg::PLAINTEXT_MODULUS)
                .set_moduli(insecure_simd::dkg::MODULI)
                .set_variance(insecure_simd::dkg::VARIANCE as usize)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::SecureThreshold8192 => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(secure_8192::DEGREE)
                .set_plaintext_modulus(secure_8192::threshold::PLAINTEXT_MODULUS)
                .set_moduli(secure_8192::threshold::MODULI)
                .set_error1_variance_str(secure_8192::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(secure_8192::DEGREE)
                .set_plaintext_modulus(secure_8192::dkg::PLAINTEXT_MODULUS)
                .set_moduli(secure_8192::dkg::MODULI)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::SecureThreshold16384 => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(secure_16384::DEGREE)
                .set_plaintext_modulus(secure_16384::threshold::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384::threshold::MODULI)
                .set_error1_variance_str(secure_16384::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(secure_16384::DEGREE)
                .set_plaintext_modulus(secure_16384::dkg::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384::dkg::MODULI)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::SecureThreshold16384Simd => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(secure_16384_simd::DEGREE)
                .set_plaintext_modulus(secure_16384_simd::threshold::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384_simd::threshold::MODULI)
                .set_error1_variance_str(secure_16384_simd::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(secure_16384_simd::DEGREE)
                .set_plaintext_modulus(secure_16384_simd::dkg::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384_simd::dkg::MODULI)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        BfvPreset::SecureThreshold16384SimdD6 => {
            let params_threshold = BfvParametersBuilder::new()
                .set_degree(secure_16384_simd_d6::DEGREE)
                .set_plaintext_modulus(secure_16384_simd_d6::threshold::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384_simd_d6::threshold::MODULI)
                .set_error1_variance_str(secure_16384_simd_d6::threshold::ERROR1_VARIANCE)
                .unwrap()
                .build_arc()
                .unwrap();

            let params_dkg = BfvParametersBuilder::new()
                .set_degree(secure_16384_simd_d6::DEGREE)
                .set_plaintext_modulus(secure_16384_simd_d6::dkg::PLAINTEXT_MODULUS)
                .set_moduli(secure_16384_simd_d6::dkg::MODULI)
                .build_arc()
                .unwrap();

            Ok((params_threshold, params_dkg))
        }
        other => Err(PresetError::MissingPair(other.name())),
    }
}

pub fn build_bfv_params_from_set(param_set: BfvParamSet) -> BfvParameters {
    build_bfv_params(
        param_set.degree,
        param_set.plaintext_modulus,
        param_set.moduli,
        param_set.error1_variance,
    )
}

pub fn build_bfv_params_from_set_arc(param_set: BfvParamSet) -> Arc<BfvParameters> {
    build_bfv_params_arc(
        param_set.degree,
        param_set.plaintext_modulus,
        param_set.moduli,
        param_set.error1_variance,
    )
}

pub fn build_bfv_params(
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
    error1_variance: Option<&str>,
) -> BfvParameters {
    let mut builder = BfvParametersBuilder::new();
    builder
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(moduli);

    if let Some(error1) = error1_variance {
        builder
            .set_error1_variance_str(error1)
            .unwrap_or_else(|e| panic!("Failed to set error1_variance: {}", e));
    }

    builder
        .build()
        .unwrap_or_else(|e| panic!("Failed to build BFV Parameters: {}", e))
}

pub fn build_bfv_params_arc(
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
    error1_variance: Option<&str>,
) -> Arc<BfvParameters> {
    let mut builder = BfvParametersBuilder::new();
    builder
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(moduli);

    if let Some(error1) = error1_variance {
        builder
            .set_error1_variance_str(error1)
            .unwrap_or_else(|e| panic!("Failed to set error1_variance: {}", e));
    }

    builder
        .build_arc()
        .unwrap_or_else(|e| panic!("Failed to build BFV Parameters wrapped in Arc: {}", e))
}

/// Fallible BFV parameter construction for public or otherwise untrusted inputs.
pub fn try_build_bfv_params_arc(
    degree: usize,
    plaintext_modulus: u64,
    moduli: &[u64],
    error1_variance: Option<&str>,
) -> Result<Arc<BfvParameters>, fhe::Error> {
    let mut builder = BfvParametersBuilder::new();
    builder
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(moduli);

    if let Some(error1_variance) = error1_variance {
        builder.set_error1_variance_str(error1_variance)?;
    }

    builder.build_arc()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{defaults, insecure, insecure_64, secure_16384, secure_8192};
    use crate::presets::BfvPreset;
    use crate::smudging::calculate_smudging_bound;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn test_build_insecure_dkg_params_arc() {
        // Test building Arc<BFV params> using insecure DKG preset constants
        let degree = insecure_64::DEGREE;
        let plaintext_modulus = insecure_64::dkg::PLAINTEXT_MODULUS;
        let moduli = insecure_64::dkg::MODULI;

        let params = build_bfv_params_arc(degree, plaintext_modulus, moduli, None);

        assert_eq!(params.degree(), degree);
        assert_eq!(params.plaintext(), plaintext_modulus);
        assert_eq!(params.moduli(), moduli);
        assert_eq!(params.variance(), defaults::VARIANCE);
        assert_eq!(
            params.get_error1_variance(),
            &BigUint::from_str(insecure_64::dkg::ERROR1_VARIANCE).unwrap()
        );
    }

    #[test]
    fn fallible_builder_rejects_invalid_degree_without_panicking() {
        let result = try_build_bfv_params_arc(7, 17, &[97], None);
        assert!(result.is_err());
    }

    #[test]
    fn secure_8192_matches_target_moduli_and_lambda() {
        let (threshold, dkg) = build_pair_for_preset(BfvPreset::SecureThreshold8192).unwrap();
        let threshold_q = threshold
            .moduli()
            .iter()
            .fold(BigUint::from(1u8), |product, &qi| product * qi);
        let dkg_q = dkg
            .moduli()
            .iter()
            .fold(BigUint::from(1u8), |product, &qi| product * qi);

        assert_eq!(threshold.degree(), 8192);
        assert_eq!(threshold.plaintext(), 17000000);
        assert_eq!(
            threshold.moduli(),
            &[0x0800000000db4001, 0x0800000000d54001, 0x0800000000cbc001]
        );
        assert_eq!(
            threshold_q.to_string(),
            "191561942622092406273068928635395424157847567961178113"
        );
        assert_eq!(
            (&threshold_q / threshold.plaintext()).to_string(),
            "11268349566005435663121701684435024950461621644"
        );
        assert_eq!(
            &threshold_q % threshold.plaintext(),
            BigUint::from(13178113u64)
        );
        assert_eq!(
            threshold.get_error1_variance().to_string(),
            "17723039943798878305460955570711717478400"
        );

        assert_eq!(dkg.degree(), 8192);
        assert_eq!(dkg.plaintext(), 576460752317792257);
        assert_eq!(dkg.moduli(), &[0x2000000000104001, 0x200000000013c001]);
        assert_eq!(dkg_q.to_string(), "5316911983145103662415181469253369857");
        assert_eq!(
            (&dkg_q / dkg.plaintext()).to_string(),
            "9223372036634312696"
        );
        assert_eq!(&dkg_q % dkg.plaintext(), BigUint::from(3169161947774985u64));
        assert_eq!(BfvPreset::SecureThreshold8192.metadata().lambda, 45);
        assert_eq!(BfvPreset::SecureDkg8192.metadata().lambda, 45);

        let defaults = BfvPreset::SecureThreshold8192.search_defaults().unwrap();
        let smudging_bound = calculate_smudging_bound(
            threshold.clone(),
            defaults.n as usize,
            defaults.z as usize,
            defaults.mult_depth,
            BfvPreset::SecureThreshold8192.lambda().unwrap(),
        )
        .unwrap();
        assert_eq!(
            smudging_bound.to_string(),
            "13292279957850296184850092126921713254400000"
        );
        let b_c = BigUint::parse_bytes(b"23058430092138912691300000", 10).unwrap();
        let delta = &threshold_q / threshold.plaintext();
        assert!(BigUint::from(2u8) * (b_c + BigUint::from(defaults.n) * smudging_bound) < delta);
    }

    #[test]
    fn test_build_insecure_dkg_params_from_set_arc() {
        // Test building Arc from BfvParamSet using insecure DKG preset
        let preset = BfvPreset::InsecureDkg64;
        let param_set = preset.into();
        let params = build_bfv_params_from_set_arc(param_set);

        assert_eq!(params.degree(), insecure_64::DEGREE);
        assert_eq!(params.plaintext(), insecure_64::dkg::PLAINTEXT_MODULUS);
        assert_eq!(params.moduli(), insecure_64::dkg::MODULI);

        let preset = BfvPreset::InsecureDkgLbfv;
        let param_set = preset.into();
        let params = build_bfv_params_from_set_arc(param_set);

        assert_eq!(params.degree(), insecure::DEGREE);
        assert_eq!(params.plaintext(), insecure::dkg::PLAINTEXT_MODULUS);
        assert_eq!(params.moduli(), insecure::dkg::MODULI);
    }

    #[test]
    fn test_build_secure_threshold_params_from_set_arc() {
        // Test building Arc from BfvParamSet using secure threshold preset
        let preset = BfvPreset::SecureThreshold8192;
        let param_set = preset.into();
        let params = build_bfv_params_from_set_arc(param_set);

        assert_eq!(params.degree(), secure_8192::DEGREE);
        assert_eq!(
            params.plaintext(),
            secure_8192::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(params.moduli(), secure_8192::threshold::MODULI);
        assert_eq!(
            params.get_error1_variance(),
            &BigUint::from_str(secure_8192::threshold::ERROR1_VARIANCE).unwrap()
        );
    }

    #[test]
    fn test_build_secure_16384_pair() {
        let (threshold, dkg) = BfvPreset::SecureThreshold16384.build_pair().unwrap();
        assert_eq!(threshold.degree(), secure_16384::DEGREE);
        assert_eq!(
            threshold.plaintext(),
            secure_16384::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(threshold.moduli(), secure_16384::threshold::MODULI);
        assert_eq!(
            threshold.get_error1_variance(),
            &BigUint::from_str(secure_16384::threshold::ERROR1_VARIANCE).unwrap()
        );
        assert_eq!(dkg.degree(), secure_16384::DEGREE);
        assert_eq!(dkg.plaintext(), secure_16384::dkg::PLAINTEXT_MODULUS);
        assert_eq!(dkg.moduli(), secure_16384::dkg::MODULI);
    }

    #[test]
    fn test_build_secure_16384_threshold_from_set() {
        let preset = BfvPreset::SecureThreshold16384;
        let param_set: BfvParamSet = preset.into();
        let params = build_bfv_params_from_set(param_set);

        assert_eq!(params.degree(), secure_16384::DEGREE);
        assert_eq!(
            params.plaintext(),
            secure_16384::threshold::PLAINTEXT_MODULUS
        );
        assert_eq!(params.moduli(), secure_16384::threshold::MODULI);
        assert_eq!(
            params.get_error1_variance(),
            &BigUint::from_str(secure_16384::threshold::ERROR1_VARIANCE).unwrap()
        );
    }

    /// Runtime feasibility guard: the `SmudgingBoundCalculator` must accept the
    /// Secure-16384 threshold parameters at the full committee (n=20) with the
    /// configured smudging `m=z=3`, `mult_depth=3`, `lambda=31`. This encodes
    /// the `2*(B_C + n*B_sm) < Delta` correctness budget; if the constants are
    /// ever tightened beyond it, this test fails.
    #[test]
    fn test_secure_16384_smudging_bound_feasible() {
        use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};
        use num_traits::Zero;

        let preset = BfvPreset::SecureThreshold16384;
        let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
        let defaults = preset.search_defaults().unwrap();

        let mut config = SmudgingConfig::new(
            params.clone(),
            defaults.n as usize,
            defaults.z as usize,
            defaults.lambda as usize,
        )
        .expect("config construction should succeed");
        config.mult_depth = defaults.mult_depth;
        let generator = SmudgingNoiseGenerator::new(config)
            .expect("2*(B_C + n*B_sm) < Delta must hold at the configured depth");
        let bound = generator.smudging_bound();
        assert!(!bound.is_zero());
    }

    /// The secure SIMD preset (t = 65537) accepts every committee (n = 3, 9, 19, 20) at `m = z = 3`,
    /// `mult_depth = 3`, `lambda = 31`: `2*(B_C + n*B_sm) < Delta` holds.
    #[test]
    fn test_secure_16384_simd_smudging_bound_feasible_for_every_committee() {
        use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};

        let preset = BfvPreset::SecureThreshold16384Simd;
        let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.mult_depth, 3);

        for n in [3, 9, 19, defaults.n as usize] {
            let mut config = SmudgingConfig::new(
                params.clone(),
                n,
                defaults.z as usize,
                defaults.lambda as usize,
            )
            .expect("config construction should succeed");
            config.mult_depth = defaults.mult_depth;
            SmudgingNoiseGenerator::new(config)
                .unwrap_or_else(|e| panic!("n = {n} must satisfy the noise budget: {e}"));
        }
    }

    /// The depth-6 secure SIMD preset accepts every committee (n = 3, 9, 19, 20) at `m = z = 3`,
    /// `mult_depth = 6`, `lambda = 31`, and refuses depth 7: the smudging check
    /// `2*(B_C + n*B_sm) < Delta` fails one level deeper.
    #[test]
    fn test_secure_16384_simd_d6_smudging_bound_covers_depth_6_and_refuses_depth_7() {
        use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};

        let preset = BfvPreset::SecureThreshold16384SimdD6;
        let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.mult_depth, 6);

        let generator_for = |n: usize, mult_depth: u32| {
            let mut config = SmudgingConfig::new(
                params.clone(),
                n,
                defaults.z as usize,
                defaults.lambda as usize,
            )?;
            config.mult_depth = mult_depth;
            SmudgingNoiseGenerator::new(config)
        };
        for n in [3, 9, 19, defaults.n as usize] {
            generator_for(n, defaults.mult_depth)
                .unwrap_or_else(|e| panic!("n = {n} must satisfy the noise budget: {e}"));
        }
        assert!(
            generator_for(3, defaults.mult_depth + 1).is_err(),
            "depth 7 must exceed the noise budget even for 3 parties"
        );
    }

    /// The insecure SIMD preset (t = 257) satisfies the depth-3 noise budget for the Minimum
    /// (n=3) and Micro (n=9) committees only. At the Small committee (n=19) the budget fails,
    /// which is why that committee is refused for this preset.
    #[test]
    fn test_insecure_simd_smudging_bound_feasibility_by_committee() {
        use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};

        let preset = BfvPreset::InsecureThresholdSimd;
        let params = build_bfv_params_from_set_arc(BfvParamSet::from(preset));
        let defaults = preset.search_defaults().unwrap();
        assert_eq!(defaults.mult_depth, 3);

        let generator_for = |n: usize| {
            let mut config = SmudgingConfig::new(
                params.clone(),
                n,
                defaults.z as usize,
                defaults.lambda as usize,
            )?;
            config.mult_depth = defaults.mult_depth;
            SmudgingNoiseGenerator::new(config)
        };

        assert!(
            generator_for(3).is_ok(),
            "Minimum committee must be feasible"
        );
        assert!(generator_for(9).is_ok(), "Micro committee must be feasible");
        assert!(
            generator_for(19).is_err(),
            "Small committee must exceed the noise budget at t=257"
        );
    }
}
