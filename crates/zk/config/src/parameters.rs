// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bind circuit configuration to the supported BFV parameter tuples.

use crate::ConfigError;
use e3_fhe_params::{constants, BfvParamSet, BfvPreset, ParameterType};
use fhe::bfv::BfvParameters;
use num_bigint::BigUint;

fn sampler_matches(preset: BfvPreset, params: &BfvParameters) -> bool {
    let expected = BfvParamSet::from(preset);
    let error1 = expected
        .error1_variance
        .expect("supported presets specify error1 variance")
        .parse::<BigUint>()
        .expect("preset variance is an integer");
    // Parameter-set builders use the standard CBD sampler. The insecure DKG pair builder
    // explicitly selects its smaller CBD variance, which also selects error1 variance.
    let standard = params.variance() == constants::defaults::VARIANCE
        && params.get_error1_variance() == &error1;
    let insecure_pair = matches!(preset, BfvPreset::InsecureDkg | BfvPreset::InsecureDkgLbfv)
        && params.variance() == constants::insecure::dkg::VARIANCE as usize
        && params.get_error1_variance() == &BigUint::from(constants::insecure::dkg::VARIANCE);
    standard || insecure_pair
}

pub(crate) fn matching_preset(
    params: &BfvParameters,
    parameter_type: ParameterType,
) -> Result<BfvPreset, ConfigError> {
    BfvPreset::ALL
        .into_iter()
        .find(|preset| {
            let expected = BfvParamSet::from(*preset);
            preset.metadata().parameter_type == parameter_type
                && params.degree() == expected.degree
                && params.plaintext() == expected.plaintext_modulus
                && params.moduli() == expected.moduli
                && sampler_matches(*preset, params)
        })
        .ok_or_else(|| {
            ConfigError::Other("BFV parameters do not match a supported circuit preset".into())
        })
}

pub(crate) fn require_threshold_preset(
    preset: BfvPreset,
    params: &BfvParameters,
) -> Result<(), ConfigError> {
    let matching = matching_preset(params, ParameterType::THRESHOLD)?;
    if matching != preset && matching.lbfv_label() != Some(preset) {
        return Err(ConfigError::Other(
            "BFV parameters do not match the requested threshold preset".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{dkg, threshold};
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::{BfvParamSet, BfvPreset, ParameterType};
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigUint;

    #[test]
    fn supported_sampler_profiles_reject_other_variances() {
        for preset in BfvPreset::ALL {
            let params = BfvParamSet::from(preset).build_arc();
            let accepted = match preset.metadata().parameter_type {
                ParameterType::DKG => dkg::pk::Configs::new(&params).is_ok(),
                ParameterType::THRESHOLD => {
                    threshold::user_data_encryption::Configs::new(&params).is_ok()
                }
            };
            assert!(accepted, "{preset:?}: supported sampler rejected");
            for (variance, error1) in [
                (params.variance() + 1, params.get_error1_variance().clone()),
                (
                    params.variance(),
                    params.get_error1_variance() + BigUint::from(1u32),
                ),
            ] {
                let altered = BfvParametersBuilder::new()
                    .set_degree(params.degree())
                    .set_plaintext_modulus(params.plaintext())
                    .set_moduli(params.moduli())
                    .set_variance(variance)
                    .set_error1_variance(error1)
                    .build_arc()
                    .unwrap();
                let rejected = match preset.metadata().parameter_type {
                    ParameterType::DKG => dkg::pk::Configs::new(&altered).is_err(),
                    ParameterType::THRESHOLD => {
                        threshold::user_data_encryption::Configs::new(&altered).is_err()
                    }
                };
                assert!(rejected, "{preset:?}: unsupported sampler accepted");
            }
        }
        for preset in BfvPreset::PAIR_PRESETS {
            let (threshold_params, dkg_params) = preset.build_pair().unwrap();
            assert!(dkg::pk::Configs::new(&dkg_params).is_ok());
            assert!(threshold::user_data_encryption::Configs::new(&threshold_params).is_ok());
        }
    }

    #[test]
    fn constructors_reject_other_parameter_families_and_tiers() {
        let preset = BfvPreset::InsecureThreshold;
        let (threshold_params, dkg_params) = preset.build_pair().unwrap();
        let (_, secure_dkg) = BfvPreset::SecureThreshold8192.build_pair().unwrap();
        let committee = CiphernodesCommitteeSize::Minimum;

        assert!(dkg::pk::Configs::new(&threshold_params).is_err());
        assert!(threshold::user_data_encryption::Configs::new(&dkg_params).is_err());
        assert!(dkg::share_decryption::Configs::new(&threshold_params, &secure_dkg).is_err());
        assert!(threshold::pk_generation::Configs::new(
            BfvPreset::SecureThreshold8192,
            &threshold_params,
            committee
        )
        .is_err());
        assert!(dkg::share_computation::Configs::new(
            BfvPreset::SecureThreshold8192,
            &threshold_params,
            committee
        )
        .is_err());

        assert!(dkg::share_decryption::Configs::new(&threshold_params, &dkg_params).is_ok());
        assert!(threshold::user_data_encryption::Configs::new(&threshold_params).is_ok());
    }
}
