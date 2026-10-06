// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared smudging-noise helpers for the BFV parameter presets.

use crate::BfvPreset;
use fhe::bfv::BfvParameters;
use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};
use fhe_math::rq::sample_uniform_coefficients_bigint;
use num_bigint::BigInt;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Arguments that produce the fresh-noise bound checked by C6.
///
/// `num_ciphertexts` is the number of fresh ciphertexts summed into one ciphertext.
/// `num_parties` is the committee size. Both values match the bound compiled for that preset.
pub struct FreshSmudgingInputs {
    pub num_parties: usize,
    pub num_ciphertexts: usize,
    pub mult_depth: u32,
    pub lambda: usize,
}

/// Return the smudging inputs for one threshold preset and committee size.
pub fn fresh_smudging_inputs(
    preset: BfvPreset,
    num_parties: usize,
) -> Result<FreshSmudgingInputs, String> {
    let defaults = preset
        .search_defaults()
        .ok_or_else(|| format!("{preset:?} has no search defaults"))?;
    let lambda = preset.lambda().map_err(|error| error.to_string())?;
    Ok(FreshSmudgingInputs {
        num_parties,
        num_ciphertexts: usize::try_from(defaults.z).map_err(|_| {
            format!("{preset:?} ciphertext count {} does not fit usize", defaults.z)
        })?,
        mult_depth: defaults.mult_depth,
        lambda,
    })
}

/// Sample one fresh smudging polynomial with the operating-system generator.
pub fn sample_fresh_smudging_error(
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: usize,
) -> Result<Vec<BigInt>, fhe::Error> {
    let mut rng = rand::rng();
    generate_smudging_error(params, n, num_ciphertexts, mult_depth, lambda, &mut rng)
}

/// Generate centered smudging coefficients for one threshold-BFV operation.
///
/// The upstream generator owns its sampled polynomial so that callers cannot reuse it. The
/// circuit witness path also needs the coefficient form, so this helper samples with the same
/// validated bound and canonical uniform sampler before the polynomial is dealt into shares.
pub fn generate_smudging_error<R: RngCore + CryptoRng>(
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: usize,
    rng: &mut R,
) -> Result<Vec<BigInt>, fhe::Error> {
    let mut config = SmudgingConfig::new(params.clone(), n, num_ciphertexts, lambda)?;
    config.mult_depth = mult_depth;
    let generator = SmudgingNoiseGenerator::new(config)?;
    let bound = BigInt::from(generator.smudging_bound().clone());
    Ok(sample_uniform_coefficients_bigint(
        &bound,
        params.degree(),
        rng,
    ))
}

/// Calculate the smudging bound for one threshold-BFV operation.
pub fn calculate_smudging_bound(
    params: Arc<BfvParameters>,
    n: usize,
    num_ciphertexts: usize,
    mult_depth: u32,
    lambda: usize,
) -> Result<BigUint, fhe::Error> {
    let mut config = SmudgingConfig::new(params, n, num_ciphertexts, lambda)?;
    config.mult_depth = mult_depth;
    Ok(SmudgingNoiseGenerator::new(config)?
        .smudging_bound()
        .clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_pair_for_preset;
    use std::fs;
    use std::path::Path;

    fn noir_field(text: &str, name: &str) -> BigUint {
        let marker = format!("pub global {name}:");
        let rest = text
            .split(&marker)
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name}"));
        let literal = rest
            .split('=')
            .nth(1)
            .unwrap_or_else(|| panic!("{name} has no value"))
            .split(';')
            .next()
            .unwrap_or_else(|| panic!("{name} has no terminator"));
        let digits: String = literal.chars().filter(|ch| ch.is_ascii_digit()).collect();
        BigUint::parse_bytes(digits.as_bytes(), 10).expect("Noir field is a decimal integer")
    }

    #[test]
    fn fresh_noise_bound_matches_compiled_c6_bound() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../circuits/lib/src/configs/committee");
        let presets = [
            (BfvPreset::InsecureThreshold, "INSECURE_E_SM_BOUND"),
            (BfvPreset::SecureThreshold8192, "SECURE_8192_E_SM_BOUND"),
            (
                BfvPreset::SecureThreshold16384,
                "SECURE_16384_E_SM_BOUND",
            ),
        ];
        for committee in ["minimum", "micro", "small"] {
            let dir = root.join(committee);
            let parties = noir_field(
                &fs::read_to_string(dir.join("mod.nr")).expect("committee module"),
                "N_PARTIES",
            );
            let num_parties: usize = parties.to_string().parse().expect("party count");
            let smudging = fs::read_to_string(dir.join("smudging.nr")).expect("smudging constants");
            for (preset, constant) in presets {
                let (params, _) = build_pair_for_preset(preset).expect("preset parameters");
                let inputs = fresh_smudging_inputs(preset, num_parties).expect("noise inputs");
                let bound = calculate_smudging_bound(
                    params,
                    inputs.num_parties,
                    inputs.num_ciphertexts,
                    inputs.mult_depth,
                    inputs.lambda,
                )
                .unwrap_or_else(|error| {
                    panic!("{preset:?} {committee} smudging bound: {error}")
                });
                assert_eq!(
                    bound,
                    noir_field(&smudging, constant),
                    "{preset:?} {committee} fresh-noise bound"
                );
            }
        }
    }
}
