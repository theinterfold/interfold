// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared smudging-noise helpers for the BFV parameter presets.

use fhe::bfv::BfvParameters;
use fhe::trbfv::{SmudgingConfig, SmudgingNoiseGenerator};
use fhe_math::rq::sample_uniform_coefficients_bigint;
use num_bigint::BigInt;
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

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
