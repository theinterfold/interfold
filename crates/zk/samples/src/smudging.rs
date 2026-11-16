// SPDX-License-Identifier: LGPL-3.0-only

//! Additive smudging setup for artificial samples; each draw remains fresh.

use e3_fhe_params::BfvPreset;
use e3_zk_witness::WitnessError;
use fhe::bfv::BfvParameters;
use fhe::trbfv::{
    SmudgingBoundCalculator, SmudgingBoundCalculatorConfig, SsSmudgingNoiseGenerator,
};
use num_bigint::BigInt;
use rand::CryptoRng;
use std::sync::Arc;

pub(crate) fn generator(
    params: &Arc<BfvParameters>,
    parties: usize,
    ciphertexts: usize,
    preset: BfvPreset,
) -> Result<SsSmudgingNoiseGenerator, WitnessError> {
    let config = SmudgingBoundCalculatorConfig::new_multiplicative(
        params.clone(),
        parties,
        ciphertexts,
        0,
        preset
            .lambda()
            .map_err(|e| WitnessError::Sample(e.to_string()))?,
    )?;
    Ok(SsSmudgingNoiseGenerator::from_bound_calculator(
        SmudgingBoundCalculator::new(config).with_accepted_participant_count(parties),
    )?)
}

/// Retain signed coefficients when a C1/C2 witness needs the sampled secret as well as its shares.
pub(crate) fn sample_coefficients(
    noise: &SsSmudgingNoiseGenerator,
    rng: &mut impl CryptoRng,
) -> Vec<BigInt> {
    fhe_math::rq::sample_uniform_coefficients_bigint(
        &noise.smudging_bound().clone().into(),
        noise.degree(),
        rng,
    )
}
