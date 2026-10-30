// SPDX-License-Identifier: LGPL-3.0-only

//! Additive smudging setup for artificial samples; each draw remains fresh.

use e3_fhe_params::BfvPreset;
use e3_zk_witness::WitnessError;
use fhe::bfv::BfvParameters;
use fhe::trbfv::smudging::SmudgingNoiseGenerator;
use fhe::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use std::sync::Arc;

pub(crate) fn generator(
    params: &Arc<BfvParameters>,
    parties: usize,
    ciphertexts: usize,
    preset: BfvPreset,
) -> Result<SmudgingNoiseGenerator, WitnessError> {
    let config = SmudgingBoundCalculatorConfig::new_multiplicative(
        params.clone(),
        parties,
        ciphertexts,
        0,
        preset
            .lambda()
            .map_err(|e| WitnessError::Sample(e.to_string()))?,
    )?;
    Ok(SmudgingNoiseGenerator::from_bound_calculator(
        SmudgingBoundCalculator::new(config).with_accepted_participant_count(parties),
    )?)
}
