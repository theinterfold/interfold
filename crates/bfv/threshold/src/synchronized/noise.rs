// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{BfvDecryptionProtocol, BfvParamSet, BfvProfile};
use fhe::trbfv::{SmudgingBoundCalculatorConfig, SmudgingNoiseGenerator};
use fhe_math::rq::sample_uniform_coefficients_bigint;
use num_bigint::BigInt;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// V1 private checkpoint format: always begin at stream offset zero and draw exactly one
/// signed integer per coefficient, as in the pinned native-to-C6 qualification.
pub fn contribution_noise_v1(
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
    seed: &[u8; 32],
) -> Result<Vec<BigInt>> {
    ensure!(
        profile.protocol() == BfvDecryptionProtocol::Synchronized,
        "SS does not use per-owner noise"
    );
    profile.validate_committee(committee)?;
    let preset = profile.threshold_preset();
    let params = BfvParamSet::from(preset).build_arc();
    let noise = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        committee.values().n,
        preset
            .search_defaults()
            .context("missing noise parameters")?
            .z as usize,
        preset.lambda()?,
    )?)?;
    Ok(sample_uniform_coefficients_bigint(
        &noise.smudging_bound().clone().into(),
        params.degree(),
        &mut ChaCha20Rng::from_seed(*seed),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronized_contribution_v1_saved_seed_keeps_its_whole_noise_polynomial() -> Result<()> {
        // A sampler dependency change that passes ordinary reopen tests can still change the
        // opening for an old allocation. This public test seed is never used by the runtime.
        let coeffs = contribution_noise_v1(
            BfvProfile::SyncDecInsecure64,
            CiphernodesCommitteeSize::Minimum,
            &[42; 32],
        )?;
        let values = coeffs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            alloy::primitives::keccak256(values).to_string(),
            "0xa91f7beb78c81fe00f7a1501430eb656c921fead55aacb70da8fd0b9ec3a4be4"
        );
        Ok(())
    }
}
