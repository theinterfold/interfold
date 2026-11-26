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
    let (noise, params) = noise_generator(profile, committee)?;
    Ok(sample_uniform_coefficients_bigint(
        &noise.smudging_bound().clone().into(),
        params.degree(),
        &mut ChaCha20Rng::from_seed(*seed),
    ))
}

pub(super) fn noise_generator(
    profile: BfvProfile,
    committee: CiphernodesCommitteeSize,
) -> Result<(
    SmudgingNoiseGenerator,
    std::sync::Arc<fhe::bfv::BfvParameters>,
)> {
    ensure!(
        profile.protocol() == BfvDecryptionProtocol::Synchronized,
        "SS does not use per-owner noise"
    );
    profile.validate_committee(committee)?;
    let preset = profile.threshold_preset();
    let params = BfvParamSet::from(preset).build_arc();
    let generator = SmudgingNoiseGenerator::new(SmudgingBoundCalculatorConfig::new(
        params.clone(),
        committee.values().n,
        preset
            .search_defaults()
            .context("missing noise parameters")?
            .z as usize,
        preset.lambda()?,
    )?)?;
    Ok((generator, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{b256, keccak256};

    #[test]
    fn synchronized_contribution_v1_saved_seed_keeps_its_whole_noise_polynomial() -> Result<()> {
        let profile = BfvProfile::SyncDecInsecure64;
        let committee = CiphernodesCommitteeSize::Minimum;
        let config_id = profile.crypto_config_id(committee)?;
        // #2542 changed the bound. The old vector describes only the old binary and tuple;
        // accepting either digest for a given configuration would hide a changed opening.
        let vectors = [
            (
                b256!("b1cb9d22ade2378a77048667354ecb1846121df390f57e6bc79b3dd7bcd3ab05"),
                b256!("a91f7beb78c81fe00f7a1501430eb656c921fead55aacb70da8fd0b9ec3a4be4"),
            ),
            (
                b256!("fe0e258735d79bc000f057bbc65136f31e6006884bd8d56f58a43bb236079fd7"),
                b256!("ae91ef8b6391f224678a7dcfd18f15733da9c10c724fce3aff3c4891189981aa"),
            ),
        ];
        let (_, expected) = vectors
            .into_iter()
            .find(|(id, _)| *id == config_id)
            .with_context(|| format!("no v1 sampler vector for {config_id}"))?;
        let coeffs = contribution_noise_v1(profile, committee, &[42; 32])?;
        let values = coeffs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(keccak256(values), expected, "v1 sampler for {config_id}");
        Ok(())
    }
}
