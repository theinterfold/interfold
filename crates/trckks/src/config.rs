// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksParameters;
use fhe_traits::Deserialize as FheDeserialize;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Threshold CKKS configuration: serialized parameters plus the committee
/// shape. The analogue of `e3_trbfv::TrBFVConfig`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrCkksConfig {
    /// Serialized CKKS parameters (`CkksParameters::to_bytes`).
    params: ArcBytes,
    /// Number of ciphernodes.
    num_parties: u64,
    /// Threshold (t+1 parties reconstruct).
    threshold: u64,
}

impl TrCkksConfig {
    /// Create a new config.
    pub fn new(params: ArcBytes, num_parties: u64, threshold: u64) -> Self {
        Self {
            params,
            num_parties,
            threshold,
        }
    }

    /// Decode the CKKS parameters.
    pub fn params(&self) -> Result<Arc<CkksParameters>> {
        Ok(Arc::new(
            CkksParameters::try_deserialize(&self.params)
                .context("failed to decode CKKS params")?,
        ))
    }

    pub fn num_parties(&self) -> u64 {
        self.num_parties
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }
}

/// The dev/insecure CKKS parameter preset: N=512, two 45-bit moduli, scale
/// 2^40. Matches the shape of the BFV `insecure-512` preset. NOT SECURE.
pub fn insecure_512_params() -> Result<Arc<CkksParameters>> {
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build insecure CKKS params")
}

/// Params for the iterated sign-extraction auction policy: delta = 2^40
/// over one 45-bit base modulus plus `1 + 3*iterations` 40-bit rescale
/// limbs (pack consumes one level, each cubic iteration three). Rescaling
/// by a ~2^40 limb keeps the working scale pinned near delta across
/// iterations. HYBRID key switching is enabled with the on-chain
/// ParamSet-2 special primes (`k = 3` × 60 bits): ONE
/// `CkksHybridRelinKey` relinearizes at every level of the ladder. NOT
/// SECURE (N=512) — demo/testing only.
pub fn sign_extraction_params(iterations: usize) -> Result<Arc<CkksParameters>> {
    let mut sizes = vec![45usize];
    sizes.extend(std::iter::repeat_n(40usize, 1 + 3 * iterations));
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&sizes)
        .set_special_moduli_sizes(&e3_fhe_params::ckks_presets::SIGN_EXTRACTION_SPECIAL_MODULI_BITS)
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build sign-extraction CKKS params")
}

/// Three-limb variant for circuits with one multiplication level (auction
/// masking, statistics sum-of-squares). NOT SECURE.
pub fn insecure_512_mul_params() -> Result<Arc<CkksParameters>> {
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build insecure CKKS mul params")
}

/// DKG-transport-compatible statistics params (on-chain ParamSet 3):
/// three 36-bit NTT-friendly primes ALL ≤ the standard `InsecureDkg512`
/// plaintext modulus (0xffffee001), scale 2^30. One genuine ct×ct
/// multiplication level for the relinearized sum-of-squares — the
/// smallest preset the salary-survey statistics policy runs on without
/// the wide DKG escalation. NOT SECURE (N=512) — demo/testing only.
pub fn statistics_transport_params() -> Result<Arc<CkksParameters>> {
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001, 0xffffbe001])
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build statistics transport CKKS params")
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe_traits::Serialize as _;

    /// The on-chain ParamSet 2 ladder (e3-fhe-params, which cannot depend
    /// on this crate) must stay byte-identical to
    /// `sign_extraction_params(SIGN_EXTRACTION_ITERATIONS)` — the params
    /// the sign-extraction policy and its e2e test are built against.
    #[test]
    fn on_chain_param_set_2_matches_sign_extraction_params() {
        let ours = sign_extraction_params(e3_fhe_params::ckks_presets::SIGN_EXTRACTION_ITERATIONS)
            .unwrap();
        let on_chain = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(2).unwrap();
        assert_eq!(
            ours.to_bytes(),
            on_chain.to_bytes(),
            "ParamSet-2 ladder drifted from sign_extraction_params"
        );
    }

    /// The on-chain ParamSet 3 statistics preset must stay byte-identical
    /// to `statistics_transport_params` — the params the statistics
    /// policy's workflow e2e and the salary-survey demo run on.
    #[test]
    fn on_chain_param_set_3_matches_statistics_transport_params() {
        let ours = statistics_transport_params().unwrap();
        let on_chain = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(3).unwrap();
        assert_eq!(
            ours.to_bytes(),
            on_chain.to_bytes(),
            "ParamSet-3 statistics params drifted from statistics_transport_params"
        );
    }
}
