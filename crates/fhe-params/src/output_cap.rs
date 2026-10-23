// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Per-preset cap on the decrypted plaintext coefficients that the decryption circuits publish.

use crate::presets::BfvPreset;

/// Cap used by every preset except the SIMD preset. It is compiled into the C6/C7 circuits and the
/// on-chain decryption verifier, so changing it changes their verification keys.
pub const DEFAULT_MAX_MSG_NON_ZERO_COEFFS: usize = 50;

/// Cap of the SIMD preset: one coefficient per ring slot (N = 128).
pub const SIMD_MAX_MSG_NON_ZERO_COEFFS: usize = 128;

impl BfvPreset {
    /// Number of plaintext coefficients the decryption circuits publish for this preset.
    ///
    /// This value MUST equal `MAX_MSG_NON_ZERO_COEFFS` in `circuits/lib/src/configs/default/mod.nr`
    /// generated for the preset and `messageCoeffsCount` of the `BfvDecryptionVerifier` deployed
    /// for its on-chain parameter set. Threshold and DKG presets of a pair return the same value.
    pub fn max_msg_non_zero_coeffs(&self) -> usize {
        match self {
            BfvPreset::InsecureThresholdSimd | BfvPreset::InsecureDkgSimd => {
                SIMD_MAX_MSG_NON_ZERO_COEFFS
            }
            BfvPreset::InsecureThreshold64
            | BfvPreset::InsecureThresholdLbfv
            | BfvPreset::InsecureDkg64
            | BfvPreset::InsecureDkgLbfv
            | BfvPreset::SecureThreshold8192
            | BfvPreset::SecureThreshold16384
            | BfvPreset::SecureDkg8192
            | BfvPreset::SecureDkg16384 => DEFAULT_MAX_MSG_NON_ZERO_COEFFS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simd_pair_publishes_every_ring_slot() {
        assert_eq!(
            BfvPreset::InsecureThresholdSimd.max_msg_non_zero_coeffs(),
            128
        );
        assert_eq!(BfvPreset::InsecureDkgSimd.max_msg_non_zero_coeffs(), 128);
    }

    #[test]
    fn existing_presets_keep_the_compiled_cap() {
        for preset in BfvPreset::ALL {
            if matches!(
                preset,
                BfvPreset::InsecureThresholdSimd | BfvPreset::InsecureDkgSimd
            ) {
                continue;
            }
            assert_eq!(preset.max_msg_non_zero_coeffs(), 50, "{preset:?}");
        }
    }
}
