// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public randomness and shape metadata for the l-BFV circuit configuration.

use crate::BfvPreset;

/// Version of the fixed l-BFV public-randomness derivation.
pub const LBFV_CONSTANTS_VERSION: u32 = 1;

/// Return whether the preset has an l-BFV CRS and URS.
#[must_use]
pub fn supports_lbfv(preset: BfvPreset) -> bool {
    lbfv_crs_seed(preset).is_some() && lbfv_urs_seed(preset).is_some()
}

/// Whether an E3 on `preset` runs the l-BFV protocol path. Accepts the threshold preset or its
/// DKG counterpart, which names the same path.
pub fn is_lbfv_path(preset: BfvPreset) -> bool {
    supports_lbfv(preset.threshold_counterpart().unwrap_or(preset))
}

/// Return the number of CRT rows required by the l-BFV preset.
///
/// The row count comes from the threshold parameter metadata. Callers must use
/// this value for proof bundles and aggregation state instead of assuming a
/// fixed secure-preset row count.
#[must_use]
pub fn lbfv_row_count(preset: BfvPreset) -> Option<usize> {
    supports_lbfv(preset).then(|| preset.metadata().num_moduli)
}

/// Return whether a row count belongs to a supported l-BFV preset.
#[must_use]
pub fn is_supported_lbfv_row_count(row_count: usize) -> bool {
    BfvPreset::PAIR_PRESETS
        .iter()
        .copied()
        .filter_map(lbfv_row_count)
        .any(|supported| supported == row_count)
}

/// SHA-256 of `interfold/lbfv/secure-16384/v1/crs`.
pub const SECURE_16384_LBFV_CRS_SEED: [u8; 32] = [
    0x23, 0x5a, 0x38, 0xb7, 0x34, 0xd5, 0xf8, 0x73, 0xbd, 0x8e, 0x54, 0x79, 0xa1, 0x9b, 0x88, 0x03,
    0xe2, 0xc6, 0xf8, 0x2d, 0x76, 0x92, 0x71, 0x34, 0x78, 0x52, 0xd4, 0x1f, 0xc1, 0xbe, 0x8d, 0xb5,
];

/// SHA-256 of `interfold/lbfv/secure-16384/v1/urs`.
pub const SECURE_16384_LBFV_URS_SEED: [u8; 32] = [
    0x1e, 0xf7, 0xb9, 0xcd, 0xfa, 0x8c, 0xc7, 0x3f, 0xa2, 0x9a, 0xf4, 0xc1, 0x89, 0x75, 0xd7, 0x37,
    0xc3, 0x96, 0xab, 0x27, 0x9a, 0xed, 0x56, 0x92, 0xb0, 0x23, 0x5b, 0xfc, 0xcd, 0x77, 0x88, 0x4b,
];

/// SHA-256 of `interfold/lbfv/secure-16384-simd/v1/crs`.
pub const SECURE_16384_SIMD_LBFV_CRS_SEED: [u8; 32] = [
    0xee, 0xc2, 0x78, 0x7b, 0x89, 0xd6, 0x5e, 0xd8, 0x8e, 0xca, 0xbb, 0x90, 0xd6, 0x53, 0x59, 0xb1,
    0x2f, 0x66, 0x7d, 0x76, 0xc4, 0x47, 0x5a, 0x85, 0x9d, 0x6d, 0xef, 0x57, 0x50, 0x96, 0x90, 0x3f,
];

/// SHA-256 of `interfold/lbfv/secure-16384-simd/v1/urs`.
pub const SECURE_16384_SIMD_LBFV_URS_SEED: [u8; 32] = [
    0x74, 0x51, 0xb1, 0xae, 0x09, 0xd7, 0x4d, 0x85, 0x3b, 0x8a, 0xc2, 0x76, 0x28, 0x1b, 0x60, 0xa8,
    0xde, 0x9c, 0x63, 0x94, 0xfa, 0xb9, 0x4c, 0xa1, 0x90, 0xb0, 0x34, 0x27, 0xf4, 0xf8, 0x16, 0xcc,
];

/// SHA-256 of `interfold/lbfv/secure-16384-simd-d6/v1/crs`.
pub const SECURE_16384_SIMD_D6_LBFV_CRS_SEED: [u8; 32] = [
    0xac, 0xdb, 0x45, 0x47, 0x9e, 0xf8, 0xd8, 0xb8, 0x40, 0x51, 0x43, 0xd3, 0x17, 0x81, 0x4a, 0x4d,
    0xc7, 0x64, 0x9f, 0xa2, 0x43, 0x24, 0x51, 0xe9, 0x07, 0x27, 0x8e, 0x8b, 0x52, 0xdc, 0x9f, 0x98,
];

/// SHA-256 of `interfold/lbfv/secure-16384-simd-d6/v1/urs`.
pub const SECURE_16384_SIMD_D6_LBFV_URS_SEED: [u8; 32] = [
    0x13, 0x8b, 0xff, 0x9b, 0x7b, 0x54, 0x79, 0x75, 0xbd, 0x76, 0x2e, 0x25, 0x59, 0x71, 0x6a, 0x9b,
    0x07, 0x81, 0x0c, 0x87, 0x6f, 0xe7, 0x33, 0xcd, 0xbc, 0xf6, 0x13, 0x02, 0xb4, 0xc3, 0x14, 0xf8,
];

/// SHA-256 of `interfold/lbfv/insecure/v1/crs`.
pub const INSECURE_LBFV_CRS_SEED: [u8; 32] = [
    0x7c, 0x5d, 0x1d, 0xda, 0xff, 0x9b, 0x83, 0x6d, 0x39, 0x08, 0x50, 0xe2, 0xc7, 0x2d, 0x0b, 0x2b,
    0xe1, 0x5d, 0xe1, 0xab, 0xb2, 0xe8, 0x19, 0xcc, 0x1b, 0x46, 0x55, 0x84, 0x09, 0x09, 0x9a, 0xab,
];

/// SHA-256 of `interfold/lbfv/insecure/v1/urs`.
pub const INSECURE_LBFV_URS_SEED: [u8; 32] = [
    0xb5, 0x5c, 0xcb, 0x5d, 0x7b, 0x3b, 0x29, 0x6d, 0x48, 0x2f, 0x9a, 0xbd, 0x0f, 0xa5, 0xf6, 0xc5,
    0x9c, 0x9d, 0xcf, 0x38, 0xa1, 0x2c, 0x18, 0x69, 0x00, 0x83, 0x78, 0x46, 0xda, 0xeb, 0xab, 0x0f,
];

/// SHA-256 of `interfold/lbfv/insecure-simd/v1/crs`.
pub const INSECURE_SIMD_LBFV_CRS_SEED: [u8; 32] = [
    0xce, 0x0e, 0x2a, 0xff, 0xf8, 0x53, 0xc8, 0x93, 0xd0, 0xe9, 0xb1, 0x2e, 0xcf, 0x97, 0x92, 0xe8,
    0xb8, 0x18, 0x36, 0xf3, 0xb1, 0x8f, 0x72, 0xb6, 0x68, 0x19, 0x3d, 0x4a, 0xcb, 0x62, 0x95, 0xc4,
];

/// SHA-256 of `interfold/lbfv/insecure-simd/v1/urs`.
pub const INSECURE_SIMD_LBFV_URS_SEED: [u8; 32] = [
    0x3a, 0x58, 0x97, 0x31, 0x03, 0x19, 0x43, 0x11, 0x94, 0x65, 0x60, 0xcd, 0xd2, 0x4b, 0x9f, 0x3b,
    0x81, 0x07, 0x5a, 0xd8, 0x26, 0x65, 0x16, 0xdc, 0xd2, 0x5b, 0xca, 0xa1, 0x3a, 0xee, 0xd2, 0x23,
];

/// Return the fixed l-BFV CRS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_crs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
        BfvPreset::InsecureThresholdLbfv => Some(INSECURE_LBFV_CRS_SEED),
        BfvPreset::InsecureThresholdSimd => Some(INSECURE_SIMD_LBFV_CRS_SEED),
        BfvPreset::SecureThreshold16384 => Some(SECURE_16384_LBFV_CRS_SEED),
        BfvPreset::SecureThreshold16384Simd => Some(SECURE_16384_SIMD_LBFV_CRS_SEED),
        BfvPreset::SecureThreshold16384SimdD6 => Some(SECURE_16384_SIMD_D6_LBFV_CRS_SEED),
        _ => None,
    }
}

/// Return the fixed l-BFV URS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_urs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
        BfvPreset::InsecureThresholdLbfv => Some(INSECURE_LBFV_URS_SEED),
        BfvPreset::InsecureThresholdSimd => Some(INSECURE_SIMD_LBFV_URS_SEED),
        BfvPreset::SecureThreshold16384 => Some(SECURE_16384_LBFV_URS_SEED),
        BfvPreset::SecureThreshold16384Simd => Some(SECURE_16384_SIMD_LBFV_URS_SEED),
        BfvPreset::SecureThreshold16384SimdD6 => Some(SECURE_16384_SIMD_D6_LBFV_URS_SEED),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::CommonRandomPolyVec;

    #[test]
    fn fixed_seeds_are_domain_separated() {
        assert_ne!(SECURE_16384_LBFV_CRS_SEED, SECURE_16384_LBFV_URS_SEED);
        assert_ne!(
            SECURE_16384_SIMD_LBFV_CRS_SEED,
            SECURE_16384_SIMD_LBFV_URS_SEED
        );
        assert_ne!(SECURE_16384_SIMD_LBFV_CRS_SEED, SECURE_16384_LBFV_CRS_SEED);
        assert_ne!(SECURE_16384_SIMD_LBFV_URS_SEED, SECURE_16384_LBFV_URS_SEED);
        assert_ne!(
            SECURE_16384_SIMD_D6_LBFV_CRS_SEED,
            SECURE_16384_SIMD_D6_LBFV_URS_SEED
        );
        assert_ne!(
            SECURE_16384_SIMD_D6_LBFV_CRS_SEED,
            SECURE_16384_SIMD_LBFV_CRS_SEED
        );
        assert_ne!(
            SECURE_16384_SIMD_D6_LBFV_URS_SEED,
            SECURE_16384_SIMD_LBFV_URS_SEED
        );
    }

    #[test]
    fn supported_lbfv_presets_are_enabled() {
        assert!(lbfv_crs_seed(BfvPreset::InsecureThresholdLbfv).is_some());
        assert!(lbfv_crs_seed(BfvPreset::InsecureThresholdSimd).is_some());
        assert!(lbfv_urs_seed(BfvPreset::InsecureThresholdSimd).is_some());
        assert_ne!(
            lbfv_crs_seed(BfvPreset::InsecureThresholdSimd),
            lbfv_crs_seed(BfvPreset::InsecureThresholdLbfv)
        );
        assert!(is_lbfv_path(BfvPreset::InsecureDkgSimd));
        assert_eq!(lbfv_row_count(BfvPreset::InsecureThresholdSimd), Some(3));
        assert!(lbfv_crs_seed(BfvPreset::InsecureThreshold64).is_none());
        assert!(lbfv_urs_seed(BfvPreset::InsecureThresholdLbfv).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_urs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold16384Simd).is_some());
        assert!(lbfv_urs_seed(BfvPreset::SecureThreshold16384Simd).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold16384SimdD6).is_some());
        assert!(lbfv_urs_seed(BfvPreset::SecureThreshold16384SimdD6).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold8192).is_none());
        assert!(lbfv_urs_seed(BfvPreset::InsecureDkg64).is_none());
        assert!(is_lbfv_path(BfvPreset::InsecureDkgLbfv));
        assert!(is_lbfv_path(BfvPreset::SecureDkg16384));
        assert!(is_lbfv_path(BfvPreset::SecureDkg16384Simd));
        assert!(is_lbfv_path(BfvPreset::SecureDkg16384SimdD6));
        assert!(!is_lbfv_path(BfvPreset::InsecureDkg64));
        assert!(!is_lbfv_path(BfvPreset::SecureDkg8192));
        assert_eq!(lbfv_row_count(BfvPreset::InsecureThresholdLbfv), Some(3));
        assert_eq!(lbfv_row_count(BfvPreset::InsecureThreshold64), None);
        assert_eq!(lbfv_row_count(BfvPreset::SecureThreshold16384), Some(5));
        assert_eq!(lbfv_row_count(BfvPreset::SecureThreshold16384Simd), Some(5));
        assert_eq!(
            lbfv_row_count(BfvPreset::SecureThreshold16384SimdD6),
            Some(8)
        );
        assert_eq!(lbfv_row_count(BfvPreset::SecureThreshold8192), None);
        assert!(is_supported_lbfv_row_count(3));
        assert!(is_supported_lbfv_row_count(5));
        assert!(!is_supported_lbfv_row_count(4));
    }

    #[test]
    fn seeded_vectors_have_independent_slots() {
        let params = crate::BfvParamSet::from(BfvPreset::InsecureThresholdLbfv).build_arc();
        let crs = CommonRandomPolyVec::from_seed(&params, INSECURE_LBFV_CRS_SEED)
            .expect("CRS seed must produce a valid vector");
        let urs = CommonRandomPolyVec::from_seed(&params, INSECURE_LBFV_URS_SEED)
            .expect("URS seed must produce a valid vector");

        assert_eq!(crs.len(), 3);
        assert_eq!(urs.len(), 3);
        assert_ne!(crs.to_polys()[0], crs.to_polys()[1]);
        assert_ne!(urs.to_polys()[0], urs.to_polys()[1]);
        assert_ne!(crs.to_polys(), urs.to_polys());
    }
}
