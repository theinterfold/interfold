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

/// Return the fixed l-BFV CRS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_crs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
        BfvPreset::InsecureThreshold512 => Some(INSECURE_LBFV_CRS_SEED),
        BfvPreset::SecureThreshold16384 => Some(SECURE_16384_LBFV_CRS_SEED),
        _ => None,
    }
}

/// Return the fixed l-BFV URS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_urs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
        BfvPreset::InsecureThreshold512 => Some(INSECURE_LBFV_URS_SEED),
        BfvPreset::SecureThreshold16384 => Some(SECURE_16384_LBFV_URS_SEED),
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
    }

    #[test]
    fn supported_lbfv_presets_are_enabled() {
        assert!(lbfv_crs_seed(BfvPreset::InsecureThreshold512).is_some());
        assert!(lbfv_urs_seed(BfvPreset::InsecureThreshold512).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_urs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold8192).is_none());
        assert!(lbfv_urs_seed(BfvPreset::InsecureDkg512).is_none());
        assert_eq!(lbfv_row_count(BfvPreset::InsecureThreshold512), Some(3));
        assert_eq!(lbfv_row_count(BfvPreset::SecureThreshold16384), Some(5));
        assert_eq!(lbfv_row_count(BfvPreset::SecureThreshold8192), None);
        assert!(is_supported_lbfv_row_count(3));
        assert!(is_supported_lbfv_row_count(5));
        assert!(!is_supported_lbfv_row_count(4));
    }

    #[test]
    fn seeded_vectors_have_independent_slots() {
        let params = crate::BfvParamSet::from(BfvPreset::InsecureThreshold512).build_arc();
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
