// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fixed public randomness for the l-BFV circuit configuration.

use crate::BfvPreset;

/// Version of the fixed l-BFV public-randomness derivation.
pub const LBFV_CONSTANTS_VERSION: u32 = 1;

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

/// Return the fixed l-BFV CRS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_crs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
        BfvPreset::SecureThreshold16384 => Some(SECURE_16384_LBFV_CRS_SEED),
        _ => None,
    }
}

/// Return the fixed l-BFV URS seed for a supported threshold preset.
#[must_use]
pub const fn lbfv_urs_seed(preset: BfvPreset) -> Option<[u8; 32]> {
    match preset {
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
    fn only_secure_16384_is_enabled() {
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_urs_seed(BfvPreset::SecureThreshold16384).is_some());
        assert!(lbfv_crs_seed(BfvPreset::SecureThreshold8192).is_none());
        assert!(lbfv_urs_seed(BfvPreset::InsecureThreshold512).is_none());
    }

    #[test]
    fn seeded_vectors_have_independent_slots() {
        let params = crate::build_bfv_params_arc(
            512,
            100,
            crate::constants::insecure_512::threshold::MODULI,
            Some(crate::constants::insecure_512::threshold::ERROR1_VARIANCE),
        );
        let crs = CommonRandomPolyVec::from_seed(&params, SECURE_16384_LBFV_CRS_SEED)
            .expect("CRS seed must produce a valid vector");
        let urs = CommonRandomPolyVec::from_seed(&params, SECURE_16384_LBFV_URS_SEED)
            .expect("URS seed must produce a valid vector");

        assert_eq!(crs.len(), 2);
        assert_eq!(urs.len(), 2);
        assert_ne!(crs.to_polys()[0], crs.to_polys()[1]);
        assert_ne!(urs.to_polys()[0], urs.to_polys()[1]);
        assert_ne!(crs.to_polys(), urs.to_polys());
    }
}
