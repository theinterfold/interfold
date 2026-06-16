// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Common Random Polynomial (CRP) construction from BFV parameters.

use fhe::bfv::BfvParameters;
use fhe::mbfv::CommonRandomPoly;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

/// Creates a Common Random Polynomial for the given BFV parameters and seed.
pub fn create_deterministic_crp_from_seed(
    params: &Arc<BfvParameters>,
    seed: [u8; 32],
) -> CommonRandomPoly {
    CommonRandomPoly::new_deterministic(params, seed).unwrap()
}

/// Creates a Common Random Polynomial for the given BFV parameters and default seed.
pub fn create_deterministic_crp_from_default_seed(params: &Arc<BfvParameters>) -> CommonRandomPoly {
    create_deterministic_crp_from_seed(params, <ChaCha8Rng as SeedableRng>::Seed::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_bfv_params_arc;
    use crate::constants::insecure_512;
    use fhe_traits::Serialize;

    #[test]
    fn crp_bytes_roundtrip_via_deserialize() {
        let params = build_bfv_params_arc(
            insecure_512::DEGREE,
            insecure_512::threshold::PLAINTEXT_MODULUS,
            insecure_512::threshold::MODULI,
            Some(insecure_512::threshold::ERROR1_VARIANCE),
        );
        let crp = create_deterministic_crp_from_default_seed(&params);
        let bytes = crp.to_bytes();

        let restored = CommonRandomPoly::deserialize(&bytes, &params)
            .expect("CRP deserialization should succeed");
        let restored_bytes = restored.to_bytes();
        assert_eq!(bytes, restored_bytes, "CRP roundtrip should match");
    }

    #[test]
    fn deterministic_crp_same_seed_same_output() {
        let params = build_bfv_params_arc(
            insecure_512::DEGREE,
            insecure_512::threshold::PLAINTEXT_MODULUS,
            insecure_512::threshold::MODULI,
            Some(insecure_512::threshold::ERROR1_VARIANCE),
        );
        let seed = [42u8; 32];

        let crp1 = create_deterministic_crp_from_seed(&params, seed);
        let crp2 = create_deterministic_crp_from_seed(&params, seed);

        assert_eq!(crp1.to_bytes(), crp2.to_bytes());
    }

    #[test]
    fn deterministic_crp_different_seed_different_output() {
        let params = build_bfv_params_arc(
            insecure_512::DEGREE,
            insecure_512::threshold::PLAINTEXT_MODULUS,
            insecure_512::threshold::MODULI,
            Some(insecure_512::threshold::ERROR1_VARIANCE),
        );
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let crp1 = create_deterministic_crp_from_seed(&params, seed1);
        let crp2 = create_deterministic_crp_from_seed(&params, seed2);

        assert_ne!(crp1.to_bytes(), crp2.to_bytes());
    }
}
