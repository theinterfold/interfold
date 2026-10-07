// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for user data encryption circuit.
//!
//! [`Sample`] produces a random BFV key pair and plaintext; the public key and plaintext are used as input
//! for codegen and tests.

use crate::{
    threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData, CircuitsErrors,
};
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use fhe::bfv::{Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::FheEncoder;

impl UserDataEncryptionCircuitData {
    /// Generates a random secret key, public key, and plaintext for the given BFV parameters.
    pub fn generate_sample(preset: BfvPreset) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;

        let mut rng = rand::rng();

        let secret_key = SecretKey::random(&threshold_params, &mut rng);
        let public_key = PublicKey::new(&secret_key, &mut rng);

        let plaintext = Plaintext::try_encode(&[1u64], Encoding::poly(), &threshold_params)
            .map_err(|e| CircuitsErrors::Sample(format!("Failed to encode plaintext: {:?}", e)))?;

        Ok(Self {
            public_key,
            plaintext,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_sample() {
        let sample =
            UserDataEncryptionCircuitData::generate_sample(BfvPreset::InsecureThreshold512)
                .unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(
            crate::math::plaintext_poly_u64(&sample.plaintext)
                .unwrap()
                .len(),
            BfvPreset::InsecureThreshold512.metadata().degree
        );
    }
}
