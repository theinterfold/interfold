// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for user data encryption circuit.
//!
//! The sample contains a random BFV key pair on the protocol CRS and a plaintext; the public key and
//! plaintext are used as input for codegen and tests.

use e3_zk_witness::{
    threshold::user_data_encryption::{public_key_on_protocol_crs, UserDataEncryptionCircuitData},
    WitnessError,
};
use fhe::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
use fhe_traits::FheEncoder;
use std::sync::Arc;

/// Generates a random secret key, a public key on the protocol CRS, and a plaintext for the given BFV parameters.
pub fn generate(
    threshold_params: &Arc<BfvParameters>,
) -> Result<UserDataEncryptionCircuitData, WitnessError> {
    let mut rng = rand::rng();

    let secret_key = SecretKey::random(threshold_params, &mut rng);
    // ct1 hard-codes the protocol CRS as `pk1`, so the sample key must be built on it.
    let public_key = public_key_on_protocol_crs(threshold_params, &secret_key, &mut rng)
        .map_err(|e| WitnessError::Sample(format!("Failed to build public key: {:?}", e)))?;

    let plaintext = Plaintext::try_encode(&[1u64], Encoding::poly(), threshold_params)
        .map_err(|e| WitnessError::Sample(format!("Failed to encode plaintext: {:?}", e)))?;

    Ok(UserDataEncryptionCircuitData {
        public_key,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_fhe_params::BfvPreset;
    use fhe::bfv::Encoding;
    use fhe_traits::FheDecoder;

    #[test]
    fn test_generate_sample() {
        let config = e3_zk_config::threshold::user_data_encryption::Configs::for_preset(
            BfvPreset::InsecureThreshold64,
        )
        .unwrap();
        let sample = generate(&config.params).unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
        assert_eq!(
            Vec::<u64>::try_decode(&sample.plaintext, Encoding::poly())
                .unwrap()
                .len(),
            BfvPreset::InsecureThreshold64.metadata().degree
        );
    }
}
