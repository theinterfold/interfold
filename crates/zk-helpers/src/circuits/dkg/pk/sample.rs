// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the pk circuit: committee and DKG public key only.

use crate::dkg::pk::PkCircuitData;
use crate::CircuitsErrors;
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use fhe::bfv::{PublicKey, SecretKey};

impl PkCircuitData {
    /// Generates sample data for the pk circuit.
    pub fn generate_sample(preset: BfvPreset) -> Result<Self, CircuitsErrors> {
        let (_, dkg_params) = build_pair_for_preset(preset).map_err(|e| {
            CircuitsErrors::Sample(format!("Failed to build pair for preset: {:?}", e))
        })?;

        let mut rng = rand::rng();
        let dkg_secret_key = SecretKey::random(&dkg_params, &mut rng);
        let dkg_public_key = PublicKey::new(&dkg_secret_key, &mut rng);

        Ok(Self {
            public_key: dkg_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::dkg::pk::PkCircuitData;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_pk_sample() {
        let sample = PkCircuitData::generate_sample(BfvPreset::InsecureThreshold512).unwrap();

        assert_eq!(sample.public_key.c.len(), 2);
    }
}
