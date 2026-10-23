// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for the pk circuit: committee and DKG public key only.

use e3_zk_witness::WitnessError;
use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use std::sync::Arc;

/// Generates sample data for the pk circuit.
pub fn generate(dkg_params: &Arc<BfvParameters>) -> Result<PublicKey, WitnessError> {
    let mut rng = rand::rng();
    Ok(PublicKey::new(
        &SecretKey::random(dkg_params, &mut rng),
        &mut rng,
    ))
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_pk_sample() {
        let config =
            e3_zk_config::dkg::pk::Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let sample = generate(&config.params).unwrap();

        assert_eq!(sample.c.len(), 2);
    }
}
