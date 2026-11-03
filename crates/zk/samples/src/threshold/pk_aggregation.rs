// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample data generation for pk aggregation circuit.
//!
//! The sample contains random BFV public key shares from H honest parties and the aggregated public key;
//! the public key shares and aggregated public key are used as input for codegen and tests.

use e3_fhe_params::create_deterministic_crp_from_default_seed;
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::threshold::pk_aggregation::Configs;
use e3_zk_witness::{threshold::pk_aggregation::PkAggregationCircuitData, WitnessError};
use fhe::bfv::{PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare};

pub fn generate(config: &Configs) -> Result<PkAggregationCircuitData, WitnessError> {
    let threshold_params = &config.params;
    let mut rng = rand::rng();

    let crp = create_deterministic_crp_from_default_seed(threshold_params);

    // Generate public key shares for each party
    let mut pk_shares = Vec::with_capacity(config.committee.values().h);
    let mut pk0_shares = Vec::with_capacity(config.committee.values().h);

    for _ in 0..config.committee.values().h {
        let sk = SecretKey::random(threshold_params, &mut rng);
        // Create PublicKeyShare - this generates the p0_share with a specific error term
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut rng).map_err(|e| {
            WitnessError::Sample(format!("Failed to create public key share: {:?}", e))
        })?;

        // Extract the p0_share Poly from the PublicKeyShare
        // This ensures we use the same error term for both aggregation and vector extraction
        let pk0_share = CrtPolynomial::from_fhe_polynomial(pk_share.p0_share());

        pk_shares.push(pk_share);
        pk0_shares.push(pk0_share);
    }

    // Aggregate public key shares to get the full public key
    let public_key: PublicKey = pk_shares
        .into_iter()
        .aggregate()
        .map_err(|e| WitnessError::Sample(format!("Failed to aggregate public key: {:?}", e)))?;

    Ok(PkAggregationCircuitData {
        public_key,
        pk0_shares,
    })
}

#[cfg(test)]
mod tests {
    use super::generate;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_zk_witness::threshold::pk_aggregation::Inputs;

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_generate_sample() {
        let preset = BfvPreset::InsecureThreshold;
        let committee = CiphernodesCommitteeSize::Small;
        let configs =
            e3_zk_config::threshold::pk_aggregation::Configs::for_preset(preset, committee)
                .unwrap();

        let sample = generate(&configs).unwrap();
        let inputs = Inputs::compute(&configs, &sample).unwrap();

        assert_eq!(inputs.pk0.len(), committee.values().h);
        assert_eq!(inputs.pk0_agg.limbs.len(), configs.params.moduli().len());
    }
}
