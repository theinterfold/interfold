// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_zk_config::CircuitName;
use e3_zk_witness::dkg::share_decryption::{Inputs, ShareDecryptionCircuitData};

use crate::ZkError;

#[derive(Debug)]
pub struct ShareDecryptionCircuit;

impl Provable for ShareDecryptionCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        // The l-BFV chunked C4 is one proof; the trBFV C4 is a limb chain.
        if !e3_fhe_params::is_lbfv_path(config.preset) {
            return Err(ZkError::InputsGenerationFailed(
                "C4 is proven as a limb chain; its final inputs need the limb proofs".into(),
            ));
        }
        let inputs = Inputs::compute(config, input)
            .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&inputs.to_json())
    }

    /// On the trBFV path, proves the limb chain and the final C4 proof (see
    /// [`crate::circuits::aggregation::c4_chain`]); on the l-BFV path, the one chunked C4 proof.
    fn prove_with_variant(
        &self,
        prover: &crate::ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<e3_events::Proof, ZkError> {
        if e3_fhe_params::is_lbfv_path(config.preset) {
            return crate::traits::prove_single_circuit(
                self,
                prover,
                config,
                input,
                e3_id,
                variant,
                artifacts_dir,
            );
        }
        crate::circuits::aggregation::c4_chain::prove_share_decryption_chain(
            prover,
            config,
            input,
            e3_id,
            variant,
            artifacts_dir,
        )
    }

    type Config = e3_zk_config::dkg::share_decryption::Configs;
    type Input = ShareDecryptionCircuitData;

    fn circuit(&self) -> CircuitName {
        CircuitName::DkgShareDecryption
    }
    fn resolve_circuit_name(&self, config: &Self::Config, _input: &Self::Input) -> CircuitName {
        if e3_fhe_params::is_lbfv_path(config.preset) {
            CircuitName::DkgShareDecryptionChunked
        } else {
            CircuitName::DkgShareDecryption
        }
    }
    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![
            CircuitName::DkgShareDecryption,
            CircuitName::DkgShareDecryptionChunked,
        ]
    }
}
