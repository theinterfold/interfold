// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_config::DkgInputType;
use e3_zk_witness::dkg::share_computation::ShareComputationCircuitData;

use crate::ZkError;

#[derive(Debug)]
pub struct ShareComputationCircuit;

impl Provable for ShareComputationCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        let _ = (config, input);
        Err(ZkError::InputsGenerationFailed(
            "C2 is proven as a chunk chain; its final inputs need the batch proofs".into(),
        ))
    }

    /// Proves the chunk chain, its batches and the final C2 proof (see
    /// [`crate::circuits::aggregation::c2_chain`]).
    fn prove_with_variant(
        &self,
        prover: &crate::ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<e3_events::Proof, ZkError> {
        crate::circuits::aggregation::c2_chain::prove_share_computation_chain(
            prover,
            config,
            input,
            e3_id,
            variant,
            artifacts_dir,
        )
    }

    type Config = e3_zk_config::dkg::share_computation::Configs;
    type Input = ShareComputationCircuitData;

    fn resolve_circuit_name(&self, _config: &Self::Config, input: &Self::Input) -> CircuitName {
        match input.dkg_input_type {
            DkgInputType::SecretKey => CircuitName::SkShareComputation,
            DkgInputType::SmudgingNoise => CircuitName::ESmShareComputation,
        }
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![
            CircuitName::SkShareComputation,
            CircuitName::ESmShareComputation,
        ]
    }

    fn circuit(&self) -> CircuitName {
        CircuitName::SkShareComputation
    }
}
