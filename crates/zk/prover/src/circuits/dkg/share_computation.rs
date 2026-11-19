// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use e3_zk_config::CircuitName;
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
            "C2 is proven as a chunk chain; its final inputs need the chunk proofs".into(),
        ))
    }

    /// Proves the chunk chain and the final C2 proof (see
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

    /// Verifies the final C2 proof and its chunk key tree. The final circuit verifies its chunk
    /// proofs against keys it only exposes as a hash, so a valid outer proof alone does not show
    /// the chunks ran this node's chunk circuits.
    fn verify_with_variant(
        &self,
        prover: &crate::ZkProver,
        proof: &e3_events::Proof,
        e3_id: &str,
        party_id: u64,
        variant: e3_events::CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        if !self.valid_circuits().contains(&proof.circuit) {
            return Err(ZkError::VerifyFailed(format!(
                "circuit mismatch: expected one of {:?}, got {}",
                self.valid_circuits(),
                proof.circuit
            )));
        }
        Ok(
            prover.verify_proof_with_variant(proof, e3_id, party_id, variant, artifacts_dir)?
                && crate::circuits::aggregation::chain_keys::check_key_tree(
                    prover,
                    proof,
                    artifacts_dir,
                )?,
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
