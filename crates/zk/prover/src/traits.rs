// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::Proof;
use e3_zk_config::{CircuitName, CircuitVariant};
use noirc_abi::InputMap;

/// Trait for types that can generate ZK proofs.
///
/// Implementors specify the circuit, config, and input types.
/// Each family adapter prepares its witness with one circuit-specific configuration.
/// The shared proof methods execute Noir and invoke the prover backend.
pub trait Provable: Send + Sync {
    type Config: Send + Sync + Clone;
    type Input: Send + Sync;

    fn circuit(&self) -> CircuitName;

    /// Override this to select a circuit variant based on config and input.
    /// Default just returns the standard circuit name.
    fn resolve_circuit_name(&self, _config: &Self::Config, _input: &Self::Input) -> CircuitName {
        self.circuit()
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![self.circuit()]
    }

    fn build_inputs(&self, config: &Self::Config, input: &Self::Input)
        -> Result<InputMap, ZkError>;

    fn prove(
        &self,
        prover: &ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        self.prove_with_variant(
            prover,
            config,
            input,
            e3_id,
            CircuitVariant::Recursive,
            artifacts_dir,
        )
    }

    fn prove_with_variant(
        &self,
        prover: &ZkProver,
        config: &Self::Config,
        input: &Self::Input,
        e3_id: &str,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<Proof, ZkError> {
        prove_single_circuit(self, prover, config, input, e3_id, variant, artifacts_dir)
    }

    fn verify(
        &self,
        prover: &ZkProver,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        self.verify_with_variant(
            prover,
            proof,
            e3_id,
            party_id,
            CircuitVariant::Recursive,
            artifacts_dir,
        )
    }

    fn verify_with_variant(
        &self,
        prover: &ZkProver,
        proof: &Proof,
        e3_id: &str,
        party_id: u64,
        variant: CircuitVariant,
        artifacts_dir: &str,
    ) -> Result<bool, ZkError> {
        if !self.valid_circuits().contains(&proof.circuit) {
            return Err(ZkError::VerifyFailed(format!(
                "circuit mismatch: expected one of {:?}, got {}",
                self.valid_circuits(),
                proof.circuit
            )));
        }

        println!(
            "Verifying proof for circuit {} with e3_id {} and party_id {}",
            proof.circuit, e3_id, party_id
        );
        prover.verify_proof_with_variant(proof, e3_id, party_id, variant, artifacts_dir)
    }
}

/// Proves `input` with the one circuit [`Provable::resolve_circuit_name`] selects, from
/// [`Provable::build_inputs`]. This is the default [`Provable::prove_with_variant`]; a circuit that
/// proves a chain on one path calls it for its other path.
pub(crate) fn prove_single_circuit<P: Provable + ?Sized>(
    provable: &P,
    prover: &ZkProver,
    config: &P::Config,
    input: &P::Input,
    e3_id: &str,
    variant: CircuitVariant,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let inputs = provable.build_inputs(config, input)?;

    let resolved_name = provable.resolve_circuit_name(config, input);
    let circuit_path = prover
        .circuits_dir(variant, artifacts_dir)
        .join(resolved_name.dir_path())
        .join(format!("{}.json", resolved_name.as_str()));

    let circuit = CompiledCircuit::from_file(&circuit_path)?;

    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&circuit, inputs)?;

    prover.generate_proof_with_variant(resolved_name, &witness, e3_id, variant, artifacts_dir)
}
