// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunked C4: proves the limb chain of `lib::core::dkg::share_decryption_chain`, then the final
//! `share_decryption` proof that verifies every limb and that peers and `c4ab_fold` consume. The
//! limb proofs never leave this node, so they are non-ZK; the final proof is a ZK proof of the same
//! circuit name as the unchunked C4.

use super::c2_chain::{load_compiled, prove_circuit};
use crate::circuits::utils::bytes_to_field_strings;
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::CompiledCircuit;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_zk_config::dkg::share_decryption::Configs;
use e3_zk_witness::dkg::share_decryption::{Inputs, ShareDecryptionCircuitData};
use e3_zk_witness::dkg::share_decryption_chain::LimbChain;
use e3_zk_witness::encoding::bigint_2d_to_json_values;
use serde_json::{json, Value};

/// The limb circuits of the final C4 circuit, loaded for proving: each limb's compiled program and
/// its `default` key, in limb order.
pub struct LimbCircuits(Vec<(CircuitName, CompiledCircuit, vk::VkArtifacts)>);

impl LimbCircuits {
    /// Loads the limb circuits of the final C4 circuit.
    pub fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        super::chain_keys::chunk_circuits(CircuitName::DkgShareDecryption)
            .expect("the final C4 circuit is chunked")
            .iter()
            .map(|&circuit| {
                Ok((
                    circuit,
                    load_compiled(prover, circuit, CircuitVariant::Default, artifacts_dir)?,
                    vk::load_vk_artifacts(&default_dir, circuit)?,
                ))
            })
            .collect::<Result<_, ZkError>>()
            .map(Self)
    }
}

/// Proves the limb chain of C4 for `input` with `limbs` and returns the final circuit's inputs: the
/// expected commitments, plus the limb keys, proofs and links.
pub fn final_share_decryption_inputs(
    prover: &ZkProver,
    config: &Configs,
    input: &ShareDecryptionCircuitData,
    limbs: &LimbCircuits,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Value, ZkError> {
    let inputs = Inputs::compute(config, input)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let chain = LimbChain::compute(config, &inputs)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    if limbs.0.len() != chain.limbs.len() {
        return Err(ZkError::InvalidInput(format!(
            "C4 has {} limb circuits for {} limbs",
            limbs.0.len(),
            chain.limbs.len()
        )));
    }

    let mut limb_vks = Vec::with_capacity(limbs.0.len());
    let mut limb_key_hashes = Vec::with_capacity(limbs.0.len());
    let mut limb_proofs = Vec::with_capacity(limbs.0.len());
    let mut limb_links = Vec::with_capacity(limbs.0.len());
    for (l, (limb, (circuit, compiled, key))) in chain.limbs.iter().zip(&limbs.0).enumerate() {
        let job_id = format!("{e3_id}-c4-limb-{l}");
        let proof = prove_circuit(
            prover,
            *circuit,
            compiled,
            CircuitVariant::Default,
            &limb.to_json(),
            &job_id,
            artifacts_dir,
        )?;
        let _ = prover.cleanup(&job_id);
        // Public: the limb's H commitments, then `h_in` and its output.
        let publics = bytes_to_field_strings(&proof.public_signals)?;
        let expected = inputs.expected_commitments.len() + 2;
        if publics.len() != expected {
            return Err(ZkError::InvalidInput(format!(
                "C4 limb {l} proof has {} public inputs, expected {expected} (H + 2)",
                publics.len()
            )));
        }
        limb_vks.push(&key.verification_key);
        limb_key_hashes.push(&key.key_hash);
        limb_proofs.push(bytes_to_field_strings(&proof.data)?);
        limb_links.push(publics[expected - 2..].to_vec());
    }

    // The final circuit reads only the commitments and the limb proofs; the decrypted shares stay in
    // the limb witnesses.
    Ok(json!({
        "expected_commitments": bigint_2d_to_json_values(&inputs.expected_commitments),
        "limb_vks": limb_vks,
        "limb_key_hashes": limb_key_hashes,
        "limb_proofs": limb_proofs,
        "limb_links": limb_links,
    }))
}

/// Proves C4 for `input` as a limb chain and returns the final proof.
pub fn prove_share_decryption_chain(
    prover: &ZkProver,
    config: &Configs,
    input: &ShareDecryptionCircuitData,
    e3_id: &str,
    variant: CircuitVariant,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let limbs = LimbCircuits::load(prover, artifacts_dir)?;
    let final_inputs =
        final_share_decryption_inputs(prover, config, input, &limbs, e3_id, artifacts_dir)?;
    let circuit = CircuitName::DkgShareDecryption;
    let compiled = load_compiled(prover, circuit, variant, artifacts_dir)?;
    prove_circuit(
        prover,
        circuit,
        &compiled,
        variant,
        &final_inputs,
        e3_id,
        artifacts_dir,
    )
}
