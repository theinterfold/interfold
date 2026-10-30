// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chunked C4: proves the limb chain of `lib::core::dkg::share_decryption_chain`, then the final
//! `share_decryption` proof that verifies every limb and that peers and `c4ab_fold` consume. The
//! limb proofs never leave this node, so they are non-ZK; the final proof is a ZK proof of the same
//! circuit name as the unchunked C4.

use super::c2_chain::prove_circuit;
use super::chain_keys::chunk_circuits;
use crate::circuits::utils::bytes_to_field_strings;
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_zk_config::dkg::share_decryption::Configs;
use e3_zk_witness::dkg::share_decryption::{Inputs, ShareDecryptionCircuitData};
use e3_zk_witness::dkg::share_decryption_chain::LimbChain;
use serde_json::json;

/// Proves C4 for `input` as a limb chain and returns the final proof.
pub fn prove_share_decryption_chain(
    prover: &ZkProver,
    config: &Configs,
    input: &ShareDecryptionCircuitData,
    e3_id: &str,
    variant: CircuitVariant,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let inputs = Inputs::compute(config, input)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let chain = LimbChain::compute(config, &inputs)
        .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
    let circuits =
        chunk_circuits(CircuitName::DkgShareDecryption).expect("the final C4 circuit is chunked");
    if circuits.len() != chain.limbs.len() {
        return Err(ZkError::InvalidInput(format!(
            "C4 has {} limb circuits for {} limbs",
            circuits.len(),
            chain.limbs.len()
        )));
    }
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);

    let mut limb_vks = Vec::with_capacity(circuits.len());
    let mut limb_key_hashes = Vec::with_capacity(circuits.len());
    let mut limb_proofs = Vec::with_capacity(circuits.len());
    let mut limb_links = Vec::with_capacity(circuits.len());
    for (l, (limb, circuit)) in chain.limbs.iter().zip(circuits).enumerate() {
        let job_id = format!("{e3_id}-c4-limb-{l}");
        let proof = prove_circuit(
            prover,
            *circuit,
            CircuitVariant::Default,
            &limb.to_json(),
            &job_id,
            artifacts_dir,
        )?;
        let _ = prover.cleanup(&job_id);
        // Public: the limb's H commitments, then `h_in` and its output.
        let publics = bytes_to_field_strings(&proof.public_signals)?;
        let key = vk::load_vk_artifacts(&default_dir, *circuit)?;
        limb_vks.push(key.verification_key);
        limb_key_hashes.push(key.key_hash);
        limb_proofs.push(bytes_to_field_strings(&proof.data)?);
        limb_links.push(publics[publics.len() - 2..].to_vec());
    }

    let mut final_inputs = inputs.to_json();
    let fields = final_inputs
        .as_object_mut()
        .expect("C4 inputs serialize as an object");
    fields.remove("decrypted_shares");
    fields.insert("limb_vks".into(), json!(limb_vks));
    fields.insert("limb_key_hashes".into(), json!(limb_key_hashes));
    fields.insert("limb_proofs".into(), json!(limb_proofs));
    fields.insert("limb_links".into(), json!(limb_links));

    prove_circuit(
        prover,
        CircuitName::DkgShareDecryption,
        variant,
        &final_inputs,
        e3_id,
        artifacts_dir,
    )
}
