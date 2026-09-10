// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{
    circuits::{
        utils::{
            bytes_to_field_strings, inputs_json_to_input_map, prove_recursive_circuit,
            prove_recursive_input_map, zk_proof_bytes_to_field_strings,
        },
        vk,
    },
    error::ZkError,
    prover::ZkProver,
};
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_zk_helpers::crt_polynomial_to_toml_json;
use e3_zk_helpers::threshold::rlk_generation::{
    derive_rlk_generation_limb_inputs, RlkGenerationCircuitData, RlkGenerationLimbCircuit,
    RlkGenerationLimbCircuitData, RlkGenerationLimbInputs,
};
use serde::Serialize;

const RLK_LIMB_PUBLIC_FIELD_COUNT: usize = 8;
const FIELD_BYTE_LEN: usize = 32;

#[derive(Serialize)]
struct RlkGenerationFinalizerInput {
    row_index: u32,
    limb_vk: Vec<String>,
    limb_proofs: Vec<Vec<String>>,
    limb_public_inputs: Vec<Vec<String>>,
    limb_key_hash: String,
    d0: serde_json::Value,
    d2: serde_json::Value,
}

/// Recursive limb proofs and their terminal RLK row proof.
pub struct RlkGenerationRowProof {
    pub limb_proofs: Vec<Proof>,
    pub terminal_proof: Proof,
}

impl Provable for RlkGenerationLimbCircuit {
    type Params = BfvPreset;
    type Input = RlkGenerationLimbCircuitData;
    type Inputs = RlkGenerationLimbInputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::RlkGenerationLimb
    }
}

/// Prove all CRT limbs of one RLK row and finalize them in canonical order.
///
/// `expected_limb_vk_hash` must come from trusted protocol configuration, not from `artifacts_dir`.
pub fn prove_rlk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &RlkGenerationCircuitData,
    expected_limb_vk_hash: &[u8; 32],
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<RlkGenerationRowProof, ZkError> {
    let limb_inputs = derive_rlk_generation_limb_inputs(preset, row)
        .map_err(|error| ZkError::InputsGenerationFailed(error.to_string()))?;
    let mut limb_proofs = Vec::with_capacity(limb_inputs.len());

    for input in limb_inputs {
        let limb_index = input.limb_index;
        let input_map = inputs_json_to_input_map(&input.to_json())?;
        limb_proofs.push(prove_recursive_input_map(
            prover,
            CircuitName::RlkGenerationLimb,
            input_map,
            &format!("{e3_id}-rlk-row-{}-limb-{limb_index}", row.row_index),
            artifacts_dir,
        )?);
    }

    let terminal_proof = finalize_rlk_generation_row(
        prover,
        preset,
        row,
        &limb_proofs,
        expected_limb_vk_hash,
        e3_id,
        artifacts_dir,
    )?;
    Ok(RlkGenerationRowProof {
        limb_proofs,
        terminal_proof,
    })
}

fn field_from_u32(value: u32) -> [u8; FIELD_BYTE_LEN] {
    let mut field = [0u8; FIELD_BYTE_LEN];
    field[FIELD_BYTE_LEN - size_of::<u32>()..].copy_from_slice(&value.to_be_bytes());
    field
}

fn validate_limb_proof_statements(
    row_index: u32,
    limb_count: usize,
    limb_proofs: &[Proof],
) -> Result<(), ZkError> {
    if limb_proofs.len() != limb_count {
        return Err(ZkError::InvalidInput(format!(
            "RLK finalizer requires {limb_count} limb proofs, got {}",
            limb_proofs.len()
        )));
    }

    let expected_row = field_from_u32(row_index);
    let mut shared_commitments = None;
    for (limb_index, proof) in limb_proofs.iter().enumerate() {
        if proof.circuit != CircuitName::RlkGenerationLimb {
            return Err(ZkError::InvalidInput(format!(
                "RLK finalizer expected {}, got {}",
                CircuitName::RlkGenerationLimb,
                proof.circuit
            )));
        }
        if proof.public_signals.len() != RLK_LIMB_PUBLIC_FIELD_COUNT * FIELD_BYTE_LEN {
            return Err(ZkError::InvalidInput(format!(
                "RLK limb proof has {} public fields; expected {RLK_LIMB_PUBLIC_FIELD_COUNT}",
                proof.public_signals.len() / FIELD_BYTE_LEN
            )));
        }

        let signals: &[u8] = proof.public_signals.as_ref();
        if signals[..FIELD_BYTE_LEN] != expected_row {
            return Err(ZkError::InvalidInput(format!(
                "RLK limb {limb_index} has the wrong row index"
            )));
        }
        let expected_limb = field_from_u32(limb_index as u32);
        if signals[FIELD_BYTE_LEN..2 * FIELD_BYTE_LEN] != expected_limb {
            return Err(ZkError::InvalidInput(format!(
                "RLK limb proof at position {limb_index} has the wrong limb index"
            )));
        }

        let shared = &signals[2 * FIELD_BYTE_LEN..6 * FIELD_BYTE_LEN];
        match shared_commitments {
            None => shared_commitments = Some(shared),
            Some(expected) if shared != expected => {
                return Err(ZkError::InvalidInput(format!(
                    "RLK limb {limb_index} has different shared commitments"
                )))
            }
            Some(_) => {}
        }
    }

    Ok(())
}

fn validate_limb_vk_hash(actual: &str, expected: &[u8; FIELD_BYTE_LEN]) -> Result<(), ZkError> {
    let actual = hex::decode(actual.trim_start_matches("0x"))
        .map_err(|error| ZkError::InvalidInput(format!("invalid RLK limb VK hash: {error}")))?;
    if actual.as_slice() != expected {
        return Err(ZkError::InvalidInput(
            "recursive RLK limb VK hash does not match the expected artifact".into(),
        ));
    }
    Ok(())
}

/// Verify all RLK limb proofs for one row and generate its recursive finalizer proof.
///
/// `expected_limb_vk_hash` must come from trusted protocol configuration, not from `artifacts_dir`.
pub fn finalize_rlk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &RlkGenerationCircuitData,
    limb_proofs: &[Proof],
    expected_limb_vk_hash: &[u8; 32],
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "RLK generation is not enabled for {preset:?}"
        )));
    }
    let limb_count = row.d0.limbs.len();
    let expected_limb_count = preset.metadata().num_moduli;
    if limb_count != expected_limb_count || row.d2.limbs.len() != expected_limb_count {
        return Err(ZkError::InvalidInput(format!(
            "RLK finalizer requires {expected_limb_count} d0 and d2 limbs"
        )));
    }
    validate_limb_proof_statements(row.row_index, limb_count, limb_proofs)?;

    let mut proof_fields = Vec::with_capacity(limb_count);
    let mut public_inputs = Vec::with_capacity(limb_count);
    for proof in limb_proofs {
        let fields = bytes_to_field_strings(&proof.public_signals)
            .map_err(|error| ZkError::InvalidInput(format!("RLK limb public signals: {error}")))?;
        public_inputs.push(fields);
        proof_fields.push(zk_proof_bytes_to_field_strings(&proof.data)?);
    }

    let limb_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::RlkGenerationLimb,
    )?;
    validate_limb_vk_hash(&limb_vk.key_hash, expected_limb_vk_hash)?;
    let input = RlkGenerationFinalizerInput {
        row_index: row.row_index,
        limb_vk: limb_vk.verification_key,
        limb_proofs: proof_fields,
        limb_public_inputs: public_inputs,
        limb_key_hash: limb_vk.key_hash,
        d0: serde_json::Value::Array(crt_polynomial_to_toml_json(&row.d0)),
        d2: serde_json::Value::Array(crt_polynomial_to_toml_json(&row.d2)),
    };

    prove_recursive_circuit(
        prover,
        CircuitName::RlkGeneration,
        &input,
        &format!("{e3_id}-rlk-row-{}", row.row_index),
        artifacts_dir,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_utils::utility_types::ArcBytes;

    fn write_u32_field(signals: &mut [u8], field_index: usize, value: u32) {
        let start = field_index * FIELD_BYTE_LEN;
        signals[start..start + FIELD_BYTE_LEN].copy_from_slice(&field_from_u32(value));
    }

    fn limb_proof(row_index: u32, limb_index: u32, shared: [u8; 4]) -> Proof {
        let mut signals = vec![0u8; RLK_LIMB_PUBLIC_FIELD_COUNT * FIELD_BYTE_LEN];
        write_u32_field(&mut signals, 0, row_index);
        write_u32_field(&mut signals, 1, limb_index);
        for (offset, value) in shared.into_iter().enumerate() {
            signals[(offset + 3) * FIELD_BYTE_LEN - 1] = value;
        }
        Proof::new(
            CircuitName::RlkGenerationLimb,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&signals),
        )
    }

    fn canonical_proofs() -> Vec<Proof> {
        (0..5)
            .map(|limb_index| limb_proof(2, limb_index, [1, 2, 3, 4]))
            .collect()
    }

    #[test]
    fn finalizer_preflight_accepts_canonical_limb_statements() {
        validate_limb_proof_statements(2, 5, &canonical_proofs()).unwrap();
    }

    #[test]
    fn finalizer_preflight_rejects_reordered_or_duplicate_limbs() {
        let mut reordered = canonical_proofs();
        reordered.swap(1, 2);
        assert!(validate_limb_proof_statements(2, 5, &reordered).is_err());

        let mut duplicate = canonical_proofs();
        duplicate[2] = duplicate[1].clone();
        assert!(validate_limb_proof_statements(2, 5, &duplicate).is_err());
    }

    #[test]
    fn finalizer_preflight_rejects_wrong_row() {
        let mut proofs = canonical_proofs();
        proofs[3] = limb_proof(1, 3, [1, 2, 3, 4]);
        assert!(validate_limb_proof_statements(2, 5, &proofs).is_err());
    }

    #[test]
    fn finalizer_preflight_rejects_mixed_shared_commitments() {
        let mut proofs = canonical_proofs();
        proofs[4] = limb_proof(2, 4, [1, 2, 9, 4]);
        assert!(validate_limb_proof_statements(2, 5, &proofs).is_err());
    }

    #[test]
    fn finalizer_preflight_rejects_wrong_vk_hash() {
        let expected = [0x11; FIELD_BYTE_LEN];
        let actual = format!("0x{}", hex::encode(expected));
        validate_limb_vk_hash(&actual, &expected).unwrap();

        assert!(validate_limb_vk_hash(&actual, &[0x22; FIELD_BYTE_LEN]).is_err());
    }
}
