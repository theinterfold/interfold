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
    config::{verify_checksum, ChecksumManifest},
    error::ZkError,
    prover::ZkProver,
};
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::{lbfv_crs_seed, BfvPreset};
use e3_zk_helpers::threshold::lbfv_proof_domain::lbfv_proof_session;
use e3_zk_helpers::threshold::pk_generation::{
    derive_lbfv_pk_generation_limb_inputs, LbfvPkGenerationCircuitData,
    LbfvPkGenerationLimbCircuit, LbfvPkGenerationLimbCircuitData, LbfvPkGenerationLimbInputs,
};
use e3_zk_helpers::{crt_polynomial_to_toml_json, Computation};
use serde::Serialize;
use std::fs;

const LBFV_PK_LIMB_PUBLIC_FIELD_COUNT: usize = 8;
const LBFV_PK_TERMINAL_PUBLIC_FIELD_COUNT: usize = 7;
const FIELD_BYTE_LEN: usize = 32;

#[derive(Serialize)]
struct LbfvPkGenerationFinalizerInput {
    session_id_hi: String,
    session_id_lo: String,
    party_id: u32,
    row_index: u32,
    limb_vk: Vec<String>,
    limb_proofs: Vec<Vec<String>>,
    limb_public_inputs: Vec<Vec<String>>,
    limb_key_hash: String,
    pk0: serde_json::Value,
}

/// Recursive limb proofs and their terminal public-key row proof.
pub struct LbfvPkGenerationRowProof {
    pub limb_proofs: Vec<Proof>,
    pub terminal_proof: Proof,
}

/// Load the public-key limb VK hash from the staged recursive artifact set.
pub fn load_staged_lbfv_pk_generation_limb_vk_hash(
    prover: &ZkProver,
    artifacts_dir: &str,
) -> Result<[u8; FIELD_BYTE_LEN], ZkError> {
    let circuit = CircuitName::LbfvPkGenerationLimb;
    let suffix = format!(
        "{}/{}/{}.vk_hash",
        CircuitVariant::Recursive.as_str(),
        circuit.dir_path(),
        circuit.as_str()
    );
    let scoped_path = format!("{artifacts_dir}/{suffix}");
    let preset = artifacts_dir.split('/').next().ok_or_else(|| {
        ZkError::InvalidInput("l-BFV artifact directory must identify a preset".into())
    })?;
    let legacy_path = format!("{preset}/{suffix}");
    let manifest_path = prover.circuits_root().join("checksums.json");
    let manifest: ChecksumManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let (relative_path, expected_checksum) = [scoped_path.as_str(), legacy_path.as_str()]
        .into_iter()
        .find_map(|path| manifest.files.get(path).map(|checksum| (path, checksum)))
        .ok_or_else(|| ZkError::ChecksumMissing(scoped_path.clone()))?;
    let hash_path = prover
        .circuits_dir(CircuitVariant::Recursive, artifacts_dir)
        .join(circuit.dir_path())
        .join(format!("{}.vk_hash", circuit.as_str()));
    let hash_bytes = fs::read(hash_path)?;
    verify_checksum(relative_path, &hash_bytes, Some(expected_checksum))?;
    hash_bytes.try_into().map_err(|bytes: Vec<u8>| {
        ZkError::InvalidInput(format!(
            "staged l-BFV public-key limb VK hash has {} bytes; expected {FIELD_BYTE_LEN}",
            bytes.len()
        ))
    })
}

/// Validate the public-key limb VK hash in a terminal row proof.
pub fn validate_lbfv_pk_generation_terminal_proof(
    prover: &ZkProver,
    proof: &Proof,
    artifacts_dir: &str,
) -> Result<(), ZkError> {
    if proof.circuit != CircuitName::LbfvPkGeneration {
        return Err(ZkError::InvalidInput(format!(
            "expected {}, got {}",
            CircuitName::LbfvPkGeneration,
            proof.circuit
        )));
    }
    if proof.public_signals.len() != LBFV_PK_TERMINAL_PUBLIC_FIELD_COUNT * FIELD_BYTE_LEN {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key terminal proof has {} public fields; expected {LBFV_PK_TERMINAL_PUBLIC_FIELD_COUNT}",
            proof.public_signals.len() / FIELD_BYTE_LEN
        )));
    }

    let expected = load_staged_lbfv_pk_generation_limb_vk_hash(prover, artifacts_dir)?;
    let actual = proof.extract_output("limb_vk_hash").ok_or_else(|| {
        ZkError::InvalidInput("l-BFV public-key terminal proof has no limb VK hash".into())
    })?;
    if &*actual != expected.as_slice() {
        return Err(ZkError::InvalidInput(
            "l-BFV public-key terminal proof uses a limb VK that is not in the staged artifact set"
                .into(),
        ));
    }
    Ok(())
}

impl Provable for LbfvPkGenerationLimbCircuit {
    type Params = BfvPreset;
    type Input = LbfvPkGenerationLimbCircuitData;
    type Inputs = LbfvPkGenerationLimbInputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::LbfvPkGenerationLimb
    }
}

/// Prove all CRT limbs of one public-key row and finalize them in canonical order.
pub fn prove_lbfv_pk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &LbfvPkGenerationCircuitData,
    expected_limb_vk_hash: &[u8; FIELD_BYTE_LEN],
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<LbfvPkGenerationRowProof, ZkError> {
    let limb_inputs = derive_lbfv_pk_generation_limb_inputs(preset, row)
        .map_err(|error| ZkError::InputsGenerationFailed(error.to_string()))?;
    let mut limb_proofs = Vec::with_capacity(limb_inputs.len());

    for input in limb_inputs {
        let limb_index = input.limb_index;
        let input_map = inputs_json_to_input_map(&input.to_json()?)?;
        limb_proofs.push(prove_recursive_input_map(
            prover,
            CircuitName::LbfvPkGenerationLimb,
            input_map,
            &format!("{e3_id}-lbfv-pk-row-{}-limb-{limb_index}", row.row_index),
            artifacts_dir,
        )?);
    }

    let terminal_proof = finalize_lbfv_pk_generation_row(
        prover,
        preset,
        row,
        &limb_proofs,
        expected_limb_vk_hash,
        e3_id,
        artifacts_dir,
    )?;
    Ok(LbfvPkGenerationRowProof {
        limb_proofs,
        terminal_proof,
    })
}

fn field_from_u32(value: u32) -> [u8; FIELD_BYTE_LEN] {
    let mut field = [0u8; FIELD_BYTE_LEN];
    field[FIELD_BYTE_LEN - size_of::<u32>()..].copy_from_slice(&value.to_be_bytes());
    field
}

fn field_from_u128(value: u128) -> [u8; FIELD_BYTE_LEN] {
    let mut field = [0u8; FIELD_BYTE_LEN];
    field[FIELD_BYTE_LEN - size_of::<u128>()..].copy_from_slice(&value.to_be_bytes());
    field
}

fn validate_limb_proof_statements(
    session_id_hi: u128,
    session_id_lo: u128,
    party_id: u32,
    row_index: u32,
    limb_count: usize,
    limb_proofs: &[Proof],
) -> Result<(), ZkError> {
    if limb_proofs.len() != limb_count {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key finalizer requires {limb_count} limb proofs, got {}",
            limb_proofs.len()
        )));
    }

    let expected_session_hi = field_from_u128(session_id_hi);
    let expected_session_lo = field_from_u128(session_id_lo);
    let expected_party = field_from_u32(party_id);
    let expected_row = field_from_u32(row_index);
    let mut shared_commitments = None;
    for (limb_index, proof) in limb_proofs.iter().enumerate() {
        if proof.circuit != CircuitName::LbfvPkGenerationLimb {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key finalizer expected {}, got {}",
                CircuitName::LbfvPkGenerationLimb,
                proof.circuit
            )));
        }
        if proof.public_signals.len() != LBFV_PK_LIMB_PUBLIC_FIELD_COUNT * FIELD_BYTE_LEN {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key limb proof has {} public fields; expected {LBFV_PK_LIMB_PUBLIC_FIELD_COUNT}",
                proof.public_signals.len() / FIELD_BYTE_LEN
            )));
        }

        let signals: &[u8] = proof.public_signals.as_ref();
        if signals[..FIELD_BYTE_LEN] != expected_session_hi
            || signals[FIELD_BYTE_LEN..2 * FIELD_BYTE_LEN] != expected_session_lo
        {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key limb {limb_index} has the wrong proof session"
            )));
        }
        if signals[2 * FIELD_BYTE_LEN..3 * FIELD_BYTE_LEN] != expected_party {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key limb {limb_index} has the wrong party ID"
            )));
        }
        if signals[3 * FIELD_BYTE_LEN..4 * FIELD_BYTE_LEN] != expected_row {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key limb {limb_index} has the wrong row index"
            )));
        }
        if signals[4 * FIELD_BYTE_LEN..5 * FIELD_BYTE_LEN] != field_from_u32(limb_index as u32) {
            return Err(ZkError::InvalidInput(format!(
                "l-BFV public-key proof at position {limb_index} has the wrong limb index"
            )));
        }

        let shared = &signals[5 * FIELD_BYTE_LEN..7 * FIELD_BYTE_LEN];
        match shared_commitments {
            None => shared_commitments = Some(shared),
            Some(expected) if shared != expected => {
                return Err(ZkError::InvalidInput(format!(
                    "l-BFV public-key limb {limb_index} has different shared commitments"
                )))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_limb_vk_hash(actual: &str, expected: &[u8; FIELD_BYTE_LEN]) -> Result<(), ZkError> {
    let actual = hex::decode(actual.trim_start_matches("0x")).map_err(|error| {
        ZkError::InvalidInput(format!("invalid l-BFV public-key limb VK hash: {error}"))
    })?;
    if actual.as_slice() != expected {
        return Err(ZkError::InvalidInput(
            "recursive l-BFV public-key limb VK hash does not match the expected artifact".into(),
        ));
    }
    Ok(())
}

/// Verify all public-key limb proofs and generate the recursive row finalizer proof.
pub fn finalize_lbfv_pk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &LbfvPkGenerationCircuitData,
    limb_proofs: &[Proof],
    expected_limb_vk_hash: &[u8; FIELD_BYTE_LEN],
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if lbfv_crs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key generation is not enabled for {preset:?}"
        )));
    }
    let limb_count = row.pk0_share.limbs.len();
    let expected_limb_count = preset.metadata().num_moduli;
    if limb_count != expected_limb_count {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key finalizer requires {expected_limb_count} limbs"
        )));
    }
    let session = lbfv_proof_session(row.proof_domain)
        .map_err(|error| ZkError::InvalidInput(error.to_string()))?;
    validate_limb_proof_statements(
        session.session_id_hi,
        session.session_id_lo,
        row.party_id,
        row.row_index,
        limb_count,
        limb_proofs,
    )?;

    let mut proof_fields = Vec::with_capacity(limb_count);
    let mut public_inputs = Vec::with_capacity(limb_count);
    for proof in limb_proofs {
        let fields = bytes_to_field_strings(&proof.public_signals).map_err(|error| {
            ZkError::InvalidInput(format!("l-BFV public-key limb public signals: {error}"))
        })?;
        public_inputs.push(fields);
        proof_fields.push(zk_proof_bytes_to_field_strings(&proof.data)?);
    }

    let limb_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::LbfvPkGenerationLimb,
    )?;
    validate_limb_vk_hash(&limb_vk.key_hash, expected_limb_vk_hash)?;
    let input = LbfvPkGenerationFinalizerInput {
        session_id_hi: session.session_id_hi.to_string(),
        session_id_lo: session.session_id_lo.to_string(),
        party_id: row.party_id,
        row_index: row.row_index,
        limb_vk: limb_vk.verification_key,
        limb_proofs: proof_fields,
        limb_public_inputs: public_inputs,
        limb_key_hash: limb_vk.key_hash,
        pk0: serde_json::Value::Array(crt_polynomial_to_toml_json(&row.pk0_share)),
    };

    prove_recursive_circuit(
        prover,
        CircuitName::LbfvPkGeneration,
        &input,
        &format!("{e3_id}-lbfv-pk-row-{}", row.row_index),
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

    fn limb_proof(row_index: u32, limb_index: u32, shared: [u8; 2]) -> Proof {
        let mut signals = vec![0u8; LBFV_PK_LIMB_PUBLIC_FIELD_COUNT * FIELD_BYTE_LEN];
        write_u32_field(&mut signals, 0, 1);
        write_u32_field(&mut signals, 1, 2);
        write_u32_field(&mut signals, 2, 0);
        write_u32_field(&mut signals, 3, row_index);
        write_u32_field(&mut signals, 4, limb_index);
        for (offset, value) in shared.into_iter().enumerate() {
            signals[(offset + 6) * FIELD_BYTE_LEN - 1] = value;
        }
        Proof::new(
            CircuitName::LbfvPkGenerationLimb,
            ArcBytes::from_bytes(&[]),
            ArcBytes::from_bytes(&signals),
        )
    }

    fn canonical_proofs() -> Vec<Proof> {
        (0..5)
            .map(|limb_index| limb_proof(2, limb_index, [1, 2]))
            .collect()
    }

    #[test]
    fn finalizer_preflight_accepts_canonical_limb_statements() {
        validate_limb_proof_statements(1, 2, 0, 2, 5, &canonical_proofs()).unwrap();
    }

    #[test]
    fn finalizer_preflight_rejects_reordered_or_mixed_limbs() {
        let mut reordered = canonical_proofs();
        reordered.swap(1, 2);
        assert!(validate_limb_proof_statements(1, 2, 0, 2, 5, &reordered).is_err());

        let mut mixed = canonical_proofs();
        mixed[4] = limb_proof(2, 4, [1, 9]);
        assert!(validate_limb_proof_statements(1, 2, 0, 2, 5, &mixed).is_err());
    }

    #[test]
    fn finalizer_preflight_rejects_wrong_vk_hash() {
        let expected = [0x11; FIELD_BYTE_LEN];
        let actual = format!("0x{}", hex::encode(expected));
        validate_limb_vk_hash(&actual, &expected).unwrap();
        assert!(validate_limb_vk_hash(&actual, &[0x22; FIELD_BYTE_LEN]).is_err());
    }
}
