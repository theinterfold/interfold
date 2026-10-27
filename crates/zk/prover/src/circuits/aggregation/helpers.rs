// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared helpers for the sequential `c3_fold` / `c6_fold` / `nodes_fold` accumulators and
//! the single-shot `node_dkg_fold` builder.

use crate::circuits::utils::bytes_to_field_strings;
use crate::error::ZkError;
use e3_events::{CircuitName, Proof};

/// Field count for `UltraHonkProof` (non-ZK) used as the `acc_proof` parameter in every
/// recursive fold step. Sourced from `bb_proof_verification::RECURSIVE_PROOF_LENGTH`.
pub const ACC_NONZK_PROOF_FIELDS: usize = 410;

/// String keys for inner-circuit public input/output extraction. Centralised so a
/// rename in the Noir ABI surfaces as a single edit instead of a runtime panic.
///
/// These names must stay in lock-step with the corresponding Noir circuit ABI
/// declarations (e.g. `expected_pk_commitment` is declared in C3 / `share_encryption.nr`).
pub mod field_keys {
    pub const EXPECTED_PK_COMMITMENT: &str = "expected_pk_commitment";
    pub const EXPECTED_MESSAGE_COMMITMENT: &str = "expected_message_commitment";
    pub const EXPECTED_SK_COMMITMENT: &str = "expected_sk_commitment";
    pub const EXPECTED_E_SM_COMMITMENT: &str = "expected_e_sm_commitment";
    pub const CT_COMMITMENT: &str = "ct_commitment";
    pub const DOMAIN_HI: &str = "domain_hi";
    pub const DOMAIN_LO: &str = "domain_lo";
    pub const D_COMMITMENT: &str = "d_commitment";
}

/// Vector of `field_count` zero-encoded 32-byte hex field strings for the genesis accumulator.
pub fn zero_field_hex_strings(field_count: usize) -> Result<Vec<String>, ZkError> {
    let bytes = vec![0u8; field_count * 32];
    bytes_to_field_strings(&bytes)
}

/// Encode a `u64` as a 32-byte field hex string (big-endian, left-padded).
pub fn u64_to_field_hex(value: u64) -> String {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    format!("0x{}", hex::encode(bytes))
}

/// Encode an EVM address as a 32-byte field hex string (20-byte address right-aligned).
pub fn address_to_field_hex(address: &alloy::primitives::Address) -> String {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    format!("0x{}", hex::encode(bytes))
}

/// Extract a single 32-byte public input/output by name. `kind` must be `"input"` or `"output"`.
pub fn extract_single_field(
    proof: &Proof,
    kind: &str,
    name: &str,
    context: &str,
) -> Result<String, ZkError> {
    let bytes = match kind {
        "input" => proof
            .extract_input(name)
            .ok_or_else(|| ZkError::InvalidInput(format!("{context}: missing input {name}")))?,
        "output" => proof
            .extract_output(name)
            .ok_or_else(|| ZkError::InvalidInput(format!("{context}: missing output {name}")))?,
        _ => {
            return Err(ZkError::InvalidInput(format!(
                "extract_single_field: kind must be input or output, got {kind}"
            )));
        }
    };
    let fields = bytes_to_field_strings(bytes.as_ref())?;
    if fields.len() != 1 {
        return Err(ZkError::InvalidInput(format!(
            "{context}: field {name} encoded as {} fields, expected 1",
            fields.len()
        )));
    }
    Ok(fields.into_iter().next().expect("len == 1 verified above"))
}

/// Parses an accumulator proof's public signals as field strings, checking its circuit and that
/// they hold at least the prefix. The per-slot width (`nodes_fold` stores a whole `node_fold`
/// statement per slot) is known only at runtime, so the caller checks the total length against
/// `prefix_len + slots * <runtime_slot_width>`.
pub fn parse_acc_public_field_strings_flat(
    proof: &Proof,
    expected_circuit: CircuitName,
    prefix_len: usize,
) -> Result<Vec<String>, ZkError> {
    if proof.circuit != expected_circuit {
        return Err(ZkError::InvalidInput(format!(
            "expected {expected_circuit} proof, got {}",
            proof.circuit
        )));
    }
    let v = bytes_to_field_strings(proof.public_signals.as_ref())?;
    if v.len() < prefix_len {
        return Err(ZkError::InvalidInput(format!(
            "unexpected {expected_circuit} public signal field count: {} (prefix={prefix_len})",
            v.len()
        )));
    }
    Ok(v)
}
