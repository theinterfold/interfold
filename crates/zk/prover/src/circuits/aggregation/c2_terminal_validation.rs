// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2 terminal-proof ingress validation.
//!
//! Binds each `SkC2ChunkFinalize` / `ESmC2ChunkFinalize` proof to the
//! deployment-time VK anchors (the canonical leaf chunk VK and the canonical
//! `C2ChunkBatch` VK) before the expensive recursive proof is verified. Loading
//! the anchors reads local artifacts, so a load failure is a local error and
//! never a verdict on the proof sender. [`validate_c2_terminal_proof`] is a pure
//! function of the signed proof and its anchors: its failure means the signed
//! proof is invalid, and the caller must treat it as such.

use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{CircuitName, CircuitVariant, Proof, ProofType};
use e3_fhe_params::BfvPreset;
use num_bigint::BigUint;

/// BN254 scalar field modulus `r` (field elements are canonical in `[0, r)`).
/// `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
const SCALAR_FIELD_MODULUS_HEX: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

fn scalar_field_modulus() -> BigUint {
    BigUint::parse_bytes(SCALAR_FIELD_MODULUS_HEX.as_bytes(), 16)
        .expect("BN254 scalar field modulus hex is valid")
}

/// Deployment-time VK anchors for C2 terminal-proof ingress validation, as canonical field
/// elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2TerminalAnchors {
    /// Hash of the canonical leaf chunk VK for this proof type.
    pub chunk_vk_hash: BigUint,
    /// Hash of the canonical `C2ChunkBatch` VK.
    pub batch_vk_hash: BigUint,
}

/// A `.vk_hash` file holds one field element; anything at or above `r` is a damaged artifact.
fn canonical_anchor(hash: [u8; 32], circuit: CircuitName) -> Result<BigUint, ZkError> {
    let value = BigUint::from_bytes_be(&hash);
    if value >= scalar_field_modulus() {
        return Err(ZkError::InvalidInput(format!(
            "{} VK hash is not a canonical field element",
            circuit.as_str()
        )));
    }
    Ok(value)
}

impl C2TerminalAnchors {
    /// Loads the deployment anchors for a C2 terminal proof type from the
    /// selected artifacts directory. Returns an error for non-C2 proof types.
    pub fn load(
        prover: &ZkProver,
        proof_type: ProofType,
        artifacts_dir: &str,
    ) -> Result<Self, ZkError> {
        let chunk_circuit = match proof_type {
            ProofType::C2aSkShareComputation => CircuitName::SkShareComputationChunk,
            ProofType::C2bESmShareComputation => CircuitName::ESmShareComputationChunk,
            _ => {
                return Err(ZkError::InvalidInput(format!(
                    "C2 terminal anchors requested for non-C2 proof type {proof_type:?}"
                )));
            }
        };
        let recursive_dir = prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir);
        let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
        let chunk_vk = vk::load_vk_artifacts(&recursive_dir, chunk_circuit)?;
        let batch_vk = vk::load_vk_artifacts(&default_dir, CircuitName::C2ChunkBatch)?;
        Ok(Self {
            chunk_vk_hash: canonical_anchor(chunk_vk.key_hash_bytes, chunk_circuit)?,
            batch_vk_hash: canonical_anchor(batch_vk.key_hash_bytes, CircuitName::C2ChunkBatch)?,
        })
    }
}

/// Expected terminal public-field count for a C2 proof: one child VK hash, the secret chunk root,
/// `N_PARTIES * L` share commitments, and one batch VK hash.
fn expected_public_field_count(
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> usize {
    let n_parties = committee_size.values().n;
    // `L` comes from the threshold config that compiled the C2 circuits, not
    // from the DKG preset's modulus count.
    let l = preset
        .threshold_counterpart()
        .unwrap_or(preset)
        .metadata()
        .num_moduli;
    1 + n_parties * l + 2
}

/// Validates a C2 terminal proof against its deployment-time VK anchors before
/// generic proof verification.
///
/// The validator is a no-op for non-C2 proof types. Every failure returns a
/// descriptive [`ZkError::InvalidInput`] so the caller can treat the signed
/// proof as invalid.
pub fn validate_c2_terminal_proof(
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
    proof_type: ProofType,
    proof: &Proof,
    anchors: &C2TerminalAnchors,
) -> Result<(), ZkError> {
    let expected_circuit = match proof_type {
        ProofType::C2aSkShareComputation => CircuitName::SkC2ChunkFinalize,
        ProofType::C2bESmShareComputation => CircuitName::ESmC2ChunkFinalize,
        _ => return Ok(()),
    };
    if proof.circuit != expected_circuit {
        return Err(ZkError::InvalidInput(format!(
            "C2 terminal proof for {proof_type:?} must be the {} circuit, got {}",
            expected_circuit.as_str(),
            proof.circuit.as_str()
        )));
    }

    let signals: &[u8] = proof.public_signals.as_ref();
    if !signals.len().is_multiple_of(32) {
        return Err(ZkError::InvalidInput(format!(
            "C2 terminal proof public signals are not 32-byte aligned (len {})",
            signals.len()
        )));
    }
    let expected_fields = expected_public_field_count(preset, committee_size);
    let actual_fields = signals.len() / 32;
    if actual_fields != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "C2 terminal proof public signal length {actual_fields} does not match the selected committee and preset (expected {expected_fields})"
        )));
    }

    let r = scalar_field_modulus();
    for (index, chunk) in signals.chunks(32).enumerate() {
        let value = BigUint::from_bytes_be(chunk);
        if value >= r {
            return Err(ZkError::InvalidInput(format!(
                "C2 terminal proof public field {index} is not a canonical field element"
            )));
        }
    }

    let chunk_vk_hash = BigUint::from_bytes_be(&signals[0..32]);
    if chunk_vk_hash != anchors.chunk_vk_hash {
        return Err(ZkError::InvalidInput(format!(
            "C2 terminal proof child VK hash does not match the canonical {} chunk VK",
            expected_circuit.as_str()
        )));
    }

    let batch_vk_hash = BigUint::from_bytes_be(&signals[signals.len() - 32..]);
    if batch_vk_hash != anchors.batch_vk_hash {
        return Err(ZkError::InvalidInput(
            "C2 terminal proof batch VK hash does not match the canonical C2ChunkBatch VK".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        expected_public_field_count, scalar_field_modulus, validate_c2_terminal_proof,
        C2TerminalAnchors,
    };
    use crate::error::ZkError;
    use e3_committee::CiphernodesCommitteeSize;
    use e3_events::{CircuitName, Proof, ProofType};
    use e3_fhe_params::BfvPreset;
    use e3_utils::ArcBytes;
    use num_bigint::BigUint;

    /// The production l-BFV shape: n = 3 dealers and L = 6 moduli at the minimum committee, so
    /// 1 + 3 * 6 + 2 = 21 public fields.
    const PRESET: BfvPreset = BfvPreset::SecureDkg16384;
    const MINIMUM_FIELDS: usize = 21;

    fn field_bytes(value: &BigUint) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let be = value.to_bytes_be();
        bytes[32 - be.len()..].copy_from_slice(&be);
        bytes
    }

    fn terminal_proof(circuit: CircuitName, fields: &[BigUint]) -> Proof {
        let mut public_signals = Vec::with_capacity(fields.len() * 32);
        for field in fields {
            public_signals.extend_from_slice(&field_bytes(field));
        }
        Proof {
            circuit,
            data: ArcBytes::from_bytes(&[0u8; 64]),
            public_signals: ArcBytes::from_bytes(&public_signals),
        }
    }

    /// Child VK hash, the secret chunk root, the share commitments, then the batch VK hash.
    fn valid_signals(chunk_hash: &BigUint, batch_hash: &BigUint) -> Vec<BigUint> {
        let mut fields = vec![chunk_hash.clone(), BigUint::from(3u8)];
        fields.extend(std::iter::repeat_with(|| BigUint::from(7u8)).take(MINIMUM_FIELDS - 3));
        fields.push(batch_hash.clone());
        fields
    }

    fn anchors(chunk: u8, batch: u8) -> C2TerminalAnchors {
        C2TerminalAnchors {
            chunk_vk_hash: BigUint::from(chunk),
            batch_vk_hash: BigUint::from(batch),
        }
    }

    fn validate(
        proof_type: ProofType,
        proof: &Proof,
        anchors: &C2TerminalAnchors,
    ) -> Result<(), ZkError> {
        validate_c2_terminal_proof(
            PRESET,
            CiphernodesCommitteeSize::Minimum,
            proof_type,
            proof,
            anchors,
        )
    }

    #[test]
    fn expected_field_count_matches_compiled_layouts() {
        assert_eq!(
            expected_public_field_count(PRESET, CiphernodesCommitteeSize::Minimum),
            MINIMUM_FIELDS
        );
        assert_eq!(
            expected_public_field_count(PRESET, CiphernodesCommitteeSize::Micro),
            1 + 9 * 6 + 2
        );
    }

    #[test]
    fn accepts_canonical_proof_for_both_c2_types() {
        for (proof_type, circuit) in [
            (
                ProofType::C2aSkShareComputation,
                CircuitName::SkC2ChunkFinalize,
            ),
            (
                ProofType::C2bESmShareComputation,
                CircuitName::ESmC2ChunkFinalize,
            ),
        ] {
            let proof = terminal_proof(
                circuit,
                &valid_signals(&BigUint::from(11u8), &BigUint::from(13u8)),
            );
            validate(proof_type, &proof, &anchors(11, 13))
                .expect("canonical C2 terminal proof must pass");
        }
    }

    #[test]
    fn non_c2_proof_types_are_ignored() {
        let proof = terminal_proof(CircuitName::ShareEncryption, &[]);
        validate(ProofType::C3aSkShareEncryption, &proof, &anchors(0, 0))
            .expect("non-C2 proof types must be ignored");
    }

    #[test]
    fn rejects_wrong_terminal_circuit() {
        let proof = terminal_proof(
            CircuitName::ESmC2ChunkFinalize,
            &valid_signals(&BigUint::from(0u8), &BigUint::from(0u8)),
        );
        let result = validate(ProofType::C2aSkShareComputation, &proof, &anchors(0, 0));
        assert!(matches!(result, Err(ZkError::InvalidInput(_))));
    }

    #[test]
    fn rejects_wrong_public_signal_length() {
        let truncated = terminal_proof(
            CircuitName::SkC2ChunkFinalize,
            &valid_signals(&BigUint::from(0u8), &BigUint::from(0u8))[..8],
        );
        assert!(validate(ProofType::C2aSkShareComputation, &truncated, &anchors(0, 0)).is_err());
    }

    #[test]
    fn rejects_noncanonical_chunk_or_batch_vk() {
        let anchors = anchors(11, 13);
        let wrong_chunk = terminal_proof(
            CircuitName::SkC2ChunkFinalize,
            &valid_signals(&BigUint::from(99u8), &BigUint::from(13u8)),
        );
        assert!(validate(ProofType::C2aSkShareComputation, &wrong_chunk, &anchors).is_err());

        let wrong_batch = terminal_proof(
            CircuitName::SkC2ChunkFinalize,
            &valid_signals(&BigUint::from(11u8), &BigUint::from(99u8)),
        );
        assert!(validate(ProofType::C2aSkShareComputation, &wrong_batch, &anchors).is_err());
    }

    #[test]
    fn rejects_noncanonical_field_encoding() {
        let mut fields = valid_signals(&BigUint::from(11u8), &BigUint::from(13u8));
        fields[1] = scalar_field_modulus();
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &fields);
        assert!(validate(ProofType::C2aSkShareComputation, &proof, &anchors(11, 13)).is_err());
    }
}
