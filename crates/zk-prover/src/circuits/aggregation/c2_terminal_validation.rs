// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C2 terminal-proof ingress validation.
//!
//! Binds each `SkC2ChunkFinalize` / `ESmC2ChunkFinalize` proof to the
//! deployment-time VK anchors (the canonical leaf chunk VK and the canonical
//! `C2ChunkBatch` VK) before the expensive recursive proof is verified. A
//! validation failure means the signed proof is invalid, not that the node is
//! misconfigured — the caller must treat it as an invalid signed proof.

use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use e3_events::{CircuitName, CircuitVariant, Proof, ProofType};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::CiphernodesCommitteeSize;
use num_bigint::BigUint;

/// BN254 scalar field modulus `r` (field elements are canonical in `[0, r)`).
/// `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
const SCALAR_FIELD_MODULUS_HEX: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

fn scalar_field_modulus() -> BigUint {
    BigUint::parse_bytes(SCALAR_FIELD_MODULUS_HEX.as_bytes(), 16)
        .expect("BN254 scalar field modulus hex is valid")
}

/// Parses a `0x`-prefixed VK-anchor hex string into its reduced field value.
fn parse_anchor_hex(hex_str: &str) -> Result<BigUint, ZkError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|error| ZkError::InvalidInput(format!("invalid VK anchor hex: {error}")))?;
    Ok(BigUint::from_bytes_be(&bytes) % scalar_field_modulus())
}

/// Deployment-time VK anchors for C2 terminal-proof ingress validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2TerminalAnchors {
    /// `0x`-prefixed hex hash of the canonical leaf chunk VK for this proof type.
    pub chunk_vk_hash: String,
    /// `0x`-prefixed hex hash of the canonical `C2ChunkBatch` VK.
    pub batch_vk_hash: String,
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
            chunk_vk_hash: chunk_vk.key_hash,
            batch_vk_hash: batch_vk.key_hash,
        })
    }
}

/// Expected terminal public-field count for a C2 proof: `1` child VK hash,
/// `N_PARTIES * L` share commitments, and `1` batch VK hash.
fn expected_public_field_count(
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> usize {
    let n_parties = committee_size.values().n;
    // `L` (number of CRT moduli) comes from the threshold config the C2
    // circuits were compiled against, never from the DKG preset's moduli.
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
    let expected_chunk = parse_anchor_hex(&anchors.chunk_vk_hash)?;
    if chunk_vk_hash != expected_chunk {
        return Err(ZkError::InvalidInput(format!(
            "C2 terminal proof child VK hash does not match the canonical {} chunk VK",
            expected_circuit.as_str()
        )));
    }

    let batch_vk_hash = BigUint::from_bytes_be(&signals[signals.len() - 32..]);
    let expected_batch = parse_anchor_hex(&anchors.batch_vk_hash)?;
    if batch_vk_hash != expected_batch {
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
    use e3_events::{CircuitName, Proof, ProofType};
    use e3_fhe_params::BfvPreset;
    use e3_utils::ArcBytes;
    use e3_zk_helpers::CiphernodesCommitteeSize;
    use num_bigint::BigUint;

    fn hex_field(value: &BigUint) -> String {
        format!("{:0>64x}", value)
    }

    fn field_bytes(value: &BigUint) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let be = value.to_bytes_be();
        bytes[32 - be.len()..].copy_from_slice(&be);
        bytes
    }

    /// Builds a synthetic C2 terminal proof with `fields` public signals.
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

    /// Minimal valid signal set for insecure-512 + minimum committee.
    /// `1 + 1 + 3*2 + 1 = 9` fields (child VK, secret root, shares, batch VK),
    /// all canonical.
    fn valid_signals(chunk_hash: &BigUint, batch_hash: &BigUint) -> Vec<BigUint> {
        let mut fields = vec![chunk_hash.clone(), BigUint::from(3u8)];
        fields.extend(std::iter::repeat_with(|| BigUint::from(7u8)).take(6));
        fields.push(batch_hash.clone());
        fields
    }

    #[test]
    fn expected_field_count_matches_compiled_layouts() {
        assert_eq!(
            expected_public_field_count(
                BfvPreset::InsecureDkg512,
                CiphernodesCommitteeSize::Minimum
            ),
            9
        );
        assert_eq!(
            expected_public_field_count(
                BfvPreset::SecureDkg8192,
                CiphernodesCommitteeSize::Minimum
            ),
            12
        );
        assert_eq!(
            expected_public_field_count(BfvPreset::InsecureDkg512, CiphernodesCommitteeSize::Micro),
            1 + 9 * 2 + 2
        );
    }

    #[test]
    fn accepts_canonical_proof_for_both_c2_types() {
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: format!("0x{}", hex_field(&BigUint::from(11u8))),
            batch_vk_hash: format!("0x{}", hex_field(&BigUint::from(13u8))),
        };
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
            let signals = valid_signals(&BigUint::from(11u8), &BigUint::from(13u8));
            let proof = terminal_proof(circuit, &signals);
            validate_c2_terminal_proof(
                BfvPreset::InsecureDkg512,
                CiphernodesCommitteeSize::Minimum,
                proof_type,
                &proof,
                &anchors,
            )
            .expect("canonical C2 terminal proof must pass");
        }
    }

    #[test]
    fn non_c2_proof_types_are_ignored() {
        let proof = terminal_proof(CircuitName::ShareEncryption, &[]);
        validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C3aSkShareEncryption,
            &proof,
            &C2TerminalAnchors {
                chunk_vk_hash: "0x00".into(),
                batch_vk_hash: "0x00".into(),
            },
        )
        .expect("non-C2 proof types must be ignored");
    }

    #[test]
    fn rejects_wrong_terminal_circuit() {
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: "0x00".into(),
            batch_vk_hash: "0x00".into(),
        };
        let proof = terminal_proof(
            CircuitName::ESmC2ChunkFinalize,
            &valid_signals(&BigUint::from(0u8), &BigUint::from(0u8)),
        );
        let result = validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        );
        assert!(matches!(result, Err(ZkError::InvalidInput(_))));
    }

    #[test]
    fn rejects_truncated_or_extended_public_signals() {
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: "0x00".into(),
            batch_vk_hash: "0x00".into(),
        };
        // Truncated: 8 fields instead of 9.
        let truncated = terminal_proof(
            CircuitName::SkC2ChunkFinalize,
            &valid_signals(&BigUint::from(0u8), &BigUint::from(0u8))[..8],
        );
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &truncated,
            &anchors,
        )
        .is_err());
        // Extended: 10 fields instead of 9.
        let mut extended = valid_signals(&BigUint::from(0u8), &BigUint::from(0u8));
        extended.push(BigUint::from(1u8));
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &extended);
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .is_err());
    }

    #[test]
    fn rejects_sk_proof_with_esm_chunk_vk() {
        // SK proof whose child VK hash equals the ESM chunk anchor.
        let sk_anchor = BigUint::from(11u8);
        let esm_anchor = BigUint::from(22u8);
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: format!("0x{}", hex_field(&sk_anchor)),
            batch_vk_hash: "0x00".into(),
        };
        let signals = valid_signals(&esm_anchor, &BigUint::from(0u8));
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &signals);
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .is_err());
    }

    #[test]
    fn rejects_noncanonical_chunk_or_batch_vk() {
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: format!("0x{}", hex_field(&BigUint::from(11u8))),
            batch_vk_hash: format!("0x{}", hex_field(&BigUint::from(13u8))),
        };
        // Wrong chunk hash.
        let signals = valid_signals(&BigUint::from(99u8), &BigUint::from(13u8));
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &signals);
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .is_err());
        // Wrong batch hash.
        let signals = valid_signals(&BigUint::from(11u8), &BigUint::from(99u8));
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &signals);
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .is_err());
    }

    #[test]
    fn rejects_non_canonical_field_encoding() {
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: format!("0x{}", hex_field(&BigUint::from(11u8))),
            batch_vk_hash: format!("0x{}", hex_field(&BigUint::from(13u8))),
        };
        let r = scalar_field_modulus();
        // Place a non-canonical field (>= r) in the secret-root slot.
        let mut fields = vec![BigUint::from(11u8), r.clone()];
        fields.extend(std::iter::repeat_with(|| BigUint::from(7u8)).take(6));
        fields.push(BigUint::from(13u8));
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &fields);
        assert!(validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .is_err());
    }

    #[test]
    fn canonical_fields_pass_with_anchor_above_scalar_order() {
        // A VK hash whose raw 32 bytes exceed the scalar modulus must still be
        // accepted when the proof field carries the reduced value.
        let r = scalar_field_modulus();
        let raw_hash = &r + BigUint::from(5u8);
        let reduced = BigUint::from(5u8);
        let anchors = C2TerminalAnchors {
            chunk_vk_hash: format!("0x{}", hex_field(&raw_hash)),
            batch_vk_hash: format!("0x{}", hex_field(&reduced)),
        };
        let signals = valid_signals(&reduced, &reduced);
        let proof = terminal_proof(CircuitName::SkC2ChunkFinalize, &signals);
        validate_c2_terminal_proof(
            BfvPreset::InsecureDkg512,
            CiphernodesCommitteeSize::Minimum,
            ProofType::C2aSkShareComputation,
            &proof,
            &anchors,
        )
        .expect("reduced anchor hash must be accepted");
    }
}
