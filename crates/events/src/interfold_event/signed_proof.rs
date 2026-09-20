// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Signed proof payload types for fault attribution.
//!
//! Every ZK proof a node broadcasts is wrapped in a [`SignedProofPayload`] — the node's
//! ECDSA signature over the canonical encoding of the data + proof.  If the proof later
//! fails verification, the signed bundle is self-authenticating evidence of fault:
//! the signature proves authorship and the proof bytes prove invalidity.

use crate::{CircuitName, E3id, Proof};
use actix::Message;
use alloy::primitives::{keccak256, Address, FixedBytes, Signature, U256};
use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, ensure, Result};
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Proof type identifier for externally signed node proofs.
///
/// Bincode encodes this enum by variant order. Do not reorder variants.
/// Add new proof types at the end. Keep retired proof types for compatibility.
#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    strum::EnumCount,
)]
pub enum ProofType {
    /// C0 — BFV public key proof (Proof 0).
    C0PkBfv = 0,
    /// C1 — TrBFV public key generation proof (Proof 1).
    C1PkGeneration = 1,
    /// C2a — Secret key share computation proof (Proof 2a).
    C2aSkShareComputation = 2,
    /// C2b — Smudging noise share computation proof (Proof 2b).
    C2bESmShareComputation = 3,
    /// C3a — Share encryption proof (Proof 3a).
    C3aSkShareEncryption = 4,
    /// C3b — Smudging noise share encryption proof (Proof 3b).
    C3bESmShareEncryption = 5,
    /// C4a — SK share decryption proof (Proof 4a).
    C4aSkShareDecryption = 6,
    /// C4b — Smudging noise share decryption proof (Proof 4b).
    C4bESmShareDecryption = 7,
    /// C5 — Public key aggregation proof (Proof 5).
    C5PkAggregation = 8,
    /// C6 — Threshold share decryption proof (Proof 6).
    C6ThresholdShareDecryption = 9,
    /// C7 — Decrypted shares aggregation proof (Proof 7).
    C7DecryptedSharesAggregation = 10,
    /// Row-level l-BFV public-key generation proof.
    LbfvPkGeneration = 11,
    /// Row-level l-BFV relinearization-key generation proof.
    RlkGeneration = 12,
    /// Row-level threshold l-BFV public-key aggregation proof.
    LbfvPkAggregation = 13,
    /// Row-level l-BFV relinearization-key aggregation proof.
    RlkAggregation = 14,
}

/// Stable identity of one externally signed proof instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofIdentity {
    pub proof_type: ProofType,
    /// Zero for singleton proof types. Row proof types use their public `row_index`.
    pub instance: u32,
}

impl ProofType {
    /// Number of row instances required for each l-BFV proof family.
    pub const LBFV_ROW_INSTANCES: u32 = 5;

    /// Complete list of externally signed proof types in durable order.
    pub const ALL: [Self; <Self as strum::EnumCount>::COUNT] = [
        Self::C0PkBfv,
        Self::C1PkGeneration,
        Self::C2aSkShareComputation,
        Self::C2bESmShareComputation,
        Self::C3aSkShareEncryption,
        Self::C3bESmShareEncryption,
        Self::C4aSkShareDecryption,
        Self::C4bESmShareDecryption,
        Self::C5PkAggregation,
        Self::C6ThresholdShareDecryption,
        Self::C7DecryptedSharesAggregation,
        Self::LbfvPkGeneration,
        Self::RlkGeneration,
        Self::LbfvPkAggregation,
        Self::RlkAggregation,
    ];

    /// Map this proof type to its corresponding circuit names.
    pub fn circuit_names(&self) -> Vec<CircuitName> {
        match self {
            ProofType::C0PkBfv => vec![CircuitName::PkBfv],
            ProofType::C1PkGeneration => vec![CircuitName::PkGeneration],
            ProofType::C2aSkShareComputation => vec![CircuitName::SkC2ChunkFinalize],
            ProofType::C2bESmShareComputation => vec![CircuitName::ESmC2ChunkFinalize],
            ProofType::C3aSkShareEncryption => vec![CircuitName::ShareEncryption],
            ProofType::C3bESmShareEncryption => vec![CircuitName::ShareEncryption],
            ProofType::C4aSkShareDecryption | ProofType::C4bESmShareDecryption => {
                vec![CircuitName::DkgShareDecryption]
            }
            ProofType::C6ThresholdShareDecryption => vec![CircuitName::ThresholdShareDecryption],
            ProofType::C7DecryptedSharesAggregation => {
                vec![CircuitName::DecryptedSharesAggregation]
            }
            ProofType::C5PkAggregation => vec![CircuitName::PkAggregation],
            ProofType::LbfvPkGeneration => vec![CircuitName::LbfvPkGeneration],
            ProofType::RlkGeneration => vec![CircuitName::RlkGeneration],
            ProofType::LbfvPkAggregation => vec![CircuitName::LbfvPkAggregation],
            ProofType::RlkAggregation => vec![CircuitName::RlkAggregation],
        }
    }

    /// Return the stable slash category for this proof type.
    pub fn slash_reason(&self) -> &'static str {
        match self {
            ProofType::C0PkBfv
            | ProofType::C1PkGeneration
            | ProofType::C2aSkShareComputation
            | ProofType::C2bESmShareComputation
            | ProofType::C3aSkShareEncryption
            | ProofType::C3bESmShareEncryption
            | ProofType::C4aSkShareDecryption
            | ProofType::C4bESmShareDecryption => "E3_BAD_DKG_PROOF",
            ProofType::C6ThresholdShareDecryption => "E3_BAD_DECRYPTION_PROOF",
            ProofType::C7DecryptedSharesAggregation => "E3_BAD_AGGREGATION_PROOF",
            ProofType::C5PkAggregation | ProofType::LbfvPkAggregation => {
                "E3_BAD_PK_AGGREGATION_PROOF"
            }
            ProofType::LbfvPkGeneration | ProofType::RlkGeneration => "E3_BAD_DKG_GENERATION_PROOF",
            ProofType::RlkAggregation => "E3_BAD_RLK_AGGREGATION_PROOF",
        }
    }

    /// Derive the Lane A policy key used by `SlashingManager._proposeSlash`.
    pub fn attestation_slash_reason(&self) -> FixedBytes<32> {
        keccak256(U256::from(*self as u8).to_be_bytes::<32>())
    }

    pub fn is_multirow(self) -> bool {
        matches!(
            self,
            Self::LbfvPkGeneration
                | Self::RlkGeneration
                | Self::LbfvPkAggregation
                | Self::RlkAggregation
        )
    }

    /// Derive the proof instance from the signed circuit public inputs.
    pub fn instance_from_public_signals(self, public_signals: &[u8]) -> Result<u32> {
        if !self.is_multirow() {
            return Ok(0);
        }

        let circuit = self.circuit_names()[0];
        let row = circuit
            .input_layout()
            .extract_field(public_signals, "row_index")
            .ok_or_else(|| anyhow!("missing row_index public input for {self:?}"))?;
        ensure!(
            row[..28].iter().all(|byte| *byte == 0),
            "row_index public input does not fit u32"
        );
        let instance = u32::from_be_bytes(row[28..].try_into().expect("four-byte u32 suffix"));
        Ok(instance)
    }

    /// Validate the circuit mapping and derive the stable proof identity.
    pub fn identity(self, proof: &Proof) -> Result<ProofIdentity> {
        ensure!(
            self.circuit_names().contains(&proof.circuit),
            "circuit {:?} does not match proof type {self:?}",
            proof.circuit
        );
        Ok(ProofIdentity {
            proof_type: self,
            instance: self.instance_from_public_signals(&proof.public_signals)?,
        })
    }
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Data payload that a node signs before broadcasting.
///
/// Only contains data needed for on-chain fault verification:
/// the E3 identifier, proof type, and the ZK proof itself.
/// Encoded via `abi.encode(chainId, e3Id, proofType, proof, publicSignals)`
/// so on-chain `ecrecover` can reconstruct the same digest.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ProofPayload {
    /// E3 computation identifier.
    pub e3_id: E3id,
    /// Which proof this payload carries.
    pub proof_type: ProofType,
    /// The ZK proof that attests to the data.
    pub proof: Proof,
}

impl ProofPayload {
    /// The typehash that domain-separates the signed message.
    ///
    /// Must match `PROOF_PAYLOAD_TYPEHASH` in `SlashingManager.sol`:
    /// `keccak256("ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)")`
    pub fn typehash() -> [u8; 32] {
        keccak256(
            "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)",
        )
        .into()
    }

    /// Compute the keccak256 digest of the canonical encoding.
    ///
    /// Uses structured hashing with a typehash prefix for domain separation,
    /// and keccak256-hashes the dynamic fields (`zkProof`, `publicSignals`)
    /// for gas efficiency on the Solidity verification side.
    ///
    /// The encoding is:
    /// ```text
    /// keccak256(abi.encode(
    ///     PROOF_PAYLOAD_TYPEHASH,   // bytes32
    ///     chainId,                   // uint256
    ///     e3Id,                      // uint256
    ///     proofType,                 // uint256
    ///     keccak256(zkProof),        // bytes32
    ///     keccak256(publicSignals)   // bytes32
    /// ))
    /// ```
    ///
    /// This matches the reconstruction in `SlashingManager.proposeSlash()`.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let e3_id_u256: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("E3id cannot be converted to U256"))?;

        let typehash = Self::typehash();

        // keccak256(abi.encode(typehash, chainId, e3Id, proofType, keccak256(proof), keccak256(publicSignals)))
        // All fields are bytes32/uint256 → pure static ABI encoding (6 × 32 = 192 bytes)
        let encoded = (
            typehash,
            U256::from(self.e3_id.chain_id()),
            e3_id_u256,
            U256::from(self.proof_type as u8),
            keccak256(&*self.proof.data),
            keccak256(&*self.proof.public_signals),
        )
            .abi_encode();

        Ok(keccak256(&encoded).into())
    }

    /// Identify the statement that this proof verifies.
    ///
    /// This digest excludes the proof bytes because a ZK prover can produce
    /// different valid proof encodings for the same public statement. Use
    /// [`Self::digest`] when authenticating the complete proof payload.
    pub fn statement_digest(&self) -> Result<[u8; 32]> {
        let e3_id: U256 = self
            .e3_id
            .clone()
            .try_into()
            .map_err(|_| anyhow!("E3id cannot be converted to U256"))?;
        let encoded = (
            keccak256("InterfoldProofStatement(uint256 chainId,uint256 e3Id,uint256 proofType,bytes32 circuitHash,bytes32 publicSignalsHash)"),
            U256::from(self.e3_id.chain_id()),
            e3_id,
            U256::from(self.proof_type as u8),
            keccak256(self.proof.circuit.dir_path()),
            keccak256(&*self.proof.public_signals),
        )
            .abi_encode();
        Ok(keccak256(encoded).into())
    }
}

/// Signed wrapper around a [`ProofPayload`].
///
/// This is the unit of data broadcast over the p2p network.  The signature
/// is an Ethereum-style `eth_sign` (EIP-191 personal message) over the
/// keccak256 digest of the payload's canonical encoding.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct SignedProofPayload {
    /// The payload that was signed.
    pub payload: ProofPayload,
    /// 65-byte ECDSA signature (r ‖ s ‖ v) computed via `eth_sign`.
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub signature: ArcBytes,
}

impl SignedProofPayload {
    /// Sign a [`ProofPayload`] with the node's ECDSA key.
    pub fn sign(payload: ProofPayload, signer: &PrivateKeySigner) -> Result<Self> {
        let digest = payload.digest()?;
        let sig = signer
            .sign_message_sync(&digest)
            .map_err(|e| anyhow!("Failed to sign proof payload: {e}"))?;

        Ok(Self {
            payload,
            signature: ArcBytes::from_bytes(&sig.as_bytes()),
        })
    }

    /// Recover the Ethereum address that produced this signature.
    pub fn recover_address(&self) -> Result<Address> {
        let sig = Signature::try_from(&self.signature[..])
            .map_err(|e| anyhow!("Invalid signature: {e}"))?;

        let digest = self.payload.digest()?;
        sig.recover_address_from_msg(digest)
            .map_err(|e| anyhow!("Failed to recover address: {e}"))
    }

    /// Verify that the recovered address matches the expected address.
    pub fn verify_address(&self, expected: &Address) -> Result<bool> {
        let recovered = self.recover_address()?;
        Ok(recovered == *expected)
    }
}

/// Emitted when a node detects a signed proof that fails ZK verification.
///
/// This event carries the complete evidence bundle: the bad proof bytes,
/// the public signals, and the faulting node's signature.  The
/// [`FaultSubmitter`] actor consumes this to submit a slash proposal
/// on-chain.
#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct SignedProofFailed {
    /// E3 computation identifier.
    pub e3_id: E3id,
    /// Ethereum address of the faulting node (recovered from signature).
    pub faulting_node: Address,
    /// Which proof type failed.
    pub proof_type: ProofType,
    /// The full signed payload — self-authenticating evidence.
    pub signed_payload: SignedProofPayload,
}

impl Display for SignedProofFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedProofFailed {{ e3_id: {}, faulting_node: {}, proof_type: {} }}",
            self.e3_id, self.faulting_node, self.proof_type
        )
    }
}

/// Encode a [`SignedProofFailed`] event into the ABI-encoded evidence bytes
/// expected by `SlashingManager.proposeSlash()` for **Lane B** (evidence-based,
/// SLASHER_ROLE) slashing.
///
/// **Not used in production.** The current production flow uses Lane A
/// (attestation-based) via `encode_attestation_evidence()` in
/// `slashing_manager_sol_writer.rs`. This function is retained for Lane B
/// integration tests and may be activated when Lane B slashing is implemented.
///
/// Returns: `abi.encode(bytes zkProof, bytes32[] publicInputs, bytes signature, uint256 chainId, uint256 proofType, address verifier)`
///
/// The `verifier` is the current on-chain verifier contract address for this
/// proof type's slash policy. The `FaultSubmitter` actor must look this up
/// before calling this function.
pub fn encode_fault_evidence(failed: &SignedProofFailed, verifier: Address) -> Vec<u8> {
    use alloy::primitives::Bytes;

    let proof = &failed.signed_payload.payload.proof;

    // Convert raw public_signals bytes → Vec<FixedBytes<32>> (one per 32-byte field)
    let public_inputs: Vec<FixedBytes<32>> = proof
        .public_signals
        .chunks(32)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            FixedBytes::from(buf)
        })
        .collect();

    // Must match the decode in SlashingManager.proposeSlash():
    // (bytes zkProof, bytes32[] publicInputs, bytes signature, uint256 chainId, uint256 proofType, address verifier)
    //
    // IMPORTANT: Use abi_encode_params() (not abi_encode()) because abi_encode()
    // wraps dynamic tuples in an outer offset word, but Solidity's abi.decode()
    // expects flat parameter encoding — the same as abi.encode(a, b, c, ...).
    (
        Bytes::copy_from_slice(&proof.data),
        public_inputs,
        Bytes::copy_from_slice(&failed.signed_payload.signature),
        U256::from(failed.e3_id.chain_id()),
        U256::from(failed.signed_payload.payload.proof_type as u8),
        verifier,
    )
        .abi_encode_params()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> PrivateKeySigner {
        // Deterministic test key
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap()
    }

    fn test_payload() -> ProofPayload {
        ProofPayload {
            e3_id: E3id::new("1", 42),
            proof_type: ProofType::C0PkBfv,
            proof: Proof::new(
                CircuitName::PkBfv,
                ArcBytes::from_bytes(&[10, 20, 30]),
                ArcBytes::from_bytes(&[100, 200]),
            ),
        }
    }

    #[test]
    fn sign_and_recover_roundtrip() {
        let signer = test_signer();
        let payload = test_payload();

        let signed =
            SignedProofPayload::sign(payload.clone(), &signer).expect("signing should succeed");

        let recovered = signed.recover_address().expect("recovery should succeed");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn verify_address_correct() {
        let signer = test_signer();
        let payload = test_payload();

        let signed = SignedProofPayload::sign(payload, &signer).expect("signing should succeed");
        assert!(signed
            .verify_address(&signer.address())
            .expect("verify should succeed"));
    }

    #[test]
    fn verify_address_wrong() {
        let signer = test_signer();
        let payload = test_payload();

        let signed = SignedProofPayload::sign(payload, &signer).expect("signing should succeed");

        let wrong_addr: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        assert!(!signed
            .verify_address(&wrong_addr)
            .expect("verify should succeed"));
    }

    #[test]
    fn different_payloads_produce_different_digests() {
        let p1 = test_payload();
        let mut p2 = test_payload();
        p2.proof_type = ProofType::C1PkGeneration;

        assert_ne!(
            p1.digest().expect("digest should succeed"),
            p2.digest().expect("digest should succeed")
        );
    }

    #[test]
    fn statement_digest_ignores_proof_randomness() {
        let first = test_payload();
        let mut second = first.clone();
        second.proof.data = ArcBytes::from_bytes(&[99, 88, 77]);

        assert_ne!(first.digest().unwrap(), second.digest().unwrap());
        assert_eq!(
            first.statement_digest().unwrap(),
            second.statement_digest().unwrap()
        );

        second.proof.public_signals = ArcBytes::from_bytes(&[7, 8, 9]);
        assert_ne!(
            first.statement_digest().unwrap(),
            second.statement_digest().unwrap()
        );

        second.proof.public_signals = first.proof.public_signals.clone();
        second.proof.circuit = CircuitName::ESmShareComputation;
        assert_ne!(
            first.statement_digest().unwrap(),
            second.statement_digest().unwrap()
        );
    }

    #[test]
    fn tampered_payload_fails_recovery() {
        let signer = test_signer();
        let payload = test_payload();

        let mut signed =
            SignedProofPayload::sign(payload, &signer).expect("signing should succeed");
        // Tamper with the payload after signing
        signed.payload.proof_type = ProofType::C1PkGeneration;

        let recovered = signed.recover_address().expect("recovery should succeed");
        // Recovered address won't match the signer because payload was tampered
        assert_ne!(recovered, signer.address());
    }

    #[test]
    fn proof_type_discriminants_preserve_durable_order() {
        let expected = [
            (ProofType::C0PkBfv, 0),
            (ProofType::C1PkGeneration, 1),
            (ProofType::C2aSkShareComputation, 2),
            (ProofType::C2bESmShareComputation, 3),
            (ProofType::C3aSkShareEncryption, 4),
            (ProofType::C3bESmShareEncryption, 5),
            (ProofType::C4aSkShareDecryption, 6),
            (ProofType::C4bESmShareDecryption, 7),
            (ProofType::C5PkAggregation, 8),
            (ProofType::C6ThresholdShareDecryption, 9),
            (ProofType::C7DecryptedSharesAggregation, 10),
            (ProofType::LbfvPkGeneration, 11),
            (ProofType::RlkGeneration, 12),
            (ProofType::LbfvPkAggregation, 13),
            (ProofType::RlkAggregation, 14),
        ];

        assert_eq!(ProofType::ALL, expected.map(|(proof_type, _)| proof_type));
        for (proof_type, discriminant) in expected {
            assert_eq!(proof_type as u8, discriminant, "{proof_type:?}");
        }
    }

    #[test]
    fn proof_type_bincode_bytes_preserve_variant_order() {
        for proof_type in ProofType::ALL {
            let discriminant = proof_type as u8;
            let expected = [discriminant, 0, 0, 0];
            assert_eq!(bincode::serialize(&proof_type).unwrap(), expected);
            assert_eq!(
                bincode::deserialize::<ProofType>(&expected).unwrap(),
                proof_type
            );
        }
    }

    #[test]
    fn proof_type_circuit_names_mapping_is_complete() {
        let expected = [
            (ProofType::C0PkBfv, CircuitName::PkBfv),
            (ProofType::C1PkGeneration, CircuitName::PkGeneration),
            (
                ProofType::C2aSkShareComputation,
                CircuitName::SkC2ChunkFinalize,
            ),
            (
                ProofType::C2bESmShareComputation,
                CircuitName::ESmC2ChunkFinalize,
            ),
            (
                ProofType::C3aSkShareEncryption,
                CircuitName::ShareEncryption,
            ),
            (
                ProofType::C3bESmShareEncryption,
                CircuitName::ShareEncryption,
            ),
            (
                ProofType::C4aSkShareDecryption,
                CircuitName::DkgShareDecryption,
            ),
            (
                ProofType::C4bESmShareDecryption,
                CircuitName::DkgShareDecryption,
            ),
            (ProofType::C5PkAggregation, CircuitName::PkAggregation),
            (
                ProofType::C6ThresholdShareDecryption,
                CircuitName::ThresholdShareDecryption,
            ),
            (
                ProofType::C7DecryptedSharesAggregation,
                CircuitName::DecryptedSharesAggregation,
            ),
            (ProofType::LbfvPkGeneration, CircuitName::LbfvPkGeneration),
            (ProofType::RlkGeneration, CircuitName::RlkGeneration),
            (ProofType::LbfvPkAggregation, CircuitName::LbfvPkAggregation),
            (ProofType::RlkAggregation, CircuitName::RlkAggregation),
        ];

        assert_eq!(ProofType::ALL, expected.map(|(proof_type, _)| proof_type));
        for (proof_type, circuit) in expected {
            assert_eq!(proof_type.circuit_names(), vec![circuit], "{proof_type:?}");
        }
    }

    #[test]
    fn proof_type_slash_categories_are_stable() {
        let expected = [
            (ProofType::C0PkBfv, "E3_BAD_DKG_PROOF"),
            (ProofType::C1PkGeneration, "E3_BAD_DKG_PROOF"),
            (ProofType::C2aSkShareComputation, "E3_BAD_DKG_PROOF"),
            (ProofType::C2bESmShareComputation, "E3_BAD_DKG_PROOF"),
            (ProofType::C3aSkShareEncryption, "E3_BAD_DKG_PROOF"),
            (ProofType::C3bESmShareEncryption, "E3_BAD_DKG_PROOF"),
            (ProofType::C4aSkShareDecryption, "E3_BAD_DKG_PROOF"),
            (ProofType::C4bESmShareDecryption, "E3_BAD_DKG_PROOF"),
            (ProofType::C5PkAggregation, "E3_BAD_PK_AGGREGATION_PROOF"),
            (
                ProofType::C6ThresholdShareDecryption,
                "E3_BAD_DECRYPTION_PROOF",
            ),
            (
                ProofType::C7DecryptedSharesAggregation,
                "E3_BAD_AGGREGATION_PROOF",
            ),
            (ProofType::LbfvPkGeneration, "E3_BAD_DKG_GENERATION_PROOF"),
            (ProofType::RlkGeneration, "E3_BAD_DKG_GENERATION_PROOF"),
            (ProofType::LbfvPkAggregation, "E3_BAD_PK_AGGREGATION_PROOF"),
            (ProofType::RlkAggregation, "E3_BAD_RLK_AGGREGATION_PROOF"),
        ];

        assert_eq!(ProofType::ALL, expected.map(|(proof_type, _)| proof_type));
        for (proof_type, slash_category) in expected {
            assert_eq!(proof_type.slash_reason(), slash_category, "{proof_type:?}");
        }
    }

    #[test]
    fn existing_proof_payload_digests_are_stable() {
        let expected = [
            (
                ProofType::C0PkBfv,
                "37507604f71509f27967c0f4249478526d7f4006d7598ef672ca9091a33bff13",
            ),
            (
                ProofType::C1PkGeneration,
                "df0b5be871f1bca9705f2f2491ad11b746d1dad82ca6ae4c18f2d7d7b10896e6",
            ),
            (
                ProofType::C2aSkShareComputation,
                "53925d98f1735af2b6bd6fe20ec37aa02f5b13af58856531407f8d54c022239b",
            ),
            (
                ProofType::C2bESmShareComputation,
                "68b1e1c357c37c7c6fd065e5d56f08fc13e8b034367f5f7bb4276c366623fad6",
            ),
            (
                ProofType::C3aSkShareEncryption,
                "d6c33915e48b266e16fc921435a2a5f543e78c157f25c14f62683a9e0f7cb462",
            ),
            (
                ProofType::C3bESmShareEncryption,
                "233970e7eb9996637b8d31c5812cc244fb69df3ecbeacec5dc6809ac20286ff4",
            ),
            (
                ProofType::C4aSkShareDecryption,
                "679bced615422ba5eee8f2d8cc0b5c9a6bc576db22176cfca2eb559170efcf60",
            ),
            (
                ProofType::C4bESmShareDecryption,
                "9665346cdf9b7d7a49092ec195edb7e7a842f531b2e4c291d5c8f1c3c069d1cf",
            ),
            (
                ProofType::C5PkAggregation,
                "cc48e7c7daf150e9c83a556cb26b4ea761a18c9372b55edbdcfc4cab288d55c2",
            ),
            (
                ProofType::C6ThresholdShareDecryption,
                "99f1e3c1c8debdfb62a4d18f79433b089e4712350daebf925f25fe96eff1357c",
            ),
            (
                ProofType::C7DecryptedSharesAggregation,
                "11729ea624067dbb9c123454c35a59522eadb7d3cbf792ea0c130417237cd157",
            ),
        ];

        for (proof_type, digest) in expected {
            let mut payload = test_payload();
            payload.proof_type = proof_type;
            assert_eq!(
                payload.digest().unwrap().as_slice(),
                hex::decode(digest).unwrap().as_slice(),
                "{proof_type:?}"
            );
        }
    }
}
