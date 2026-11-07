// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{BlobRef, E3Id};
use alloy_primitives::{eip191_hash_message, keccak256, Address, Bytes, Signature, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

/// The proof numbering that `SlashingManager` uses for `proofType`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofType {
    C0PkBfv = 0,
    C1PkGeneration = 1,
    C2aSkShareComputation = 2,
    C2bESmShareComputation = 3,
    C3aSkShareEncryption = 4,
    C3bESmShareEncryption = 5,
    C4aSkShareDecryption = 6,
    C4bESmShareDecryption = 7,
    C5PkAggregation = 8,
    C6ThresholdShareDecryption = 9,
    C7DecryptedSharesAggregation = 10,
}

impl ProofType {
    pub(crate) fn word(self) -> U256 {
        U256::from(self as u8)
    }
}

/// A prover's output: its proof bytes, kept in the blob store, and its public inputs. Signing and
/// signature checks need only the bytes' hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ZkProof {
    pub data: BlobRef,
    pub public_inputs: Vec<B256>,
}

/// The layout every verifier contract decodes: `abi.encode(bytes proof, bytes32[] inputs)`.
pub fn verifier_calldata(proof: &[u8], public_inputs: &[B256]) -> Bytes {
    (Bytes::copy_from_slice(proof), public_inputs.to_vec())
        .abi_encode_params()
        .into()
}

impl ZkProof {
    /// The hash an operator signs to vouch for this proof. `SlashingManager` rebuilds the
    /// `ProofPayload` digest and recovers the signer with the EIP-191 message prefix.
    pub fn payload_signing_hash(&self, e3: E3Id, proof_type: ProofType) -> B256 {
        eip191_hash_message(self.payload_digest(e3, proof_type))
    }

    fn payload_digest(&self, e3: E3Id, proof_type: ProofType) -> B256 {
        let typehash = keccak256(
            "ProofPayload(uint256 chainId,uint256 e3Id,uint256 proofType,bytes zkProof,bytes publicSignals)",
        );
        let public_signals: Vec<u8> = self.public_inputs.iter().flat_map(|word| word.0).collect();
        keccak256(
            (
                typehash,
                U256::from(e3.chain_id),
                e3.number,
                proof_type.word(),
                self.data.hash,
                keccak256(public_signals),
            )
                .abi_encode(),
        )
    }
}

/// A proof with its prover's signature over the proof payload, which the slashing contracts accept
/// as evidence against the prover.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedProof {
    pub proof: ZkProof,
    pub signature: Bytes,
}

impl SignedProof {
    pub fn is_signed_by(&self, signer: Address, e3: E3Id, proof_type: ProofType) -> bool {
        let hash = self.proof.payload_signing_hash(e3, proof_type);
        Signature::try_from(self.signature.as_ref())
            .ok()
            .and_then(|signature| signature.recover_address_from_prehash(&hash).ok())
            == Some(signer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anvil's first development account; it signed the reference vectors below.
    const SIGNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    const PROOF_BYTES: [u8; 64] = [0x11; 64];

    fn proof() -> ZkProof {
        ZkProof {
            data: BlobRef::of(&PROOF_BYTES),
            public_inputs: vec![B256::repeat_byte(0x22); 3],
        }
    }

    fn e3() -> E3Id {
        E3Id {
            chain_id: 31337,
            number: U256::from(42),
        }
    }

    #[test]
    fn a_signature_from_the_current_node_recovers_to_its_signer() {
        let signed = SignedProof {
            proof: proof(),
            signature: hex::decode("cb0515edb11ec668720b96399da6b48cdcc90b14f3b11f83d645ad7642d27548708c2d49fbb614aa1cf7b3d49bbb96fe6b9d48bf4c9e84a1b6180f0191b55e4f1b").unwrap().into(),
        };
        let signer = SIGNER.parse().unwrap();
        assert!(signed.is_signed_by(signer, e3(), ProofType::C5PkAggregation));
        assert!(!signed.is_signed_by(signer, e3(), ProofType::C4aSkShareDecryption));
    }

    #[test]
    fn calldata_matches_the_current_node() {
        let expected = hex::decode(concat!(
            "0000000000000000000000000000000000000000000000000000000000000040",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "2222222222222222222222222222222222222222222222222222222222222222",
        ))
        .unwrap();
        let calldata = verifier_calldata(&PROOF_BYTES, &proof().public_inputs);
        assert_eq!(calldata, Bytes::from(expected));
    }
}
