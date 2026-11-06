// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3Id;
use alloy_primitives::{eip191_hash_message, keccak256, Bytes, B256, U256};
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

/// A prover's output: the proof bytes and its public inputs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZkProof {
    pub data: Bytes,
    pub public_inputs: Vec<B256>,
}

impl ZkProof {
    /// The layout every verifier contract decodes: `abi.encode(bytes proof, bytes32[] inputs)`.
    pub fn calldata(&self) -> Bytes {
        (self.data.clone(), self.public_inputs.clone())
            .abi_encode_params()
            .into()
    }

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
                keccak256(&self.data),
                keccak256(public_signals),
            )
                .abi_encode(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Signature};

    /// Anvil's first development account; it signed the reference vectors below.
    const SIGNER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn proof() -> ZkProof {
        ZkProof {
            data: Bytes::from(vec![0x11; 64]),
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
        let signature = Signature::try_from(
            &hex::decode("cb0515edb11ec668720b96399da6b48cdcc90b14f3b11f83d645ad7642d27548708c2d49fbb614aa1cf7b3d49bbb96fe6b9d48bf4c9e84a1b6180f0191b55e4f1b").unwrap()[..],
        )
        .unwrap();
        let hash = proof().payload_signing_hash(e3(), ProofType::C5PkAggregation);
        assert_eq!(
            signature.recover_address_from_prehash(&hash).unwrap(),
            SIGNER.parse::<Address>().unwrap()
        );
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
        assert_eq!(proof().calldata(), Bytes::from(expected));
    }
}
