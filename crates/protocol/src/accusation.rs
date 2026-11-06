// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{contract_domain, proof::ProofType, E3Id};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolStruct, SolValue};
use serde::{Deserialize, Serialize};

mod typed {
    alloy_sol_types::sol! {
        struct AccusationVote {
            uint256 e3Id;
            bytes32 accusationId;
            address voter;
            bytes32 dataHash;
            uint256 issuedAt;
            uint256 deadline;
        }
    }
}

/// `SlashingManager` derives the same id to match votes to the accusation they answer.
pub fn accusation_id(e3: E3Id, accused: Address, proof_type: ProofType) -> B256 {
    keccak256(
        (
            U256::from(e3.chain_id),
            e3.number,
            accused,
            proof_type.word(),
        )
            .abi_encode_packed(),
    )
}

/// A committee member's vote that an accused proof failed. Every voter signs the same window.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Vote {
    pub e3: E3Id,
    pub accusation_id: B256,
    pub voter: Address,
    pub data_hash: B256,
    pub issued_at: u64,
    pub deadline: u64,
}

impl Vote {
    /// The EIP-712 hash that `SlashingManager` verifies, under its "InterfoldSlashing" domain.
    pub fn signing_hash(&self, slashing_manager: Address) -> B256 {
        typed::AccusationVote {
            e3Id: self.e3.number,
            accusationId: self.accusation_id,
            voter: self.voter,
            dataHash: self.data_hash,
            issuedAt: U256::from(self.issued_at),
            deadline: U256::from(self.deadline),
        }
        .eip712_signing_hash(&contract_domain(
            "InterfoldSlashing",
            self.e3.chain_id,
            slashing_manager,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedVote {
    pub vote: Vote,
    pub signature: Bytes,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("slash evidence needs at least one vote")]
    NoVotes,
    #[error("slash evidence needs the disputed proof bytes")]
    NoProofBytes,
}

/// The attestation evidence `SlashingManager.proposeSlash` decodes. Voters are sorted ascending
/// because the contract rejects duplicates by requiring strictly increasing addresses.
pub fn slash_evidence(
    proof_type: ProofType,
    votes: &[SignedVote],
    disputed_proof: &[u8],
) -> Result<Bytes, EvidenceError> {
    if disputed_proof.is_empty() {
        return Err(EvidenceError::NoProofBytes);
    }
    let mut votes: Vec<&SignedVote> = votes.iter().collect();
    votes.sort_by_key(|signed| signed.vote.voter);
    let window = votes.first().ok_or(EvidenceError::NoVotes)?;
    let (issued_at, deadline) = (window.vote.issued_at, window.vote.deadline);
    Ok((
        proof_type.word(),
        votes
            .iter()
            .map(|signed| signed.vote.voter)
            .collect::<Vec<_>>(),
        votes
            .iter()
            .map(|signed| signed.vote.data_hash)
            .collect::<Vec<_>>(),
        Bytes::copy_from_slice(disputed_proof),
        U256::from(issued_at),
        U256::from(deadline),
        votes
            .iter()
            .map(|signed| signed.signature.clone())
            .collect::<Vec<_>>(),
    )
        .abi_encode_params()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3() -> E3Id {
        E3Id {
            chain_id: 31337,
            number: U256::from(42),
        }
    }

    fn address(text: &str) -> Address {
        text.parse().unwrap()
    }

    #[test]
    fn vote_hash_matches_the_independent_eip712_vector() {
        let accusation = accusation_id(
            e3(),
            address("0x1111111111111111111111111111111111111111"),
            ProofType::C0PkBfv,
        );
        assert_eq!(
            accusation,
            "0x4511f8ed6c3d679b420f7632b2e7603a3efc8a630e779ce7260a15e4b92dca96"
                .parse::<B256>()
                .unwrap()
        );
        let vote = Vote {
            e3: e3(),
            accusation_id: accusation,
            voter: address("0x2222222222222222222222222222222222222222"),
            data_hash: B256::repeat_byte(0xab),
            issued_at: 1_000,
            deadline: 2_800,
        };
        assert_eq!(
            vote.signing_hash(address("0x9999999999999999999999999999999999999999")),
            "0xcb216d9b5829c294d91eb7a47e64aec925818d691097005aa78e844591667545"
                .parse::<B256>()
                .unwrap()
        );
    }

    fn signed(voter: &str, fill: u8) -> SignedVote {
        SignedVote {
            vote: Vote {
                e3: e3(),
                accusation_id: B256::repeat_byte(0x01),
                voter: address(voter),
                data_hash: B256::repeat_byte(fill),
                issued_at: 1_000,
                deadline: 2_800,
            },
            signature: Bytes::from(vec![fill; 65]),
        }
    }

    #[test]
    fn slash_evidence_matches_the_current_node() {
        let votes = [
            signed("0x2222222222222222222222222222222222222222", 0xaa),
            signed("0x2111111111111111111111111111111111111111", 0xbb),
        ];
        let expected = hex::decode(concat!(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "00000000000000000000000000000000000000000000000000000000000000e0",
            "0000000000000000000000000000000000000000000000000000000000000140",
            "00000000000000000000000000000000000000000000000000000000000001a0",
            "00000000000000000000000000000000000000000000000000000000000003e8",
            "0000000000000000000000000000000000000000000000000000000000000af0",
            "0000000000000000000000000000000000000000000000000000000000000200",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000002111111111111111111111111111111111111111",
            "0000000000000000000000002222222222222222222222222222222222222222",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0000000000000000000000000000000000000000000000000000000000000028",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "5555555555555555000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "00000000000000000000000000000000000000000000000000000000000000c0",
            "0000000000000000000000000000000000000000000000000000000000000041",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bb00000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000041",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aa00000000000000000000000000000000000000000000000000000000000000",
        ))
        .unwrap();
        assert_eq!(
            slash_evidence(ProofType::C1PkGeneration, &votes, &[0x55; 40]).unwrap(),
            Bytes::from(expected)
        );
    }

    #[test]
    fn slash_evidence_needs_votes_and_the_disputed_proof() {
        let votes = [signed("0x2222222222222222222222222222222222222222", 0xaa)];
        assert_eq!(
            slash_evidence(ProofType::C1PkGeneration, &[], &[0x55; 40]),
            Err(EvidenceError::NoVotes)
        );
        assert_eq!(
            slash_evidence(ProofType::C1PkGeneration, &votes, &[]),
            Err(EvidenceError::NoProofBytes)
        );
    }
}
