// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Accusations against a committee member whose signed proof fails: what members send each other,
//! the votes `SlashingManager.proposeSlash` takes, and its evidence.

mod cases;

pub use cases::Accusations;

use crate::{
    contract_domain,
    proof::{ProofType, SignedProof, ZkProof},
    E3Id, UnixSecs,
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolStruct, SolValue};
use serde::{Deserialize, Serialize};

/// What an E3's request snapshotted for slashing: the manager whose domain votes sign under, and
/// the longest window a vote may sign, zero when accusations are off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slashing {
    pub manager: Address,
    pub validity: UnixSecs,
}

/// What a check of a member's message found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Valid,
    /// The message does not hold, though no proof in it fails: its bytes do not decode, or they
    /// are not the bytes its proofs commit to. The member is left out but not accused.
    Invalid,
    /// A proof the member signed fails, so the member is left out and accused.
    Fails(Fault),
}

impl Verdict {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// A signed proof that fails, and the hash of the evidence that `proposeSlash` would carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fault {
    pub proof_type: ProofType,
    pub proof: ZkProof,
    pub data_hash: B256,
}

/// What committee members send each other about a proof that fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccusationMessage {
    /// The accuser's vote, with the signed proof it accuses, so every member checks the same
    /// bytes.
    Accuse {
        accused: Address,
        proof_type: ProofType,
        proof: SignedProof,
        vote: SignedVote,
    },
    /// Another member's vote for an accusation it checked.
    Vote(SignedVote),
}

impl AccusationMessage {
    pub(crate) fn blobs(&self) -> Vec<crate::BlobRef> {
        match self {
            Self::Accuse { proof, .. } => vec![proof.proof.data],
            Self::Vote(_) => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccusationWork {
    /// Whether `proof` fails, and the hash of its evidence.
    Verify {
        proof_type: ProofType,
        proof: ZkProof,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccusationWorkResult {
    Verified {
        proof_type: ProofType,
        proof: ZkProof,
        fails: bool,
        data_hash: B256,
    },
}

/// One accusation, the window every vote for it signs, and the evidence those votes sign: the
/// contract takes one evidence hash for all the votes of a slash, so votes for two count apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ballot {
    pub accusation_id: B256,
    pub data_hash: B256,
    pub issued_at: UnixSecs,
    pub deadline: UnixSecs,
}

impl Ballot {
    pub(crate) fn of(vote: &Vote) -> Self {
        Self {
            accusation_id: vote.accusation_id,
            data_hash: vote.data_hash,
            issued_at: vote.issued_at,
            deadline: vote.deadline,
        }
    }
}

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

/// The disputed proof as the slash evidence carries it, as the current node encodes it: the proof's
/// bytes and its public signals. Votes sign its hash.
pub fn disputed_proof(proof: &[u8], public_inputs: &[B256]) -> Bytes {
    let signals: Vec<u8> = public_inputs.iter().flat_map(|input| input.0).collect();
    (Bytes::copy_from_slice(proof), Bytes::from(signals))
        .abi_encode()
        .into()
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
mod tests;
