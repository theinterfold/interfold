// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure ABI encoding of committee attestation evidence for slash submission.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol_types::SolValue,
};
use e3_events::AccusationQuorumReached;

/// Encode `AccusationQuorumReached` into the attestation evidence format expected
/// by both `SlashingManager.proposeSlash()` and `SlashingManager.proposeSlashByDkgParty()`:
/// `abi.encode(uint256 proofType, address[] voters, bytes32[] dataHashes, bytes evidence, uint256 deadline, bytes[] signatures)`
///
/// Voters are sorted ascending by address to satisfy the contract's duplicate-prevention
/// check. All `votes_for` share the same `deadline` (the accuser stamps one value at
/// accusation time and `AccusationManager::on_vote_received` rejects votes whose
/// deadline disagrees), so the encoder pulls it from the first vote. Returns `None`
/// if `votes_for` is empty — the on-chain submitter must skip the submission in that
/// case rather than send malformed calldata.
pub fn encode_attestation_evidence(data: &AccusationQuorumReached) -> Option<Vec<u8>> {
    if data.votes_for.is_empty() || data.evidence.is_empty() {
        return None;
    }

    // Collect and sort votes by voter address (ascending)
    let mut votes = data.votes_for.clone();
    votes.sort_by_key(|v| v.voter);

    let proof_type = U256::from(data.proof_type as u8);
    let voters: Vec<Address> = votes.iter().map(|v| v.voter).collect();
    let data_hashes: Vec<[u8; 32]> = votes.iter().map(|v| v.data_hash).collect();
    let evidence = data.evidence.clone();
    // All voters signed the same deadline (enforced off-chain by AccusationManager);
    // pick any one — the first vote suffices.
    let deadline = U256::from(votes[0].deadline);
    let signatures: Vec<Bytes> = votes
        .iter()
        .map(|v| Bytes::from(v.signature.extract_bytes()))
        .collect();

    Some(
        (
            proof_type,
            voters,
            data_hashes,
            evidence,
            deadline,
            signatures,
        )
            .abi_encode_params(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use e3_events::{AccusationOutcome, AccusationVote, E3id, ProofType};
    use e3_utils::ArcBytes;

    fn vote(voter: Address, deadline: u64) -> AccusationVote {
        AccusationVote {
            e3_id: E3id::new("1".to_string(), 1),
            accusation_id: [0u8; 32],
            voter,
            data_hash: [7u8; 32],
            deadline,
            signature: ArcBytes::from_bytes(&[1, 2, 3]),
        }
    }

    fn quorum(votes_for: Vec<AccusationVote>, evidence: &[u8]) -> AccusationQuorumReached {
        AccusationQuorumReached {
            e3_id: E3id::new("1".to_string(), 1),
            accuser: Address::repeat_byte(0xFF),
            accused: Address::repeat_byte(0xEE),
            proof_type: ProofType::C0PkBfv,
            votes_for,
            outcome: AccusationOutcome::AccusedFaulted,
            evidence: evidence.to_vec().into(),
        }
    }

    #[test]
    fn test_returns_none_for_empty_votes() {
        let q = quorum(vec![], b"abc");
        assert!(encode_attestation_evidence(&q).is_none());
    }

    #[test]
    fn test_returns_none_for_empty_evidence() {
        let q = quorum(vec![vote(Address::repeat_byte(0x01), 100)], b"");
        assert!(encode_attestation_evidence(&q).is_none());
    }

    #[test]
    fn test_voters_are_sorted_ascending() {
        // Provide voters in descending order; encoding must sort them ascending.
        let hi = Address::repeat_byte(0x22);
        let lo = Address::repeat_byte(0x01);
        let q = quorum(vec![vote(hi, 100), vote(lo, 100)], b"evidence");
        let encoded = encode_attestation_evidence(&q).expect("should encode");

        let decoded =
            <(U256, Vec<Address>, Vec<B256>, Bytes, U256, Vec<Bytes>)>::abi_decode_params(&encoded)
                .expect("decodes");
        assert_eq!(decoded.1, vec![lo, hi]);
        assert_eq!(decoded.4, U256::from(100u64));
    }
}
