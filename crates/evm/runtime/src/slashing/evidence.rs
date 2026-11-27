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
use e3_events::LbfvAccusationQuorumReached;

/// Encode a quorum report of either proving path into the attestation evidence format expected by
/// both `SlashingManager.proposeSlash()` and `SlashingManager.proposeSlashByDkgParty()`:
/// `abi.encode(uint256 proofType, address[] voters, bytes32[] dataHashes, bytes evidence, uint256 issuedAt, uint256 deadline, bytes[] signatures)`
///
/// The l-BFV row families ([`ProofType::is_multirow`]) name their row, so their evidence has a
/// `uint256 proofInstance` after `proofType`. Every other proof type has one instance and no such
/// field, so a trBFV report has the bytes that it had before l-BFV.
///
/// Voters are sorted ascending by address to satisfy the contract's duplicate-prevention
/// check. All `votes_for` share the same `issued_at` and `deadline` values. The
/// accuser sets both values, and `AccusationManager::on_vote_received` rejects a
/// vote when either value differs. The encoder therefore reads them from the
/// first vote. Returns `None`
/// if `votes_for` is empty, or if a proof type with one instance names another — the on-chain
/// submitter must skip the submission in that case rather than send malformed calldata.
pub fn encode_attestation_evidence(data: &LbfvAccusationQuorumReached) -> Option<Vec<u8>> {
    if data.votes_for.is_empty() || data.evidence.is_empty() {
        return None;
    }
    let multirow = data.proof_type.is_multirow();
    if !multirow && data.proof_instance != 0 {
        return None;
    }

    // Collect and sort votes by voter address (ascending)
    let mut votes = data.votes_for.clone();
    votes.sort_by_key(|v| v.voter);

    let proof_type = U256::from(data.proof_type as u8);
    let proof_instance = U256::from(data.proof_instance);
    let voters: Vec<Address> = votes.iter().map(|v| v.voter).collect();
    let data_hashes: Vec<[u8; 32]> = votes.iter().map(|v| v.data_hash).collect();
    let evidence = data.evidence.clone();
    let issued_at = U256::from(votes[0].issued_at);
    // All voters signed the same deadline (enforced off-chain by AccusationManager);
    // pick any one — the first vote suffices.
    let deadline = U256::from(votes[0].deadline);
    let signatures: Vec<Bytes> = votes
        .iter()
        .map(|v| Bytes::from(v.signature.extract_bytes()))
        .collect();

    Some(if multirow {
        (
            proof_type,
            proof_instance,
            voters,
            data_hashes,
            evidence,
            issued_at,
            deadline,
            signatures,
        )
            .abi_encode_params()
    } else {
        (
            proof_type,
            voters,
            data_hashes,
            evidence,
            issued_at,
            deadline,
            signatures,
        )
            .abi_encode_params()
    })
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
            issued_at: deadline.saturating_sub(10),
            deadline,
            signature: ArcBytes::from_bytes(&[1, 2, 3]),
        }
    }

    fn quorum(votes_for: Vec<AccusationVote>, evidence: &[u8]) -> LbfvAccusationQuorumReached {
        LbfvAccusationQuorumReached {
            e3_id: E3id::new("1".to_string(), 1),
            accuser: Address::repeat_byte(0xFF),
            accused: Address::repeat_byte(0xEE),
            proof_type: ProofType::C0PkBfv,
            proof_instance: 0,
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
            <(U256, Vec<Address>, Vec<B256>, Bytes, U256, U256, Vec<Bytes>)>::abi_decode_params(
                &encoded,
            )
            .expect("decodes");
        assert_eq!(decoded.1, vec![lo, hi]);
        assert_eq!(decoded.4, U256::from(90u64));
        assert_eq!(decoded.5, U256::from(100u64));
    }

    /// A trBFV report encodes as main's evidence did: no `proofInstance` field.
    #[test]
    fn a_trbfv_report_has_the_evidence_bytes_of_main() {
        let voter = Address::repeat_byte(0x01);
        let q = quorum(vec![vote(voter, 100)], b"evidence");
        let encoded = encode_attestation_evidence(&q).expect("should encode");

        let main = (
            U256::from(ProofType::C0PkBfv as u8),
            vec![voter],
            vec![[7u8; 32]],
            Bytes::from_static(b"evidence"),
            U256::from(90u64),
            U256::from(100u64),
            vec![Bytes::from_static(&[1, 2, 3])],
        )
            .abi_encode_params();
        assert_eq!(encoded, main);
    }

    /// An l-BFV row family names its row after the proof type.
    #[test]
    fn an_lbfv_row_report_carries_its_instance() {
        let voter = Address::repeat_byte(0x01);
        let q = LbfvAccusationQuorumReached {
            proof_type: ProofType::RlkAggregation,
            proof_instance: 9,
            ..quorum(vec![vote(voter, 100)], b"evidence")
        };
        let encoded = encode_attestation_evidence(&q).expect("should encode");

        let decoded = <(
            U256,
            U256,
            Vec<Address>,
            Vec<B256>,
            Bytes,
            U256,
            U256,
            Vec<Bytes>,
        )>::abi_decode_params(&encoded)
        .expect("decodes");
        assert_eq!(decoded.0, U256::from(ProofType::RlkAggregation as u8));
        assert_eq!(decoded.1, U256::from(9u64));
        assert_eq!(decoded.2, vec![voter]);
    }

    /// A proof type with one instance has no field for another one.
    #[test]
    fn a_singleton_proof_type_cannot_name_a_row() {
        let q = LbfvAccusationQuorumReached {
            proof_instance: 1,
            ..quorum(vec![vote(Address::repeat_byte(0x01), 100)], b"evidence")
        };
        assert!(encode_attestation_evidence(&q).is_none());
    }
}
