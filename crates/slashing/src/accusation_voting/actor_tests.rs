// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::primitives::{keccak256, FixedBytes, U256};
use alloy::signers::SignerSync;
use alloy::sol_types::SolValue;
use e3_events::{VOTE_DOMAIN_NAME, VOTE_DOMAIN_VERSION, VOTE_TYPEHASH_STR};
use e3_utils::ArcBytes;

/// Default clock-skew allowance when validating peer-stamped accusation
/// deadlines (mirrors the production extension default).
const DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS: u64 = 30;

/// Independent re-derivation of the EIP-712 vote digest, mirroring exactly
/// what `SlashingManager._verifyVotes` computes on chain.
fn reference_vote_digest(
    chain_id: u64,
    verifying_contract: Address,
    e3_id: u64,
    accusation_id: [u8; 32],
    voter: Address,
    data_hash: [u8; 32],
    issued_at: u64,
    deadline: u64,
) -> [u8; 32] {
    let domain_typehash: [u8; 32] = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
    .into();
    let name_hash: [u8; 32] = keccak256(VOTE_DOMAIN_NAME).into();
    let version_hash: [u8; 32] = keccak256(VOTE_DOMAIN_VERSION).into();
    let domain_separator: [u8; 32] = keccak256(
        (
            domain_typehash,
            name_hash,
            version_hash,
            U256::from(chain_id),
            verifying_contract,
        )
            .abi_encode(),
    )
    .into();

    let typehash: [u8; 32] = keccak256(VOTE_TYPEHASH_STR).into();
    let struct_hash: [u8; 32] = keccak256(
        (
            typehash,
            U256::from(e3_id),
            FixedBytes::<32>::from(accusation_id),
            voter,
            FixedBytes::<32>::from(data_hash),
            U256::from(issued_at),
            U256::from(deadline),
        )
            .abi_encode(),
    )
    .into();

    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(&domain_separator);
    buf.extend_from_slice(&struct_hash);
    keccak256(&buf).into()
}

/// The actor's `vote_digest` must equal the reference digest byte-for-byte.
#[test]
fn vote_digest_matches_reference() {
    let chain_id = 31337u64;
    let verifying_contract: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let voter: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let accusation_id = [0xab; 32];
    let data_hash = [0xcd; 32];
    let issued_at = 1_699_999_000;
    let deadline: u64 = 1_700_000_000;

    let vote = AccusationVote {
        e3_id: E3id::new("42", chain_id),
        accusation_id,
        voter,
        data_hash,
        issued_at,
        deadline,
        signature: ArcBytes::default(),
    };

    let actor = AccusationManager::vote_digest(&vote, verifying_contract);
    let reference = reference_vote_digest(
        chain_id,
        verifying_contract,
        42,
        accusation_id,
        voter,
        data_hash,
        issued_at,
        deadline,
    );

    assert_eq!(
        actor, reference,
        "AccusationManager::vote_digest drifted from the reference EIP-712 \
             computation. Check VOTE_TYPEHASH_STR / VOTE_DOMAIN_NAME against \
             SlashingManager.sol — these MUST stay byte-equal across crates."
    );
}

/// Sign-and-recover round-trip using the actor's digest.
#[test]
fn actor_signature_recovers_to_voter() {
    let signer: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
            .parse()
            .unwrap();
    let voter = signer.address();
    let verifying_contract: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let chain_id = 31337u64;

    let vote = AccusationVote {
        e3_id: E3id::new("12345", chain_id),
        accusation_id: [0x07; 32],
        voter,
        data_hash: [0x08; 32],
        issued_at: 1_699_999_000,
        deadline: 1_700_000_000,
        signature: ArcBytes::default(),
    };

    let digest = AccusationManager::vote_digest(&vote, verifying_contract);
    let sig = signer
        .sign_hash_sync(&FixedBytes::<32>::from(digest))
        .unwrap();
    let recovered = sig
        .recover_address_from_prehash(&FixedBytes::<32>::from(digest))
        .expect("recover");
    assert_eq!(
        recovered, voter,
        "signing the actor's digest and recovering must yield the voter"
    );
}

/// The accusation digest must include `deadline`.
#[test]
fn accusation_digest_binds_deadline() {
    let make = |deadline: u64, proof_instance: u32| ProofFailureAccusation {
        e3_id: E3id::new("9", 31337),
        accuser: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
        accused: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .unwrap(),
        accused_party_id: 1,
        proof_type: ProofType::C1PkGeneration,
        proof_instance,
        data_hash: [0x42; 32],
        issued_at: 1_699_999_000,
        deadline,
        signed_payload: None,
        signature: ArcBytes::default(),
    };
    let a = AccusationVoting::accusation_digest(&make(1_700_000_000, 0));
    let b = AccusationVoting::accusation_digest(&make(1_700_000_001, 0));
    assert_ne!(a, b, "deadline must be part of the accusation digest");

    let row = make(1_700_000_000, 1);
    assert_ne!(
        a,
        AccusationVoting::accusation_digest(&row),
        "nonzero proof instances must use a distinct accusation signature domain"
    );
    assert_ne!(
        AccusationVoting::accusation_id(&make(1_700_000_000, 0)),
        AccusationVoting::accusation_id(&row),
        "nonzero proof instances must produce distinct accusation IDs"
    );
}

#[test]
fn peer_deadline_acceptance_enforces_local_window() {
    let now = 1_700_000_000u64;
    let validity = 1_800u64;
    let skew = DEFAULT_ACCUSATION_DEADLINE_SKEW_SECS;
    let issued_at = now + skew;
    let max_ok = issued_at + validity;

    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(now, now, now, validity, skew),
        "deadline equal to now must be rejected"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(
            now - validity,
            now - 1,
            now,
            validity,
            skew
        ),
        "expired deadline must be rejected"
    );
    assert!(
        AccusationVoting::is_peer_deadline_acceptable(issued_at, max_ok, now, validity, skew),
        "deadline at upper bound must be accepted"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(issued_at, max_ok + 1, now, validity, skew),
        "far-future deadline must be rejected"
    );
    assert!(
        !AccusationVoting::is_peer_deadline_acceptable(now, now + 10, now, 0, skew),
        "vote_validity_secs=0 must reject peer accusations"
    );
}
