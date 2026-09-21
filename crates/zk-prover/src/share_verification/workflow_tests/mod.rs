// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use alloy::{
    primitives::{address, B256, U256},
    signers::local::PrivateKeySigner,
};
use e3_committee_hash::{
    hash_lbfv_accepted_party_set, hash_lbfv_proof_session, split_hash_to_field_limbs,
    LbfvProofDomainContext,
};
use e3_events::{
    LbfvAcceptedPartyCommitments, LbfvAggregationVerificationContext, LbfvVerificationContext,
    LbfvVerificationContextV2, Proof, ProofPayload, ProofType,
};
use e3_fhe_params::BfvPreset;

fn signer() -> PrivateKeySigner {
    PrivateKeySigner::random()
}

fn minimum_committee(mut members: Vec<Address>) -> Vec<Address> {
    while members.len() < CiphernodesCommitteeSize::Minimum.values().n {
        let candidate = signer().address();
        if !members.contains(&candidate) {
            members.push(candidate);
        }
    }
    members
}

fn signed_proof(
    s: &PrivateKeySigner,
    e3_id: &E3id,
    proof_type: ProofType,
    marker: u8,
) -> SignedProofPayload {
    let proof = Proof::new(
        proof_type.circuit_names()[0],
        ArcBytes::from_bytes(&[marker, 2, 3]),
        ArcBytes::from_bytes(&[4, 5, marker]),
    );
    let payload = ProofPayload {
        e3_id: e3_id.clone(),
        proof_type,
        proof,
    };
    SignedProofPayload::sign(payload, s).expect("sign")
}

fn signed_share_bundle(
    s: &PrivateKeySigner,
    e3_id: &E3id,
    num_share_rows: usize,
) -> Vec<SignedProofPayload> {
    let mut proofs = vec![
        signed_proof(s, e3_id, ProofType::C2aSkShareComputation, 2),
        signed_proof(s, e3_id, ProofType::C2bESmShareComputation, 3),
    ];
    for _ in 0..num_share_rows {
        proofs.push(signed_proof(s, e3_id, ProofType::C3aSkShareEncryption, 4));
    }
    for _ in 0..num_share_rows {
        proofs.push(signed_proof(s, e3_id, ProofType::C3bESmShareEncryption, 5));
    }
    proofs
}

/// Build a signed C1 (PkGeneration) proof for `party_id` under `e3_id`,
/// optionally with a deliberately wrong circuit name.
fn signed_pk(s: &PrivateKeySigner, e3_id: &E3id, wrong_circuit: bool) -> SignedProofPayload {
    use e3_events::CircuitName;
    let proof_type = ProofType::C1PkGeneration;
    if !wrong_circuit {
        return signed_proof(s, e3_id, proof_type, 1);
    }
    let circuit = if wrong_circuit {
        CircuitName::PkBfv
    } else {
        proof_type.circuit_names()[0]
    };
    let proof = Proof::new(
        circuit,
        ArcBytes::from_bytes(&[1, 2, 3]),
        ArcBytes::from_bytes(&[4, 5, 6]),
    );
    let payload = ProofPayload {
        e3_id: e3_id.clone(),
        proof_type,
        proof,
    };
    SignedProofPayload::sign(payload, s).expect("sign")
}

fn e3() -> E3id {
    E3id::new("1", 1)
}

fn lbfv_proof_domain(e3_id: &E3id) -> LbfvProofDomainContext {
    LbfvProofDomainContext {
        protocol_version: 4,
        chain_id: e3_id.chain_id(),
        interfold_address: address!("0x1111111111111111111111111111111111111111"),
        e3_id: U256::try_from(e3_id.clone()).unwrap(),
        crypto_config_id: B256::repeat_byte(0x22),
        finalized_committee_hash: B256::repeat_byte(0x33),
        lbfv_constants_version: 1,
        ciphertext_level: 0,
        key_level: 0,
    }
}

fn lbfv_generation_context(e3_id: &E3id) -> LbfvVerificationContext {
    LbfvVerificationContext::V2(LbfvVerificationContextV2 {
        proof_domain: lbfv_proof_domain(e3_id),
        aggregation: None,
    })
}

mod ecdsa;
mod shape;
mod tally;
