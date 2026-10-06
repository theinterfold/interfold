// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

/// Agreeing votes that disagree on data_hash at quorum yield Equivocation.
#[test]
fn equivocation_when_hashes_differ_at_quorum() {
    let me = signer(1);
    let b = signer(2);
    let accused = signer(9).address();
    let committee = vec![me.address(), b.address(), accused];
    let mut v = voting_with(&me, committee, 1, 2);
    let sm = v.slashing_manager;
    let data_hash_a = [0x11; 32];
    let data_hash_b = [0x22; 32];

    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash_a, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash_a, NOW + VALIDITY, own);
    v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

    // Voter b agrees but reports a different data_hash → equivocation.
    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash_b, NOW + VALIDITY);
    let actions = v.on_vote_received(vote_b, &ctx());
    let outcome = actions.iter().find_map(|a| match a {
        VoteAction::PublishQuorum { quorum, .. } => Some(quorum.outcome.clone()),
        _ => None,
    });
    assert_eq!(
        outcome,
        Some(AccusationOutcome::Equivocation),
        "differing data hashes at quorum must yield Equivocation"
    );
}

/// Timeout below threshold yields Inconclusive; at/above threshold yields
/// AccusedFaulted.
#[test]
fn timeout_outcome_depends_on_vote_count() {
    let me = signer(1);
    let accused = signer(9).address();
    let committee = vec![me.address(), signer(2).address(), accused];
    let mut v = voting_with(&me, committee, 1, 2);
    let sm = v.slashing_manager;
    let data_hash = [0x11; 32];

    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);

    // Only one agreeing vote, threshold is 2 → Inconclusive.
    let (quorum, _ec) = v.on_vote_timeout(id).expect("timeout emits a decision");
    assert_eq!(quorum.outcome, AccusationOutcome::Inconclusive);
    assert!(v.on_vote_timeout(id).is_none(), "second timeout is a no-op");
}

/// After a slash shrinks the live roster, ZK re-verification must still use the
/// canonical circuit committee size cached at construction.
#[test]
fn committee_size_unchanged_after_slash() {
    let me = signer(1);
    // Micro committee (T=4, N=9) — canonical pair in `from_threshold`.
    let committee: Vec<Address> = (1..=9u8).map(|b| signer(b).address()).collect();
    let mut v = voting_with(&me, committee.clone(), 4, 5);

    let slashed = committee[8];
    v.on_slash_executed(SlashExecuted {
        e3_id: v.e3_id.clone(),
        proposal_id: 1,
        operator: slashed,
        reason: [0u8; 32],
        ticket_amount: 0,
        ciphernode_bond_amount: 0,
    });
    assert_eq!(v.committee.len(), 8);
    assert_eq!(v.committee_n, 9);
    // Shrunken roster must not drive circuit resolution.
    assert!(
        CiphernodesCommitteeSize::from_threshold(v.circuit_threshold_t, v.committee.len()).is_err()
    );
    assert_eq!(
        CiphernodesCommitteeSize::from_threshold(v.circuit_threshold_t, v.committee_n).unwrap(),
        CiphernodesCommitteeSize::Micro
    );
}

#[test]
fn local_proof_failure_requires_the_claimed_dealers_signature() {
    let me = signer(1);
    let dealer = signer(2);
    let other = signer(3);
    for forgery in [
        "zero address",
        "unrecoverable",
        "wrong signer",
        "wrong slot",
        "wrong E3",
        "wrong type",
        "wrong hash",
    ] {
        let mut voting = voting_with(
            &me,
            vec![other.address(), dealer.address(), me.address()],
            1,
            2,
        );
        let payload = e3_events::ProofPayload {
            e3_id: voting.e3_id.clone(),
            proof_type: ProofType::C3aSkShareEncryption,
            proof: e3_events::Proof::new(
                e3_events::CircuitName::ShareEncryption,
                ArcBytes::from_bytes(&[1]),
                ArcBytes::from_bytes(&[2]),
            ),
        };
        let signed = SignedProofPayload::sign(payload, &dealer).unwrap();
        let evidence = (
            Bytes::copy_from_slice(&signed.payload.proof.data),
            Bytes::copy_from_slice(&signed.payload.proof.public_signals),
        )
            .abi_encode();
        let genuine = ProofVerificationFailed {
            e3_id: voting.e3_id.clone(),
            accused_party_id: 1,
            accused_address: dealer.address(),
            proof_type: ProofType::C3aSkShareEncryption,
            data_hash: keccak256(evidence).into(),
            signed_payload: signed,
        };
        let mut forged = genuine.clone();
        match forgery {
            "zero address" => {
                forged.accused_address = Address::ZERO;
                forged.signed_payload.signature = ArcBytes::from_bytes(&[0; 65]);
            }
            "unrecoverable" => forged.signed_payload.signature = ArcBytes::from_bytes(&[0; 65]),
            "wrong signer" => {
                forged.signed_payload =
                    SignedProofPayload::sign(forged.signed_payload.payload, &other).unwrap()
            }
            "wrong slot" => forged.accused_party_id = 2,
            "wrong E3" => {
                forged.signed_payload.payload.e3_id = E3id::new("43", CHAIN_ID);
                forged.signed_payload =
                    SignedProofPayload::sign(forged.signed_payload.payload, &dealer).unwrap();
            }
            "wrong type" => forged.proof_type = ProofType::C3bESmShareEncryption,
            "wrong hash" => forged.data_hash = [9; 32],
            _ => unreachable!(),
        }
        assert!(
            voting.on_local_proof_failure(forged, &ctx()).is_empty(),
            "{forgery} caused an accusation"
        );
        assert!(voting.received_data.is_empty());
        voting.on_slash_executed(SlashExecuted {
            e3_id: voting.e3_id.clone(),
            proposal_id: 1,
            operator: other.address(),
            reason: [0; 32],
            ticket_amount: 0,
            ciphernode_bond_amount: 0,
        });
        let actions = voting.on_local_proof_failure(genuine, &ctx());
        assert!(actions.iter().any(|action| matches!(action,
            VoteAction::PublishAccusation { accusation, .. } if accusation.accused == dealer.address()
                && accusation.accused_party_id == 1)), "authenticated proof failure was not attributed");
    }
}
