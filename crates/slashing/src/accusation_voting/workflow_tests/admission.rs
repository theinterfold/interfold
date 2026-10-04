// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{
    ComputeRequestKind, PartyVerificationResult, Proof, ProofPayload, VerifyShareProofsResponse,
};

fn proof_failure(
    who: &PrivateKeySigner,
    party_id: u64,
    proof_type: ProofType,
) -> ProofVerificationFailed {
    let e3_id = E3id::new("42", CHAIN_ID);
    let proof_data = Bytes::from(vec![0x11; 32]);
    let public_signals = Bytes::from(vec![0x22; 96]);
    let signed_payload = SignedProofPayload::sign(
        ProofPayload {
            e3_id: e3_id.clone(),
            proof_type,
            proof: Proof::new(
                proof_type.circuit_names()[0],
                ArcBytes::from_bytes(&proof_data),
                ArcBytes::from_bytes(&public_signals),
            ),
        },
        who,
    )
    .unwrap();
    ProofVerificationFailed {
        e3_id,
        accused_party_id: party_id,
        accused_address: who.address(),
        proof_type,
        data_hash: keccak256((proof_data, public_signals).abi_encode()).into(),
        signed_payload,
    }
}

fn accusation_from_failure(
    accuser: &PrivateKeySigner,
    failure: &ProofVerificationFailed,
    forwarded: bool,
    issued_at: u64,
) -> ProofFailureAccusation {
    let mut accusation = ProofFailureAccusation {
        e3_id: failure.e3_id.clone(),
        accuser: accuser.address(),
        accused: failure.accused_address,
        accused_party_id: failure.accused_party_id,
        proof_type: failure.proof_type,
        data_hash: failure.data_hash,
        issued_at,
        deadline: issued_at + VALIDITY,
        signed_payload: forwarded.then(|| failure.signed_payload.clone()),
        signature: ArcBytes::default(),
    };
    let sig = accuser
        .sign_message_sync(&AccusationVoting::accusation_digest(&accusation))
        .unwrap();
    accusation.signature = ArcBytes::from_bytes(&sig.as_bytes());
    accusation
}

fn assert_quorum(actions: &[VoteAction], accused: Address, voters: &[Address]) {
    let quorums: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            VoteAction::PublishQuorum { quorum, .. } => Some(quorum),
            _ => None,
        })
        .collect();
    assert_eq!(quorums.len(), 1);
    let quorum = quorums[0];
    assert_eq!(quorum.accused, accused);
    assert_eq!(quorum.outcome, AccusationOutcome::AccusedFaulted);
    assert_eq!(quorum.votes_for.len(), voters.len());
    assert_eq!(
        quorum
            .votes_for
            .iter()
            .map(|vote| vote.voter)
            .collect::<HashSet<_>>(),
        voters.iter().copied().collect()
    );
    assert!(!quorum.evidence.is_empty());
}

#[test]
fn forwarded_accusations_only_reverify_c3() {
    let me = signer(1);
    let accuser = signer(2);
    let accused = signer(3);
    let committee = vec![me.address(), accuser.address(), accused.address()];

    for proof_type in [
        ProofType::C3aSkShareEncryption,
        ProofType::C3bESmShareEncryption,
        ProofType::C6ThresholdShareDecryption,
    ] {
        let mut v = voting_with(&me, committee.clone(), 1, 2);
        let failure = proof_failure(&accused, 2, proof_type);
        let accusation = accusation_from_failure(&accuser, &failure, true, NOW);
        let id = AccusationVoting::accusation_id(&accusation);
        let vote = signed_vote(
            &accuser,
            v.slashing_manager,
            &v.e3_id,
            id,
            failure.data_hash,
            accusation.deadline,
        );
        assert!(v.on_vote_received(vote.clone(), &ctx()).is_empty());
        let actions = v.on_accusation_received(accusation, &ctx());

        if proof_type == ProofType::C6ThresholdShareDecryption {
            assert!(
                actions.is_empty(),
                "forwarded C6 must not start voting or ZK"
            );
            assert!(v.on_vote_received(vote, &ctx()).is_empty());
            assert!(v.on_vote_timeout(id).is_none());
            let ordinary = accusation_from_failure(&accuser, &failure, false, NOW);
            assert!(v.on_accusation_received(ordinary, &ctx()).is_empty());
            assert!(v.pending_reverifications.is_empty());
            assert!(v.received_data.is_empty());
            continue;
        }

        assert!(!actions.iter().any(|action| matches!(
            action,
            VoteAction::PublishVote { .. } | VoteAction::PublishQuorum { .. }
        )));
        let request = actions
            .iter()
            .find_map(|action| match action {
                VoteAction::DispatchZk { request, .. } => Some(request),
                _ => None,
            })
            .expect("forwarded C3 must be verified before voting");
        let ComputeRequestKind::Zk(ZkRequest::VerifyShareProofs(batch)) = &request.request else {
            panic!("expected forwarded share proof verification");
        };
        assert_eq!(batch.committee_size, CiphernodesCommitteeSize::Minimum);
        assert_eq!(batch.party_proofs.len(), 1);
        assert_eq!(batch.party_proofs[0].sender_party_id, 2);
        assert_eq!(
            batch.party_proofs[0].signed_proofs,
            vec![failure.signed_payload.clone()]
        );

        let response = ComputeResponse::zk(
            ZkResponse::VerifyShareProofs(VerifyShareProofsResponse {
                party_results: vec![PartyVerificationResult {
                    sender_party_id: 2,
                    all_verified: false,
                    failed_signed_payload: Some(failure.signed_payload),
                    recovered_address: Some(accused.address()),
                }],
            }),
            request.correlation_id,
            v.e3_id.clone(),
        );
        let actions = v.handle_reverification_response(TypedEvent::new(response, ctx()));
        assert!(actions.iter().any(|action| matches!(
            action,
            VoteAction::PublishVote { vote, .. } if vote.voter == me.address()
        )));
        assert_quorum(
            &actions,
            accused.address(),
            &[me.address(), accuser.address()],
        );
        assert!(v.on_vote_timeout(id).is_none());
    }
}

#[test]
fn forwarded_c6_cannot_use_cached_evidence_or_change_a_vote_window() {
    let me = signer(1);
    let accuser = signer(2);
    let accused = signer(3);
    let committee = vec![me.address(), accuser.address(), accused.address()];
    let mut v = voting_with(&me, committee, 1, 2);
    let failure = proof_failure(&accused, 2, ProofType::C6ThresholdShareDecryption);
    let actions = v.on_local_proof_failure(failure.clone(), &ctx());
    assert!(actions.iter().any(|action| matches!(
        action,
        VoteAction::PublishAccusation { accusation, .. } if accusation.signed_payload.is_none()
    )));

    let forwarded = accusation_from_failure(&accuser, &failure, true, NOW + 5);
    let id = AccusationVoting::accusation_id(&forwarded);
    assert!(v.on_accusation_received(forwarded, &ctx()).is_empty());
    let vote = signed_vote(
        &accuser,
        v.slashing_manager,
        &v.e3_id,
        id,
        failure.data_hash,
        NOW + VALIDITY,
    );
    let actions = v.on_vote_received(vote.clone(), &ctx());
    assert_quorum(
        &actions,
        accused.address(),
        &[me.address(), accuser.address()],
    );

    let forwarded = accusation_from_failure(&accuser, &failure, true, NOW);
    assert!(v.on_accusation_received(forwarded, &ctx()).is_empty());
    assert!(v.on_vote_timeout(id).is_none());
    let ordinary = accusation_from_failure(&accuser, &failure, false, NOW);
    let mut actions = v.on_accusation_received(ordinary, &ctx());
    actions.extend(v.on_vote_received(vote, &ctx()));
    assert_quorum(
        &actions,
        accused.address(),
        &[me.address(), accuser.address()],
    );
}

#[test]
fn local_self_accusations_are_ignored() {
    let me = signer(1);
    let other = signer(2);
    let removed = signer(3);
    let committee = vec![removed.address(), me.address(), other.address()];

    for after_slash in [false, true] {
        for consistency in [false, true] {
            for (address, party_id) in [
                (me.address(), 1),
                (me.address(), 2),
                (other.address(), 1),
                (Address::ZERO, 1),
            ] {
                if consistency && address == Address::ZERO {
                    continue;
                }
                let mut v = voting_with(&me, committee.clone(), 1, 2);
                if after_slash {
                    v.on_slash_executed(SlashExecuted {
                        e3_id: v.e3_id.clone(),
                        proposal_id: 1,
                        operator: removed.address(),
                        reason: [0; 32],
                        ticket_amount: 0,
                        ciphernode_bond_amount: 0,
                    });
                }
                let mut failure = proof_failure(&me, party_id, ProofType::C3aSkShareEncryption);
                failure.accused_address = address;
                let actions = if consistency {
                    v.on_consistency_violation(
                        CommitmentConsistencyViolation {
                            e3_id: failure.e3_id,
                            accused_address: address,
                            accused_party_id: party_id,
                            proof_type: failure.proof_type,
                            data_hash: failure.data_hash,
                            evidence: Bytes::from(vec![0x11; 32]),
                        },
                        &ctx(),
                    )
                } else {
                    v.on_local_proof_failure(failure, &ctx())
                };
                assert!(
                    actions.is_empty(),
                    "self-accusation: consistency={consistency}, after_slash={after_slash}, address={address}, party_id={party_id}"
                );
                assert!(v.received_data.is_empty());
                assert!(v.pending.is_empty());
                assert!(v.accused_proofs.is_empty());
            }
        }
    }
}

#[test]
fn received_self_accusations_are_ignored() {
    let me = signer(1);
    let accuser = signer(2);
    let other = signer(3);
    let committee = vec![me.address(), accuser.address(), other.address()];

    for (accused, party_id) in [(&accuser, 1), (&accuser, 2)] {
        for (cached, forwarded) in [(false, true), (true, false), (true, true)] {
            let mut v = voting_with(&me, committee.clone(), 1, 2);
            let failure = proof_failure(accused, party_id, ProofType::C3bESmShareEncryption);
            let accusation = accusation_from_failure(&accuser, &failure, forwarded, NOW);
            let id = AccusationVoting::accusation_id(&accusation);
            if cached {
                let actions = v.on_local_proof_failure(failure.clone(), &ctx());
                assert!(!actions.is_empty());
                assert_eq!(
                    v.on_vote_timeout(id).unwrap().0.outcome,
                    AccusationOutcome::Inconclusive
                );
            }
            let vote = signed_vote(
                &accuser,
                v.slashing_manager,
                &v.e3_id,
                id,
                failure.data_hash,
                NOW + VALIDITY,
            );
            assert!(v.on_vote_received(vote.clone(), &ctx()).is_empty());
            assert!(
                v.on_accusation_received(accusation, &ctx()).is_empty(),
                "self-accusation: accused={}, party_id={party_id}, cached={cached}, forwarded={forwarded}",
                accused.address()
            );
            assert!(v.on_vote_received(vote, &ctx()).is_empty());
            assert!(v.on_vote_timeout(id).is_none());
            assert!(v.pending_reverifications.is_empty());
        }
    }
}

#[test]
fn received_accusations_with_changed_party_ids_reach_quorum() {
    let me = signer(1);
    let accuser = signer(2);
    let accused = signer(3);
    let committee = vec![me.address(), accuser.address(), accused.address()];

    for proof_type in [
        ProofType::C3aSkShareEncryption,
        ProofType::C3bESmShareEncryption,
    ] {
        for forwarded in [false, true] {
            let mut v = voting_with(&me, committee.clone(), 1, 2);
            let failure = proof_failure(&accused, 2, proof_type);
            let mut accusation = accusation_from_failure(&accuser, &failure, forwarded, NOW);
            accusation.accused_party_id = 1;
            let id = AccusationVoting::accusation_id(&accusation);

            if !forwarded {
                assert!(!v.on_local_proof_failure(failure.clone(), &ctx()).is_empty());
                assert_eq!(
                    v.on_vote_timeout(id).unwrap().0.outcome,
                    AccusationOutcome::Inconclusive
                );
            }

            let vote = signed_vote(
                &accuser,
                v.slashing_manager,
                &v.e3_id,
                id,
                failure.data_hash,
                accusation.deadline,
            );
            assert!(v.on_vote_received(vote, &ctx()).is_empty());
            let mut actions = v.on_accusation_received(accusation, &ctx());

            if forwarded {
                let request = actions
                    .iter()
                    .find_map(|action| match action {
                        VoteAction::DispatchZk { request, .. } => Some(request),
                        _ => None,
                    })
                    .expect("forwarded C3 must be verified before voting");
                let response = ComputeResponse::zk(
                    ZkResponse::VerifyShareProofs(VerifyShareProofsResponse {
                        party_results: vec![PartyVerificationResult {
                            sender_party_id: 1,
                            all_verified: false,
                            failed_signed_payload: Some(failure.signed_payload),
                            recovered_address: Some(accused.address()),
                        }],
                    }),
                    request.correlation_id,
                    v.e3_id.clone(),
                );
                actions.extend(v.handle_reverification_response(TypedEvent::new(response, ctx())));
            }

            assert!(actions.iter().any(|action| matches!(
                action,
                VoteAction::PublishVote { vote, .. } if vote.voter == me.address()
            )));
            assert_quorum(
                &actions,
                accused.address(),
                &[me.address(), accuser.address()],
            );
            assert!(v.on_vote_timeout(id).is_none());
        }
    }
}
