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
        let ComputeRequestKind::Zk(ZkRequest::ReverifyAccusedProof(batch)) = &request.request
        else {
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

    for after_expulsion in [false, true] {
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
                if after_expulsion {
                    v.on_member_expelled(&CommitteeMemberExpelled {
                        e3_id: v.e3_id.clone(),
                        node: removed.address(),
                        reason: [0; 32],
                        active_count_after: 2,
                        party_id: Some(0),
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
                    "self-accusation: consistency={consistency}, after_expulsion={after_expulsion}, address={address}, party_id={party_id}"
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
                // A local failure accuses only the dealer that holds the claimed finalized slot.
                if committee[party_id as usize] == accused.address() {
                    assert!(!actions.is_empty());
                    assert_eq!(
                        v.on_vote_timeout(id).unwrap().0.outcome,
                        AccusationOutcome::Inconclusive
                    );
                } else {
                    assert!(actions.is_empty());
                }
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

/// Startup replays the event log before `EffectsEnabled`. A replayed failure signs no accusation
/// then. At `EffectsEnabled` it is accused, unless the log holds this node's own accusation of the
/// proof, or a peer's accusation of it that this node voted on.
#[test]
fn a_replayed_failure_is_accused_once_effects_run_unless_the_log_holds_the_accusation() {
    let me = signer(1);
    let first = signer(2);
    let second = signer(3);
    let third = signer(4);
    let peer = signer(5);
    let committee = vec![
        me.address(),
        first.address(),
        second.address(),
        third.address(),
        peer.address(),
    ];
    let mut v = voting_with(&me, committee, 1, 3);
    v.hold_accusations_until_effects();
    let accused_by_me = proof_failure(&first, 1, ProofType::C1PkGeneration);
    let accused_by_peer = proof_failure(&second, 2, ProofType::C1PkGeneration);
    let not_yet_accused = proof_failure(&third, 3, ProofType::C1PkGeneration);

    for failure in [&accused_by_me, &accused_by_peer, &not_yet_accused] {
        assert!(v.on_local_proof_failure(failure.clone(), &ctx()).is_empty());
    }
    let own = accusation_from_failure(&me, &accused_by_me, false, NOW - 60);
    assert!(v.on_accusation_received(own, &ctx()).is_empty());
    let by_peer = accusation_from_failure(&peer, &accused_by_peer, false, NOW - 30);
    let by_peer_id = AccusationVoting::accusation_id(&by_peer);
    v.on_accusation_received(by_peer, &ctx());

    let accused: Vec<Address> = v
        .on_effects_enabled()
        .iter()
        .filter_map(|action| match action {
            VoteAction::PublishAccusation { accusation, .. } => Some(accusation.accused),
            _ => None,
        })
        .collect();
    assert_eq!(accused, vec![third.address()]);
    assert_eq!(v.pending[&by_peer_id].accusation.accuser, peer.address());
}

/// A held failure is skipped only when this node has voted on the matching peer accusation. A peer
/// accusation that still waits for this node's re-verification does not stop this node from
/// accusing at `EffectsEnabled`.
#[test]
fn a_held_failure_is_accused_when_the_peer_accusation_lacks_this_nodes_vote() {
    let me = signer(1);
    let accused = signer(2);
    let peer = signer(3);
    let committee = vec![
        me.address(),
        accused.address(),
        peer.address(),
        signer(4).address(),
        signer(5).address(),
    ];
    let mut v = voting_with(&me, committee, 1, 3);
    v.hold_accusations_until_effects();
    let failure = proof_failure(&accused, 1, ProofType::C1PkGeneration);
    assert!(v.on_local_proof_failure(failure.clone(), &ctx()).is_empty());
    let by_peer = accusation_from_failure(&peer, &failure, false, NOW - 30);
    v.pending.insert(
        AccusationVoting::accusation_id(&by_peer),
        PendingAccusation {
            accusation: by_peer,
            votes_for: Vec::new(),
            ec: ctx(),
            timeout_at: NOW + 300,
        },
    );

    let accused_now: Vec<Address> = v
        .on_effects_enabled()
        .iter()
        .filter_map(|action| match action {
            VoteAction::PublishAccusation { accusation, .. } => Some(accusation.accused),
            _ => None,
        })
        .collect();
    assert_eq!(accused_now, vec![accused.address()]);
}

/// During startup a peer's forwarded C3 accusation can start re-verification before this node's
/// own failure of the proof is held. When this node then accuses at `EffectsEnabled`, the late
/// re-verification result adds no second vote from it, so the quorum still needs H distinct voters.
#[test]
fn a_late_reverification_does_not_count_this_node_twice() {
    let me = signer(1);
    let accuser = signer(2);
    let accused = signer(3);
    let committee = vec![me.address(), accuser.address(), accused.address()];
    let mut v = voting_with(&me, committee, 1, 2);
    v.hold_accusations_until_effects();
    let failure = proof_failure(&accused, 2, ProofType::C3aSkShareEncryption);
    let accusation = accusation_from_failure(&accuser, &failure, true, NOW);
    let id = AccusationVoting::accusation_id(&accusation);

    // The peer's accusation comes first: without local data, this node re-verifies the proof.
    let request = v
        .on_accusation_received(accusation, &ctx())
        .into_iter()
        .find_map(|action| match action {
            VoteAction::DispatchZk { request, .. } => Some(request),
            _ => None,
        })
        .expect("forwarded C3 is re-verified");
    // Then this node's own failure of the proof arrives and is held.
    assert!(v.on_local_proof_failure(failure.clone(), &ctx()).is_empty());
    assert!(v
        .on_effects_enabled()
        .iter()
        .any(|action| matches!(action, VoteAction::PublishAccusation { .. })));

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
    assert!(!actions.iter().any(|action| matches!(
        action,
        VoteAction::PublishVote { .. } | VoteAction::PublishQuorum { .. }
    )));
    let my_votes = v.pending[&id]
        .votes_for
        .iter()
        .filter(|vote| vote.voter == me.address())
        .count();
    assert_eq!(my_votes, 1);
}
