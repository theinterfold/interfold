// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[test]
fn production_vote_signature_binds_every_admitted_field() {
    let me = signer(1);
    let voting = voting_with(&me, vec![me.address()], 1, 1);
    let mut vote = AccusationVote {
        e3_id: voting.e3_id.clone(),
        accusation_id: [0x07; 32],
        voter: me.address(),
        data_hash: [0x08; 32],
        issued_at: NOW,
        deadline: NOW + VALIDITY,
        signature: ArcBytes::default(),
    };
    vote.signature = ArcBytes::from_bytes(&voting.sign_vote_digest(&vote).unwrap());
    assert!(voting.verify_vote_signature(&vote));

    let tampers: [fn(&mut AccusationVote); 6] = [
        |vote| vote.e3_id = E3id::new("43", CHAIN_ID),
        |vote| vote.accusation_id[0] ^= 1,
        |vote| vote.voter = signer(2).address(),
        |vote| vote.data_hash[0] ^= 1,
        |vote| vote.issued_at += 1,
        |vote| vote.deadline += 1,
    ];
    for tamper in tampers {
        let mut tampered = vote.clone();
        tamper(&mut tampered);
        assert!(!voting.verify_vote_signature(&tampered));
    }
}

/// A second agreeing vote that reaches `vote_quorum_h` must produce a single
/// AccusedFaulted quorum decision and remove the pending accusation.
#[test]
fn tally_reaches_quorum_at_threshold() {
    let me = signer(1);
    let b = signer(2);
    let accused = signer(9).address();
    let committee = vec![me.address(), b.address(), accused];
    let mut v = voting_with(&me, committee, 1, 2);
    let sm = v.slashing_manager;
    let data_hash = [0x11; 32];

    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
    // own vote's accusation_id was a placeholder; fix it to the real id.
    v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
    let actions = v.on_vote_received(vote_b, &ctx());

    let quorum = actions
        .iter()
        .filter_map(|a| match a {
            VoteAction::PublishQuorum { quorum, .. } => Some(quorum),
            _ => None,
        })
        .count();
    assert_eq!(quorum, 1, "exactly one quorum decision expected");
    assert!(
        !v.pending.contains_key(&id),
        "pending accusation removed after quorum"
    );
}

/// Inserting the same voter twice must not double-count nor re-trigger quorum.
#[test]
fn idempotent_vote_insert() {
    let me = signer(1);
    let b = signer(2);
    let accused = signer(9).address();
    let committee = vec![me.address(), b.address(), accused];
    let mut v = voting_with(&me, committee, 1, 3); // quorum above what 2 votes reach
    let sm = v.slashing_manager;
    let data_hash = [0x11; 32];

    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
    v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
    let _ = v.on_vote_received(vote_b.clone(), &ctx());
    let len_after_first = v.pending.get(&id).unwrap().votes_for.len();

    // Same voter again — must be ignored.
    let actions = v.on_vote_received(vote_b, &ctx());
    let len_after_second = v.pending.get(&id).unwrap().votes_for.len();
    assert_eq!(
        len_after_first, len_after_second,
        "duplicate voter must not be counted twice"
    );
    assert!(
        actions.is_empty(),
        "duplicate vote must not emit any actions"
    );
}

/// Quorum must trigger exactly at the M-th agreeing vote, not before.
#[test]
fn quorum_boundary() {
    let me = signer(1);
    let b = signer(2);
    let c = signer(3);
    let accused = signer(9).address();
    let committee = vec![me.address(), b.address(), c.address(), accused];
    let mut v = voting_with(&me, committee, 1, 3);
    let sm = v.slashing_manager;
    let data_hash = [0x11; 32];

    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
    v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;

    // 2nd vote — below threshold of 3, no quorum.
    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
    let actions = v.on_vote_received(vote_b, &ctx());
    assert!(
        actions.is_empty(),
        "no quorum before reaching threshold M=3"
    );
    assert!(v.pending.contains_key(&id));

    // 3rd vote — reaches threshold, quorum fires.
    let vote_c = signed_vote(&c, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
    let actions = v.on_vote_received(vote_c, &ctx());
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, VoteAction::PublishQuorum { .. })),
        "quorum must fire at the M-th vote"
    );
}

/// Build and sign an accusation as `who` with an explicit vote window.
fn signed_accusation(
    who: &PrivateKeySigner,
    e3_id: &E3id,
    accused: Address,
    accused_party_id: u64,
    data_hash: [u8; 32],
    issued_at: u64,
    deadline: u64,
) -> ProofFailureAccusation {
    let mut accusation = ProofFailureAccusation {
        e3_id: e3_id.clone(),
        accuser: who.address(),
        accused,
        accused_party_id,
        proof_type: ProofType::C1PkGeneration,
        data_hash,
        issued_at,
        deadline,
        signed_payload: None,
        signature: ArcBytes::default(),
    };
    let digest = AccusationVoting::accusation_digest(&accusation);
    let sig = who.sign_message_sync(&digest).unwrap();
    accusation.signature = ArcBytes::from_bytes(&sig.as_bytes());
    accusation
}

/// Two honest accusers of the same fault sign different vote windows; the
/// committee must converge on the later one so a single-window quorum forms.
#[test]
fn concurrent_accusers_converge_on_one_vote_window() {
    let me = signer(1);
    let b = signer(2);
    let c = signer(3);
    let accused = signer(9).address();
    let committee = vec![me.address(), b.address(), c.address(), accused];
    let mut v = voting_with(&me, committee, 1, 3);
    let sm = v.slashing_manager;
    let data_hash = [0x11; 32];

    // I saw the fault first: my own accusation with my window.
    let mine = signed_accusation(&me, &v.e3_id, accused, 3, data_hash, NOW, NOW + VALIDITY);
    let id = AccusationVoting::accusation_id(&mine);
    let own = signed_vote(&me, sm, &v.e3_id, id, data_hash, NOW + VALIDITY);
    insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
    v.received_data.insert(
        (accused, ProofType::C1PkGeneration),
        ReceivedProofData {
            data_hash,
            verification_passed: false,
            evidence: Bytes::new(),
        },
    );

    // B accused 5 s later. C votes on B's window before B's accusation reaches me.
    let later = NOW + 5;
    let vote_c = signed_vote(&c, sm, &v.e3_id, id, data_hash, later + VALIDITY);
    let mut actions = v.on_vote_received(vote_c, &ctx());

    let b_accusation =
        signed_accusation(&b, &v.e3_id, accused, 3, data_hash, later, later + VALIDITY);
    assert_eq!(AccusationVoting::accusation_id(&b_accusation), id);
    actions.extend(v.on_accusation_received(b_accusation, &ctx()));

    // I must re-vote against B's window so my vote is valid alongside B's and C's.
    let my_revote = actions.iter().find_map(|a| match a {
        VoteAction::PublishVote { vote, .. } if vote.voter == me.address() => Some(vote),
        _ => None,
    });
    let my_revote = my_revote.expect("must re-vote against the peer's window");
    assert_eq!(my_revote.deadline, later + VALIDITY);
    assert_eq!(my_revote.issued_at, later);
    assert_eq!(my_revote.accusation_id, id);
    // The adopted window starts a new vote collection, so the old timeout must not end it.
    let restarts_timeout = actions.windows(2).any(|pair| match pair {
        [VoteAction::CancelTimeout(a), VoteAction::StartTimeout(b)] => *a == id && *b == id,
        _ => false,
    });
    assert!(
        restarts_timeout,
        "the adopted window must get a full vote timeout"
    );

    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, later + VALIDITY);
    actions.extend(v.on_vote_received(vote_b, &ctx()));

    let quorum = actions.iter().find_map(|a| match a {
        VoteAction::PublishQuorum { quorum, .. } => Some(quorum),
        _ => None,
    });
    let quorum = quorum.expect("3 votes on the same window must reach the 3-vote quorum");
    assert_eq!(quorum.votes_for.len(), 3);
    assert!(
        quorum
            .votes_for
            .iter()
            .all(|vote| vote.deadline == later + VALIDITY),
        "every vote in the attestation must share one deadline or the contract rejects it"
    );
}

/// Only a later window from a peer other than the accused moves a pending window, once per peer.
#[test]
fn vote_window_moves_once_per_peer_and_never_for_the_accused() {
    let me = signer(1);
    let b = signer(2);
    let accused = signer(9);
    let committee = vec![me.address(), b.address(), accused.address()];
    let mut v = voting_with(&me, committee, 1, 3);
    let (sm, e3_id, target) = (v.slashing_manager, v.e3_id.clone(), accused.address());
    let data_hash = [0x11; 32];
    let accuse = |who: &PrivateKeySigner, issued_at: u64, deadline: u64| {
        signed_accusation(who, &e3_id, target, 2, data_hash, issued_at, deadline)
    };
    let id = AccusationVoting::accusation_id(&accuse(&me, NOW, NOW + VALIDITY));
    let own = signed_vote(&me, sm, &e3_id, id, data_hash, NOW + VALIDITY);
    insert_pending(&mut v, &me, target, data_hash, NOW + VALIDITY, own);
    // A move publishes my vote for this accusation, re-signed for the new window.
    let mut moved = |accusation| {
        let actions = v.on_accusation_received(accusation, &ctx());
        actions.iter().any(|a| match a {
            VoteAction::PublishVote { vote, .. } => vote.accusation_id == id,
            _ => false,
        })
    };

    assert!(!moved(accuse(&accused, NOW + 5, NOW + VALIDITY + 5)));
    assert!(!moved(accuse(&b, NOW + 5, NOW + 10)));
    assert!(moved(accuse(&b, NOW + 6, NOW + VALIDITY + 6)));
    assert!(!moved(accuse(&b, NOW + 7, NOW + VALIDITY + 7)));
    assert_eq!(v.pending[&id].accusation.deadline, NOW + VALIDITY + 6);
}
