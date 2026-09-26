// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

#[test]
fn vote_digest_is_deterministic() {
    let sm: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let voter: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let vote = AccusationVote {
        e3_id: E3id::new("42", CHAIN_ID),
        accusation_id: [0xab; 32],
        voter,
        data_hash: [0xcd; 32],
        issued_at: NOW.saturating_sub(VALIDITY),
        deadline: NOW,
        signature: ArcBytes::default(),
    };
    let a = AccusationVoting::vote_digest(&vote, sm);
    let b = AccusationVoting::vote_digest(&vote, sm);
    assert_eq!(a, b, "vote digest must be deterministic");

    let mut vote2 = vote.clone();
    vote2.deadline = NOW + 1;
    assert_ne!(
        a,
        AccusationVoting::vote_digest(&vote2, sm),
        "changing deadline must change the digest"
    );

    let mut vote3 = vote;
    vote3.issued_at += 1;
    assert_ne!(
        a,
        AccusationVoting::vote_digest(&vote3, sm),
        "changing issued_at must change the digest"
    );
}

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
