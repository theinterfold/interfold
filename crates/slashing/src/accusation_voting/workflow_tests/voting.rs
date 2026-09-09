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
    data_hash: [u8; 32],
    issued_at: u64,
    deadline: u64,
) -> ProofFailureAccusation {
    let mut accusation = ProofFailureAccusation {
        e3_id: e3_id.clone(),
        accuser: who.address(),
        accused,
        accused_party_id: 1,
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

/// Two honest nodes that both see the same bad proof each initiate an accusation, a few
/// seconds apart. Both accusations get the same `accusation_id` (it is keyed on
/// `(chain, e3, accused, proof_type)` only) but different `(issued_at, deadline)` windows.
/// Each node keeps whichever it saw first and, before the fix, rejected every vote signed
/// against the other window as "does not match the accusation" — so with two accusers a
/// 3-of-4 quorum could never form, and a genuine fault went unslashed by accident.
///
/// A node that already holds a pending accusation must accept a peer's later duplicate as
/// confirmation of the *same* accusation and re-vote against the peer's window, so both
/// sides converge on a set of votes the contract will verify together.
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
    let own = signed_vote(&me, sm, &v.e3_id, [0u8; 32], data_hash, NOW + VALIDITY);
    let id = insert_pending(&mut v, &me, accused, data_hash, NOW + VALIDITY, own);
    v.pending.get_mut(&id).unwrap().votes_for[0].accusation_id = id;
    v.received_data.insert(
        (accused, ProofType::C1PkGeneration),
        ReceivedProofData {
            data_hash,
            verification_passed: false,
            evidence: Bytes::new(),
        },
    );

    // B saw it 5 s later and accused independently, with a later window.
    let later = NOW + 5;
    let b_accusation = signed_accusation(&b, &v.e3_id, accused, data_hash, later, later + VALIDITY);
    assert_eq!(AccusationVoting::accusation_id(&b_accusation), id);
    let actions = v.on_accusation_received(b_accusation, &ctx());

    // I must re-vote against B's window so my vote is valid alongside B's and C's.
    let my_revote = actions.iter().find_map(|a| match a {
        VoteAction::PublishVote { vote, .. } if vote.voter == me.address() => Some(vote),
        _ => None,
    });
    let my_revote = my_revote.expect("must re-vote against the peer's window");
    assert_eq!(my_revote.deadline, later + VALIDITY);
    assert_eq!(my_revote.issued_at, later);

    // C (who also saw the fault) votes against B's window, as B's own vote will.
    let vote_b = signed_vote(&b, sm, &v.e3_id, id, data_hash, later + VALIDITY);
    let vote_c = signed_vote(&c, sm, &v.e3_id, id, data_hash, later + VALIDITY);
    let mut actions = v.on_vote_received(vote_b, &ctx());
    actions.extend(v.on_vote_received(vote_c, &ctx()));

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
