// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Decryption at its own boundary, fed the inputs the node routes to it. The committee is
//! operators 1, 2, 3, and ME with a Minimum committee's T = 1; each test picks the roster.

use super::*;
use crate::{
    node::{Fetch, Fetched, Input, JobDone, Signed, WorkResult},
    testing::*,
};
use e3_committee::CiphernodesCommitteeSize;

const NOW: u64 = 150_000;
const PLAINTEXT_BUDGET: u64 = 10 * 60;
const KEY: BlobRef = BlobRef {
    hash: B256::repeat_byte(0x4e),
    len: 100,
};

/// The committee's operators in party order, ascending by address.
fn ordered() -> [u64; 4] {
    let mut operators = [1, 2, 3, ME];
    operators.sort_by_key(|n| address(*n));
    operators
}

fn members(operators: &[u64]) -> Vec<Address> {
    let mut members: Vec<Address> = operators.iter().map(|n| address(*n)).collect();
    members.sort();
    members
}

/// The key commitments the chain recorded for `member`.
fn anchor_of(member: Address) -> KeyAnchor {
    KeyAnchor {
        sk_agg_commit: B256::left_padding_from(member.as_slice()),
        esm_agg_commit: B256::right_padding_from(member.as_slice()),
    }
}

fn decryption(me: u64, roster: &[u64], key: bool) -> Decryption {
    let committee = members(&ordered());
    let handover = Handover {
        roster: members(roster),
        key: key.then_some(KEY),
        expelled: BTreeSet::new(),
    };
    let published = PublishedKey {
        interfold: INTERFOLD,
        committee: committee.clone(),
        commitment: KEY_COMMITMENT,
        anchors: committee
            .iter()
            .map(|member| (*member, anchor_of(*member)))
            .collect(),
    };
    Decryption::new(
        e3(1),
        address(me),
        committee,
        params(CiphernodesCommitteeSize::Minimum),
        handover,
        published,
    )
}

/// Apply passed deadlines, then `input`, as the node does.
fn deliver(decryption: &mut Decryption, now: UnixSecs, input: Input) -> Vec<Effect> {
    let mut effects = decryption.pass_deadlines(now);
    effects.extend(match input {
        Input::Peer(PeerMessage {
            sender,
            body: Body::Decryption(message),
            ..
        }) => decryption.receive(now, sender, message),
        Input::Job(JobDone {
            result: WorkResult::Decryption(result),
            ..
        }) => decryption.job_done(now, result),
        Input::Signed(Signed {
            purpose: Purpose::Decryption(purpose),
            signatures,
            ..
        }) => decryption.signed(now, purpose, signatures),
        Input::Fetched(Fetched { blob, .. }) => decryption.ciphertext_fetched(now, blob),
        Input::Tick => Vec::new(),
        other => panic!("not a decryption input: {other:?}"),
    });
    effects
}

/// The chain names the ciphertext and the fetcher returns its bytes.
fn ciphertext(decryption: &mut Decryption) -> Vec<Effect> {
    decryption.ciphertext_ready(CIPHERTEXT_DATA, DECRYPTION_DEADLINE);
    deliver(decryption, NOW, ciphertext_fetched(e3(1)))
}

/// Operator `me`, a roster member that decrypted and sent its share.
fn with_its_share(me: u64, roster: &[u64]) -> Decryption {
    let mut decryption = decryption(me, roster, true);
    ciphertext(&mut decryption);
    let effects = deliver(
        &mut decryption,
        NOW,
        decryption_shares_made(e3(1), own_decryption_shares(0xd6)),
    );
    deliver(&mut decryption, NOW, sign(me, signing(&effects)));
    decryption
}

fn works(effects: &[Effect]) -> Vec<&DecryptionWork> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Run(Job {
                work: Work::Decryption(work),
                ..
            }) => Some(work),
            _ => None,
        })
        .collect()
}

fn checked(effects: &[Effect]) -> Vec<Address> {
    let checks = works(effects).into_iter().filter_map(|work| match work {
        DecryptionWork::CheckShares { member, .. } => Some(*member),
        _ => None,
    });
    checks.collect()
}

fn combined(effects: &[Effect]) -> Vec<Vec<Address>> {
    let combinations = works(effects).into_iter().filter_map(|work| match work {
        DecryptionWork::AggregatePlaintext { shares, .. } => Some(shares.keys().copied().collect()),
        _ => None,
    });
    combinations.collect()
}

#[test]
fn a_member_fetches_the_ciphertext_the_chain_names() {
    let [a, b, c, _] = ordered();
    let mut decryption = decryption(c, &[a, b], false);
    let effects = decryption.ciphertext_ready(CIPHERTEXT_DATA, DECRYPTION_DEADLINE);
    let fetch = Effect::Fetch(Fetch {
        e3: e3(1),
        data: CIPHERTEXT_DATA,
    });
    assert_eq!(effects, vec![fetch]);
}

#[test]
fn a_roster_member_decrypts_with_its_sealed_key_under_the_contract_s_domain() {
    let [a, b, ..] = ordered();
    let mut decryption = decryption(a, &[a, b], true);
    let effects = ciphertext(&mut decryption);
    let domain = decryption_domain(
        e3(1),
        INTERFOLD,
        committee_hash(&members(&ordered())),
        CIPHERTEXT.hash,
        KEY_COMMITMENT,
    );
    let make = DecryptionWork::MakeShares {
        key: KEY,
        ciphertext: CIPHERTEXT,
        domain,
    };
    assert_eq!(works(&effects), vec![&make]);
}

#[test]
fn a_member_without_a_decryption_key_does_not_decrypt() {
    let [a, b, c, _] = ordered();
    let mut decryption = decryption(c, &[a, b], false);
    let effects = ciphertext(&mut decryption);
    assert!(works(&effects).is_empty());
}

#[test]
fn a_roster_member_sends_shares_its_peers_accept() {
    let [a, b, ..] = ordered();
    let mut decryption = decryption(a, &[a, b], true);
    ciphertext(&mut decryption);
    let effects = deliver(
        &mut decryption,
        NOW,
        decryption_shares_made(e3(1), own_decryption_shares(0xd6)),
    );
    let effects = deliver(&mut decryption, NOW, sign(a, signing(&effects)));
    let [Effect::Gossip(sent)] = effects.as_slice() else {
        panic!("one gossip, got {effects:?}");
    };
    let mut peer = decryption_of(b, &[a, b]);
    deliver(&mut peer, NOW, Input::Peer(sent.clone()));
    assert!(peer.shares_of(&address(a)).is_some());
}

fn decryption_of(me: u64, roster: &[u64]) -> Decryption {
    let mut decryption = decryption(me, roster, false);
    ciphertext(&mut decryption);
    decryption
}

#[test]
fn only_a_roster_member_s_first_correctly_signed_shares_count() {
    let [a, b, c, d] = ordered();
    let mut decryption = decryption_of(d, &[a, b]);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), c, c));
    deliver(&mut decryption, NOW, decryption_shares(e3(1), a, b));
    assert!(decryption.shares_of(&address(c)).is_none());
    assert!(decryption.shares_of(&address(a)).is_none());
    deliver(&mut decryption, NOW, decryption_shares(e3(1), a, a));
    assert!(decryption.shares_of(&address(a)).is_some());
}

#[test]
fn shares_that_arrive_before_the_ciphertext_s_bytes_are_checked_once_they_are_here() {
    let [a, b, c, _] = ordered();
    let mut decryption = decryption(a, &[b, c], false);
    decryption.ciphertext_ready(CIPHERTEXT_DATA, DECRYPTION_DEADLINE);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    let effects = deliver(&mut decryption, NOW, decryption_shares(e3(1), c, c));
    assert!(checked(&effects).is_empty());
    let effects = deliver(&mut decryption, NOW, ciphertext_fetched(e3(1)));
    assert_eq!(checked(&effects), members(&[b, c]));
}

/// Each member's shares are checked against the key commitments the chain recorded for that
/// member, so a C6 proof copied from another member does not count.
#[test]
fn each_member_s_shares_are_checked_against_its_own_key_commitments() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(a, &[a, b]);
    let effects = deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    let anchors: Vec<(Address, Option<KeyAnchor>)> = works(&effects)
        .into_iter()
        .filter_map(|work| match work {
            DecryptionWork::CheckShares { member, anchor, .. } => Some((*member, *anchor)),
            _ => None,
        })
        .collect();
    let expected: Vec<(Address, Option<KeyAnchor>)> = members(&[a, b])
        .into_iter()
        .map(|member| (member, Some(anchor_of(member))))
        .collect();
    assert_eq!(anchors, expected);
}

#[test]
fn the_aggregator_checks_shares_once_t_plus_one_are_here() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(a, &[a, b]);
    let effects = deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    assert_eq!(checked(&effects), members(&[a, b]));
}

#[test]
fn the_aggregator_combines_exactly_t_plus_one_valid_shares() {
    let [a, b, c, _] = ordered();
    let mut decryption = with_its_share(a, &[a, b, c]);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    deliver(&mut decryption, NOW, decryption_shares(e3(1), c, c));
    deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), c, true),
    );
    let effects = deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), a, true),
    );
    assert_eq!(combined(&effects), vec![members(&[a, c])]);
}

#[test]
fn a_failed_share_waits_for_a_backup() {
    let [a, b, c, _] = ordered();
    let mut decryption = with_its_share(a, &[a, b, c]);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), a, true),
    );
    let effects = deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), b, false),
    );
    assert!(combined(&effects).is_empty());
    let effects = deliver(&mut decryption, NOW, decryption_shares(e3(1), c, c));
    assert_eq!(checked(&effects), members(&[c]));
    let effects = deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), c, true),
    );
    assert_eq!(combined(&effects), vec![members(&[a, c])]);
}

#[test]
fn decryption_fails_once_t_plus_one_valid_shares_are_impossible() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(a, &[a, b]);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), b, false),
    );
    assert_eq!(decryption.failure(), Some(DecryptionFailure::TooFewShares));
}

#[test]
fn the_aggregator_asks_the_chain_writer_to_publish_the_plaintext() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(a, &[a, b]);
    deliver(&mut decryption, NOW, decryption_shares(e3(1), b, b));
    deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), a, true),
    );
    deliver(
        &mut decryption,
        NOW,
        decryption_shares_checked(e3(1), b, true),
    );
    let effects = deliver(&mut decryption, NOW, plaintext_made(e3(1), 0x7e));
    assert!(matches!(
        effects.as_slice(),
        [Effect::Submit(Submission {
            transaction: Transaction::PublishPlaintext(_),
            ..
        })]
    ));
}

#[test]
fn the_next_member_aggregates_when_the_aggregator_s_budget_runs_out() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(b, &[a, b]);
    let effects = deliver(&mut decryption, NOW, decryption_shares(e3(1), a, a));
    assert!(checked(&effects).is_empty());
    let effects = deliver(&mut decryption, NOW + PLAINTEXT_BUDGET, Input::Tick);
    assert_eq!(checked(&effects), members(&[a, b]));
}

#[test]
fn decryption_stops_at_its_deadline() {
    let [a, b, ..] = ordered();
    let mut decryption = with_its_share(a, &[a, b]);
    deliver(&mut decryption, DECRYPTION_DEADLINE, Input::Tick);
    assert_eq!(
        decryption.failure(),
        Some(DecryptionFailure::DeadlinePassed)
    );
    assert_eq!(decryption.next_deadline(), None);
}

/// After a restart the outbox repeats the fetch, so the bytes can arrive twice.
#[test]
fn bytes_fetched_twice_start_decryption_once() {
    let [a, b, ..] = ordered();
    let mut decryption = decryption(a, &[a, b], true);
    let first = ciphertext(&mut decryption);
    let again = deliver(&mut decryption, NOW, ciphertext_fetched(e3(1)));
    assert_eq!(works(&first).len(), 1);
    assert!(works(&again).is_empty());
}
