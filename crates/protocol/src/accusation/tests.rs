// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

fn e3() -> E3Id {
    E3Id {
        chain_id: 31337,
        number: U256::from(42),
    }
}

fn address(text: &str) -> Address {
    text.parse().unwrap()
}

#[test]
fn vote_hash_matches_the_independent_eip712_vector() {
    let accusation = accusation_id(
        e3(),
        address("0x1111111111111111111111111111111111111111"),
        ProofType::C0PkBfv,
    );
    assert_eq!(
        accusation,
        "0x4511f8ed6c3d679b420f7632b2e7603a3efc8a630e779ce7260a15e4b92dca96"
            .parse::<B256>()
            .unwrap()
    );
    let vote = Vote {
        e3: e3(),
        accusation_id: accusation,
        voter: address("0x2222222222222222222222222222222222222222"),
        data_hash: B256::repeat_byte(0xab),
        issued_at: 1_000,
        deadline: 2_800,
    };
    assert_eq!(
        vote.signing_hash(address("0x9999999999999999999999999999999999999999")),
        "0xcb216d9b5829c294d91eb7a47e64aec925818d691097005aa78e844591667545"
            .parse::<B256>()
            .unwrap()
    );
}

fn signed(voter: &str, fill: u8) -> SignedVote {
    SignedVote {
        vote: Vote {
            e3: e3(),
            accusation_id: B256::repeat_byte(0x01),
            voter: address(voter),
            data_hash: B256::repeat_byte(fill),
            issued_at: 1_000,
            deadline: 2_800,
        },
        signature: Bytes::from(vec![fill; 65]),
    }
}

#[test]
fn slash_evidence_matches_the_current_node() {
    let votes = [
        signed("0x2222222222222222222222222222222222222222", 0xaa),
        signed("0x2111111111111111111111111111111111111111", 0xbb),
    ];
    let expected = hex::decode(concat!(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "00000000000000000000000000000000000000000000000000000000000000e0",
        "0000000000000000000000000000000000000000000000000000000000000140",
        "00000000000000000000000000000000000000000000000000000000000001a0",
        "00000000000000000000000000000000000000000000000000000000000003e8",
        "0000000000000000000000000000000000000000000000000000000000000af0",
        "0000000000000000000000000000000000000000000000000000000000000200",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000002111111111111111111111111111111111111111",
        "0000000000000000000000002222222222222222222222222222222222222222",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0000000000000000000000000000000000000000000000000000000000000028",
        "5555555555555555555555555555555555555555555555555555555555555555",
        "5555555555555555000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000040",
        "00000000000000000000000000000000000000000000000000000000000000c0",
        "0000000000000000000000000000000000000000000000000000000000000041",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bb00000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000041",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aa00000000000000000000000000000000000000000000000000000000000000",
    ))
    .unwrap();
    assert_eq!(
        slash_evidence(ProofType::C1PkGeneration, &votes, &[0x55; 40]).unwrap(),
        Bytes::from(expected)
    );
}

#[test]
fn slash_evidence_needs_votes_and_the_disputed_proof() {
    let votes = [signed("0x2222222222222222222222222222222222222222", 0xaa)];
    assert_eq!(
        slash_evidence(ProofType::C1PkGeneration, &[], &[0x55; 40]),
        Err(EvidenceError::NoVotes)
    );
    assert_eq!(
        slash_evidence(ProofType::C1PkGeneration, &votes, &[]),
        Err(EvidenceError::NoProofBytes)
    );
}

mod cases {
    use super::super::{AccusationMessage, AccusationWorkResult};
    use crate::{
        accusation::{accusation_id, SignedVote, Vote},
        node::{
            Body, ChainFact, Effect, Input, JobDone, Node, PeerMessage, Purpose, Stage, Submission,
            Transaction, Work, WorkResult,
        },
        proof::{ProofType, SignedProof},
        testing::*,
        Machine,
    };
    use alloy_primitives::{Address, B256};

    const MANAGER: Address = Address::repeat_byte(0x5a);
    const VALIDITY: u64 = 600;
    const NOW: u64 = 1_000;

    /// Operator `me` in the committee of operators 1, 2, and `me`, whose request snapshotted the
    /// slashing manager, with operator 1's key received.
    fn member(me: u64) -> Node {
        member_of(me, &[1, 2])
    }

    fn member_of(me: u64, others: &[u64]) -> Node {
        let mut node = Node::new(address(me));
        node.step(0, chain(2, ChainFact::SlashingManager { manager: MANAGER }));
        node.step(0, chain(3, ChainFact::VoteValidity { secs: VALIDITY }));
        node.step(0, requested(10, e3(1)));
        let mut members: Vec<Address> = others.iter().chain([&me]).map(|n| address(*n)).collect();
        members.sort();
        node.step(0, finalized(11, e3(1), members));
        node.step(NOW, key_from(e3(1), 1));
        node
    }

    fn data_hash(n: u64) -> B256 {
        B256::repeat_byte(0xd0 + n as u8)
    }

    /// Operator 1's C0 proof, signed by `signer`.
    fn key_proof(signer: u64) -> SignedProof {
        let proof = proof(1);
        let hash = proof.payload_signing_hash(e3(1), ProofType::C0PkBfv);
        SignedProof {
            signature: signature(signer, hash),
            proof,
        }
    }

    /// Operator `owner`'s own C0 proof, signed by `owner`.
    fn signed_key(owner: u64) -> SignedProof {
        let proof = proof(owner as u8);
        let hash = proof.payload_signing_hash(e3(1), ProofType::C0PkBfv);
        SignedProof {
            signature: signature(owner, hash),
            proof,
        }
    }

    fn signed_vote(voter: u64, vote: Vote) -> SignedVote {
        let signature = signature(voter, vote.signing_hash(MANAGER));
        SignedVote { vote, signature }
    }

    fn vote(voter: u64, issued_at: u64) -> SignedVote {
        let vote = Vote {
            e3: e3(1),
            accusation_id: accusation_id(e3(1), address(1), ProofType::C0PkBfv),
            voter: address(voter),
            data_hash: data_hash(1),
            issued_at,
            deadline: issued_at + VALIDITY,
        };
        let signature = signature(voter, vote.signing_hash(MANAGER));
        SignedVote { vote, signature }
    }

    fn from(sender: u64, message: AccusationMessage) -> Input {
        Input::Peer(PeerMessage {
            e3: e3(1),
            sender: address(sender),
            body: Body::Accusation(message),
        })
    }

    /// Operator `accuser`'s accusation of operator 1's key, issued at `issued_at`.
    fn accusation(accuser: u64, issued_at: u64, signer: u64) -> Input {
        from(
            accuser,
            AccusationMessage::Accuse {
                accused: address(1),
                proof_type: ProofType::C0PkBfv,
                proof: key_proof(signer),
                vote: vote(accuser, issued_at),
            },
        )
    }

    fn verified(fails: bool) -> Input {
        Input::Job(JobDone {
            e3: e3(1),
            result: WorkResult::Accusation(AccusationWorkResult::Verified {
                proof_type: ProofType::C0PkBfv,
                proof: proof(1),
                fails,
                data_hash: data_hash(1),
            }),
        })
    }

    fn gossiped(effects: &[Effect]) -> Vec<&AccusationMessage> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Gossip(PeerMessage {
                    body: Body::Accusation(message),
                    ..
                }) => Some(message),
                _ => None,
            })
            .collect()
    }

    fn slashes(effects: &[Effect]) -> Vec<(Address, usize)> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Submit(Submission {
                    transaction:
                        Transaction::ProposeSlash {
                            manager,
                            accused,
                            votes,
                            ..
                        },
                    ..
                }) => {
                    assert_eq!(*manager, MANAGER);
                    Some((*accused, votes.len()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_member_whose_signed_proof_fails_is_accused_with_the_proof_and_the_accuser_s_vote() {
        let mut node = member(ME);
        let effects = node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        let signing = signing(&effects);
        assert_eq!(signing.hashes, [vote(ME, NOW).vote.signing_hash(MANAGER)]);
        assert!(matches!(signing.purpose, Purpose::Accusation(_)));

        let effects = node.step(NOW, sign(ME, signing));
        let [AccusationMessage::Accuse {
            accused,
            proof_type,
            proof,
            vote: signed,
        }] = gossiped(&effects)[..]
        else {
            panic!("one accusation, got {effects:?}");
        };
        assert_eq!((*accused, *proof_type), (address(1), ProofType::C0PkBfv));
        assert_eq!(*proof, key_proof(1));
        assert_eq!(*signed, vote(ME, NOW));
    }

    #[test]
    fn a_member_votes_for_an_accusation_once_its_own_check_of_the_proof_fails() {
        let mut node = member(ME);
        let effects = node.step(NOW, accusation(2, NOW, 1));
        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Run(job) if matches!(job.work, Work::Accusation(_))
        )));

        let effects = node.step(NOW, verified(true));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        assert_eq!(
            gossiped(&effects),
            [&AccusationMessage::Vote(vote(ME, NOW))]
        );
    }

    #[test]
    fn a_proof_that_verifies_gets_no_vote() {
        let mut node = member(ME);
        node.step(NOW, accusation(2, NOW, 1));
        assert!(node.step(NOW, verified(false)).is_empty());
    }

    #[test]
    fn an_accusation_counts_only_with_the_accused_s_signature_on_the_proof() {
        let mut node = member(ME);
        assert!(node.step(NOW, accusation(2, NOW, 2)).is_empty());
    }

    #[test]
    fn h_votes_in_one_window_go_to_the_slashing_manager_from_the_first_voters_in_turn() {
        // H is two for the Minimum committee: the accuser's vote and this node's.
        let mut node = member(ME);
        node.step(NOW, accusation(2, NOW, 1));
        let effects = node.step(NOW, verified(true));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        let first = address(2).min(address(ME)) == address(ME);
        match first {
            true => assert_eq!(slashes(&effects), [(address(1), 2)]),
            false => {
                assert!(slashes(&effects).is_empty());
                let later = node.step(NOW + 30, Input::Tick);
                assert_eq!(slashes(&later), [(address(1), 2)]);
            }
        }
    }

    #[test]
    fn a_vote_that_comes_before_its_accusation_counts_once_the_accusation_arrives() {
        let mut node = member_of(ME, &[1, 2, 3]);
        node.step(NOW, from(3, AccusationMessage::Vote(vote(3, NOW))));
        node.step(NOW, accusation(2, NOW, 1));
        let effects = node.step(NOW, verified(true));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        let later = node.step(NOW + 60, Input::Tick);
        let slashes: Vec<_> = slashes(&effects)
            .into_iter()
            .chain(slashes(&later))
            .collect();
        assert_eq!(slashes, [(address(1), 3)]);
    }

    #[test]
    fn a_completed_e3_stays_until_its_accusations_close() {
        let mut node = member(ME);
        let effects = node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        node.step(NOW, sign(ME, signing(&effects)));
        node.step(
            NOW,
            chain(
                20,
                ChainFact::StageChanged {
                    e3: e3(1),
                    stage: Stage::Complete,
                },
            ),
        );
        assert!(node.e3(&e3(1)).is_some());
        node.step(NOW + VALIDITY + 1, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
    }

    /// An accuser that pairs an honest member's valid proof with the evidence hash of a proof this
    /// node found failing gets no vote: the node checks the accused proof itself.
    #[test]
    fn a_failure_found_in_one_proof_gives_no_vote_against_another() {
        let mut node = member_of(ME, &[1, 2, 3]);
        node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        let vote = Vote {
            e3: e3(1),
            accusation_id: accusation_id(e3(1), address(3), ProofType::C0PkBfv),
            voter: address(2),
            data_hash: data_hash(1),
            issued_at: NOW,
            deadline: NOW + VALIDITY,
        };
        let effects = node.step(
            NOW,
            from(
                2,
                AccusationMessage::Accuse {
                    accused: address(3),
                    proof_type: ProofType::C0PkBfv,
                    proof: signed_key(3),
                    vote: signed_vote(2, vote),
                },
            ),
        );
        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Run(job) if matches!(job.work, Work::Accusation(_))
        )));
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::Sign(_))));
    }

    /// A vote whose window starts later than the chain's time plus the contract's clock skew is
    /// not taken, so it cannot hold a window open to the end of time.
    #[test]
    fn a_vote_from_the_far_future_is_not_taken() {
        let mut node = member_of(ME, &[1, 2, 3]);
        let before = node.next_deadline();
        let vote = Vote {
            e3: e3(1),
            accusation_id: accusation_id(e3(1), address(1), ProofType::C0PkBfv),
            voter: address(3),
            data_hash: data_hash(1),
            issued_at: u64::MAX - VALIDITY,
            deadline: u64::MAX,
        };
        node.step(NOW, from(3, AccusationMessage::Vote(signed_vote(3, vote))));
        assert_eq!(node.next_deadline(), before);
    }

    /// The operator reads who signed the proof that failed, and which circuit it was.
    #[test]
    fn a_failing_proof_is_noted_with_its_member_and_type() {
        use crate::node::{Note, Noted};
        let mut node = member(ME);
        let effects = node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        assert!(effects.iter().any(|effect| matches!(
            effect,
            Effect::Note(Note {
                event: Noted::ProofFailed { member, proof_type: ProofType::C0PkBfv },
                ..
            }) if *member == address(1)
        )));
    }

    /// Two members that find the same proof failing in the same second open the same window. Each
    /// counts the other's vote, so a committee where H is two still reaches its quorum.
    #[test]
    fn members_that_accuse_in_the_same_second_count_each_other_s_votes() {
        let mut node = member(ME);
        let effects = node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        assert!(matches!(
            gossiped(&effects)[..],
            [AccusationMessage::Accuse { .. }]
        ));
        let effects = node.step(NOW, accusation(2, NOW, 1));
        let later = node.step(NOW + 30, Input::Tick);
        let slashes: Vec<_> = slashes(&effects)
            .into_iter()
            .chain(slashes(&later))
            .collect();
        assert_eq!(slashes, [(address(1), 2)]);
    }

    /// The contract checks one evidence hash for all votes, so a vote for another does not join.
    #[test]
    fn an_accusation_for_other_evidence_does_not_join_an_open_window() {
        let mut node = member(ME);
        let effects = node.step(NOW, key_failed(e3(1), 1, data_hash(1)));
        node.step(NOW, sign(ME, signing(&effects)));
        let mut other = vote(2, NOW).vote;
        other.data_hash = data_hash(2);
        let accusation = from(
            2,
            AccusationMessage::Accuse {
                accused: address(1),
                proof_type: ProofType::C0PkBfv,
                proof: key_proof(1),
                vote: signed_vote(2, other),
            },
        );
        let effects = node.step(NOW, accusation);
        assert!(slashes(&effects).is_empty());
        assert!(slashes(&node.step(NOW + 60, Input::Tick)).is_empty());
    }

    /// With no validity on chain, a member cannot open a window that lasts no time at all.
    #[test]
    fn a_chain_without_a_vote_validity_takes_no_accusation() {
        let mut node = Node::new(address(ME));
        node.step(0, chain(2, ChainFact::SlashingManager { manager: MANAGER }));
        node.step(0, requested(10, e3(1)));
        let mut members = vec![address(1), address(2), address(ME)];
        members.sort();
        node.step(0, finalized(11, e3(1), members));
        let mut instant = vote(2, NOW).vote;
        instant.deadline = NOW;
        let accusation = from(
            2,
            AccusationMessage::Accuse {
                accused: address(1),
                proof_type: ProofType::C0PkBfv,
                proof: key_proof(1),
                vote: signed_vote(2, instant),
            },
        );
        assert!(node.step(NOW, accusation).is_empty());
    }

    /// A member has one window open for an accusation at a time, so it cannot make the others
    /// keep windows without end; once its window closes it can open another.
    #[test]
    fn a_member_opens_one_window_at_a_time_for_an_accusation() {
        let mut node = member(ME);
        let opens = |effects: Vec<Effect>| {
            effects.iter().any(|effect| {
                matches!(
                    effect,
                    Effect::Run(job) if matches!(job.work, Work::Accusation(_))
                )
            })
        };
        assert!(opens(node.step(NOW, accusation(2, NOW, 1))));
        assert!(!opens(node.step(NOW + 1, accusation(2, NOW + 1, 1))));
        let after = NOW + VALIDITY + 1;
        node.step(after, Input::Tick);
        assert!(opens(node.step(after, accusation(2, after, 1))));
    }

    /// A member's votes that come before their accusations wait in a bounded number; one past it
    /// does not count when its accusation arrives.
    #[test]
    fn a_member_s_votes_that_come_before_their_accusations_wait_in_a_bounded_number() {
        let mut node = member_of(ME, &[1, 2, 3]);
        for earlier in 1..=super::super::cases::EARLY_VOTES_PER_MEMBER as u64 {
            node.step(
                NOW,
                from(3, AccusationMessage::Vote(vote(3, NOW - earlier))),
            );
        }
        node.step(NOW, from(3, AccusationMessage::Vote(vote(3, NOW))));
        node.step(NOW, accusation(2, NOW, 1));
        let effects = node.step(NOW, verified(true));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        let later = node.step(NOW + 60, Input::Tick);
        let slashes: Vec<_> = slashes(&effects)
            .into_iter()
            .chain(slashes(&later))
            .collect();
        assert_eq!(slashes, [(address(1), 2)]);
    }

    /// An expulsion that leaves a window short of H votes stops this node's turn to submit it, so
    /// it never sends a slash the contract rejects; a new vote brings the window back to H.
    #[test]
    fn a_window_that_loses_a_vote_to_an_expulsion_waits_for_another_vote() {
        // Operator 33 sorts before this node, so it submits first and this node waits its turn.
        assert!(address(33) < address(ME) && address(ME) < address(2));
        let mut node = member_of(ME, &[1, 2, 33]);
        node.step(NOW, accusation(33, NOW, 1));
        let effects = node.step(NOW, verified(true));
        let effects = node.step(NOW, sign(ME, signing(&effects)));
        assert!(slashes(&effects).is_empty());
        let expelled = ChainFact::MemberExpelled {
            e3: e3(1),
            member: address(33),
        };
        node.step(NOW + 10, chain(20, expelled));
        assert!(slashes(&node.step(NOW + 30, Input::Tick)).is_empty());
        let effects = node.step(NOW + 40, from(2, AccusationMessage::Vote(vote(2, NOW))));
        assert_eq!(slashes(&effects), [(address(1), 2)]);
    }

    /// A slash this node already sent can wait for the chain while a voter in it is expelled; the
    /// contract rejects it then, so the window goes again with the votes left once H voted.
    #[test]
    fn a_sent_slash_that_loses_a_vote_to_an_expulsion_goes_again() {
        let mut node = member_of(ME, &[1, 2, 33]);
        node.step(NOW, accusation(33, NOW, 1));
        let effects = node.step(NOW, verified(true));
        node.step(NOW, sign(ME, signing(&effects)));
        assert_eq!(
            slashes(&node.step(NOW + 30, Input::Tick)),
            [(address(1), 2)]
        );
        let expelled = ChainFact::MemberExpelled {
            e3: e3(1),
            member: address(33),
        };
        node.step(NOW + 35, chain(20, expelled));
        assert!(slashes(&node.step(NOW + 60, Input::Tick)).is_empty());
        let effects = node.step(NOW + 70, from(2, AccusationMessage::Vote(vote(2, NOW))));
        assert_eq!(slashes(&effects), [(address(1), 2)]);
    }
}
