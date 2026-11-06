// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Committee selection: which operators submit a ticket for an E3, and in which order they call
//! the finalizer. Every node ranks the same candidates from the same request-time registry, so
//! ranks agree without messages.

use crate::E3Id;
use alloy_primitives::{keccak256, Address, U256};
use alloy_sol_types::SolValue;
use std::collections::BTreeMap;

/// An operator's ticket score, as the registry computes it: `keccak256(abi.encodePacked(operator,
/// ticketNumber, e3Id, seed))`. Lower is better.
pub fn ticket_score(operator: Address, ticket: u64, e3: E3Id, seed: U256) -> U256 {
    let packed = (operator, U256::from(ticket), e3.number, seed).abi_encode_packed();
    U256::from_be_bytes(keccak256(packed).0)
}

/// An operator that may submit for a request: eligible at the request time, with its ticket count
/// and, when the registry knew it, its bond owner then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Eligible {
    pub(crate) operator: Address,
    pub(crate) tickets: u64,
    pub(crate) owner: Option<Address>,
}

/// An operator's best ticket and its place among the candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) operator: Address,
    pub(crate) ticket: u64,
    pub(crate) score: U256,
}

/// How many distinct owners a node shortlists for a committee of `n` with threshold `t`: the
/// committee, the members it can lose, and a margin that grows as the threshold tightens.
pub(crate) fn candidate_owners(n: usize, t: usize) -> usize {
    let margin = if 5 * t >= 4 * n {
        3
    } else if 5 * t >= 3 * n {
        2
    } else {
        1
    };
    n + n.saturating_sub(t) + margin
}

/// The candidates in submission rank. With `owner_cap`, the contract keeps one candidate per
/// request-time owner, so the shortlist holds the `owners` best owners, each owner's best operator
/// before its backups. Without the cap, or when any owner is unknown, every eligible operator is a
/// candidate, ranked by its best ticket.
pub(crate) fn candidates(
    e3: E3Id,
    seed: U256,
    eligible: &[Eligible],
    owner_cap: bool,
    owners: usize,
) -> Vec<Candidate> {
    let mut ranked: Vec<(Candidate, Option<Address>)> = eligible
        .iter()
        .filter(|operator| operator.tickets > 0)
        .map(|operator| (best_ticket(e3, seed, operator), operator.owner))
        .collect();
    ranked.sort_by_key(|(candidate, _)| (candidate.score, candidate.ticket, candidate.operator));
    let owners_known = ranked.iter().all(|(_, owner)| owner.is_some());
    if !owner_cap || !owners_known {
        return ranked.into_iter().map(|(candidate, _)| candidate).collect();
    }
    // The capped contract breaks ties between operators by address, not by ticket.
    ranked.sort_by_key(|(candidate, _)| (candidate.score, candidate.operator));
    let mut owner_ranks: BTreeMap<Address, (usize, usize)> = BTreeMap::new();
    let mut shortlist = Vec::new();
    for (candidate, owner) in ranked {
        let next = owner_ranks.len();
        let (owner_rank, member_rank) = owner_ranks
            .entry(owner.expect("every owner is known"))
            .or_insert((next, 0));
        if *owner_rank < owners {
            shortlist.push(((*member_rank, *owner_rank), candidate));
            *member_rank += 1;
        }
    }
    shortlist.sort_by_key(|(rank, _)| *rank);
    shortlist
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

fn best_ticket(e3: E3Id, seed: U256, operator: &Eligible) -> Candidate {
    (1..=operator.tickets)
        .map(|ticket| Candidate {
            operator: operator.operator,
            ticket,
            score: ticket_score(operator.operator, ticket, e3, seed),
        })
        .min_by_key(|candidate| (candidate.score, candidate.ticket))
        .expect("an operator with tickets has a best one")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3() -> E3Id {
        E3Id {
            chain_id: 1,
            number: U256::from(7),
        }
    }

    #[test]
    fn the_ticket_score_matches_the_registry() {
        let e3 = E3Id {
            chain_id: 1,
            number: "18458939420885977824981152629962741023865184457287647280899939019117062782978"
                .parse()
                .unwrap(),
        };
        let seed = U256::from_be_bytes(
            alloy_primitives::b256!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )
            .0,
        );
        let expected: U256 = "0x54839d0ce89af4ea0767d9ea472d9129c58222e25a0e38a65c2ba3ef522e758b"
            .parse()
            .unwrap();
        let operator = Address::repeat_byte(0x11);
        assert_eq!(ticket_score(operator, 1, e3, seed), expected);
    }

    #[test]
    fn the_shortlist_grows_as_the_threshold_tightens() {
        assert_eq!(candidate_owners(19, 9), 19 + 10 + 1);
        assert_eq!(candidate_owners(5, 3), 5 + 2 + 2);
        assert_eq!(candidate_owners(5, 4), 5 + 1 + 3);
        assert_eq!(candidate_owners(3, 1), 3 + 2 + 1);
    }

    fn operator(n: u8, tickets: u64, owner: Option<u8>) -> Eligible {
        Eligible {
            operator: Address::repeat_byte(n),
            tickets,
            owner: owner.map(Address::repeat_byte),
        }
    }

    #[test]
    fn every_operator_ranks_by_its_best_ticket_without_the_owner_cap() {
        let eligible = [
            operator(1, 3, Some(9)),
            operator(2, 1, Some(9)),
            operator(3, 0, None),
        ];
        let ranked = candidates(e3(), U256::from(5), &eligible, false, 1);
        assert_eq!(ranked.len(), 2);
        assert!(ranked[0].score < ranked[1].score);
        let best = |n: u8, tickets: u64| {
            (1..=tickets)
                .map(|ticket| ticket_score(Address::repeat_byte(n), ticket, e3(), U256::from(5)))
                .min()
                .unwrap()
        };
        assert!(ranked
            .iter()
            .any(|c| c.operator == Address::repeat_byte(1) && c.score == best(1, 3)));
    }

    #[test]
    fn the_owner_cap_shortlists_owners_and_keeps_their_backup_operators_last() {
        let eligible = [
            operator(1, 2, Some(10)),
            operator(2, 2, Some(10)),
            operator(3, 2, Some(11)),
            operator(4, 2, Some(12)),
        ];
        let ranked = candidates(e3(), U256::from(5), &eligible, true, 2);
        let all = candidates(e3(), U256::from(5), &eligible, false, 2);
        let owner = |candidate: &Candidate| {
            eligible
                .iter()
                .find(|e| e.operator == candidate.operator)
                .unwrap()
                .owner
        };
        let mut first_owners = Vec::new();
        for candidate in &all {
            if !first_owners.contains(&owner(candidate)) {
                first_owners.push(owner(candidate));
            }
        }
        let shortlisted: Vec<_> = first_owners[..2].to_vec();
        assert!(ranked.iter().all(|c| shortlisted.contains(&owner(c))));
        let first_two: Vec<_> = ranked[..2].iter().map(owner).collect();
        assert_eq!(
            first_two, shortlisted,
            "each owner's best operator comes first"
        );
    }

    #[test]
    fn an_unknown_owner_turns_the_shortlist_off() {
        let eligible = [
            operator(1, 2, Some(10)),
            operator(2, 2, None),
            operator(3, 2, Some(10)),
        ];
        assert_eq!(candidates(e3(), U256::from(5), &eligible, true, 1).len(), 3);
    }
}
