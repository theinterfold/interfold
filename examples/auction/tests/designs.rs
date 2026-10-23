// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use auction_designs::run::run_with_ties;
use auction_designs::{
    run, Design, FirstPrice, FirstPriceBlind, Profile, PublicResult, Rank, RankBatched,
    RatioFirstPrice, RatioSecondPrice, SecondPrice, SecondPriceBlind, SetupError, Vickrey,
    VickreyCompact,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const LEVELS: usize = 16;

/// Bid sets that exercise ties, the range ends, and 2 to 8 bidders.
const BID_SETS: &[&[u64]] = &[
    &[7, 3, 9, 9],
    &[9, 9, 3, 7],
    &[5, 5, 5, 5, 5],
    &[0, 15],
    &[15, 0],
    &[0, 0],
    &[1, 14, 2, 13, 3, 12, 4, 11],
];

/// Runs `design` on every bid set with at most `max_bidders` bidders.
fn assert_correct<D: Design>(design: &D, max_bidders: usize) {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for bids in BID_SETS.iter().filter(|bids| bids.len() <= max_bidders) {
        let report = run(design, Profile::Toy, bids, LEVELS, &mut rng)
            .unwrap_or_else(|error| panic!("{} on {bids:?}: {error}", design.name()));
        assert!(
            report.is_correct(),
            "{} on {bids:?}: public {:?}, expected {:?}, own ranks {:?}, expected {:?}",
            design.name(),
            report.public,
            report.expected,
            report.own_ranks,
            report.expected_ranks
        );
    }
}

#[test]
fn rank_names_the_winner_and_each_bidder_reads_its_own_rank() {
    assert_correct(&Rank, usize::MAX);
}

/// Ties for the highest bid give several zeros; ranks are competition ranks.
#[test]
fn rank_batched_names_the_winner_and_each_bidder_reads_its_own_rank() {
    // 3 · n² · B must fit the 1024 toy slots: 4 bidders at 16 levels.
    assert_correct(&RankBatched, 4);
}

#[test]
fn first_price_reveals_the_winner_and_the_winning_bid() {
    assert_correct(&FirstPrice, usize::MAX);
}

#[test]
fn first_price_blind_reveals_the_winner_and_the_winning_bid() {
    assert_correct(&FirstPriceBlind, usize::MAX);
}

#[test]
fn second_price_reveals_the_winner_and_the_second_highest_bid() {
    assert_correct(&SecondPrice, usize::MAX);
}

#[test]
fn second_price_blind_reveals_the_winner_and_the_second_highest_bid() {
    assert_correct(&SecondPriceBlind, usize::MAX);
}

/// A contract checks a claimed result by evaluating the plaintext at slot points. The check
/// must accept the true result and refuse a neighbouring winner or price.
#[test]
fn blind_claim_checks_accept_only_the_true_result() {
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let claim = |winner, price| PublicResult {
        winner: Some(winner),
        price: Some(price),
    };

    let first = run(
        &FirstPriceBlind,
        Profile::Toy,
        &[4, 12, 9, 12],
        LEVELS,
        &mut rng,
    )
    .unwrap();
    let verify = |c| FirstPriceBlind.verify(&first.setup, &first.output.coefficients, c);
    assert!(verify(claim(3, 12)));
    assert!(!verify(claim(1, 12)), "the tie goes to the higher index");
    assert!(!verify(claim(3, 11)));
    assert!(!verify(claim(3, 13)));

    let second = run(
        &SecondPriceBlind,
        Profile::Toy,
        &[4, 12, 9, 2],
        LEVELS,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        SecondPriceBlind.winning_bid(&second.setup, &second.output),
        12
    );
    let verify =
        |c, top| SecondPriceBlind.verify(&second.setup, &second.output.coefficients, c, top);
    assert!(verify(claim(1, 9), 12));
    assert!(!verify(claim(1, 8), 12));
    assert!(!verify(claim(1, 10), 12));
    assert!(!verify(claim(1, 9), 11));
    assert!(!verify(claim(2, 9), 12));
}

/// Which (bidder, level) slots are non-zero in one or more copies of the vickrey output. Bidder
/// `j` owns the region at its tie priority.
fn vickrey_pattern(report: &auction_designs::Report) -> Vec<bool> {
    let setup = &report.setup;
    let (n, levels) = (setup.bidders, setup.levels);
    let copies = setup.params.degree() / (n * levels);
    (0..n)
        .flat_map(|bidder| {
            let start = setup.tie_priority[bidder] * levels;
            (start..start + levels).map(move |position| {
                (0..copies).any(|copy| report.output.slots[copy * n * levels + position] != 0)
            })
        })
        .collect()
}

#[test]
fn vickrey_reveals_the_winner_and_the_second_highest_bid() {
    assert_correct(&Vickrey, usize::MAX);
}

#[test]
fn vickrey_compact_reveals_the_winner_and_the_second_highest_bid() {
    assert_correct(&VickreyCompact, usize::MAX);
}

/// The output must be a function of the winner and the price only: bid sets with the same
/// result give the same zero pattern. The sets differ in the winning bid, the runner-up, the
/// number of bids at the price, and whether the top is a tie.
fn assert_output_depends_only_on_the_result<D: Design>(design: &D) {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    // Bidder 1 has the highest priority, so it wins the tie in the third set.
    let priority = || vec![2, 3, 0, 1];
    let same_result: [&[u64]; 4] = [
        &[3, 12, 9, 9],
        &[9, 15, 2, 9],
        &[9, 9, 3, 5],
        &[9, 10, 9, 0],
    ];
    let reports: Vec<_> = same_result
        .iter()
        .map(|bids| {
            run_with_ties(design, Profile::Toy, bids, LEVELS, priority(), &mut rng).unwrap()
        })
        .collect();
    for report in &reports {
        assert_eq!(
            report.public,
            PublicResult {
                winner: Some(1),
                price: Some(9)
            }
        );
        assert_eq!(
            vickrey_pattern(report),
            vickrey_pattern(&reports[0]),
            "{} on {:?}",
            design.name(),
            report.bids
        );
    }
    let other_winner = run_with_ties(
        design,
        Profile::Toy,
        &[9, 3, 12, 9],
        LEVELS,
        priority(),
        &mut rng,
    )
    .unwrap();
    assert_ne!(vickrey_pattern(&other_winner), vickrey_pattern(&reports[0]));
}

#[test]
fn vickrey_output_depends_only_on_the_winner_and_the_price() {
    assert_output_depends_only_on_the_result(&Vickrey);
    assert_output_depends_only_on_the_result(&VickreyCompact);
}

/// A tie for the highest bid goes to the tied bidder with the highest tie priority, whatever its
/// index.
#[test]
fn vickrey_tie_goes_to_the_tied_bidder_with_the_highest_priority() {
    fn assert_tie_winners<D: Design>(design: &D) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        // Bidders 0, 2, and 3 tie at 9. Bidder 1 has a lower bid, so its priority does not count.
        for (priority, winner) in [
            (vec![3, 0, 1, 2], 0),
            (vec![0, 3, 2, 1], 2),
            (vec![1, 2, 0, 3], 3),
        ] {
            let report = run_with_ties(
                design,
                Profile::Toy,
                &[9, 3, 9, 9],
                LEVELS,
                priority.clone(),
                &mut rng,
            )
            .unwrap();
            assert_eq!(
                report.public,
                PublicResult {
                    winner: Some(winner),
                    price: Some(9)
                },
                "{} with priority {priority:?}",
                design.name()
            );
        }
    }
    assert_tie_winners(&Vickrey);
    assert_tie_winners(&VickreyCompact);
}

/// The claim check must accept the true result and refuse a loser, a neighbouring price, and a
/// loser that claims one level more.
#[test]
fn vickrey_claim_check_accepts_only_the_true_result() {
    let mut rng = ChaCha20Rng::seed_from_u64(6);
    let report = run(&Vickrey, Profile::Toy, &[4, 12, 9, 2], LEVELS, &mut rng).unwrap();
    let verify = |winner, price| {
        Vickrey.verify(
            &report.setup,
            &report.output.coefficients,
            PublicResult {
                winner: Some(winner),
                price: Some(price),
            },
        )
    };
    assert!(verify(1, 9));
    for (winner, price) in [(2, 9), (0, 9), (1, 8), (1, 10), (2, 10), (0, 10), (1, 0)] {
        assert!(!verify(winner, price), "claim ({winner}, {price})");
    }
}

/// The output of the first-price program must not depend on the losing bids.
#[test]
fn first_price_output_is_the_same_for_all_bids_with_the_same_result() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let a = run(&FirstPrice, Profile::Toy, &[2, 11, 6], LEVELS, &mut rng).unwrap();
    let b = run(&FirstPrice, Profile::Toy, &[10, 11, 0], LEVELS, &mut rng).unwrap();
    assert_eq!(a.public, b.public);
    assert_eq!(a.output.coefficients, b.output.coefficients);
}

/// The largest auction that fits the ring gives the right result; one more level is refused
/// instead of giving a wrong result.
#[test]
fn each_design_runs_at_its_slot_limit_and_refuses_one_more_level() {
    fn at_limit<D: Design>(design: &D, levels: usize) {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let top = levels as u64 - 1;
        let report = run(design, Profile::Toy, &[top, top], levels, &mut rng).unwrap();
        assert!(report.is_correct(), "{} at {levels} levels", design.name());
        assert!(matches!(
            run(design, Profile::Toy, &[top, top], levels + 1, &mut rng),
            Err(SetupError::NotEnoughSlots { .. })
        ));
    }
    // Toy ring: N = 1024 slots, 2 bidders.
    at_limit(&Rank, 1024 / 6);
    at_limit(&RankBatched, 1024 / 12);
    at_limit(&FirstPrice, 1024 / 2);
    at_limit(&FirstPriceBlind, 1024 / 2);
    at_limit(&SecondPrice, 1024 / 3);
    at_limit(&SecondPriceBlind, 1024 / 3);
    at_limit(&Vickrey, 1024 / 2);
    at_limit(&VickreyCompact, 1024 / 2);
    // The ratio designs do not depend on the bidder count: 1 lane (2 for the second price) for
    // each weight group and level, and the random lane.
    at_limit(&RatioFirstPrice, 1023);
    at_limit(&RatioSecondPrice, 511);
}
