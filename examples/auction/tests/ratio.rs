// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The ratio-lane designs: the price, the tie set, and the winner that the random lane picks.
//!
//! The toy profile has `t = 12289`, so a weight group holds 13 bidders. Bid sets with 14 or more
//! bidders use two or more weight groups.

use auction_designs::designs::group_size;
use auction_designs::designs::LaneReading;
use auction_designs::encoding::inverse;
use auction_designs::{
    run, Design, Output, Profile, RatioFirstPrice, RatioSecondPrice, Report, Setup, SetupError,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const LEVELS: usize = 16;
const T: u64 = 12289;

/// Bid sets with ties at the top and for the second price, in one and in several weight groups.
fn bid_sets() -> Vec<Vec<u64>> {
    // 16 bidders: weight groups 0..13 and 13..16.
    let mut across_groups = vec![4; 16];
    across_groups[2] = 11;
    across_groups[14] = 11;
    let mut top_in_second_group = vec![3; 16];
    top_in_second_group[15] = 12;
    top_in_second_group[1] = 7;
    let mut top_tie_of_three = vec![0; 16];
    for bidder in [0, 12, 13] {
        top_tie_of_three[bidder] = 9;
    }
    vec![
        vec![7, 3, 9, 9],
        vec![9, 9, 3, 7],
        vec![5, 5, 5, 5, 5],
        vec![0, 15],
        vec![15, 0],
        vec![0, 0],
        vec![1, 14, 2, 13, 3, 12, 4, 11],
        across_groups,
        top_in_second_group,
        top_tie_of_three,
    ]
}

fn tie_set(bids: &[u64]) -> Vec<usize> {
    let top = bids.iter().max().unwrap();
    (0..bids.len()).filter(|&k| bids[k] == *top).collect()
}

/// The price, the tie set, and the winner of the random lane must match the plaintext rule, for
/// several mask draws (the random lane differs in each).
fn assert_reads_price_and_tie_set<D: Design>(
    design: &D,
    read: impl Fn(&Setup, &Output) -> Option<LaneReading>,
    price_of: impl Fn(&[u64]) -> u64,
) {
    for (seed, bids) in (0u64..).zip(bid_sets()) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        for _draw in 0..3 {
            let report = run(design, Profile::Toy, &bids, LEVELS, &mut rng).unwrap();
            let reading = read(&report.setup, &report.output)
                .unwrap_or_else(|| panic!("{} on {bids:?}: no reading", design.name()));
            assert_eq!(
                reading.price,
                price_of(&bids),
                "{} on {bids:?}",
                design.name()
            );
            assert_eq!(
                reading.tie_set,
                tie_set(&bids),
                "{} on {bids:?}",
                design.name()
            );
            // The winner is chosen by the random lane, and the report derives its expectation
            // from the sum of the bidder masks.
            assert!(report.is_correct(), "{} on {bids:?}", design.name());
            assert!(reading.tie_set.contains(&reading.winner()));
        }
    }
}

#[test]
fn first_price_shows_the_top_bid_and_the_tie_set() {
    assert_reads_price_and_tie_set(
        &RatioFirstPrice,
        |setup, output| RatioFirstPrice.read(setup, output),
        |bids| *bids.iter().max().unwrap(),
    );
}

#[test]
fn second_price_shows_the_second_highest_bid_and_the_tie_set() {
    assert_reads_price_and_tie_set(
        &RatioSecondPrice,
        |setup, output| RatioSecondPrice.read(setup, output),
        |bids| {
            let mut sorted = bids.to_vec();
            sorted.sort_unstable_by(|a, b| b.cmp(a));
            sorted[1]
        },
    );
}

/// With several tied bidders, the random lane must choose between all of them. Over many auctions
/// each tied bidder wins some, and the winner is always the one that the lane value names.
#[test]
fn every_tied_bidder_can_win() {
    let bids = [9, 3, 9, 9];
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let mut wins = [0usize; 4];
    for _ in 0..24 {
        for report in [
            run(&RatioFirstPrice, Profile::Toy, &bids, LEVELS, &mut rng).unwrap(),
            run(&RatioSecondPrice, Profile::Toy, &bids, LEVELS, &mut rng).unwrap(),
        ] {
            assert!(report.is_correct());
            wins[report.public.winner.unwrap()] += 1;
        }
    }
    assert_eq!(wins[1], 0, "a bidder below the top never wins");
    assert!(wins[0] > 0 && wins[2] > 0 && wins[3] > 0, "wins {wins:?}");
}

/// `n(n-1) < t` bounds the second price, and `n < t` the first price. Both designs give the right
/// result at the largest bidder count that the toy modulus allows, in 9 weight groups.
#[test]
fn bidder_limits_follow_the_plaintext_modulus() {
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let levels = 2;
    let bids = |n: usize| -> Vec<u64> { (0..n as u64).map(|k| u64::from(k % 5 == 0)).collect() };
    // 111 · 110 = 12210 < 12289 ≤ 112 · 111 = 12432.
    let second = run(
        &RatioSecondPrice,
        Profile::Toy,
        &bids(111),
        levels,
        &mut rng,
    )
    .unwrap();
    assert!(second.is_correct());
    assert!(matches!(
        run(
            &RatioSecondPrice,
            Profile::Toy,
            &bids(112),
            levels,
            &mut rng
        ),
        Err(SetupError::PlaintextModulusTooSmall { .. })
    ));
    let first = run(&RatioFirstPrice, Profile::Toy, &bids(112), levels, &mut rng).unwrap();
    assert!(first.is_correct());
    assert_eq!(first.setup.bidders.div_ceil(group_size(&first.setup)), 9);
}

/// Output slots with the lanes of one copy at `(copy · lanes + lane) · levels + level`.
struct Slots {
    levels: usize,
    lanes: usize,
    values: Vec<u64>,
}

impl Slots {
    fn new(setup: &Setup, lanes: usize) -> Self {
        Slots {
            levels: setup.levels,
            lanes,
            values: vec![0; setup.params.degree()],
        }
    }

    fn set(&mut self, copy: usize, lane: usize, level: usize, value: u64) {
        self.values[(copy * self.lanes + lane) * self.levels + level] = value;
    }

    fn set_random(&mut self, copies: usize, value: u64) {
        self.values[copies * self.lanes * self.levels] = value;
    }

    fn output(self) -> Output {
        Output {
            coefficients: vec![],
            slots: self.values,
        }
    }
}

fn toy_setup(bidders: usize, levels: usize) -> Setup {
    Setup::new(Profile::Toy.build(3), bidders, levels)
}

/// The first price reads the bits of every group at the highest non-zero level, below which the
/// lanes are random.
#[test]
fn first_price_decoder_reads_the_group_values_at_the_price() {
    let setup = toy_setup(16, 8);
    let mut slots = Slots::new(&setup, 2);
    // Random lanes below the price; bidders 0 and 12 in group 0, bidder 15 (bit 2) in group 1.
    slots.set(0, 0, 1, 777);
    slots.set(0, 1, 3, 5000);
    slots.set(0, 0, 4, 1 | 1 << 12);
    slots.set(0, 1, 4, 1 << 2);
    slots.set_random(1, 4242);
    let reading = RatioFirstPrice.read(&setup, &slots.output()).unwrap();
    assert_eq!(reading.price, 4);
    assert_eq!(reading.tie_set, [0, 12, 15]);
    assert_eq!(reading.random, 4242);
}

/// A copy whose `R` is zero at the price shows a lower price. The decoder takes the highest price
/// over the copies, and the ratios of every copy that shows it must agree.
#[test]
fn second_price_decoder_takes_the_price_from_the_copies_that_show_it() {
    let setup = toy_setup(16, 8);
    let copies = RatioSecondPrice.copies(&setup);
    assert!(copies >= 3);
    // Lane 0 is `y`, lanes 1 and 2 are `z` of groups 0 and 1. Winner set {1, 2} and {14}.
    let ratios = [0b110, 0b10];
    let build = |wrong_ratio: Option<u64>| {
        let mut slots = Slots::new(&setup, 3);
        // Copy 0: `R = 0` at level 5, random lanes below.
        slots.set(0, 0, 3, 91);
        slots.set(0, 1, 3, 1234);
        // Copies 1 and 2 show level 5 with different factors `R · c`.
        for (copy, y) in [(1, 50u64), (2, 11)] {
            slots.set(copy, 0, 5, y);
            for (group, &correct) in ratios.iter().enumerate() {
                let ratio = wrong_ratio
                    .filter(|_| copy == 2 && group == 0)
                    .unwrap_or(correct);
                slots.set(copy, 1 + group, 5, y * ratio % T);
            }
        }
        slots.set_random(copies, 31);
        slots.output()
    };
    let reading = RatioSecondPrice.read(&setup, &build(None)).unwrap();
    assert_eq!(reading.price, 5);
    assert_eq!(reading.tie_set, [1, 2, 14]);
    assert_eq!(reading.random, 31);
    assert_eq!(RatioSecondPrice.read(&setup, &build(Some(0b1))), None);
}

/// A value that is not a set of group members, and an output without a non-zero lane, give no
/// result instead of a wrong one.
#[test]
fn decoders_refuse_a_group_value_that_is_not_a_member_set() {
    let setup = toy_setup(4, 8);
    // Group 0 has 4 members: bit 4 is no bidder.
    let mut first = Slots::new(&setup, 1);
    first.set(0, 0, 2, 1 << 4);
    assert_eq!(RatioFirstPrice.read(&setup, &first.output()), None);
    assert_eq!(
        RatioFirstPrice.read(&setup, &Slots::new(&setup, 1).output()),
        None
    );

    let mut second = Slots::new(&setup, 2);
    second.set(0, 0, 2, 7);
    second.set(0, 1, 2, 7 << 4);
    assert_eq!(RatioSecondPrice.read(&setup, &second.output()), None);
    // `y ≠ 0` with a zero ratio: no bidder is in the set.
    let mut empty = Slots::new(&setup, 2);
    empty.set(0, 0, 2, 7);
    assert_eq!(RatioSecondPrice.read(&setup, &empty.output()), None);
}

/// What the output fixes and what it leaves uniform, for one slot of a lane.
#[derive(Debug, PartialEq, Eq)]
enum Cell {
    Zero,
    Exact(u64),
    Uniform(u64),
}

/// Classifies every lane slot of `report` from its price. Above the price a slot is 0, at the price
/// it is exact (FP: the group value; SP: the ratio `z / y`, while `y` is uniform), and below the
/// price it is uniform (SP: also the ratio).
fn cells(report: &Report, second_price: bool) -> Vec<Cell> {
    let setup = &report.setup;
    let levels = setup.levels;
    let groups = setup.bidders.div_ceil(group_size(setup));
    let price = report.public.price.unwrap() as usize;
    let slots = &report.output.slots;
    let (lanes, copies) = if second_price {
        let lanes = 1 + groups;
        (lanes, RatioSecondPrice.copies(setup))
    } else {
        (groups, 1)
    };
    let slot =
        |copy: usize, lane: usize, level: usize| slots[(copy * lanes + lane) * levels + level];
    let mut cells = Vec::new();
    for copy in 0..copies {
        for lane in 0..lanes {
            for level in 0..levels {
                let value = slot(copy, lane, level);
                // The second price shows a `z` lane as its ratio to `y`: the factor `R · c` of
                // the lane pair drops out.
                let shown = if second_price && lane > 0 {
                    let y = slot(copy, 0, level);
                    if y == 0 {
                        0
                    } else {
                        value * inverse(y, T) % T
                    }
                } else {
                    value
                };
                cells.push(if level > price {
                    assert_eq!(value, 0, "copy {copy} lane {lane} level {level}");
                    Cell::Zero
                } else if level < price || (second_price && lane == 0) {
                    Cell::Uniform(shown)
                } else {
                    Cell::Exact(shown)
                });
            }
        }
    }
    cells.push(Cell::Uniform(slots[copies * lanes * levels]));
    cells
}

/// The part of the output that bids can change: the zero slots and the ratios.
fn fixed(cells: &[Cell]) -> Vec<Option<&Cell>> {
    cells
        .iter()
        .map(|cell| (!matches!(cell, Cell::Uniform(_))).then_some(cell))
        .collect()
}

/// The output must be a function of the price, the tie set, and the random lane only: bid sets
/// with the same price and tie set give the same zero slots and the same exact values, and the
/// other slots are fresh uniform values, also for the same bids.
fn assert_output_depends_only_on_price_and_tie_set<D: Design>(
    design: &D,
    second_price: bool,
    same_result: &[&[u64]],
    other_tie_set: &[u64],
    other_price: &[u64],
) {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    let mut run_on = |bids: &[u64]| run(design, Profile::Toy, bids, LEVELS, &mut rng).unwrap();
    let reports: Vec<Report> = same_result.iter().map(|bids| run_on(bids)).collect();
    let reference = cells(&reports[0], second_price);
    for report in &reports {
        assert_eq!(
            report.public,
            reports[0].public,
            "{} on {:?}",
            design.name(),
            report.bids
        );
        assert_eq!(
            fixed(&cells(report, second_price)),
            fixed(&reference),
            "{} on {:?}",
            design.name(),
            report.bids
        );
    }
    assert_ne!(
        fixed(&cells(&run_on(other_tie_set), second_price)),
        fixed(&reference)
    );
    assert_ne!(
        fixed(&cells(&run_on(other_price), second_price)),
        fixed(&reference)
    );

    // Fresh masks: the same bids with other masks leave the uniform slots different. A missing
    // mask would leave them equal (a function of the bids).
    let again = cells(&run_on(same_result[0]), second_price);
    let uniform: Vec<_> = reference
        .iter()
        .zip(&again)
        .filter_map(|pair| match pair {
            (Cell::Uniform(a), Cell::Uniform(b)) => Some(a == b),
            _ => None,
        })
        .collect();
    let equal = uniform.iter().filter(|&&same| same).count();
    assert!(!uniform.is_empty());
    assert!(
        equal * 100 <= uniform.len(),
        "{equal} of {} uniform slots repeat",
        uniform.len()
    );
}

#[test]
fn first_price_output_depends_only_on_the_price_and_the_tie_set() {
    // Price 9, tie set {1}: the losing bids and their counts differ.
    assert_output_depends_only_on_price_and_tie_set(
        &RatioFirstPrice,
        false,
        &[&[3, 9, 2, 5], &[0, 9, 8, 1], &[1, 9, 0, 0], &[8, 9, 8, 8]],
        &[9, 9, 2, 5],
        &[3, 10, 2, 5],
    );
}

#[test]
fn second_price_output_depends_only_on_the_price_and_the_tie_set() {
    // Price 9, tie set {1}: the winning bid, the runner-up count, and the others differ.
    assert_output_depends_only_on_price_and_tie_set(
        &RatioSecondPrice,
        true,
        &[
            &[3, 12, 9, 9],
            &[9, 15, 2, 9],
            &[9, 10, 9, 0],
            &[9, 11, 9, 9],
        ],
        &[9, 9, 3, 5],
        &[3, 12, 8, 2],
    );
}
