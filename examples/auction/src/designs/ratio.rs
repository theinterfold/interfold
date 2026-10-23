// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Ratio-lane (RL) auctions: first price and second price with a price range that does not
//! depend on the number of bidders. The output shows the price and the tie set (the bidders whose
//! bid equals the price). A random value that nobody controls picks the winner from the tie set.
//!
//! The vickrey design needs one region of `B` slots for each bidder, so `n · B ≤ N`. The RL
//! designs do not test each bidder in its own region. They give the winner as a value at one
//! lane of the price level. A lane is one SIMD slot position at one level.
//!
//! # Weights
//!
//! `W` is the largest number with `2^W ≤ t`. Bidder `k` is in weight group `⌊k / W⌋` and has the
//! weight `2^(k mod W)`. The sum of the weights of a group is below `t`, so a group sum shows the
//! set of its members bit by bit. There are `g = ⌈n / W⌉` groups.
//!
//! # First price
//!
//! Below, `ge_k[p] = [b_k ≥ p]`, `gt_k[p] = [b_k > p]`, `A = Σ gt_k`, and `m` is the sum of the
//! bidder masks. A mask is uniform in every slot. Each level `p` has one lane for each group `γ`:
//!
//! ```text
//! out_γ[p] = Σ_{k ∈ γ} w_k · ge_k[p] + m_γ[p] · A[p]          1 ct×ct, depth 1
//! ```
//!
//! - `p > max`: 0, because no bid is at or above `p`.
//! - `p = max`: `A = 0`, so the lane is `Σ_{k ∈ T ∩ γ} w_k`. `T` is the tie set.
//! - `p < max`: `A ≥ 1`, so the lane is uniform.
//!
//! The decoder takes the highest level with a non-zero lane as the price, and reads `T` from the
//! bits of the group values at that level. The price lane has no mask, so this design has no error
//! probability and uses one copy.
//!
//! # Second price
//!
//! Each level has one `y` lane and one `z_γ` lane for each group. With `C = Σ ge_k`,
//! `G_γ = Σ_{k ∈ γ} w_k · gt_k`, and `E_γ = Σ_{k ∈ γ} w_k · (ge_k − gt_k)`:
//!
//! ```text
//! c   = C (C − 1)            u   = A (A − 1)            L_γ = G_γ + (1 − A) · E_γ
//! y   = R · c        + m_y  · u
//! z_γ = R · c · L_γ  + m_zγ · u                           6 ct×ct, depth 3
//! ```
//!
//! `R` is the sum of the pair masks. A pair mask has the same value in the `y` lane and in every
//! `z` lane of one level and copy. With `s` the second-highest bid (the top bid on a top tie):
//!
//! - `p > s`: `C ≤ 1` and `A ≤ 1`, so `c = u = 0` and the lanes are 0.
//! - `p = s`: `u = 0`, so the lanes are `(R·c, R·c·L_γ)`. With a unique top bidder, `L_γ` is the
//!   weight of the top bidder in its group and 0 in the other groups. On a top tie, `L_γ` is
//!   `Σ_{k ∈ T ∩ γ} w_k`. The ratio `z_γ / y = L_γ` shows this and hides the factor `R·c`.
//! - `p < s`: `A ≥ 2`, so `u ≠ 0` (this needs `n (n − 1) < t`). The lanes are uniform and
//!   independent.
//!
//! `R·c` is zero by error when `R` is zero at level `s`: probability `1/t` for each copy. Spare
//! slots hold copies of the lanes under independent `R`. The decoder takes the highest price over
//! the copies, so the error is `t^-copies`.
//!
//! # Random lane and ties
//!
//! One slot outside every lane holds `m` at that slot. It is uniform if one bidder mask is
//! honest, and it is fixed by the encrypted masks, so no bidder can predict it or grind it
//! after it sees the other bids. The winner is `T_sorted[random mod |T|]`, with `T` sorted by
//! bidder index.

use super::{check_capacity, Design, Output, PriceRule, PublicResult, Setup, SetupError};
use crate::encoding::{constant_slots, inverse, ones_in, simd};
use crate::evaluator::Evaluator;
use fhe::bfv::{Ciphertext, Plaintext};
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};

/// First price with ratio lanes. Inputs: `[b ≥ p]`, `[b > p]`, and a mask (3 ciphertexts).
/// Depth 1.
pub struct RatioFirstPrice;

/// Second price with ratio lanes. Inputs: `[b ≥ p]`, `[b > p]`, a mask, and a pair mask (4
/// ciphertexts). Depth 3.
pub struct RatioSecondPrice;

/// What the decrypted output of an RL design shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneReading {
    /// The price level.
    pub price: u64,
    /// The bidders whose bid equals the top bid, ascending.
    pub tie_set: Vec<usize>,
    /// The value of the random lane.
    pub random: u64,
}

impl LaneReading {
    /// The winner: `tie_set[random mod |tie_set|]`.
    pub fn winner(&self) -> usize {
        self.tie_set[(self.random % self.tie_set.len() as u64) as usize]
    }

    fn result(reading: Option<Self>) -> PublicResult {
        PublicResult {
            winner: reading.as_ref().map(Self::winner),
            price: reading.map(|reading| reading.price),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    First,
    Second,
}

/// Where the lanes are. A copy has `lanes` blocks of `levels` slots each. The slot of lane `j` at
/// level `p` in copy `c` is `(c · lanes + j) · levels + p`. The random lane is the slot behind the
/// last copy.
struct Layout {
    levels: usize,
    lanes: usize,
    copies: usize,
    groups: usize,
}

impl Layout {
    fn new(setup: &Setup, kind: Kind) -> Self {
        let groups = setup.bidders.div_ceil(group_size(setup));
        let lanes = match kind {
            Kind::First => groups,
            Kind::Second => 1 + groups,
        };
        let fit = (setup.params.degree() - 1) / (lanes * setup.levels);
        Layout {
            levels: setup.levels,
            lanes,
            groups,
            copies: match kind {
                Kind::First => fit.min(1),
                Kind::Second => fit,
            },
        }
    }

    fn slot(&self, copy: usize, lane: usize, level: usize) -> usize {
        (copy * self.lanes + lane) * self.levels + level
    }

    fn random_slot(&self) -> usize {
        self.copies * self.lanes * self.levels
    }

    /// The lane that holds the group `group` values: `z_γ` has lane `1 + γ` in the second price.
    fn group_lane(&self, kind: Kind, group: usize) -> usize {
        match kind {
            Kind::First => group,
            Kind::Second => 1 + group,
        }
    }
}

/// `W`: bidders in a full weight group. `2^W ≤ t` makes every group sum `2^W − 1` less than `t`.
pub fn group_size(setup: &Setup) -> usize {
    setup.params.plaintext().ilog2() as usize
}

fn weight(setup: &Setup, bidder: usize) -> u64 {
    1 << (bidder % group_size(setup))
}

/// The number of bidders in weight group `group`.
fn members(setup: &Setup, group: usize) -> usize {
    let size = group_size(setup);
    (setup.bidders - group * size).min(size)
}

/// The thermometers `[b ≥ p]` and `[b > p]` in every lane of every copy. The slots outside the
/// lanes, the random lane included, are 0.
fn thermometers(setup: &Setup, layout: &Layout, bid: usize) -> (Vec<u64>, Vec<u64>) {
    let (mut at_least, mut above) = (
        vec![0u64; setup.params.degree()],
        vec![0u64; setup.params.degree()],
    );
    for copy in 0..layout.copies {
        for lane in 0..layout.lanes {
            let start = layout.slot(copy, lane, 0);
            at_least[start..=start + bid].fill(1);
            above[start..start + bid].fill(1);
        }
    }
    (at_least, above)
}

/// The weight plaintext of `bidder`: its weight in the lane of its group in every copy.
fn weights_of(setup: &Setup, layout: &Layout, kind: Kind, bidder: usize) -> Plaintext {
    let lane = layout.group_lane(kind, bidder / group_size(setup));
    let mut slots = vec![0u64; setup.params.degree()];
    for copy in 0..layout.copies {
        let start = layout.slot(copy, lane, 0);
        slots[start..start + layout.levels].fill(weight(setup, bidder));
    }
    simd(&setup.params, &slots)
}

/// The unit vector of the random lane.
fn random_unit(setup: &Setup, layout: &Layout) -> Plaintext {
    let slot = layout.random_slot();
    ones_in(&setup.params, std::iter::once(slot..slot + 1))
}

/// The submission of a bidder: the thermometers, a mask, and for the second price a pair mask.
/// The secret is the mask value at the random lane.
fn submit_slots<R: RngCore + CryptoRng>(
    setup: &Setup,
    layout: &Layout,
    kind: Kind,
    bid: u64,
    public_key: &LBFVPublicKey,
    rng: &mut R,
) -> (Vec<Ciphertext>, u64) {
    let (degree, t) = (setup.params.degree(), setup.params.plaintext());
    let (at_least, above) = thermometers(setup, layout, bid as usize);
    let mask: Vec<u64> = (0..degree).map(|_| rng.random_range(0..t)).collect();
    let secret = mask[layout.random_slot()];
    let mut plaintexts = vec![at_least, above, mask];
    if kind == Kind::Second {
        plaintexts.push(pair_mask(layout, degree, t, rng));
    }
    let ciphertexts = plaintexts
        .iter()
        .map(|slots| {
            public_key
                .try_encrypt(&simd(&setup.params, slots), rng)
                .expect("encryption under a valid key")
        })
        .collect();
    (ciphertexts, secret)
}

/// A uniform value for each (copy, level), the same in every lane of that copy and level.
fn pair_mask<R: RngCore>(layout: &Layout, degree: usize, t: u64, rng: &mut R) -> Vec<u64> {
    let mut slots = vec![0u64; degree];
    for copy in 0..layout.copies {
        for level in 0..layout.levels {
            let value = rng.random_range(0..t);
            for lane in 0..layout.lanes {
                slots[layout.slot(copy, lane, level)] = value;
            }
        }
    }
    slots
}

fn sum<'a>(cts: impl IntoIterator<Item = &'a Ciphertext>) -> Ciphertext {
    cts.into_iter()
        .cloned()
        .reduce(|acc, ct| &acc + &ct)
        .expect("check() requires two or more bidders")
}

/// `Σ_k w_k · ct_k` with the weights in the lane of the group of bidder `k`: `n` ct×pt.
fn weighted_sum<'a>(
    setup: &Setup,
    layout: &Layout,
    kind: Kind,
    cts: impl Iterator<Item = &'a Ciphertext>,
    evaluator: &Evaluator,
) -> Ciphertext {
    let products: Vec<Ciphertext> = cts
        .enumerate()
        .map(|(bidder, ct)| evaluator.mul_plain(ct, &weights_of(setup, layout, kind, bidder)))
        .collect();
    sum(&products)
}

/// The bits of `value` as bidder indices of `group`. `None` if `value` has a bit outside the
/// group, or no bit.
fn bidders_of(setup: &Setup, group: usize, value: u64) -> Option<Vec<usize>> {
    let size = group_size(setup);
    (value >> members(setup, group) == 0).then(|| {
        (0..members(setup, group))
            .filter(|bit| value >> bit & 1 == 1)
            .map(|bit| group * size + bit)
            .collect()
    })
}

/// The tie set from the group values `values[γ]`. `None` if a value is not a set of members of its
/// group, or the set is empty.
fn tie_set(setup: &Setup, values: &[u64]) -> Option<Vec<usize>> {
    let mut set = Vec::new();
    for (group, &value) in values.iter().enumerate() {
        set.extend(bidders_of(setup, group, value)?);
    }
    (!set.is_empty()).then_some(set)
}

/// The tie set of plaintext bids, ascending.
fn top_set(bids: &[u64]) -> Vec<usize> {
    let top = bids.iter().max().expect("an auction has bidders");
    (0..bids.len()).filter(|&k| bids[k] == *top).collect()
}

fn mul_mod(a: u64, b: u64, t: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(t)) as u64
}

fn check(setup: &Setup, kind: Kind) -> Result<(), SetupError> {
    let layout = Layout::new(setup, kind);
    let needed = layout.lanes * setup.levels + 1;
    // The first price needs `A ≠ 0 mod t` when `A ≥ 1`: `n < t`. The second price needs
    // `u = A (A − 1) ≠ 0 mod t` when `A ≥ 2`: `n (n − 1) < t`.
    let values = match kind {
        Kind::First => setup.bidders,
        Kind::Second => setup.bidders * (setup.bidders - 1),
    } as u64;
    check_capacity(setup, needed, values + 1)
}

/// The expected result on plaintext bids: the price, the tie set, and the winner that the random
/// lane `Σ mask` picks.
fn expected(setup: &Setup, bids: &[u64], masks: &[u64], rule: PriceRule) -> PublicResult {
    let mut sorted = bids.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let price = match rule {
        PriceRule::First => sorted[0],
        PriceRule::Second => sorted[1],
        PriceRule::None => unreachable!("the RL designs have a price"),
    };
    let t = setup.params.plaintext();
    let random = masks.iter().fold(0, |acc, &mask| (acc + mask) % t);
    LaneReading::result(Some(LaneReading {
        price,
        tie_set: top_set(bids),
        random,
    }))
}

impl RatioFirstPrice {
    /// The price, the tie set, and the random lane. `None` when the output does not decode.
    pub fn read(&self, setup: &Setup, output: &Output) -> Option<LaneReading> {
        let layout = Layout::new(setup, Kind::First);
        let at = |lane, level| output.slots[layout.slot(0, lane, level)];
        let price = (0..setup.levels)
            .rev()
            .find(|&level| (0..layout.groups).any(|lane| at(lane, level) != 0))?;
        let values: Vec<u64> = (0..layout.groups).map(|lane| at(lane, price)).collect();
        Some(LaneReading {
            price: price as u64,
            tie_set: tie_set(setup, &values)?,
            random: output.slots[layout.random_slot()],
        })
    }
}

impl RatioSecondPrice {
    /// The number of copies of the lanes that fit the ring.
    pub fn copies(&self, setup: &Setup) -> usize {
        Layout::new(setup, Kind::Second).copies
    }

    /// The price, the tie set, and the random lane. `None` when the output does not decode, or
    /// the copies that fix the price disagree.
    pub fn read(&self, setup: &Setup, output: &Output) -> Option<LaneReading> {
        let layout = Layout::new(setup, Kind::Second);
        let t = setup.params.plaintext();
        let at = |copy, lane, level| output.slots[layout.slot(copy, lane, level)];
        let last = |copy| {
            (0..setup.levels)
                .rev()
                .find(|&level| at(copy, 0, level) != 0)
        };
        let price = (0..layout.copies).filter_map(last).max()?;
        // The ratios `z_γ / y` of each copy that shows the price. They must agree.
        let mut ratios: Vec<Vec<u64>> = (0..layout.copies)
            .filter(|&copy| at(copy, 0, price) != 0)
            .map(|copy| {
                let inverse = inverse(at(copy, 0, price), t);
                (0..layout.groups)
                    .map(|group| {
                        mul_mod(
                            at(copy, layout.group_lane(Kind::Second, group), price),
                            inverse,
                            t,
                        )
                    })
                    .collect()
            })
            .collect();
        let values = ratios.pop()?;
        ratios.iter().all(|other| *other == values).then_some(())?;
        Some(LaneReading {
            price: price as u64,
            tie_set: tie_set(setup, &values)?,
            random: output.slots[layout.random_slot()],
        })
    }

    /// The SIMD slot values of the 3 bid ciphertexts of `bid` that depend on the bid, without the
    /// masks: `[b ≥ p]`, `[b > p]`. `submit` encrypts exactly these.
    pub fn bid_slots(&self, setup: &Setup, bid: u64) -> Vec<Vec<u64>> {
        let (at_least, above) =
            thermometers(setup, &Layout::new(setup, Kind::Second), bid as usize);
        vec![at_least, above]
    }
}

impl Design for RatioFirstPrice {
    type Secret = u64;

    fn name(&self) -> &'static str {
        "rl-first-price"
    }

    fn disclosure(&self) -> &'static str {
        "winning bid and the tie set, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::First
    }

    fn readout(&self) -> &'static str {
        "reads the group values at the highest non-zero level, and the random lane"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        1
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        check(setup, Kind::First)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        // The submission does not depend on the index: the program applies the weights.
        _index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, u64) {
        let layout = Layout::new(setup, Kind::First);
        submit_slots(setup, &layout, Kind::First, bid, public_key, rng)
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let layout = Layout::new(setup, Kind::First);
        let weighted = weighted_sum(
            setup,
            &layout,
            Kind::First,
            submissions.iter().map(|s| &s[0]),
            evaluator,
        );
        let above = sum(submissions.iter().map(|s| &s[1]));
        let masks = sum(submissions.iter().map(|s| &s[2]));
        // `m · (A + e)`: the unit `e` at the random lane makes that lane `m`.
        let blind = evaluator.mul(&masks, &(&above + &random_unit(setup, &layout)));
        &weighted + &blind
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        LaneReading::result(self.read(setup, output))
    }

    fn expected(&self, setup: &Setup, bids: &[u64], secrets: &[u64]) -> PublicResult {
        expected(setup, bids, secrets, PriceRule::First)
    }

    fn tie_note(&self, setup: &Setup, output: &Output) -> Option<String> {
        self.read(setup, output).map(|reading| note(&reading))
    }
}

impl Design for RatioSecondPrice {
    type Secret = u64;

    fn name(&self) -> &'static str {
        "rl-second-price"
    }

    fn disclosure(&self) -> &'static str {
        "second-highest bid and the tie set, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::Second
    }

    fn readout(&self) -> &'static str {
        "reads the ratios z / y at the highest level with y ≠ 0, and the random lane"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        3
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        check(setup, Kind::Second)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        _index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, u64) {
        let layout = Layout::new(setup, Kind::Second);
        submit_slots(setup, &layout, Kind::Second, bid, public_key, rng)
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let layout = Layout::new(setup, Kind::Second);
        let kind = Kind::Second;
        let params = &setup.params;
        let one = constant_slots(params, 1);
        let at_least = sum(submissions.iter().map(|s| &s[0]));
        let above = sum(submissions.iter().map(|s| &s[1]));
        let masks = sum(submissions.iter().map(|s| &s[2]));
        let pair_masks = sum(submissions.iter().map(|s| &s[3]));

        // Level 1: `c = C (C − 1)`, `u = A (A − 1)`, and `L = G + (1 − A) · E`.
        let c = evaluator.mul(&at_least, &(&at_least - &one));
        let u = evaluator.mul(&above, &(&above - &one));
        let weighted_ge = weighted_sum(
            setup,
            &layout,
            kind,
            submissions.iter().map(|s| &s[0]),
            evaluator,
        );
        let weighted_gt = weighted_sum(
            setup,
            &layout,
            kind,
            submissions.iter().map(|s| &s[1]),
            evaluator,
        );
        let ties = &weighted_ge - &weighted_gt;
        let not_above = &(-&above) + &one;
        let l = &weighted_gt + &evaluator.mul(&not_above, &ties);
        // The `y` lanes hold the factor 1 where the `z` lanes hold `L`.
        let y_lanes = ones_in(
            params,
            (0..layout.copies).map(|copy| layout.slot(copy, 0, 0)..layout.slot(copy, 1, 0)),
        );
        let l = &l + &y_lanes;

        // Level 2: `R · c`, and `m · (u + e)`. Level 3: `(R · c) · L`.
        let signal = evaluator.mul(&evaluator.mul(&pair_masks, &c), &l);
        let blind = evaluator.mul(&masks, &(&u + &random_unit(setup, &layout)));
        &signal + &blind
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        LaneReading::result(self.read(setup, output))
    }

    fn expected(&self, setup: &Setup, bids: &[u64], secrets: &[u64]) -> PublicResult {
        expected(setup, bids, secrets, PriceRule::Second)
    }

    fn tie_note(&self, setup: &Setup, output: &Output) -> Option<String> {
        self.read(setup, output).map(|reading| note(&reading))
    }
}

fn note(reading: &LaneReading) -> String {
    format!(
        "tie set {:?}, random lane {}, winner = tie set[{} mod {}]",
        reading.tie_set,
        reading.random,
        reading.random,
        reading.tie_set.len()
    )
}
