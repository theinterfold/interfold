// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Second-price (Vickrey) auction with 4 ct×ct products for any number of bidders. The output
//! shows the winner and the second-highest bid only.
//!
//! The slots hold one region of `B` slots for each candidate winner. Region `k` belongs to the
//! bidder with tie priority `k` ([`Setup::tie_priority`]); below, `b_k` is the bid of that bidder.
//! Slot `p` of region `k` tests whether that bidder beats every other bidder at level `p`:
//!
//! ```text
//! g_k[p] = #{j ≠ k : b_j > p} + [b_k < p] + [b_k = p] · #{j > k : b_j = p}
//! ```
//!
//! `g_k[p] = 0` exactly when no other bid is above `p`, `b_k ≥ p`, and no higher priority ties
//! `k` at `p`. The program outputs `g · c'(c' - 1) · r`, where `c'[p] = #{j : b_j ≥ p}` and `r`
//! is the sum of the bidder masks. With `s` the second-highest bid:
//!
//! - `p < s`: two or more bids are above `p`, so `g ≥ 1` and `c' ≥ 2`. The slot is uniform.
//! - `p = s`: `c' ≥ 2`, and `g = 0` only in the region of the winner (ties go to the higher
//!   priority). The slot is 0 for the winner and uniform for all other regions.
//! - `p > s`: one bid or none is at or above `p`, so `c'(c' - 1) = 0`. The slot is 0.
//!
//! Thus the output is a function of the winner and `s` only, plus uniform values. It does not
//! show the winning bid, the runner-up, any count, or a tie.
//!
//! Each bidder sends 3 ciphertexts that do not depend on its index: the thermometers `[b ≥ p]`
//! and `[b > p]`, copied into every region, and a mask. Their difference is the one-hot
//! `[b = p]`. The program places the own-region and tie-break terms with plaintext selectors
//! (ct×pt). Thus the tie priority can be drawn at random after the bids close, at no cost, and
//! a tie goes to a random tied bidder. A bid proof shows only that the two thermometers come from
//! one bid `b`. The mask needs no shape proof.
//!
//! Spare slots hold copies of the regions under independent mask values. A slot reads as zero
//! by error only when it is zero in every copy, with probability `t^-copies`.

use super::{check_capacity, Design, Output, PriceRule, PublicResult, Setup, SetupError};
use crate::encoding::{constant_slots, evaluate, ones_in, simd, slot_points};
use crate::evaluator::Evaluator;
use fhe::bfv::Ciphertext;
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};

/// Inputs: the thermometers `[b ≥ p]` and `[b > p]`, and a mask (3 ciphertexts). Depth 3.
pub struct Vickrey;

/// Inputs: one bid ciphertext `[b ≥ p] + [b = p]` (values 0, 1, 2), and a mask (2 ciphertexts).
/// The program squares each bid ciphertext to get both thermometers: `n` more ct×ct, depth 4.
pub struct VickreyCompact;

/// The slots of one copy: one region of `B` slots for each bidder.
fn copy_size(setup: &Setup) -> usize {
    setup.bidders * setup.levels
}

/// The number of copies of the regions that fit the ring.
pub fn copies(setup: &Setup) -> usize {
    setup.params.degree() / copy_size(setup)
}

fn slot(setup: &Setup, copy: usize, region: usize, level: usize) -> usize {
    copy * copy_size(setup) + region * setup.levels + level
}

/// The level of SIMD slot `index`, or `None` for a slot beyond the last copy. Every region of every
/// copy holds the same bid plaintext, so a bid proof needs only this map from slots to levels.
pub fn slot_level(setup: &Setup, index: usize) -> Option<usize> {
    (index < copies(setup) * copy_size(setup)).then(|| index % setup.levels)
}

/// Whether slot `level` of `region` is non-zero in one or more copies.
fn is_set(setup: &Setup, slots: &[u64], region: usize, level: usize) -> bool {
    (0..copies(setup)).any(|copy| slots[slot(setup, copy, region, level)] != 0)
}

/// The thermometers `[b ≥ p]` and `[b > p]` in every region of every copy.
fn thermometers(setup: &Setup, bid: usize) -> (Vec<u64>, Vec<u64>) {
    let degree = setup.params.degree();
    let (mut at_least, mut above) = (vec![0u64; degree], vec![0u64; degree]);
    for copy in 0..copies(setup) {
        for region in 0..setup.bidders {
            let start = slot(setup, copy, region, 0);
            at_least[start..=start + bid].fill(1);
            above[start..start + bid].fill(1);
        }
    }
    (at_least, above)
}

/// The slots of the one bid ciphertext of `VickreyCompact`: `[b ≥ p] + [b = p]` = `2 · [b ≥ p] - [b > p]`.
fn compact_slots(setup: &Setup, bid: usize) -> Vec<u64> {
    let (at_least, above) = thermometers(setup, bid);
    at_least
        .iter()
        .zip(&above)
        .map(|(&ge, &gt)| 2 * ge - gt)
        .collect()
}

fn encrypt_all<R: RngCore + CryptoRng>(
    setup: &Setup,
    plaintexts: &[Vec<u64>],
    public_key: &LBFVPublicKey,
    rng: &mut R,
) -> Vec<Ciphertext> {
    let t = setup.params.plaintext();
    let mask: Vec<u64> = (0..setup.params.degree())
        .map(|_| rng.random_range(0..t))
        .collect();
    plaintexts
        .iter()
        .chain([&mask])
        .map(|slots| {
            public_key
                .try_encrypt(&simd(&setup.params, slots), rng)
                .expect("encryption under a valid key")
        })
        .collect()
}

fn sum(cts: Vec<Ciphertext>) -> Ciphertext {
    cts.into_iter()
        .reduce(|acc, ct| &acc + &ct)
        .expect("check() requires two or more bidders")
}

/// The program after the bids are thermometers: `g · c'(c' - 1) · r`, 4 ct×ct at depth 3 above
/// the depth of the inputs. `bids[j]` is `([b_j ≥ p], [b_j > p])`.
fn tests_under_mask(
    setup: &Setup,
    bids: &[(Ciphertext, Ciphertext)],
    masks: Ciphertext,
    evaluator: &Evaluator,
) -> Ciphertext {
    let params = &setup.params;
    let copies = 0..copies(setup);
    // Region r: its own slots, and the slots of the regions below it (r wins a tie there).
    let own = |r: usize| {
        ones_in(
            params,
            copies
                .clone()
                .map(|c| slot(setup, c, r, 0)..slot(setup, c, r + 1, 0)),
        )
    };
    let lower = |r: usize| {
        ones_in(
            params,
            copies
                .clone()
                .map(|c| slot(setup, c, 0, 0)..slot(setup, c, r, 0)),
        )
    };
    let (mut own_at_least, mut own_above, mut ties_above) = (vec![], vec![], vec![]);
    for (j, (at_least, above)) in bids.iter().enumerate() {
        let region = setup.tie_priority[j];
        let selector = own(region);
        own_at_least.push(evaluator.mul_plain(at_least, &selector));
        own_above.push(evaluator.mul_plain(above, &selector));
        ties_above.push(evaluator.mul_plain(&(at_least - above), &lower(region)));
    }
    let own_at_least = sum(own_at_least);
    let own_above = sum(own_above);
    let at_least = sum(bids.iter().map(|b| b.0.clone()).collect());
    let above = sum(bids.iter().map(|b| b.1.clone()).collect());

    let one = constant_slots(params, 1);
    // [b_k = p] · #{j > k : b_j = p} in region k.
    let ties = evaluator.mul(&(&own_at_least - &own_above), &sum(ties_above));
    // #{j ≠ k : b_j > p} + [b_k < p] + ties.
    let others_above = &above - &own_above;
    let beaten = &(&(&others_above + &one) - &own_at_least) + &ties;
    let two_at_least = evaluator.mul(&at_least, &(&at_least - &one));
    let tests = evaluator.mul(&beaten, &two_at_least);
    evaluator.mul(&tests, &masks)
}

fn decode_pattern(setup: &Setup, output: &Output) -> PublicResult {
    let (n, levels) = (setup.bidders, setup.levels);
    // Loser regions are non-zero on 0..=s, the winner region on 0..s.
    let last = |region| {
        (0..levels)
            .rev()
            .find(|&level| is_set(setup, &output.slots, region, level))
    };
    let Some(price) = (0..n).filter_map(last).max() else {
        // Only when every loser slot `s` reads as zero by error.
        return PublicResult {
            winner: None,
            price: None,
        };
    };
    let winners: Vec<usize> = (0..n)
        .filter(|&region| !is_set(setup, &output.slots, region, price))
        .collect();
    let bidder = |region| setup.tie_priority.iter().position(|&r| r == region);
    PublicResult {
        winner: match winners[..] {
            [region] => bidder(region),
            _ => None,
        },
        price: Some(price as u64),
    }
}

/// The check that a contract runs on a claimed result, with 1 to `2 · copies + 1` slot
/// evaluations of N multiplications mod t each:
///
/// 1. Slot `s` of the winner region is zero.
/// 2. Slot `s - 1` of the winner region is non-zero (when `s > 0`).
/// 3. Slot `s` of one other region is non-zero.
///
/// Check 2 refuses a lower price, and check 3 refuses a loser that claims price `s + 1`.
fn verify_claim(setup: &Setup, coefficients: &[u64], claim: PublicResult) -> bool {
    let (Some(winner), Some(price)) = (claim.winner, claim.price) else {
        return false;
    };
    let (n, price) = (setup.bidders, price as usize);
    if winner >= n || price >= setup.levels {
        return false;
    }
    let region = setup.tie_priority[winner];
    let (t, points) = (setup.params.plaintext(), slot_points(&setup.params));
    let at =
        |copy, region, level| evaluate(coefficients, points[slot(setup, copy, region, level)], t);
    let set = |region, level| (0..copies(setup)).any(|copy| at(copy, region, level) != 0);
    at(0, region, price) == 0
        && (price == 0 || set(region, price - 1))
        && set((region + 1) % n, price)
}

impl Vickrey {
    /// The SIMD slot values of the 2 bid ciphertexts, `[b ≥ p]` and `[b > p]`, without the mask.
    /// `submit` encrypts exactly these.
    pub fn bid_slots(&self, setup: &Setup, bid: u64) -> Vec<Vec<u64>> {
        let (at_least, above) = thermometers(setup, bid as usize);
        vec![at_least, above]
    }

    /// See [`verify_claim`].
    pub fn verify(&self, setup: &Setup, coefficients: &[u64], claim: PublicResult) -> bool {
        verify_claim(setup, coefficients, claim)
    }
}

impl VickreyCompact {
    /// The SIMD slot values of the bid ciphertext, `2 · [b ≥ p] - [b > p]`, without the mask.
    /// `submit` encrypts exactly these.
    pub fn bid_slots(&self, setup: &Setup, bid: u64) -> Vec<Vec<u64>> {
        vec![compact_slots(setup, bid as usize)]
    }

    /// See [`verify_claim`].
    pub fn verify(&self, setup: &Setup, coefficients: &[u64], claim: PublicResult) -> bool {
        verify_claim(setup, coefficients, claim)
    }
}

impl Design for Vickrey {
    type Secret = ();

    fn name(&self) -> &'static str {
        "vickrey"
    }

    fn disclosure(&self) -> &'static str {
        "winner and second-highest bid, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::Second
    }

    fn readout(&self) -> &'static str {
        "checks a claim at 3 slot points: 3 · N multiplications mod t"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        3
    }

    fn random_tie_order(&self) -> bool {
        true
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        // g ≤ 2n - 1 and c' ≤ n must be non-zero mod t when they are non-zero.
        check_capacity(setup, copy_size(setup), 2 * setup.bidders as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        // The submission does not depend on the index: the program applies it.
        _index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, ()) {
        (
            encrypt_all(setup, &self.bid_slots(setup, bid), public_key, rng),
            (),
        )
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let bids: Vec<_> = submissions
            .iter()
            .map(|s| (s[0].clone(), s[1].clone()))
            .collect();
        let masks = sum(submissions.iter().map(|s| s[2].clone()).collect());
        tests_under_mask(setup, &bids, masks, evaluator)
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        decode_pattern(setup, output)
    }
}

impl Design for VickreyCompact {
    type Secret = ();

    fn name(&self) -> &'static str {
        "vickrey-compact"
    }

    fn disclosure(&self) -> &'static str {
        "winner and second-highest bid, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::Second
    }

    fn readout(&self) -> &'static str {
        "checks a claim at 3 slot points: 3 · N multiplications mod t"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        4
    }

    fn random_tie_order(&self) -> bool {
        true
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        Vickrey.check(setup)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        _index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, ()) {
        // 1 below the bid, 2 at the bid, 0 above.
        (
            encrypt_all(setup, &self.bid_slots(setup, bid), public_key, rng),
            (),
        )
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let t = setup.params.plaintext();
        let half = constant_slots(&setup.params, t.div_ceil(2));
        // With v ∈ {0, 1, 2}: [b ≥ p] = v(3 - v)/2 and [b > p] = v(2 - v).
        let bids: Vec<_> = submissions
            .iter()
            .map(|s| {
                let v = &s[0];
                let square = evaluator.mul(v, v);
                let triple = &(v + v) + v;
                let at_least = evaluator.mul_plain(&(&triple - &square), &half);
                let above = &(v + v) - &square;
                (at_least, above)
            })
            .collect();
        let masks = sum(submissions.iter().map(|s| s[1].clone()).collect());
        tests_under_mask(setup, &bids, masks, evaluator)
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        decode_pattern(setup, output)
    }
}
