// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Auctions by blinded counting: a fixed number of ct×ct products for any number of bidders.
//!
//! Each bidder submits a SIMD thermometer and a uniform SIMD mask. The program adds the
//! thermometers, which gives `c[p]`, the number of bids above slot `p`. It adds the masks, which
//! gives `r`, uniform when 1 mask is honest. Because `t` is prime, `f(c)[p] · r[p]` is 0 when
//! `f(c)[p] = 0` and a uniform non-zero value otherwise. The output shows only where a slot test
//! is zero.
//!
//! The result is a zero pattern, not a value in coefficient 0. A contract checks a claimed result
//! by evaluating the published plaintext at 2 slot points for each region (N multiplications mod
//! t each). A slot where `r[p] = 0` reads as zero by error, with probability `1/t`.

use super::{check_capacity, Design, Output, PriceRule, PublicResult, Setup, SetupError};
use crate::encoding::{evaluate, ones_in, simd, slot_points};
use crate::evaluator::Evaluator;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};
use std::ops::Range;
use std::sync::Arc;

/// First-price with 1 ct×ct product.
pub struct FirstPriceBlind;

/// Second-price with 2 ct×ct products. The winning bid is public too.
pub struct SecondPriceBlind;

fn sum(cts: impl Iterator<Item = Ciphertext>) -> Ciphertext {
    cts.reduce(|acc, ct| &acc + &ct)
        .expect("check() requires two or more bidders")
}

/// The thermometer and the mask of one bidder.
fn submission<R: RngCore + CryptoRng>(
    setup: &Setup,
    ladder: impl IntoIterator<Item = Range<usize>>,
    public_key: &LBFVPublicKey,
    rng: &mut R,
) -> Vec<Ciphertext> {
    let t = setup.params.plaintext();
    let mask: Vec<u64> = (0..setup.params.degree())
        .map(|_| rng.random_range(0..t))
        .collect();
    [ones_in(&setup.params, ladder), simd(&setup.params, &mask)]
        .iter()
        .map(|plaintext| {
            public_key
                .try_encrypt(plaintext, rng)
                .expect("encryption under a valid key")
        })
        .collect()
}

/// The length of the non-zero prefix of `region`: the top of the thermometer in that region.
fn top(slot_values: &[u64], region: Range<usize>) -> usize {
    region
        .clone()
        .rev()
        .find(|&p| slot_values[p] != 0)
        .map_or(0, |p| p + 1 - region.start)
}

/// What a contract checks for a claimed top `value` of `region`: the slot below is non-zero
/// and the slot at `value` is zero. Each check evaluates the plaintext at one slot point.
fn check_top(
    params: &Arc<BfvParameters>,
    output: &[u64],
    region: Range<usize>,
    value: usize,
) -> bool {
    let (t, points) = (params.plaintext(), slot_points(params));
    let at = |slot: usize| evaluate(output, points[slot], t);
    let below_is_set = value == 0 || at(region.start + value - 1) != 0;
    let at_is_clear = region.start + value >= region.end || at(region.start + value) == 0;
    below_is_set && at_is_clear
}

fn folded(setup: &Setup, index: usize, bid: u64) -> usize {
    bid as usize * setup.bidders + index
}

fn split(setup: &Setup, folded: usize) -> (usize, u64) {
    (folded % setup.bidders, (folded / setup.bidders) as u64)
}

impl FirstPriceBlind {
    /// The check that a contract runs on a claimed result: 2 slot evaluations.
    pub fn verify(&self, setup: &Setup, output: &[u64], claim: PublicResult) -> bool {
        let (Some(winner), Some(price)) = (claim.winner, claim.price) else {
            return false;
        };
        let region = 0..setup.bidders * setup.levels;
        winner < setup.bidders
            && check_top(&setup.params, output, region, folded(setup, winner, price))
    }
}

impl Design for FirstPriceBlind {
    type Secret = ();

    fn name(&self) -> &'static str {
        "first-price-blind"
    }

    fn disclosure(&self) -> &'static str {
        "winner and winning bid, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::First
    }

    fn readout(&self) -> &'static str {
        "checks a claim at 2 slot points: 2 · N multiplications mod t"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        1
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        check_capacity(setup, setup.bidders * setup.levels, setup.bidders as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, ()) {
        let top = folded(setup, index, bid);
        (
            submission(setup, std::iter::once(0..top), public_key, rng),
            (),
        )
    }

    fn evaluate(
        &self,
        _setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let count = sum(submissions.iter().map(|s| s[0].clone()));
        let blinding = sum(submissions.iter().map(|s| s[1].clone()));
        evaluator.mul(&count, &blinding)
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        let region = 0..setup.bidders * setup.levels;
        let (winner, price) = split(setup, top(&output.slots, region));
        PublicResult {
            winner: Some(winner),
            price: Some(price),
        }
    }
}

impl SecondPriceBlind {
    /// The check that a contract runs on a claimed result: 4 slot evaluations. The claim names
    /// the winning bid as well, because the output reveals it.
    pub fn verify(
        &self,
        setup: &Setup,
        output: &[u64],
        claim: PublicResult,
        winning_bid: u64,
    ) -> bool {
        let (Some(winner), Some(price)) = (claim.winner, claim.price) else {
            return false;
        };
        let region_a = setup.bidders * setup.levels;
        winner < setup.bidders
            && check_top(
                &setup.params,
                output,
                0..region_a,
                folded(setup, winner, winning_bid),
            )
            && check_top(
                &setup.params,
                output,
                region_a..region_a + setup.levels,
                price as usize,
            )
    }

    /// The winning bid, which this design also makes public.
    pub fn winning_bid(&self, setup: &Setup, output: &Output) -> u64 {
        split(setup, top(&output.slots, 0..setup.bidders * setup.levels)).1
    }
}

impl Design for SecondPriceBlind {
    type Secret = ();

    fn name(&self) -> &'static str {
        "second-price-blind"
    }

    fn disclosure(&self) -> &'static str {
        "winner, second-highest bid, and winning bid (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::Second
    }

    fn readout(&self) -> &'static str {
        "checks a claim at 4 slot points: 4 · N multiplications mod t"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        2
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        let region_a = setup.bidders * setup.levels;
        check_capacity(setup, region_a + setup.levels, setup.bidders as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, ()) {
        let region_a = setup.bidders * setup.levels;
        let ladder = [
            0..folded(setup, index, bid),
            region_a..region_a + bid as usize,
        ];
        (submission(setup, ladder, public_key, rng), ())
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let region_a = setup.bidders * setup.levels;
        let count = sum(submissions.iter().map(|s| s[0].clone()));
        let blinding = sum(submissions.iter().map(|s| s[1].clone()));
        // Region A: c · c, non-zero when 1 or more bids are above. Region B: c · (c - 1),
        // non-zero when 2 or more bids are above.
        let one_in_b = ones_in(
            &setup.params,
            std::iter::once(region_a..region_a + setup.levels),
        );
        let selected = evaluator.mul(&count, &(&count - &one_in_b));
        evaluator.mul(&selected, &blinding)
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        let values = &output.slots;
        let region_a = setup.bidders * setup.levels;
        let (winner, _) = split(setup, top(values, 0..region_a));
        PublicResult {
            winner: Some(winner),
            price: Some(top(values, region_a..region_a + setup.levels) as u64),
        }
    }
}
