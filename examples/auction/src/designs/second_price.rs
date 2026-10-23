// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Second-price (Vickrey) auction with a masked readout.
//!
//! The slots have two regions:
//!
//! - Region A, `0..n·B`: the folded thermometer of `bid · n + index`. The program finds the slot
//!   of the largest folded value and tags it with the index of its owner.
//! - Region B, `n·B..(n+1)·B`: the plain bid thermometer. The program keeps the slots where two
//!   or more bids are above the slot, which is the thermometer of the second-highest bid.
//!
//! Coefficient 0 of the output is `N⁻¹ · (n · second_price + winner)`. The other coefficients
//! hold the bid ladders, so each bidder also submits a mask that is uniform except for a zero at
//! coefficient 0. One honest mask makes all of those coefficients uniform.

use super::{
    check_capacity, tree_depth, Design, Output, PriceRule, PublicResult, Setup, SetupError,
};
use crate::encoding::{constant_slots, ones_in, poly, simd, slot_sum};
use crate::evaluator::Evaluator;
use fhe::bfv::Ciphertext;
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};

pub struct SecondPrice;

impl Design for SecondPrice {
    type Secret = ();

    fn name(&self) -> &'static str {
        "second-price"
    }

    fn disclosure(&self) -> &'static str {
        "winner and second-highest bid, nothing else (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::Second
    }

    fn readout(&self) -> &'static str {
        "reads coefficient 0: N · c0 mod t = second_price · n + winner"
    }

    fn depth(&self, bidders: usize) -> u32 {
        tree_depth(bidders) + 1
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        let region_a = setup.bidders * setup.levels;
        check_capacity(setup, region_a + setup.levels, region_a as u64)
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
        let folded = bid as usize * setup.bidders + index;
        let ladder = ones_in(
            &setup.params,
            [0..folded, region_a..region_a + bid as usize],
        );
        let shifted = ones_in(&setup.params, std::iter::once(0..folded.saturating_sub(1)));
        let t = setup.params.plaintext();
        let mut mask: Vec<u64> = (0..setup.params.degree())
            .map(|_| rng.random_range(0..t))
            .collect();
        mask[0] = 0;
        let mask = poly(&setup.params, &mask);
        let ciphertexts = [ladder, shifted, mask]
            .iter()
            .map(|plaintext| {
                public_key
                    .try_encrypt(plaintext, rng)
                    .expect("encryption under a valid key")
            })
            .collect();
        (ciphertexts, ())
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let params = &setup.params;
        let (n, levels) = (setup.bidders, setup.levels);
        let region_a = n * levels;
        let ones = constant_slots(params, 1);
        let ladders: Vec<Ciphertext> = submissions.iter().map(|s| s[0].clone()).collect();
        let below: Vec<Ciphertext> = ladders.iter().map(|x| &(-x) + &ones).collect();
        let below_shifted: Vec<Ciphertext> =
            submissions.iter().map(|s| &(-&s[1]) + &ones).collect();

        // Region B: [two or more bids > p] = 1 - [no bid > p] - [exactly one bid > p].
        let (none_above, exactly_one) = evaluator.product_and_exactly_one(&below, &ladders);
        let two_or_more = &(&(-&none_above) + &ones) - &exactly_one;
        let mut weights = vec![0u64; params.degree()];
        weights[region_a..region_a + levels].fill(n as u64);
        let mut output = evaluator.mul_plain(&two_or_more, &simd(params, &weights));

        // Region A: one-hot of the largest folded value, then tagged with the owner's index.
        let top = &evaluator.product(&below_shifted) - &none_above;
        for (index, submission) in submissions.iter().enumerate().skip(1) {
            let own_slot = &submission[0] - &submission[1];
            let owned = evaluator.mul(&own_slot, &top);
            let mut tag = vec![0u64; params.degree()];
            tag[..region_a].fill(index as u64);
            output += &evaluator.mul_plain(&owned, &simd(params, &tag));
        }

        for submission in submissions {
            output += &submission[2];
        }
        output
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        let value = slot_sum(&setup.params, output.coefficients[0]);
        let bidders = setup.bidders as u64;
        PublicResult {
            winner: Some((value % bidders) as usize),
            price: Some(value / bidders),
        }
    }
}
