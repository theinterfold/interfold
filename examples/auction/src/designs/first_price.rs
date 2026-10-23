// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! First-price auction as an OR of SIMD thermometers.
//!
//! Bidder `i` encrypts the slots `T_i[p] = [bid_i · n + i > p]`. Folding the index into the value
//! makes all values distinct. The program outputs `1 - ∏(1 - T_i)`, which is the thermometer of
//! the largest folded value. That output is a function of the winner and the price only.

use super::{
    check_capacity, tree_depth, Design, Output, PriceRule, PublicResult, Setup, SetupError,
};
use crate::encoding::{constant_slots, ones_in, slot_sum};
use crate::evaluator::Evaluator;
use fhe::bfv::Ciphertext;
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, RngCore};

pub struct FirstPrice;

impl Design for FirstPrice {
    type Secret = ();

    fn name(&self) -> &'static str {
        "first-price"
    }

    fn disclosure(&self) -> &'static str {
        "winner and winning bid, nothing else"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::First
    }

    fn readout(&self) -> &'static str {
        "reads coefficient 0: N · c0 mod t = bid · n + winner"
    }

    fn depth(&self, bidders: usize) -> u32 {
        tree_depth(bidders)
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        let values = setup.bidders * setup.levels;
        check_capacity(setup, values, values as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, ()) {
        let folded = bid as usize * setup.bidders + index;
        let thermometer = ones_in(&setup.params, std::iter::once(0..folded));
        let ciphertext = public_key
            .try_encrypt(&thermometer, rng)
            .expect("encryption under a valid key");
        (vec![ciphertext], ())
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let ones = constant_slots(&setup.params, 1);
        let below: Vec<Ciphertext> = submissions
            .iter()
            .map(|submission| &(-&submission[0]) + &ones)
            .collect();
        &(-&evaluator.product(&below)) + &ones
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        let largest = slot_sum(&setup.params, output.coefficients[0]);
        let bidders = setup.bidders as u64;
        PublicResult {
            winner: Some((largest % bidders) as usize),
            price: Some(largest / bidders),
        }
    }
}
