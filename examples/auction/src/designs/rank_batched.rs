// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Rank scores for all bidders with 2 ct×ct products, for any number of bidders.
//!
//! Each bidder `i` places its bid in its own window: `A_i = X^(s_i + b_i)` with
//! `s_i = 3B·i + 2B`. The program multiplies `ΣA_i` by `ΣX^-b_j · Σ_k X^-k` once. Coefficient
//! `s_i` of the product is `W_i = #{j : b_j ≤ b_i}`, and the windows of width `3B` do not overlap.
//!
//! The second product applies the blinding of each bidder to its own score only:
//! `R = Σ_k ρ_k X^(3Bn·k)`. Score `i` times `ρ_k` lands at `3B(i + n·k) + 2B`, so the pairs
//! `(i, k)` never collide, and the pairs with `i = k` are the published scores
//! `ρ_i · (W_i - n)`. Bidder masks hide all other coefficients.
//!
//! Costs of the fixed depth: `3 · n² · B` coefficients, and a tie for the highest bid is public
//! (all tied bidders show a zero). Ranks are competition ranks: `1 + #{j : b_j > b_i}`.

use super::rank::step;
use super::{
    check_capacity, Design, Output, PriceRule, PublicResult, RankSecret, Setup, SetupError,
};
use crate::encoding::{inverse, monomial, poly};
use crate::evaluator::Evaluator;
use fhe::bfv::Ciphertext;
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};

pub struct RankBatched;

fn window(setup: &Setup) -> usize {
    3 * setup.levels
}

/// Where the score of bidder `index` sits before blinding.
fn window_center(setup: &Setup, index: usize) -> usize {
    index * window(setup) + 2 * setup.levels
}

/// Where the blinding of bidder `index` shifts its own score.
fn blinding_shift(setup: &Setup, index: usize) -> usize {
    index * setup.bidders * window(setup)
}

fn score_position(setup: &Setup, index: usize) -> usize {
    window_center(setup, index) + blinding_shift(setup, index)
}

impl Design for RankBatched {
    type Secret = RankSecret;

    fn name(&self) -> &'static str {
        "rank-batched"
    }

    fn disclosure(&self) -> &'static str {
        "winner only, and a tie for the highest bid; each bidder can read its own rank (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::None
    }

    fn readout(&self) -> &'static str {
        "reads n score coefficients: a zero names a winner"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        2
    }

    fn reveals_own_rank(&self) -> bool {
        true
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        let n = setup.bidders;
        check_capacity(setup, n * n * window(setup), n as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, RankSecret) {
        let params = &setup.params;
        let (degree, t) = (params.degree(), params.plaintext());
        let blinding = rng.random_range(1..t);
        let mut blinding_term = vec![0u64; degree];
        blinding_term[blinding_shift(setup, index)] = blinding;
        let mut mask: Vec<u64> = (0..degree).map(|_| rng.random_range(0..t)).collect();
        for other in 0..setup.bidders {
            mask[score_position(setup, other)] = 0;
        }
        let placed_bid = (window_center(setup, index) + bid as usize) as i64;
        let plaintexts = [
            poly(params, &monomial(degree, t, placed_bid)),
            poly(params, &monomial(degree, t, -(bid as i64))),
            poly(params, &blinding_term),
            poly(params, &mask),
        ];
        let ciphertexts = plaintexts
            .iter()
            .map(|plaintext| {
                public_key
                    .try_encrypt(plaintext, rng)
                    .expect("encryption under a valid key")
            })
            .collect();
        (ciphertexts, RankSecret { blinding })
    }

    fn evaluate(
        &self,
        setup: &Setup,
        submissions: &[Vec<Ciphertext>],
        evaluator: &Evaluator,
    ) -> Ciphertext {
        let params = &setup.params;
        let (degree, t, n) = (params.degree(), params.plaintext(), setup.bidders);
        let sum = |part: usize| {
            submissions
                .iter()
                .map(|s| s[part].clone())
                .reduce(|acc, ct| &acc + &ct)
                .expect("check() requires two or more bidders")
        };
        let at_most = evaluator.mul_plain(&sum(1), &poly(params, &step(setup, 0)));
        let wins = evaluator.mul(&sum(0), &at_most);
        let mut all = vec![0u64; degree];
        for index in 0..n {
            all[window_center(setup, index)] = n as u64 % t;
        }
        let scores = evaluator.mul(&(&wins - &poly(params, &all)), &sum(2));
        &scores + &sum(3)
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        // On a tie for the highest bid, every tied bidder shows a zero. The highest index wins.
        let winner = (0..setup.bidders)
            .rev()
            .find(|&index| output.coefficients[score_position(setup, index)] == 0);
        PublicResult {
            winner,
            price: None,
        }
    }

    fn own_rank(
        &self,
        setup: &Setup,
        output: &Output,
        index: usize,
        secret: &RankSecret,
    ) -> Option<usize> {
        let t = u128::from(setup.params.plaintext());
        let n = setup.bidders as u128;
        let score = u128::from(output.coefficients[score_position(setup, index)]);
        // score = ρ · (W - n), so W = score / ρ + n, and the rank is n - W + 1.
        let at_or_below = (score * u128::from(inverse(secret.blinding, t as u64)) + n) % t;
        (1..=n)
            .contains(&at_or_below)
            .then(|| (n - at_or_below + 1) as usize)
    }

    fn expected_ranks(&self, bids: &[u64]) -> Vec<usize> {
        bids.iter()
            .map(|&bid| 1 + bids.iter().filter(|&&other| other > bid).count())
            .collect()
    }
}
