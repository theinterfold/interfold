// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Rank scores with bids in the exponent. The depth is 2 for any number of bidders.
//!
//! Bidder `i` submits `X^b`, `X^-b`, a secret blinding `ρ ≠ 0`, and a mask. The product
//! `X^b_i · X^-b_j · Σ_k X^-k` has a 1 in coefficient 0 exactly when `b_i ≥ b_j`, so coefficient 0
//! of `Z_i` counts the bidders that `i` beats (`W_i`). The program publishes
//! `ρ_i · (W_i - (n - 1))` at a score position for each bidder:
//!
//! - It is 0 for the winner only.
//! - For a loser it is a uniform non-zero value, because `t` is prime. Only bidder `i` knows `ρ_i`,
//!   so only bidder `i` can read its own rank.
//!
//! Each bidder owns a window of `3B` coefficients around its score position. The other
//! coefficients of the window hold `b_i - b_j`, so each bidder also submits a mask that is uniform
//! except for zeros at the score positions. The design does not compute a price: the winner
//! opens a bid commitment outside the program.

use super::{check_capacity, Design, Output, PriceRule, PublicResult, Setup, SetupError};
use crate::encoding::{inverse, monomial, poly};
use crate::evaluator::Evaluator;
use fhe::bfv::Ciphertext;
use fhe::lbfv::LBFVPublicKey;
use fhe_traits::FheEncrypter;
use rand::{CryptoRng, Rng, RngCore};

pub struct Rank;

/// The blinding that lets a bidder read its own rank.
pub struct RankSecret {
    pub blinding: u64,
}

fn window(setup: &Setup) -> usize {
    3 * setup.levels
}

/// `Z_i` spans the exponents `-2B..B`, so the score sits `2B` into the window of bidder `i`.
fn score_position(setup: &Setup, index: usize) -> usize {
    index * window(setup) + 2 * setup.levels
}

/// `Σ_{k=from}^{B-1} X^-k`. Coefficient 0 of `X^d` times this is `[d ≥ from]` for `|d| < B`.
pub(super) fn step(setup: &Setup, from: usize) -> Vec<u64> {
    let (degree, t) = (setup.params.degree(), setup.params.plaintext());
    let mut coefficients = vec![0u64; degree];
    for k in from..setup.levels {
        for (sum, term) in coefficients
            .iter_mut()
            .zip(monomial(degree, t, -(k as i64)))
        {
            *sum = (*sum + term) % t;
        }
    }
    coefficients
}

impl Design for Rank {
    type Secret = RankSecret;

    fn name(&self) -> &'static str {
        "rank"
    }

    fn disclosure(&self) -> &'static str {
        "winner only; each bidder can read its own rank (if 1 bidder mask is honest)"
    }

    fn price_rule(&self) -> PriceRule {
        PriceRule::None
    }

    fn readout(&self) -> &'static str {
        "reads n score coefficients: the single zero names the winner"
    }

    fn depth(&self, _bidders: usize) -> u32 {
        2
    }

    fn reveals_own_rank(&self) -> bool {
        true
    }

    fn check(&self, setup: &Setup) -> Result<(), SetupError> {
        check_capacity(setup, setup.bidders * window(setup), setup.bidders as u64)
    }

    fn submit<R: RngCore + CryptoRng>(
        &self,
        setup: &Setup,
        _index: usize,
        bid: u64,
        public_key: &LBFVPublicKey,
        rng: &mut R,
    ) -> (Vec<Ciphertext>, RankSecret) {
        let params = &setup.params;
        let (degree, t) = (params.degree(), params.plaintext());
        let blinding = rng.random_range(1..t);
        let mut blinding_polynomial = vec![0u64; degree];
        blinding_polynomial[0] = blinding;
        let mut mask: Vec<u64> = (0..degree).map(|_| rng.random_range(0..t)).collect();
        for index in 0..setup.bidders {
            mask[score_position(setup, index)] = 0;
        }
        let plaintexts = [
            poly(params, &monomial(degree, t, bid as i64)),
            poly(params, &monomial(degree, t, -(bid as i64))),
            poly(params, &blinding_polynomial),
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
        // Bidder i beats a lower index on a tie (≥) and loses to a higher index on a tie (>).
        let at_least = poly(params, &step(setup, 0));
        let above = poly(params, &step(setup, 1));
        let mut rivals = vec![0u64; degree];
        rivals[0] = (n as u64 - 1) % t;
        let rivals = poly(params, &rivals);

        // lower[i] = Σ_{j<i} X^-b_j and higher[i] = Σ_{j>i} X^-b_j, in O(n) additions.
        let mut lower: Vec<Option<Ciphertext>> = vec![None; n];
        let mut higher: Vec<Option<Ciphertext>> = vec![None; n];
        for i in 1..n {
            lower[i] = Some(match &lower[i - 1] {
                Some(sum) => sum + &submissions[i - 1][1],
                None => submissions[i - 1][1].clone(),
            });
        }
        for i in (0..n - 1).rev() {
            higher[i] = Some(match &higher[i + 1] {
                Some(sum) => sum + &submissions[i + 1][1],
                None => submissions[i + 1][1].clone(),
            });
        }

        let mut output: Option<Ciphertext> = None;
        for (i, submission) in submissions.iter().enumerate() {
            let shifted_rivals = match (&lower[i], &higher[i]) {
                (Some(lo), Some(hi)) => {
                    &evaluator.mul_plain(lo, &at_least) + &evaluator.mul_plain(hi, &above)
                }
                (Some(lo), None) => evaluator.mul_plain(lo, &at_least),
                (None, Some(hi)) => evaluator.mul_plain(hi, &above),
                (None, None) => unreachable!("check() requires two or more bidders"),
            };
            let wins = evaluator.mul(&submission[0], &shifted_rivals);
            let score = evaluator.mul(&(&wins - &rivals), &submission[2]);
            let placed = evaluator.mul_plain(
                &score,
                &poly(
                    params,
                    &monomial(degree, t, score_position(setup, i) as i64),
                ),
            );
            output = Some(match output {
                Some(sum) => &sum + &placed,
                None => placed,
            });
        }
        let mut output = output.expect("check() requires two or more bidders");
        for submission in submissions {
            output += &submission[3];
        }
        output
    }

    fn decode(&self, setup: &Setup, output: &Output) -> PublicResult {
        let zeros: Vec<usize> = (0..setup.bidders)
            .filter(|&index| output.coefficients[score_position(setup, index)] == 0)
            .collect();
        PublicResult {
            winner: match zeros[..] {
                [winner] => Some(winner),
                _ => None,
            },
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
        let t = setup.params.plaintext();
        let n = setup.bidders as u64;
        let score = output.coefficients[score_position(setup, index)];
        let beaten = ((u128::from(score) * u128::from(inverse(secret.blinding, t))
            + u128::from(n - 1))
            % u128::from(t)) as u64;
        (beaten < n).then(|| (n - beaten) as usize)
    }
}
