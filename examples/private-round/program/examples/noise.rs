// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Measures the noise of the output of the private-round program.
//!
//! For each committee size it generates a threshold l-BFV key (one public-key share and one
//! relinearization-key share per party, as the committee does), encrypts rounds of bids and masks,
//! runs [`e3_user_program::evaluate`], and measures the noise of the output with the sum of the
//! secret keys. It also decodes the decrypted output and compares the outcome with the one on the
//! plaintext bids.
//!
//! ```text
//! cargo run --release -p e3-user-program --example noise -- [--parties 3,9] [--trials 3]
//! ```
//!
//! The table has one row per number of lane factors `D` (the depth is `ceil(log2(D + 1))`): the
//! highest noise in bits over all the rounds of that `D`, and the mean.

use anyhow::Result;
use e3_fhe_params::{BfvPreset, build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed};
use e3_user_program::evaluate;
use e3_user_program::layout::{
    MAX_BIDDERS, MAX_LOTS, Outcome, RoundParams, bid_slots, decode_round, lane_factors,
};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe::trlbfv::{
    LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare,
    aggregate_relinearization_key,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::Rng;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

struct Committee {
    params: Arc<BfvParameters>,
    secret_key: SecretKey,
    public_key: LBFVPublicKey,
    rlk: LBFVRelinearizationKey,
}

fn committee(parties: usize) -> Result<Committee> {
    let mut rng = rand::rng();
    let (params, _) = build_pair_for_preset(PRESET)?;
    let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap())?;
    let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).unwrap())?;
    let keys: Vec<SecretKey> = (0..parties)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();
    let shares = keys
        .iter()
        .map(|sk| PublicKeyShare::contribute_with_crp(sk, &crs, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let public_key: LBFVPublicKey = shares.into_iter().aggregate()?;
    let rlk_shares = keys
        .iter()
        .map(|sk| RelinKeyShare::contribution_with_crp(sk, &urs, &crs, 0, 0, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
    let mut sum = vec![0i64; params.degree()];
    for key in &keys {
        for (acc, c) in sum.iter_mut().zip(key.coeffs.iter()) {
            *acc += c;
        }
    }
    Ok(Committee {
        secret_key: SecretKey::new(sum, &params),
        params,
        public_key,
        rlk,
    })
}

fn encrypt(committee: &Committee, slots: &[u64]) -> Result<Ciphertext> {
    let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &committee.params)?;
    Ok(committee
        .public_key
        .try_encrypt(&plaintext, &mut rand::rng())?)
}

/// One measured round: the noise in bits of the output, and whether the decoded outcome is the one
/// on the plaintext bids.
fn measure(committee: &Committee, round: &RoundParams, n: usize) -> Result<(usize, bool)> {
    let mut rng = rand::rng();
    let t = committee.params.plaintext();
    let bids: Vec<usize> = (0..n).map(|_| rng.random_range(0..round.levels)).collect();
    let mut bid_sum: Option<Ciphertext> = None;
    let mut mask_sum: Option<Ciphertext> = None;
    for (i, &b) in bids.iter().enumerate() {
        let slots = bid_slots(committee.params.degree(), round, b, i, 1);
        let mask: Vec<u64> = (0..slots.len()).map(|_| rng.random_range(0..t)).collect();
        let (bid, mask) = (encrypt(committee, &slots)?, encrypt(committee, &mask)?);
        bid_sum = Some(bid_sum.map_or(bid.clone(), |acc| &acc + &bid));
        mask_sum = Some(mask_sum.map_or(mask.clone(), |acc| &acc + &mask));
    }
    let out = evaluate(
        &committee.params,
        &committee.rlk,
        round,
        n,
        &bid_sum.unwrap(),
        &mask_sum.unwrap(),
    );
    let noise = unsafe { committee.secret_key.measure_noise(&out)? };
    let decrypted = committee.secret_key.try_decrypt(&out)?;
    let slots = Vec::<u64>::try_decode(&decrypted, Encoding::simd())?;
    let decoded = decode_round(&slots, round);

    let demand = |l: usize| bids.iter().filter(|&&b| b >= l).count();
    let expected = if demand(round.reserve_step) < round.min_lots {
        (Outcome::NotMet, None)
    } else if demand(round.reserve_step) < round.lots {
        (Outcome::Undersubscribed, Some(round.reserve_step))
    } else {
        let step = (round.reserve_step..round.levels)
            .rev()
            .find(|&l| demand(l) >= round.lots)
            .unwrap();
        (Outcome::SoldOut, Some(step))
    };
    Ok((noise, (decoded.outcome, decoded.step) == expected))
}

fn argument(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> Result<()> {
    let parties: Vec<usize> = argument("--parties")
        .unwrap_or_else(|| "3,9".to_string())
        .split(',')
        .map(|p| p.parse().expect("--parties is a comma-separated list"))
        .collect();
    let trials: usize =
        argument("--trials").map_or(3, |t| t.parse().expect("--trials is a number"));
    let mut rng = rand::rng();

    for &p in &parties {
        let started = Instant::now();
        let committee = committee(p)?;
        let q_bits: f64 = committee
            .params
            .moduli()
            .iter()
            .map(|&m| (m as f64).log2())
            .sum();
        let delta_bits = q_bits - (committee.params.plaintext() as f64).log2();
        println!(
            "parties {p}: log2(q) = {q_bits:.1}, log2(q / t) = {delta_bits:.1}, key generation {:.1} s",
            started.elapsed().as_secs_f64()
        );

        // For each number of factors: the noise of every round, and the rounds that decoded wrong.
        let mut by_factors: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut wrong = 0usize;
        let mut rounds = 0usize;
        let started = Instant::now();
        let mut cases: Vec<(usize, usize, usize)> = Vec::new();
        // The worst case first: 13 bidders for every K and m.
        for lots in 1..=MAX_LOTS {
            for min_lots in 1..=lots {
                cases.push((13, lots, min_lots));
            }
        }
        // Every number of bidders for the worst K = m = 7.
        for n in 1..=MAX_BIDDERS {
            cases.push((n, 7, 7));
        }
        for (n, lots, min_lots) in cases {
            for _ in 0..trials {
                let levels = rng.random_range(2..=16);
                let round = RoundParams {
                    levels,
                    reserve_step: rng.random_range(0..levels),
                    lots,
                    min_lots,
                };
                let (noise, ok) = measure(&committee, &round, n)?;
                by_factors
                    .entry(lane_factors(&round, n))
                    .or_default()
                    .push(noise);
                rounds += 1;
                if !ok {
                    wrong += 1;
                }
            }
        }
        println!("  D  depth  rounds  max noise (bits)  mean");
        for (factors, noises) in &by_factors {
            let depth = (usize::BITS - factors.leading_zeros()) as usize; // ceil(log2(D + 1))
            let max = noises.iter().max().unwrap();
            let mean = noises.iter().sum::<usize>() as f64 / noises.len() as f64;
            println!(
                "  {factors}  {depth}      {:>6}  {max:>16}  {mean:.1}",
                noises.len()
            );
        }
        println!(
            "  {rounds} rounds in {:.1} s, {wrong} decoded to a wrong outcome",
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}
