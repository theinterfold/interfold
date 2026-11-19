// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The auction on the parameters of the parameter search, decrypted by a committee.
//!
//! Each test searches the parameters of an auction shape and of a failure probability
//! (`e3_fhe_params::search::auction`), and builds a committee the way the protocol does: every
//! party has its own secret key, the public key and the relinearization key are the aggregates of
//! the shares of the parties, and the secret keys are Shamir-shared. The output of the program is
//! decrypted by threshold decryption. Every party adds smudging noise up to the bound fhe.rs
//! computes for the `z` and the depth of the search, so a decryption carries the largest noise the
//! protocol adds. The tests check the winner and the price, and the noise against its bounds.
//!
//! The tests at degree 16384 take minutes in a debug build and are ignored by default:
//!
//! ```text
//! cargo test --release -p e3-user-program --test threshold -- --include-ignored --nocapture
//! ```

use anyhow::{Result, anyhow, ensure};
use e3_compute_provider::FHEProcessorInput;
use e3_fhe_params::build_bfv_params_arc;
use e3_fhe_params::search::auction::{AuctionSearchConfig, AuctionSearchResult, auction_search};
use e3_fhe_params::search::utils::{log2_big, variance_uniform_sym};
use e3_user_program::{AuctionShape, ROLES, config_input, decode_result, run_auction};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{BfvParameters, Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe::trbfv::{
    AggregatedSecretKeyShare, SecretKeyShare, ShareManager, SmudgingConfig,
    SmudgingNoiseGenerator, SmudgingShare,
};
use fhe::trlbfv::{
    LBFVPublicKey, LBFVRelinearizationKey, PublicKeyShare, RelinKeyShare,
    aggregate_relinearization_key,
};
use fhe_traits::{DeserializeParametrized, FheDecoder, FheEncoder, FheEncrypter, Serialize};
use ndarray::{Array2, ArrayView};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::Instant;

/// The search inputs of the tests, with the defaults of the secure presets: error bound 20,
/// ternary secret keys and a margin of 2 bits.
fn search_config(shape: AuctionShape, failure_bits: u32, n: u128, lambda: u32) -> AuctionSearchConfig {
    AuctionSearchConfig {
        bidders: shape.max_bidders as u32,
        levels: shape.levels as u32,
        failure_bits,
        n,
        lambda,
        b: 20,
        b_chi: 1,
        min_margin: 2.0,
        d: None,
        insecure: false,
        min_prime_bits: 50,
        verbose: false,
    }
}

/// The BFV parameters of a search result, built as a preset is: the variance of `e1` is the one
/// of the uniform distribution on `[-B_Enc, B_Enc]`.
fn parameters(search: &AuctionSearchResult) -> Arc<BfvParameters> {
    let error1_variance = variance_uniform_sym(&search.bfv.benc_min).to_str_radix(10);
    build_bfv_params_arc(
        search.bfv.d as usize,
        search.plaintext_modulus,
        &search.bfv.qi_values(),
        Some(&error1_variance),
    )
}

/// A committee of `n` parties after key generation.
struct Committee {
    params: Arc<BfvParameters>,
    n: usize,
    threshold: usize,
    /// The inputs fhe.rs sizes the smudging noise with.
    z: usize,
    mult_depth: u32,
    lambda: usize,
    shares: ShareManager,
    public_key: LBFVPublicKey,
    rlk: LBFVRelinearizationKey,
    /// The share each party holds of the joint secret key.
    secret_key_shares: Vec<AggregatedSecretKeyShare>,
    /// The sum of the secret keys of the parties. No party has it; the tests use it only to
    /// measure the noise of a ciphertext.
    joint_secret_key: SecretKey,
}

/// The rows of party `receiver` in the shares one dealer made: one row per modulus.
fn rows_of(dealt: &[Array2<u64>], receiver: usize, degree: usize) -> Array2<u64> {
    let mut rows = Array2::zeros((0, degree));
    for modulus in dealt {
        rows.push_row(ArrayView::from(&modulus.row(receiver).to_owned()))
            .expect("a share has one value per coefficient");
    }
    rows
}

impl Committee {
    /// Key generation of `n` parties with the threshold `(n - 1) / 2`: every party samples a
    /// secret key, contributes to the l-BFV public key and to the relinearization key, and deals
    /// Shamir shares of its secret key to the others.
    fn new(search: &AuctionSearchResult, n: usize, lambda: usize) -> Result<Self> {
        let mut rng = rand::rng();
        let params = parameters(search);
        let degree = params.degree();
        let threshold = (n - 1) / 2;
        let shares = ShareManager::new(n, threshold, params.clone())?;
        let crs = CommonRandomPolyVec::new(&params, &mut rng)?;
        let urs = CommonRandomPolyVec::new(&params, &mut rng)?;

        let (mut public_key_shares, mut rlk_shares) = (Vec::new(), Vec::new());
        let mut received: Vec<Vec<SecretKeyShare>> = (0..n).map(|_| Vec::new()).collect();
        let mut joint = vec![0i64; degree];
        for _ in 0..n {
            let secret_key = SecretKey::random(&params, &mut rng);
            public_key_shares.push(PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)?);
            rlk_shares.push(RelinKeyShare::contribution_with_crp(
                &secret_key,
                &urs,
                &crs,
                0,
                0,
                &mut rng,
            )?);
            let polynomial = shares.coeffs_to_poly_level0(secret_key.coeffs.clone().as_ref())?;
            let dealt = shares
                .generate_secret_key_shares(polynomial, &mut rng)?
                .into_transport();
            for (receiver, collected) in received.iter_mut().enumerate() {
                collected.push(SecretKeyShare::from_transport(rows_of(&dealt, receiver, degree)));
            }
            for (sum, coefficient) in joint.iter_mut().zip(secret_key.coeffs.iter()) {
                *sum += *coefficient;
            }
        }
        let public_key: LBFVPublicKey = public_key_shares.into_iter().aggregate()?;
        let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;
        let secret_key_shares = received
            .into_iter()
            .map(|collected| shares.aggregate_secret_key_shares(collected))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            joint_secret_key: SecretKey::new(joint, &params),
            params,
            n,
            threshold,
            z: search.z as usize,
            mult_depth: search.mult_depth,
            lambda,
            shares,
            public_key,
            rlk,
            secret_key_shares,
        })
    }

    /// The smudging noise generator of one party. fhe.rs refuses to build it unless
    /// `2 (B_C + n B_sm) < Δ` for its bound `B_C` of `z` ciphertexts and the depth.
    fn smudging(&self) -> Result<SmudgingNoiseGenerator> {
        let mut config = SmudgingConfig::new(self.params.clone(), self.n, self.z, self.lambda)?;
        config.mult_depth = self.mult_depth;
        Ok(SmudgingNoiseGenerator::new(config)?)
    }

    /// The bytes of the encryption of `slots` under the committee key.
    fn encrypt(&self, slots: &[u64]) -> Result<Vec<u8>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &self.params)?;
        let ciphertext: Ciphertext = self.public_key.try_encrypt(&plaintext, &mut rand::rng())?;
        Ok(ciphertext.to_bytes())
    }

    /// Threshold decryption by the parties `parties` (1-based, `threshold + 1` of them). Every
    /// party of the committee samples fresh smudging noise and deals its shares; a decryption
    /// share is `c0 + c1 * sk_share + smudging_share`.
    fn decrypt(&self, ciphertext: &Arc<Ciphertext>, parties: &[usize]) -> Result<Vec<u64>> {
        ensure!(parties.len() == self.threshold + 1, "threshold + 1 parties decrypt");
        let mut rng = rand::rng();
        let degree = self.params.degree();
        let generator = self.smudging()?;
        let mut received: Vec<Vec<SmudgingShare>> = (0..self.n).map(|_| Vec::new()).collect();
        for _ in 0..self.n {
            let noise = generator.generate(&mut rng)?;
            let dealt = self
                .shares
                .generate_smudging_shares(noise, &mut rng)?
                .into_transport();
            for &party in parties {
                received[party - 1].push(SmudgingShare::from_transport(rows_of(
                    &dealt,
                    party - 1,
                    degree,
                )));
            }
        }
        let mut decryption_shares = Vec::new();
        for &party in parties {
            let smudging = self
                .shares
                .aggregate_smudging_shares(std::mem::take(&mut received[party - 1]))?;
            decryption_shares.push(self.shares.decryption_share(
                ciphertext.clone(),
                &self.secret_key_shares[party - 1],
                smudging,
            )?);
        }
        let plaintext =
            self.shares
                .decrypt_from_shares(decryption_shares, parties.to_vec(), ciphertext.clone())?;
        Ok(Vec::<u64>::try_decode(&plaintext, Encoding::simd())?)
    }

    /// The noise of `ciphertext` under the joint secret key, in bits.
    fn noise_bits(&self, ciphertext: &Ciphertext) -> Result<usize> {
        // SAFETY: `measure_noise` has a variable-time path that depends on the noise. The test
        // holds the secret key and only reads the size of the noise.
        Ok(unsafe { self.joint_secret_key.measure_noise(ciphertext) }?)
    }
}

/// The slots of the four ciphertexts of a bid: the two thermometers of period `levels` and two
/// uniform shares.
fn bid_slots(params: &BfvParameters, levels: usize, bid: usize, rng: &mut StdRng) -> Vec<Vec<u64>> {
    let (degree, t) = (params.degree(), params.plaintext());
    let thermometer = |inclusive: bool| -> Vec<u64> {
        (0..degree)
            .map(|i| u64::from(bid > i % levels || (inclusive && bid == i % levels)))
            .collect()
    };
    let mut roles = vec![thermometer(true), thermometer(false)];
    for _ in 2..ROLES {
        roles.push((0..degree).map(|_| rng.random_range(0..t)).collect());
    }
    roles
}

/// The winner and the price on the plaintext bids: the highest bid wins (a tie goes to the lowest
/// position) and pays the second-highest bid.
fn expected(bids: &[usize]) -> (usize, usize) {
    let mut order: Vec<usize> = (0..bids.len()).collect();
    order.sort_by_key(|&j| std::cmp::Reverse(bids[j]));
    (order[0], bids[order[1]])
}

/// What one auction measured.
struct Round {
    /// The noise of the output under the joint key, before the smudging noise, in bits.
    noise_bits: usize,
    /// Seconds the program ran.
    seconds: f64,
}

/// Runs the auction of `bids` on the committee and checks the result of two decryptions by
/// different parties.
fn auction(committee: &Committee, shape: AuctionShape, bids: &[usize], seed: u64) -> Result<Round> {
    let mut rng = StdRng::seed_from_u64(seed);
    let t = committee.params.plaintext();
    let mut inputs = vec![(config_input(), 0u64)];
    // Whether both share sums are zero in a slot, which is where the mask is zero.
    let mut sums = vec![[0u64; 2]; committee.params.degree()];
    for &bid in bids {
        let roles = bid_slots(&committee.params, shape.levels, bid, &mut rng);
        for (role, slots) in roles.iter().enumerate() {
            if role >= 2 {
                for (sum, value) in sums.iter_mut().zip(slots) {
                    sum[role - 2] = (sum[role - 2] + value) % t;
                }
            }
            let index = inputs.len() as u64;
            inputs.push((committee.encrypt(slots)?, index));
        }
    }
    let zero_masks = sums[..bids.len() * shape.levels]
        .iter()
        .filter(|sum| **sum == [0, 0])
        .count();

    let started = Instant::now();
    let output = run_auction(
        shape,
        FHEProcessorInput {
            ciphertexts: &mut inputs.into_iter(),
            params: &committee.params,
            relinearization_key: Some(&committee.rlk),
        },
    );
    let seconds = started.elapsed().as_secs_f64();
    let output = Arc::new(Ciphertext::from_bytes(&output, &committee.params)?);
    let noise_bits = committee.noise_bits(&output)?;

    // The first threshold + 1 parties, and the last ones.
    let first: Vec<usize> = (1..=committee.threshold + 1).collect();
    let last: Vec<usize> = (committee.n - committee.threshold..=committee.n).collect();
    let slots = committee.decrypt(&output, &first)?;
    ensure!(
        slots == committee.decrypt(&output, &last)?,
        "two sets of parties decrypted different plaintexts"
    );

    let decoded = decode_result(&slots, shape, bids.len());
    if zero_masks == 0 {
        ensure!(
            decoded == Some(expected(bids)),
            "bids {bids:?}: decoded {decoded:?}, expected {:?}",
            expected(bids)
        );
    } else {
        // The failure the parameters allow. One zero mask never gives another winner or price.
        ensure!(
            decoded.is_none() || decoded == Some(expected(bids)),
            "bids {bids:?}: a round with a zero mask decoded to {decoded:?}"
        );
    }
    Ok(Round { noise_bits, seconds })
}

/// Searches the parameters of `shape`, runs `rounds` on a committee of `n` parties and checks
/// the measured noise against the bounds of the search.
fn run(
    shape: AuctionShape,
    failure_bits: u32,
    n: usize,
    lambda: u32,
    configure: impl FnOnce(&mut AuctionSearchConfig),
    rounds: &[&[usize]],
) -> Result<AuctionSearchResult> {
    let mut config = search_config(shape, failure_bits, n as u128, lambda);
    configure(&mut config);
    let search = auction_search(&config).map_err(|error| anyhow!("{error}"))?;
    let committee = Committee::new(&search, n, lambda as usize)?;

    // fhe.rs accepts the parameters for z and the depth, with the smudging bound of the search.
    let generator = committee.smudging()?;
    ensure!(
        *generator.smudging_bound() == search.bfv.b_sm_min,
        "the smudging bound of fhe.rs is not the one of the search"
    );

    let log2_q = log2_big(&search.bfv.q_bfv);
    let log2_delta = search.bfv.rhs_log2;
    let bound_bits = log2_big(&search.bfv.b_c_final);
    let auction_bound_bits = log2_big(&search.b_c_auction);
    let smudging_bits = log2_big(&search.bfv.b_sm_min) + (n as f64).log2();
    eprintln!(
        "{} bidders x {} levels, failure 2^{:.1}: d = {}, t = {}, {} moduli, log2 q = {log2_q:.1}, n = {n}, z = {}",
        shape.max_bidders,
        shape.levels,
        search.failure_log2,
        search.bfv.d,
        search.plaintext_modulus,
        search.bfv.selected_primes.len(),
        search.z,
    );
    eprintln!(
        "  bounds: auction noise 2^{auction_bound_bits:.1}, fhe.rs noise 2^{bound_bits:.1}, \
         smudging of {n} parties 2^{smudging_bits:.1}, limit Δ/2 = 2^{:.1}",
        log2_delta - 1.0
    );
    for (seed, bids) in rounds.iter().enumerate() {
        let round = auction(&committee, shape, bids, 7000 + seed as u64)?;
        eprintln!(
            "  {} bidders {bids:?}: winner and price {:?}, noise {} bits \
             ({:.1} bits under its bound), program {:.1} s",
            bids.len(),
            expected(bids),
            round.noise_bits,
            auction_bound_bits - round.noise_bits as f64,
            round.seconds,
        );
        // The measured noise is below the worst-case bound of the auction, which is below the
        // bound fhe.rs sizes the smudging noise with.
        ensure!(
            (round.noise_bits as f64) < auction_bound_bits,
            "the noise passes the bound of the auction"
        );
        ensure!(auction_bound_bits <= bound_bits + 1e-9);
        // The noise and the smudging noise of every party stay below Δ/2, so decryption cannot
        // fail on noise.
        let total = (round.noise_bits as f64).exp2() + smudging_bits.exp2();
        ensure!(
            total.log2() < log2_delta - 1.0,
            "the noise and the smudging noise pass Δ/2"
        );
    }
    Ok(search)
}

const LEVELS_16_BIDDERS_8: AuctionShape = AuctionShape {
    levels: 16,
    max_bidders: 8,
};

/// Degree 128 with 9 parties and threshold 4, as the demo committee of the example. λ is 40
/// here: at the λ = 2 of the demo preset the formula of fhe.rs cannot cover the auction, and the
/// search says so. The degree makes the set insecure; the noise bounds are the real ones.
#[test]
fn a_committee_of_nine_decrypts_every_bidder_count_at_degree_128() -> Result<()> {
    let rounds: [&[usize]; 12] = [
        &[4, 4],
        &[0, 15],
        &[12, 5, 9],
        &[5, 12, 9],
        &[7, 3, 7],
        &[7, 7, 7],
        &[5, 9, 2, 9],
        &[1, 2, 3, 4, 5],
        &[0, 0, 0, 0, 0, 0],
        &[15, 3, 15, 8, 15, 1, 0],
        &[2, 3, 9, 1, 9, 9, 0, 9],
        &[15, 15, 15, 15, 15, 15, 15, 15],
    ];
    let search = run(
        LEVELS_16_BIDDERS_8,
        9,
        9,
        40,
        |config| {
            config.d = Some(128);
            config.insecure = true;
        },
        &rounds,
    )?;
    assert_eq!((search.bfv.d, search.plaintext_modulus), (128, 257));
    Ok(())
}

/// The parameters of 8 bidders, 16 levels and a failure probability of 2^-40: degree 16384 and
/// t = 12451841, with a committee of 20 parties and threshold 9.
#[test]
#[ignore = "degree 16384: run with --release -- --include-ignored"]
fn a_committee_of_twenty_decrypts_the_auction_at_degree_16384() -> Result<()> {
    // Every bidder count, with unique tops, ties at the top and equal bids.
    let rounds: [&[usize]; 8] = [
        &[11, 4],
        &[7, 3, 7],
        &[5, 9, 2, 9],
        &[0, 7, 3, 7, 12],
        &[0, 0, 0, 0, 0, 0],
        &[15, 3, 15, 8, 15, 1, 0],
        &[2, 3, 9, 1, 9, 9, 0, 9],
        &[15, 15, 15, 15, 15, 15, 15, 15],
    ];
    let search = run(LEVELS_16_BIDDERS_8, 40, 20, 31, |_| {}, &rounds)?;
    assert_eq!((search.bfv.d, search.plaintext_modulus), (16384, 12451841));
    assert_eq!(search.bfv.selected_primes.len(), 6);
    Ok(())
}

/// Another shape and another failure probability: 16 bidders and 32 levels at 2^-30.
#[test]
#[ignore = "degree 16384: run with --release -- --include-ignored"]
fn sixteen_bidders_and_thirty_two_levels_at_degree_16384() -> Result<()> {
    let shape = AuctionShape {
        levels: 32,
        max_bidders: 16,
    };
    let rounds: [&[usize]; 2] = [
        &[31, 4, 17, 17, 0, 30, 30, 2, 9, 31, 12, 5, 5, 28, 1, 16],
        &[6, 20, 20],
    ];
    let search = run(shape, 30, 20, 31, |_| {}, &rounds)?;
    assert_eq!(search.bfv.d, 16384);
    Ok(())
}
