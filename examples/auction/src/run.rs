// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs one auction end to end: keys, bids, program, decryption, and decoding.

use crate::designs::{Design, Output, PublicResult, Setup};
use crate::encoding::{coefficients, slot_values};
use crate::evaluator::Evaluator;
use crate::keys::Keys;
use crate::params::Profile;
use fhe_traits::{FheDecrypter, Serialize};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use std::time::{Duration, Instant};

pub use crate::designs::SetupError;

pub struct Stats {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub moduli: usize,
    pub log2_q: f64,
    pub depth: u32,
    pub ciphertexts_per_bidder: usize,
    pub bytes_per_bidder: usize,
    pub relinearization_key_bytes: usize,
    pub ciphertext_products: usize,
    pub plaintext_products: usize,
    pub encrypt: Duration,
    pub evaluate: Duration,
    pub decrypt: Duration,
    /// log2(Δ) - 1 - noise after the program. Threshold decryption spends part of this budget.
    pub noise_budget_bits: f64,
}

pub struct Report {
    pub design: &'static str,
    pub disclosure: &'static str,
    pub readout: &'static str,
    pub setup: Setup,
    pub bids: Vec<u64>,
    pub public: PublicResult,
    /// The tie set and the random lane, for designs that show them.
    pub ties: Option<String>,
    pub expected: PublicResult,
    /// The rank that each bidder reads with its own secret, for designs that allow it.
    pub own_ranks: Option<Vec<Option<usize>>>,
    pub expected_ranks: Vec<usize>,
    pub output: Output,
    pub stats: Stats,
}

impl Report {
    pub fn is_correct(&self) -> bool {
        let ranks_match = self.own_ranks.as_ref().is_none_or(|own| {
            own.iter()
                .zip(&self.expected_ranks)
                .all(|(own, expected)| *own == Some(*expected))
        });
        self.public == self.expected && ranks_match
    }
}

/// Runs one auction. A design with [`Design::random_tie_order`] gets a random tie priority. In an
/// E3, this order comes from public randomness that is fixed after the bids close.
pub fn run<D: Design, R: RngCore + CryptoRng>(
    design: &D,
    profile: Profile,
    bids: &[u64],
    levels: usize,
    rng: &mut R,
) -> Result<Report, SetupError> {
    let mut tie_priority: Vec<usize> = (0..bids.len()).collect();
    if design.random_tie_order() {
        tie_priority.shuffle(rng);
    }
    run_with_ties(design, profile, bids, levels, tie_priority, rng)
}

/// [`run`] with a given tie priority. A design without [`Design::random_tie_order`] needs the
/// identity.
pub fn run_with_ties<D: Design, R: RngCore + CryptoRng>(
    design: &D,
    profile: Profile,
    bids: &[u64],
    levels: usize,
    tie_priority: Vec<usize>,
    rng: &mut R,
) -> Result<Report, SetupError> {
    let bidders = bids.len();
    let mut sorted = tie_priority.clone();
    sorted.sort_unstable();
    assert!(
        sorted.iter().copied().eq(0..bidders),
        "the tie priority must be a permutation of 0..{bidders}"
    );
    assert!(
        design.random_tie_order() || sorted == tie_priority,
        "{} breaks ties by index",
        design.name()
    );
    if bidders < 2 {
        return Err(SetupError::TooFewBidders { bidders });
    }
    if let Some((index, &bid)) = bids
        .iter()
        .enumerate()
        .find(|(_, &bid)| bid >= levels as u64)
    {
        return Err(SetupError::BidOutOfRange { index, bid, levels });
    }
    let depth = design.depth(bidders);
    let required_bits = Profile::required_log2_q(depth);
    if let Some(limit_bits) = profile.security_limit_bits() {
        if required_bits > limit_bits {
            return Err(SetupError::DepthTooLarge {
                depth,
                required_bits,
                limit_bits,
            });
        }
    }
    let setup = Setup {
        params: profile.build(depth),
        bidders,
        levels,
        tie_priority,
    };
    design.check(&setup)?;
    let keys = Keys::generate(&setup.params, rng);

    let started = Instant::now();
    let (submissions, secrets): (Vec<_>, Vec<_>) = bids
        .iter()
        .enumerate()
        .map(|(index, &bid)| design.submit(&setup, index, bid, &keys.public, rng))
        .unzip();
    let encrypt = started.elapsed();

    let evaluator = Evaluator::new(&keys.relinearization);
    let started = Instant::now();
    let output = design.evaluate(&setup, &submissions, &evaluator);
    let evaluate = started.elapsed();

    // SAFETY: `measure_noise` is unsafe because the noise depends on the secret key. The demo
    // holds the secret key anyway and only prints the remaining budget.
    let noise = unsafe { keys.secret.measure_noise(&output) }.expect("a two-component ciphertext");
    let started = Instant::now();
    let plaintext = keys
        .secret
        .try_decrypt(&output)
        .expect("decryption under the same key");
    let output = Output {
        coefficients: coefficients(&plaintext),
        slots: slot_values(&plaintext),
    };
    let decrypt = started.elapsed();

    let log2_q: f64 = setup
        .params
        .moduli()
        .iter()
        .map(|&q| (q as f64).log2())
        .sum();
    let log2_delta = log2_q - (setup.params.plaintext() as f64).log2();
    let own_ranks = design.reveals_own_rank().then(|| {
        (0..bidders)
            .map(|index| design.own_rank(&setup, &output, index, &secrets[index]))
            .collect::<Vec<_>>()
    });
    let stats = Stats {
        degree: setup.params.degree(),
        plaintext_modulus: setup.params.plaintext(),
        moduli: setup.params.moduli().len(),
        log2_q,
        depth,
        ciphertexts_per_bidder: submissions[0].len(),
        bytes_per_bidder: submissions[0].iter().map(|ct| ct.to_bytes().len()).sum(),
        relinearization_key_bytes: keys.relinearization.to_bytes().len(),
        ciphertext_products: evaluator.ciphertext_products(),
        plaintext_products: evaluator.plaintext_products(),
        encrypt,
        evaluate,
        decrypt,
        noise_budget_bits: log2_delta - 1.0 - noise as f64,
    };
    Ok(Report {
        design: design.name(),
        disclosure: design.disclosure(),
        readout: design.readout(),
        bids: bids.to_vec(),
        public: design.decode(&setup, &output),
        ties: design.tie_note(&setup, &output),
        expected: design.expected(&setup, bids, &secrets),
        own_ranks,
        expected_ranks: design.expected_ranks(bids),
        setup,
        output,
        stats,
    })
}
