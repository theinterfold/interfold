// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Parameter search for the sealed-bid second-price auction of `examples/auction-e2e`.
//!
//! [`auction_search`] takes the shape of an auction (the most bidders and the number of price
//! levels) and the failure probability it may have, and returns a BFV parameter set for it. The
//! inputs that [`bfv_search`](crate::search::bfv::bfv_search) asks for are derived:
//!
//! - the plaintext modulus `k`, from the failure probability (see [`plaintext_modulus`]);
//! - the multiplicative depth, which the auction program fixes at [`AUCTION_MULT_DEPTH`];
//! - `z`, the ciphertext count that fhe.rs gets for its smudging bound.
//!
//! # The auction
//!
//! Every bidder sends four ciphertexts: the thermometers `ge` (`[b >= p]`) and `gt` (`[b > p]`) of
//! its bid `b`, repeated in every lane, and two mask shares `s1` and `s2` that are uniform in
//! every slot. Lane `j` holds the test of bidder position `j`; a lane is `levels` slots. With `S1`
//! and `S2` the sums of the shares, `c` a quadratic non-residue mod `k` and `sel` the lane
//! selectors, the program computes
//!
//! ```text
//! ties   = (sum_j (ge_j - gt_j) * sel_j) x (sum_j (ge_j - gt_j) * sel_{>j})
//! beaten = (sum_j gt_j) * used - sum_j gt_j * sel_j + used - sum_j ge_j * sel_j + ties
//! two    = (sum_j ge_j) x (sum_j ge_j - 1)
//! mask   = S1 x S1 - c * (S2 x S2)
//! out    = beaten x (two x mask)
//! ```
//!
//! where `x` is a ciphertext product with relinearization and `*` a product with a plaintext.
//! There are 6 ciphertext products and the depth is 3. `beaten` carries the noise of the lane
//! selectors, so it is multiplied last.
//!
//! # Plaintext modulus
//!
//! `mask` is the norm of `S1 + S2 sqrt(c)` in the quadratic extension of the integers mod `k`.
//! It is zero only when `S1 = S2 = 0`, and otherwise uniform over the non-zero residues when
//! `(S1, S2)` is uniform, which one honest bidder guarantees. A slot fails when its mask is zero,
//! with probability `1 / k^2`, so an auction of `slots = bidders * levels` used slots fails with
//! probability at most `slots / k^2`. The search takes the smallest prime `k` with
//!
//! - `k^2 >= slots * 2^failure_bits`,
//! - `k = 1 (mod 2d)`, which SIMD encoding needs,
//! - `k > bidders * (bidders - 1)`, so no test value wraps to zero.
//!
//! # Noise
//!
//! [`auction_noise_bound`] bounds the noise of `out` in the worst case, with the bounds
//! `bfv_search` uses (Eq. 26, 28 and 30 of <https://eprint.iacr.org/2024/1285>) and the bound of a
//! product with a plaintext. The committee sizes its smudging noise with fhe.rs, whose formula
//! knows only a ciphertext count `z` and a depth: `z` fresh ciphertexts are added, then every
//! level multiplies the noise by `2 k d^2 ||sk||` and adds the relinearization noise. The search
//! therefore returns the smallest `z` for which that formula is at least the bound of the
//! auction, and checks correctness with the value of the formula. The search, fhe.rs and the
//! circuit configuration then use one bound, and it covers the auction.

use crate::search::bfv::{bfv_search_with_max_primes, BfvSearchConfig, BfvSearchResult, RING_DIM};
use crate::search::constants::{D_POW2_MAX, K_MAX};
use crate::search::errors::{BfvParamsError, BfvParamsResult, SearchError, ValidationError};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use std::collections::HashSet;

/// Multiplicative depth of the auction program.
pub const AUCTION_MULT_DEPTH: u32 = 3;

/// Ciphertexts one bidder sends: two thermometers and two mask shares.
pub const AUCTION_ROLES: usize = 4;

/// Largest number of primes the auction search tries at one ring dimension. A large plaintext
/// modulus can need more than the 6 primes of `bfv_search` and still fit under the security
/// limit of the ring dimension.
const MAX_NUM_PRIMES: usize = 8;

/// fhe.rs holds a SIMD plaintext modulus in at most 62 bits.
const PLAINTEXT_MAX_BITS: u64 = 62;

/// Rounds of the search for `z`. `z` only grows, and it settles in two or three rounds.
const MAX_Z_ROUNDS: usize = 8;

/// Inputs of the auction parameter search.
#[derive(Debug, Clone)]
pub struct AuctionSearchConfig {
    /// Most bidders of an auction, which is the number of lanes.
    pub bidders: u32,
    /// Price levels: a bid is in `0..levels`, and a lane is `levels` slots.
    pub levels: u32,
    /// The auction may fail with probability at most `2^-failure_bits`.
    pub failure_bits: u32,
    /// Number of parties n (ciphernodes).
    pub n: u128,
    /// Statistical security parameter λ.
    pub lambda: u32,
    /// Bound B on the error distribution.
    pub b: u128,
    /// Bound B_χ on the secret key distribution.
    pub b_chi: u128,
    /// Min supported correctness margin in bits.
    pub min_margin: f64,
    /// Ring dimension. `None` searches d = 8192, 16384 and 32768.
    pub d: Option<u64>,
    /// Skip the RLWE security limit. Only for insecure test presets.
    pub insecure: bool,
    /// Smallest prime bit-length (see `BfvSearchConfig::min_prime_bits`).
    pub min_prime_bits: u8,
    /// Verbose output of every `bfv_search` round.
    pub verbose: bool,
}

/// Result of the auction parameter search.
#[derive(Debug, Clone)]
pub struct AuctionSearchResult {
    /// The parameter set, as `bfv_search` returns it for [`AuctionSearchResult::bfv_config`].
    /// `bfv.b_c_final` and `bfv.b_sm_min` are the bounds fhe.rs computes for `z` and the depth.
    pub bfv: BfvSearchResult,
    /// The inputs `bfv_search` ran with: the derived `k`, `z` and depth.
    pub bfv_config: BfvSearchConfig,
    /// Plaintext modulus k.
    pub plaintext_modulus: u64,
    /// The smallest quadratic non-residue mod k: the `c` of `mask = S1^2 - c S2^2`.
    pub non_residue: u64,
    /// Ciphertext count to give fhe.rs for the smudging bound (`num_ciphertexts`).
    pub z: u128,
    /// Multiplicative depth to give fhe.rs for the smudging bound.
    pub mult_depth: u32,
    /// Slots an auction with every bidder uses: `bidders * levels`.
    pub slots: u64,
    /// log2 of the bound `slots / k^2` on the failure probability.
    pub failure_log2: f64,
    /// Worst-case noise of the auction output ([`auction_noise_bound`]). `bfv.b_c_final` is at
    /// least this.
    pub b_c_auction: BigUint,
}

/// Deterministic Miller-Rabin for 64-bit integers.
pub fn is_prime_u64(n: u64) -> bool {
    const WITNESSES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    if n < 2 {
        return false;
    }
    for p in WITNESSES {
        if n.is_multiple_of(p) {
            return n == p;
        }
    }
    let (mut odd, mut twos) = (n - 1, 0u32);
    while odd % 2 == 0 {
        odd /= 2;
        twos += 1;
    }
    // These 12 witnesses decide every n below 2^64.
    'witness: for a in WITNESSES {
        let mut x = pow_mod(a, odd, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..twos {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn mul_mod(a: u64, b: u64, n: u64) -> u64 {
    ((a as u128 * b as u128) % n as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64, n: u64) -> u64 {
    let mut result = 1 % n;
    base %= n;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, n);
        }
        base = mul_mod(base, base, n);
        exponent >>= 1;
    }
    result
}

/// The smallest quadratic non-residue modulo the odd prime `k`, by Euler's criterion.
///
/// The auction program computes the same value from its plaintext modulus, so the search and the
/// program agree on `c` without passing it.
pub fn smallest_non_residue(k: u64) -> u64 {
    debug_assert!(k > 2 && is_prime_u64(k), "k must be an odd prime");
    (2..k)
        .find(|&c| pow_mod(c, (k - 1) / 2, k) == k - 1)
        .expect("an odd prime has a quadratic non-residue")
}

/// The smallest plaintext modulus of an auction at ring dimension `d`: a prime `k = 1 (mod 2d)`
/// with `k^2 >= slots * 2^failure_bits` and `k > bidders * (bidders - 1)`, which is not in
/// `excluded`. `None` when it would pass 62 bits.
pub fn plaintext_modulus(
    d: u64,
    slots: u64,
    bidders: u32,
    failure_bits: u32,
    excluded: &HashSet<u64>,
) -> Option<u64> {
    // ceil(sqrt(slots * 2^failure_bits))
    let target = BigUint::from(slots) << failure_bits;
    let mut root = target.sqrt();
    if &root * &root < target {
        root += BigUint::one();
    }
    let no_wrap = bidders as u64 * (bidders as u64 - 1) + 1;
    let lower = root.max(BigUint::from(no_wrap)).max(BigUint::from(3u32));
    if lower.bits() > PLAINTEXT_MAX_BITS {
        return None;
    }
    let lower = lower.to_u64()?;
    let step = 2 * d;
    // The smallest value >= lower that is 1 mod 2d.
    let mut candidate = lower + (step + 1 - lower % step) % step;
    while candidate >> PLAINTEXT_MAX_BITS == 0 {
        if is_prime_u64(candidate) && !excluded.contains(&candidate) {
            return Some(candidate);
        }
        candidate += step;
    }
    None
}

/// Worst-case noise of the auction output for the parameter set `bfv`, with `bidders` bidders.
///
/// The rules, with `r = q mod k`, `||sk|| = n B_χ` and `B_relin` the relinearization noise of the
/// set:
///
/// - a fresh ciphertext has the noise `f = B_fresh + r`;
/// - an addition adds the noises and `r` (Eq. 26);
/// - a product with a SIMD plaintext multiplies the noise by at most `d (k - 1)` and adds
///   `r d k`: fhe.rs lifts the plaintext to coefficients in `0..k`;
/// - a product with a constant `c` multiplies the noise by `c` and adds `r c`;
/// - a ciphertext product with relinearization gives
///   `d k (e1 + e2) (d ||sk|| + 1) + 2 k^2 d^2 (||sk|| + 1)^2 + B_relin` (Eq. 28 and 30).
pub fn auction_noise_bound(
    config: &AuctionSearchConfig,
    bfv: &BfvSearchResult,
    non_residue: u64,
) -> BigUint {
    let d = BigUint::from(bfv.d);
    let k = BigUint::from(bfv.k_plain_eff);
    let r = BigUint::from(bfv.rkq);
    let bidders = BigUint::from(config.bidders);
    let sk_norm = BigUint::from(config.n) * BigUint::from(config.b_chi);
    let c = BigUint::from(non_residue);
    let two = BigUint::from(2u32);

    let times_plaintext = |e: &BigUint| &d * (&k - BigUint::one()) * e + &r * &d * &k;
    let product = |e1: &BigUint, e2: &BigUint| {
        &d * &k * (e1 + e2) * (&d * &sk_norm + BigUint::one())
            + &two * &k * &k * &d * &d * (&sk_norm + BigUint::one()) * (&sk_norm + BigUint::one())
            + &bfv.b_relin
    };

    // One fresh ciphertext, and a sum of one ciphertext of every bidder.
    let fresh = &bfv.b_fresh + &r;
    let sum = &bidders * &fresh;

    // sum_j ge_j * sel_j and sum_j gt_j * sel_j.
    let own = &bidders * times_plaintext(&fresh);
    // sum_j (ge_j - gt_j) * sel_{>j}.
    let ties_before = &bidders * times_plaintext(&(&two * &fresh + &r));
    let ties = product(&(&two * &own + &r), &ties_before);
    // (sum_j gt_j) * used - own_gt + used - own_ge + ties: four additions.
    let beaten = times_plaintext(&sum) + &two * &own + &ties + BigUint::from(4u32) * &r;
    let two_at_least = product(&sum, &(&sum + &r));
    // S1 x S1 - c * (S2 x S2).
    let square = product(&sum, &sum);
    let mask = &square + &c * &square + (&c + BigUint::one()) * &r;
    let two_masked = product(&two_at_least, &mask);
    product(&beaten, &two_masked)
}

/// The noise bound fhe.rs computes for `z` ciphertexts and [`AUCTION_MULT_DEPTH`] levels on the
/// parameter set `bfv`: `B(0) = z (B_fresh + r)` and `B(i + 1) = 2 k d^2 ||sk|| B(i) + B_relin`.
/// It is `bfv.b_c_final` when `z` is the `z` of the search that returned `bfv`.
pub fn runtime_noise_bound(
    config: &AuctionSearchConfig,
    bfv: &BfvSearchResult,
    z: u128,
) -> BigUint {
    let (coeff, fresh) = runtime_terms(config, bfv);
    let mut bound = BigUint::from(z) * fresh;
    for _ in 0..AUCTION_MULT_DEPTH {
        bound = &coeff * bound + &bfv.b_relin;
    }
    bound
}

/// `2 k d^2 ||sk||` and `B_fresh + r` of `bfv`.
fn runtime_terms(config: &AuctionSearchConfig, bfv: &BfvSearchResult) -> (BigUint, BigUint) {
    let d = BigUint::from(bfv.d);
    let coeff = BigUint::from(2u32)
        * BigUint::from(bfv.k_plain_eff)
        * &d
        * &d
        * BigUint::from(config.n)
        * BigUint::from(config.b_chi);
    (coeff, &bfv.b_fresh + BigUint::from(bfv.rkq))
}

/// The smallest `z >= 1` for which [`runtime_noise_bound`] is at least `bound`.
fn runtime_z(config: &AuctionSearchConfig, bfv: &BfvSearchResult, bound: &BigUint) -> BigUint {
    let (coeff, fresh) = runtime_terms(config, bfv);
    // The bound is `coeff^depth z fresh + B_relin (coeff^(depth-1) + ... + 1)`.
    let mut scale = BigUint::one();
    let mut relin = BigUint::zero();
    for _ in 0..AUCTION_MULT_DEPTH {
        relin = &coeff * relin + &bfv.b_relin;
        scale *= &coeff;
    }
    if bound <= &relin {
        return BigUint::one();
    }
    let per_ciphertext = scale * fresh;
    let needed = (bound - relin + &per_ciphertext - BigUint::one()) / per_ciphertext;
    needed.max(BigUint::one())
}

/// What [`search_modulus`] found at one ring dimension.
enum ModulusSearch {
    Found(Box<(BfvSearchConfig, BfvSearchResult, BigUint)>),
    /// No set satisfies correctness under the security limit.
    NoSet,
    /// The formula of fhe.rs cannot reach the bound of the auction with a `z` up to `K_MAX` and
    /// up to the plaintext modulus. Its `z` term grows with the fresh noise only, so this happens
    /// when the relinearization noise dominates, which a small λ causes.
    RelinearizationDominates,
}

/// The parameter set of one plaintext modulus at one ring dimension, with its `z`.
fn search_modulus(
    config: &AuctionSearchConfig,
    d: u64,
    k: u64,
    non_residue: u64,
) -> BfvParamsResult<ModulusSearch> {
    let mut z: u128 = 1;
    for _ in 0..MAX_Z_ROUNDS {
        let bfv_config = BfvSearchConfig {
            n: config.n,
            z,
            k: k as u128,
            lambda: config.lambda,
            b: config.b,
            b_chi: config.b_chi,
            min_margin: config.min_margin,
            d: Some(d),
            insecure: config.insecure,
            mult_depth: AUCTION_MULT_DEPTH,
            min_prime_bits: config.min_prime_bits,
            verbose: config.verbose,
        };
        let bfv = match bfv_search_with_max_primes(&bfv_config, MAX_NUM_PRIMES) {
            Ok(bfv) => bfv,
            // No set at this ring dimension. Every other error is an invalid input.
            Err(BfvParamsError::Search { .. }) => return Ok(ModulusSearch::NoSet),
            Err(error) => return Err(error),
        };
        let bound = auction_noise_bound(config, &bfv, non_residue);
        // `bfv_search` takes max(k, z) as the plaintext modulus, so z must stay at or below k for
        // the set to be the one of the plaintext modulus k.
        let needed = match runtime_z(config, &bfv, &bound).to_u128() {
            Some(needed) if needed <= K_MAX && needed <= k as u128 => needed,
            _ => return Ok(ModulusSearch::RelinearizationDominates),
        };
        if needed <= z {
            return Ok(ModulusSearch::Found(Box::new((bfv_config, bfv, bound))));
        }
        // A larger z can move the search to another set, so the set is searched again.
        z = needed;
    }
    Ok(ModulusSearch::NoSet)
}

/// Searches a BFV parameter set for an auction of `config.bidders` bidders and `config.levels`
/// price levels that fails with probability at most `2^-config.failure_bits`.
///
/// The ring dimensions are tried in increasing order and the first set wins, as in `bfv_search`.
/// At each ring dimension the plaintext modulus is the smallest that serves the auction.
pub fn auction_search(config: &AuctionSearchConfig) -> BfvParamsResult<AuctionSearchResult> {
    let invalid = |reason: &str| -> BfvParamsResult<AuctionSearchResult> {
        Err(ValidationError::InvalidAuction {
            reason: reason.to_string(),
        }
        .into())
    };
    if config.bidders < 2 {
        return invalid("an auction needs two or more bidders");
    }
    if config.levels == 0 {
        return invalid("an auction needs one or more price levels");
    }
    if config.failure_bits == 0 || config.failure_bits > 256 {
        return invalid("failure_bits must be in 1..=256");
    }
    let slots = config.bidders as u64 * config.levels as u64;
    if slots > D_POW2_MAX {
        return invalid("bidders * levels exceeds the largest ring dimension (32768)");
    }

    let ring_dims: Vec<u64> = match config.d {
        Some(d) => {
            if !d.is_power_of_two() || !(8..=D_POW2_MAX).contains(&d) {
                return Err(ValidationError::InvalidRingDimension { d }.into());
            }
            if slots > d {
                return invalid("bidders * levels exceeds the ring dimension");
            }
            vec![d]
        }
        None => std::iter::successors(Some(RING_DIM), |d| Some(d << 1))
            .take_while(|d| *d <= D_POW2_MAX)
            .filter(|d| slots <= *d)
            .collect(),
    };

    let (mut modulus_fits, mut relin_dominates) = (false, false);
    for d in ring_dims {
        // A plaintext modulus that is also a ciphertext modulus is not coprime to q. It is
        // skipped, and the next prime is taken.
        let mut excluded = HashSet::new();
        while let Some(k) =
            plaintext_modulus(d, slots, config.bidders, config.failure_bits, &excluded)
        {
            modulus_fits = true;
            let non_residue = smallest_non_residue(k);
            let (bfv_config, bfv, b_c_auction) = match search_modulus(config, d, k, non_residue)? {
                ModulusSearch::Found(found) => *found,
                ModulusSearch::NoSet => break,
                ModulusSearch::RelinearizationDominates => {
                    relin_dominates = true;
                    break;
                }
            };
            if bfv
                .selected_primes
                .iter()
                .any(|p| p.value == BigUint::from(k))
            {
                excluded.insert(k);
                continue;
            }
            let failure_log2 = (slots as f64).log2() - 2.0 * (k as f64).log2();
            return Ok(AuctionSearchResult {
                z: bfv_config.z,
                bfv,
                bfv_config,
                plaintext_modulus: k,
                non_residue,
                mult_depth: AUCTION_MULT_DEPTH,
                slots,
                failure_log2,
                b_c_auction,
            });
        }
    }

    if !modulus_fits {
        return invalid("the failure probability needs a plaintext modulus above 62 bits");
    }
    if relin_dominates {
        return Err(SearchError::RelinearizationDominates.into());
    }
    Err(SearchError::NoFeasibleParameters.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_bfv_params_arc;
    use crate::constants::defaults::{DEFAULT_INSECURE_LAMBDA, DEFAULT_SECURE_16384_LAMBDA};
    use crate::constants::search_defaults::{B, B_CHI, SEARCH_N};
    use crate::search::constants::{DEFAULT_MIN_PRIME_BITS, MIN_MARGIN_BITS};
    use crate::search::security::max_log2_q;
    use crate::search::utils::{log2_big, variance_uniform_sym};

    /// A λ at which the fresh noise at d = 128 is large enough for the formula of fhe.rs to
    /// cover the auction with a small z.
    const SMALL_RING_LAMBDA: u32 = 40;

    fn config(bidders: u32, levels: u32, failure_bits: u32) -> AuctionSearchConfig {
        AuctionSearchConfig {
            bidders,
            levels,
            failure_bits,
            n: SEARCH_N,
            lambda: DEFAULT_SECURE_16384_LAMBDA as u32,
            b: B,
            b_chi: B_CHI,
            min_margin: MIN_MARGIN_BITS,
            d: None,
            insecure: false,
            min_prime_bits: DEFAULT_MIN_PRIME_BITS,
            verbose: false,
        }
    }

    /// The properties every result must have, whatever the inputs.
    fn check(config: &AuctionSearchConfig, result: &AuctionSearchResult) {
        let k = result.plaintext_modulus;
        let d = result.bfv.d;
        assert!(is_prime_u64(k));
        assert_eq!(k % (2 * d), 1, "k must be 1 mod 2d for SIMD");
        assert!(result.slots <= d);
        assert!(k as u128 > config.bidders as u128 * (config.bidders as u128 - 1));
        // slots / k^2 <= 2^-failure_bits
        assert!(
            BigUint::from(k) * BigUint::from(k)
                >= BigUint::from(result.slots) << config.failure_bits
        );
        assert!(result.failure_log2 <= -(config.failure_bits as f64) + 1e-9);
        assert_eq!(pow_mod(result.non_residue, (k - 1) / 2, k), k - 1);
        assert!(result
            .bfv
            .selected_primes
            .iter()
            .all(|p| p.value != BigUint::from(k)));

        // The bound of fhe.rs for `z` is the one of the search, and it covers the auction.
        assert_eq!(result.bfv.k_plain_eff, k as u128);
        assert!(result.z <= k as u128);
        assert_eq!(result.bfv_config.z, result.z);
        assert_eq!(result.bfv.mult_depth, AUCTION_MULT_DEPTH);
        assert_eq!(
            runtime_noise_bound(config, &result.bfv, result.z),
            result.bfv.b_c_final
        );
        assert!(result.bfv.b_c_final >= result.b_c_auction);
        assert_eq!(
            result.b_c_auction,
            auction_noise_bound(config, &result.bfv, result.non_residue)
        );

        // Correctness with the margin, and the security limit.
        assert!(result.bfv.rhs_log2 - result.bfv.lhs_log2 >= config.min_margin);
        if !config.insecure {
            let limit = max_log2_q(config.b, config.b_chi, d).0;
            assert!(log2_big(&result.bfv.q_bfv) <= limit);
        }
    }

    #[test]
    fn miller_rabin_agrees_with_trial_division() {
        let slow = |n: u64| {
            n >= 2
                && (2..)
                    .take_while(|i| i * i <= n)
                    .all(|i| !n.is_multiple_of(i))
        };
        for n in 0..20_000u64 {
            assert_eq!(is_prime_u64(n), slow(n), "n = {n}");
        }
        // Carmichael numbers, a strong pseudoprime to the bases 2, 3, 5 and 7, and large primes.
        for composite in [561u64, 41041, 825265, 3215031751, 0xffff_ffff_ffff_ffff] {
            assert!(!is_prime_u64(composite), "{composite}");
        }
        for prime in [
            257u64,
            65537,
            12451841,
            140737488486401,
            0xffff_ffff_ffff_ffc5,
        ] {
            assert!(is_prime_u64(prime), "{prime}");
        }
    }

    #[test]
    fn the_norm_is_zero_only_at_zero_and_uniform_elsewhere() {
        // mask = S1^2 - c S2^2 over every pair (S1, S2) mod k: zero once, and every other value
        // k + 1 times.
        for k in [17u64, 97, 257, 769] {
            let c = smallest_non_residue(k);
            let mut counts = vec![0u64; k as usize];
            for s1 in 0..k {
                for s2 in 0..k {
                    counts[((s1 * s1 + (k - c) * (s2 * s2 % k)) % k) as usize] += 1;
                }
            }
            assert_eq!(counts[0], 1, "k = {k}");
            assert!(counts[1..].iter().all(|&count| count == k + 1), "k = {k}");
        }
    }

    #[test]
    fn three_is_the_non_residue_of_the_usual_moduli() {
        for k in [257u64, 65537, 12451841] {
            assert_eq!(smallest_non_residue(k), 3, "k = {k}");
        }
        // 3 is a square mod 786433, and the search takes the next non-residue.
        assert_eq!(smallest_non_residue(786433), 5);
    }

    #[test]
    fn the_plaintext_modulus_is_the_smallest_that_serves_the_auction() {
        let none = HashSet::new();
        // 8 bidders, 16 levels, 2^-40: k^2 >= 2^47.
        assert_eq!(plaintext_modulus(16384, 128, 8, 40, &none), Some(12451841));
        // A loose target stops at the smallest SIMD modulus of the ring dimension.
        assert_eq!(plaintext_modulus(16384, 128, 8, 20, &none), Some(65537));
        assert_eq!(plaintext_modulus(128, 128, 8, 9, &none), Some(257));
        // An excluded modulus is skipped.
        let excluded = HashSet::from([12451841u64]);
        let next = plaintext_modulus(16384, 128, 8, 40, &excluded).unwrap();
        assert!(next > 12451841 && is_prime_u64(next) && next % 32768 == 1);
        // k^2 >= 128 * 2^130 needs 69 bits.
        assert_eq!(plaintext_modulus(16384, 128, 8, 130, &none), None);
    }

    #[test]
    fn eight_bidders_and_sixteen_levels_fit_six_primes_at_16384() {
        let config = config(8, 16, 40);
        let result = auction_search(&config).unwrap();
        check(&config, &result);
        assert_eq!(result.bfv.d, 16384);
        assert_eq!(result.plaintext_modulus, 12451841);
        assert_eq!(result.non_residue, 3);
        assert_eq!(result.slots, 128);
        assert_eq!(result.bfv.selected_primes.len(), 6);
        eprintln!(
            "8 x 16, 2^-40: d = {}, k = {}, z = {}, {} x {}-bit, log2 q = {:.1}, margin {:.2}",
            result.bfv.d,
            result.plaintext_modulus,
            result.z,
            result.bfv.selected_primes.len(),
            result.bfv.selected_primes[0].bitlen,
            log2_big(&result.bfv.q_bfv),
            result.bfv.rhs_log2 - result.bfv.lhs_log2,
        );
    }

    #[test]
    fn other_shapes_and_targets_have_a_set() {
        for (bidders, levels, failure_bits) in [
            (2, 16, 40),
            (4, 16, 40),
            (8, 16, 20),
            (8, 64, 40),
            (16, 32, 30),
            (32, 128, 40),
            (8, 16, 60),
            (8, 16, 80),
            (64, 256, 40),
        ] {
            let config = config(bidders, levels, failure_bits);
            let result = auction_search(&config)
                .unwrap_or_else(|e| panic!("{bidders} x {levels}, 2^-{failure_bits}: {e}"));
            check(&config, &result);
            eprintln!(
                "{bidders} x {levels}, 2^-{failure_bits}: d = {}, k = {} (2^{:.1}), c = {}, z = {}, {} x {}-bit, log2 q = {:.1}, margin {:.2}",
                result.bfv.d,
                result.plaintext_modulus,
                (result.plaintext_modulus as f64).log2(),
                result.non_residue,
                result.z,
                result.bfv.selected_primes.len(),
                result.bfv.selected_primes[0].bitlen,
                log2_big(&result.bfv.q_bfv),
                result.bfv.rhs_log2 - result.bfv.lhs_log2,
            );
        }
    }

    #[test]
    fn a_stricter_target_never_shrinks_the_modulus() {
        let mut last = (0u64, 0.0f64);
        for failure_bits in [20, 30, 40, 50, 60] {
            let config = config(8, 16, failure_bits);
            let result = auction_search(&config).unwrap();
            let q_bits = log2_big(&result.bfv.q_bfv);
            assert!(result.plaintext_modulus >= last.0);
            assert!(q_bits >= last.1 - 1e-9);
            last = (result.plaintext_modulus, q_bits);
        }
    }

    #[test]
    fn the_smudging_bound_is_the_one_fhe_rs_computes() {
        let config = config(8, 16, 40);
        let result = auction_search(&config).unwrap();
        let error1_variance = variance_uniform_sym(&result.bfv.benc_min).to_str_radix(10);
        let params = build_bfv_params_arc(
            result.bfv.d as usize,
            result.plaintext_modulus,
            &result.bfv.qi_values(),
            Some(&error1_variance),
        );
        // fhe.rs also checks 2 (B_C + n B_sm) < Δ when it builds the generator.
        let fhe_b_sm = crate::smudging::calculate_smudging_bound(
            params,
            config.n as usize,
            result.z as usize,
            result.mult_depth,
            config.lambda as usize,
        )
        .unwrap();
        assert_eq!(result.bfv.b_sm_min, fhe_b_sm);
    }

    #[test]
    fn a_small_ring_dimension_takes_257() {
        // d = 128 with 9 parties, as the insecure SIMD preset of the example, but with a λ at
        // which the formula of fhe.rs covers the auction. The degree makes the set insecure.
        let mut config = config(8, 16, 9);
        config.d = Some(128);
        config.insecure = true;
        config.n = 9;
        config.lambda = SMALL_RING_LAMBDA;
        let result = auction_search(&config).unwrap();
        check(&config, &result);
        assert_eq!(result.plaintext_modulus, 257);
        assert_eq!(result.non_residue, 3);
        assert_eq!(result.bfv.d, 128);
        eprintln!(
            "d = 128, λ = {SMALL_RING_LAMBDA}: z = {}, {} x {}-bit, log2 q = {:.1}",
            result.z,
            result.bfv.selected_primes.len(),
            result.bfv.selected_primes[0].bitlen,
            log2_big(&result.bfv.q_bfv),
        );
    }

    #[test]
    fn says_when_the_relinearization_noise_dominates() {
        // λ = 2 at d = 128: the fresh noise is far below the relinearization noise, and the
        // formula of fhe.rs has no z that reaches the bound of the auction.
        let mut config = config(8, 16, 9);
        config.d = Some(128);
        config.insecure = true;
        config.n = 9;
        config.lambda = DEFAULT_INSECURE_LAMBDA as u32;
        let error = auction_search(&config).unwrap_err().to_string();
        assert!(error.contains("relinearization noise dominates"), "{error}");
    }

    #[test]
    fn rejects_inputs_it_cannot_serve() {
        let message =
            |config: AuctionSearchConfig| auction_search(&config).unwrap_err().to_string();
        assert!(message(config(1, 16, 40)).contains("two or more bidders"));
        assert!(message(config(8, 0, 40)).contains("price levels"));
        assert!(message(config(8, 16, 0)).contains("failure_bits"));
        assert!(message(config(1024, 64, 40)).contains("largest ring dimension"));
        assert!(message(config(8, 16, 130)).contains("above 62 bits"));
        let mut small_ring = config(64, 256, 40);
        small_ring.d = Some(8192);
        assert!(message(small_ring).contains("exceeds the ring dimension"));
        let mut odd_ring = config(8, 16, 40);
        odd_ring.d = Some(12000);
        assert!(message(odd_ring).contains("ring dimension"));
    }
}
