// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Search Library
//!
//! Searches for BFV (Brakerski–Fan–Vercauteren) parameters over the fixed
//! ring dimension N = 16384 using NTT-friendly CRT primes. The first parameter
//! set models multiplicative depth (`z` is the total circuit depth) with a
//! relinearization-noise recursion (Proposition 20 of the White Paper), and the
//! second set satisfies the centered-RNS "large gap" rule `qi > 2·max_qi_first`.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

use crate::search::constants::{K_MAX, RING_DIM, TARGET_NUM_PRIMES};
use crate::search::errors::{BfvParamsResult, SearchError, ValidationError};
use crate::search::prime::{build_prime_items, build_prime_items_for_second};
use crate::search::prime::{group_by_bits, has_duplicate_primes, PrimeItem};
use crate::search::utils::{log2_big, product};

/// Fixed ring dimension used for both parameter sets.
const D: u64 = RING_DIM;

/// Minimum prime bit-size for the first set.
const FIRST_MIN_PRIME_BITS: u8 = 50;
/// Maximum prime bit-size for the first set.
const FIRST_MAX_PRIME_BITS: u8 = 62;

/// Minimum prime bit-size for the second set.
const SECOND_MIN_PRIME_BITS: u8 = 50;
/// Maximum prime bit-size for the second set.
const SECOND_MAX_PRIME_BITS: u8 = 62;
/// Target number of primes for the second set.
const SECOND_TARGET_NUM_PRIMES: usize = 2;
/// Maximum number of primes to try for the second set.
const SECOND_MAX_NUM_PRIMES: usize = 8;

/// Configuration for BFV parameter search.
#[derive(Debug, Clone)]
pub struct BfvSearchConfig {
    /// Number of parties n (e.g. ciphernodes).
    pub n: u128,
    /// Number of fresh-ciphertext additions z summed before the multiplicative
    /// circuit (e.g. number of votes). This scales the additive `B_C^0` term
    /// and caps the plaintext space (`k_plain_eff = max(k, z)`).
    pub z: u128,
    /// Plaintext modulus k (plaintext space).
    pub k: u128,
    /// Statistical security parameter λ (negl(λ) = 2^{-λ}).
    pub lambda: u32,
    /// Total multiplicative circuit depth applied by the Prop. 20 recursion.
    pub mult_depth: u32,
    /// Bound B on the error distribution ψ (e.g. 20 for CBD with σ ≈ 3.2).
    pub b: u128,
    /// Bound B_χ on the secret-key distribution χ.
    pub b_chi: u128,
    /// Minimum correctness margin in bits (log2(Δ) − log2(LHS)).
    pub min_margin: f64,
    /// Verbose per-candidate logging.
    pub verbose: bool,
}

/// Result of BFV parameter search.
#[derive(Debug, Clone)]
pub struct BfvSearchResult {
    /// Chosen degree and primes.
    pub d: u64,
    /// Effective plaintext space (max of user k and z).
    pub k_plain_eff: u128,
    /// Ciphertext modulus q.
    pub q_bfv: BigUint,
    /// Selected CRT primes.
    pub selected_primes: Vec<PrimeItem>,
    /// q mod k.
    pub rkq: u128,
    /// Δ = ⌊q/k⌋.
    pub delta: BigUint,

    /// Noise budgets.
    pub benc_min: BigUint,
    pub b_fresh: BigUint,
    /// B_C after `z` additions (before multiplication) for the first set.
    pub b_c: BigUint,
    /// B_C after `mult_depth` levels of mult + relin (first set; = B_C if no mult).
    pub b_c_final: BigUint,
    /// 2^{λ+1}·d·B_C (first-set smudging bound).
    pub b_sm_min: BigUint,
    /// Relinearization noise bound from Eq. (30) (zero if no mult).
    pub b_relin: BigUint,
    /// Total multiplicative depth ⌈log2(z)⌉ (first set), 0 for the second set.
    pub mult_depth: u32,

    /// Validation logs.
    pub lhs_log2: f64,
    pub rhs_log2: f64,
}

impl BfvSearchResult {
    /// Extract prime values as u64 for BFV parameter construction.
    pub fn qi_values(&self) -> Vec<u64> {
        self.selected_primes
            .iter()
            .map(|p| p.value.to_u64().expect("Prime value too large for u64"))
            .collect()
    }
}

/// Search for the first BFV parameter set over the fixed ring dimension N=16384.
pub fn bfv_search(first: &BfvSearchConfig) -> BfvParamsResult<BfvSearchResult> {
    if first.z == 0 || first.z > K_MAX {
        return Err(ValidationError::InvalidVotes {
            z: first.z,
            reason: "z must be positive and at most 1_000_000".to_string(),
        }
        .into());
    }

    let prime_items = build_prime_items();
    match bfv_search_first(first, &prime_items) {
        Some(res) => Ok(res),
        None => Err(SearchError::NoFeasibleParameters.into()),
    }
}

/// Search for the first BFV parameter set (fixed d = 16384, exactly 5 primes).
pub fn bfv_search_first(
    config: &BfvSearchConfig,
    prime_items: &[PrimeItem],
) -> Option<BfvSearchResult> {
    if config.z == 0 {
        eprintln!("ERROR: number of votes z must be positive.");
        return None;
    }

    let d = D;
    let log2_b = (config.b as f64).log2();
    let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

    let min_log2_q = calculate_min_q_bits(config, d);

    if config.verbose {
        println!("\n[BFV-1st] Fixed d={d}");
        println!("  Security limit: log2(q) <= {log2_q_limit:.1}");
        println!("  Correctness requires: log2(q) >= {min_log2_q:.1}");
    }

    let by_bits = group_by_bits(prime_items, false);

    if config.verbose {
        for bb in FIRST_MIN_PRIME_BITS..=FIRST_MAX_PRIME_BITS {
            if let Some(bucket) = by_bits.get(&bb) {
                let max_log2 = bucket.first().map(|p| p.log2).unwrap_or(0.0);
                let min_log2 = bucket.last().map(|p| p.log2).unwrap_or(0.0);
                println!(
                    "  {bb}-bit bucket: {} primes, log2 range [{min_log2:.2}, {max_log2:.2}]",
                    bucket.len()
                );
            }
        }
    }

    for num_primes in TARGET_NUM_PRIMES..=TARGET_NUM_PRIMES {
        if config.verbose {
            println!("\n  === Trying {num_primes} primes ===");
        }

        for bb in FIRST_MIN_PRIME_BITS..=FIRST_MAX_PRIME_BITS {
            let bucket = match by_bits.get(&bb) {
                Some(b) => b,
                None => continue,
            };

            if bucket.len() < num_primes {
                if config.verbose {
                    println!(
                        "  {num_primes} × {bb}-bit: only {} primes available (need {num_primes})",
                        bucket.len()
                    );
                }
                continue;
            }

            let sel: Vec<PrimeItem> = bucket.iter().take(num_primes).cloned().collect();

            let q = product(sel.iter().map(|pi| pi.value.clone()));
            let q_bits = log2_big(&q);
            let max_qi_log2 = sel.iter().map(|p| p.log2).fold(0.0_f64, f64::max);

            if q_bits < min_log2_q {
                if config.verbose {
                    println!(
                        "  {num_primes} × {bb}-bit: log2(q)={q_bits:.2} < {min_log2_q:.1} needed, skipping"
                    );
                }
                continue;
            }

            if q_bits > log2_q_limit {
                if config.verbose {
                    println!(
                        "  {num_primes} × {bb}-bit: log2(q)={q_bits:.2} > {log2_q_limit:.1} security limit, skipping"
                    );
                }
                continue;
            }

            if let Some(res) = finalize_first_param(config, d, sel.clone(), config.verbose) {
                if config.verbose {
                    println!(
                        "\n✓ Found first set: {num_primes} × {bb}-bit primes, log2(q)={q_bits:.2}, max_qi={max_qi_log2:.2}"
                    );
                }
                return Some(res);
            } else if config.verbose {
                println!(
                    "  {num_primes} × {bb}-bit: log2(q)={q_bits:.2} ❌ fails correctness or margin < {:.1} bits",
                    config.min_margin
                );
            }
        }
    }

    eprintln!("\nERROR: No valid first parameter set found");
    None
}

/// Total multiplicative depth: the search models the circuit depth directly.
fn total_mult_depth(config: &BfvSearchConfig) -> u32 {
    config.mult_depth
}

/// Relinearization noise bound from Eq. (30):
/// `||e_relin|| ≤ N·l·||sk||·B_g·B + 2·N²·l²·||sk||²·B_g·B`
/// where `||sk||_∞ = n_sk_norm = n · B_χ`.
fn compute_b_relin(d: u64, l: u64, n_sk_norm: &BigUint, b_g: &BigUint, b: u128) -> BigUint {
    let d_big = BigUint::from(d);
    let l_big = BigUint::from(l);
    let b_big = BigUint::from(b);
    let term1 = &d_big * &l_big * n_sk_norm * b_g * &b_big;
    let term2 = BigUint::from(2u32)
        * &d_big
        * &d_big
        * &l_big
        * &l_big
        * n_sk_norm
        * n_sk_norm
        * b_g
        * &b_big;
    term1 + term2
}

/// Apply the Proposition 20 noise recursion for `depth` levels of BFV mult+relin:
/// `B_C^(i+1) = k · N² · ||sk|| · 2 · B_C^(i) + B_relin`.
/// Returns (b_c_final, b_relin); b_relin is zero when depth == 0.
#[allow(clippy::too_many_arguments)]
fn apply_mult_recursion(
    b_c_init: &BigUint,
    depth: u32,
    k: u128,
    d: u64,
    l: u64,
    n_sk_norm: &BigUint,
    b_g: &BigUint,
    b: u128,
) -> (BigUint, BigUint) {
    if depth == 0 {
        return (b_c_init.clone(), BigUint::zero());
    }
    let b_relin = compute_b_relin(d, l, n_sk_norm, b_g, b);
    let k_big = BigUint::from(k);
    let d_big = BigUint::from(d);
    // Prop. 20 first-term coefficient: k · N² · ||sk|| · 2.
    let coeff = BigUint::from(2u32) * &k_big * &d_big * &d_big * n_sk_norm;
    let mut b_c = b_c_init.clone();
    for _ in 0..depth {
        b_c = &coeff * &b_c + &b_relin;
    }
    (b_c, b_relin)
}

/// Minimum log2(q) needed for correctness (conservative pruning lower bound).
fn calculate_min_q_bits(config: &BfvSearchConfig, d: u64) -> f64 {
    let two_pow_lambda = BigUint::one() << config.lambda;

    let benc_min = BigUint::from(2u32)
        * BigUint::from(d)
        * BigUint::from(config.n)
        * BigUint::from(config.b)
        * BigUint::from(config.b_chi)
        * &two_pow_lambda;

    // d·||e^(ek)||·B_χ + d·B·||sk||: e^(ek) and sk are each n-term sums (DKG Eq. 3),
    // so both terms scale with n.
    let term_dn_bb_chi = BigUint::from(d)
        * BigUint::from(config.b)
        * BigUint::from(config.b_chi)
        * BigUint::from(config.n);
    let b_fresh = &benc_min + &term_dn_bb_chi + &term_dn_bb_chi;

    let b_c_agg = BigUint::from(config.z) * &b_fresh;

    let depth = total_mult_depth(config);
    let n_sk_norm = BigUint::from(config.n * config.b_chi);
    // Conservative B_g underestimate (2^FIRST_MIN_PRIME_BITS) avoids pruning valid candidates.
    let b_g_conservative = BigUint::one() << FIRST_MIN_PRIME_BITS;
    let k_eff = config.k.max(config.z);
    let (b_c_final, _) = apply_mult_recursion(
        &b_c_agg,
        depth,
        k_eff,
        d,
        TARGET_NUM_PRIMES as u64,
        &n_sk_norm,
        &b_g_conservative,
        config.b,
    );

    let b_sm_min = &b_c_final * (&two_pow_lambda << 1u32) * BigUint::from(d);
    let lhs = (&b_c_final + BigUint::from(config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);

    let log2_k = (k_eff as f64).log2();
    lhs_log2 + log2_k
}

/// Finalize and verify the first parameter set.
pub fn finalize_first_param(
    config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
    verbose: bool,
) -> Option<BfvSearchResult> {
    if has_duplicate_primes(&chosen) {
        return None;
    }

    let q_bfv = product(chosen.iter().map(|pi| pi.value.clone()));
    let k_plain_eff = config.k.max(config.z);
    let k_big = BigUint::from(k_plain_eff);

    let rkq: u128 = (&q_bfv % &k_big).to_u128().unwrap_or(0);
    let delta = &q_bfv / &k_big;

    let two_pow_lambda = BigUint::one() << config.lambda;

    let benc_min = BigUint::from(2u32)
        * BigUint::from(d)
        * BigUint::from(config.n)
        * BigUint::from(config.b)
        * BigUint::from(config.b_chi)
        * &two_pow_lambda;

    let term_dn_bb_chi = BigUint::from(d)
        * BigUint::from(config.b)
        * BigUint::from(config.b_chi)
        * BigUint::from(config.n);
    let b_fresh = &benc_min + &term_dn_bb_chi + &term_dn_bb_chi;

    let b_c = BigUint::from(config.z) * (&b_fresh + BigUint::from(rkq));

    // Multiplication noise: B_g = max prime (RNS gadget), l = number of primes.
    let depth = total_mult_depth(config);
    let l = chosen.len() as u64;
    let b_g = chosen
        .iter()
        .map(|p| p.value.clone())
        .max()
        .unwrap_or_else(BigUint::zero);
    let n_sk_norm = BigUint::from(config.n * config.b_chi);
    let (b_c_final, b_relin) =
        apply_mult_recursion(&b_c, depth, k_plain_eff, d, l, &n_sk_norm, &b_g, config.b);

    let b_sm_min = &b_c_final * (&two_pow_lambda << 1u32) * BigUint::from(d);
    let lhs = (&b_c_final + BigUint::from(config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);

    let margin = rhs_log2 - lhs_log2;
    let ok = lhs < delta && margin >= config.min_margin;

    if verbose {
        if depth > 0 {
            println!(
                "    mult_depth={depth}, log2(B_relin)={:.2}, log2(B_C_final)={:.2}",
                log2_big(&b_relin),
                log2_big(&b_c_final)
            );
        }
        println!(
            "    Detailed check: log2(LHS)={lhs_log2:.2}, log2(Δ)={rhs_log2:.2}, margin={margin:.2} bits => {}",
            if ok { "PASS" } else { "FAIL" }
        );
    }

    if !ok {
        return None;
    }

    Some(BfvSearchResult {
        d,
        k_plain_eff,
        q_bfv,
        selected_primes: chosen,
        rkq,
        delta,
        benc_min,
        b_fresh,
        b_c: b_c.clone(),
        b_c_final,
        b_sm_min,
        b_relin,
        mult_depth: depth,
        lhs_log2,
        rhs_log2,
    })
}

/// Search for the second BFV parameter set.
///
/// k_second = max(qi_first); the centered-RNS rule requires every second-set
/// prime `qi > 2·max_qi_first` (large gap), and second-set primes must be
/// disjoint from the first set. The smallest valid primes are chosen.
pub fn bfv_search_second_param(
    config: &BfvSearchConfig,
    first: &BfvSearchResult,
) -> Option<BfvSearchResult> {
    let d = first.d;

    let max_qi_first: BigUint = first
        .selected_primes
        .iter()
        .map(|pi| &pi.value)
        .max()
        .unwrap()
        .clone();
    let max_qi_bits = log2_big(&max_qi_first);

    let k_second: u128 = max_qi_first.to_u128().unwrap_or(u128::MAX);

    // fhe.rs centered RNS requires qi_second > 2·max(qi_first) to avoid
    // sign-flip errors in the centered-representation scaler.
    let min_qi_second = &max_qi_first << 1;
    let min_qi_log2 = log2_big(&min_qi_second);

    let log2_b = (config.b as f64).log2();
    let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

    if config.verbose {
        println!("\n[BFV-2nd] Fixed d={d}, k = max_qi_first = {k_second} ({max_qi_bits:.2} bits)");
        println!("  Minimum qi required: {min_qi_log2:.2} bits (fhe.rs centered RNS: qi > 2*k)");
        println!("  Security limit: log2(q) <= {log2_q_limit:.1}");
    }

    let prime_items = build_prime_items_for_second();
    let by_bits = group_by_bits(&prime_items, true);

    let first_set_primes: std::collections::HashSet<String> = first
        .selected_primes
        .iter()
        .map(|p| p.hex.clone())
        .collect();

    if config.verbose {
        for bb in SECOND_MIN_PRIME_BITS..=SECOND_MAX_PRIME_BITS {
            if let Some(bucket) = by_bits.get(&bb) {
                let available: Vec<_> = bucket
                    .iter()
                    .filter(|p| !first_set_primes.contains(&p.hex) && p.value > min_qi_second)
                    .collect();
                if !available.is_empty() {
                    let min_log2 = available.first().map(|p| p.log2).unwrap_or(0.0);
                    let max_log2 = available.last().map(|p| p.log2).unwrap_or(0.0);
                    println!(
                        "  {bb}-bit bucket: {} primes with qi > 2k, log2 range [{min_log2:.2}, {max_log2:.2}]",
                        available.len()
                    );
                }
            }
        }
    }

    for num_primes in SECOND_TARGET_NUM_PRIMES..=SECOND_MAX_NUM_PRIMES {
        if config.verbose {
            println!("\n  === Trying {num_primes} primes ===");
        }

        for bb in SECOND_MIN_PRIME_BITS..=SECOND_MAX_PRIME_BITS {
            let bucket = match by_bits.get(&bb) {
                Some(b) => b,
                None => continue,
            };

            let valid_primes: Vec<&PrimeItem> = bucket
                .iter()
                .filter(|pi| pi.value > min_qi_second && !first_set_primes.contains(&pi.hex))
                .collect();

            if valid_primes.len() < num_primes {
                if config.verbose {
                    println!(
                        "  {num_primes} × {bb}-bit: only {} valid primes with large gap (need {num_primes})",
                        valid_primes.len()
                    );
                }
                continue;
            }

            let sel: Vec<PrimeItem> = valid_primes
                .iter()
                .take(num_primes)
                .map(|pi| (*pi).clone())
                .collect();

            let q = product(sel.iter().map(|pi| pi.value.clone()));
            let q_bits = log2_big(&q);

            let min_selected = sel.iter().map(|p| &p.value).min().unwrap();
            let gap = min_selected - &max_qi_first;
            let gap_bits = log2_big(&gap);

            if config.verbose {
                println!(
                    "  {num_primes} × {bb}-bit: log2(q) = {q_bits:.2}, min gap = 2^{gap_bits:.1}"
                );
            }

            if let Some(res) = finalize_second_param(config, d, sel, k_second, config.verbose) {
                if config.verbose {
                    println!(
                        "\n✓ Found second set: {num_primes} × {bb}-bit, log2(q)={q_bits:.2}, gap=2^{gap_bits:.1}"
                    );
                }
                return Some(res);
            } else if config.verbose {
                println!("    ❌ Fails correctness check");
            }
        }
    }

    eprintln!("\nWARNING: No valid second parameter set found");
    eprintln!("  Consider: first set used primes with max = {max_qi_bits:.2} bits");
    eprintln!(
        "  Second set needs primes > 2*{} but max available is 62 bits",
        k_second
    );
    None
}

/// Finalize and verify the second parameter set with simplified noise bounds.
pub fn finalize_second_param(
    config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
    k_plain: u128,
    verbose: bool,
) -> Option<BfvSearchResult> {
    if has_duplicate_primes(&chosen) {
        return None;
    }

    let k_second_big = BigUint::from(k_plain);

    // Centered-RNS gap rule: every second-set prime must exceed 2·k.
    let min_qi_threshold = &k_second_big << 1;
    for pi in &chosen {
        if pi.value <= min_qi_threshold {
            if verbose {
                println!("    qi {} <= 2k (rejected)", pi.hex);
            }
            return None;
        }
    }

    let q_bfv = product(chosen.iter().map(|pi| pi.value.clone()));
    let rkq: u128 = (&q_bfv % &k_second_big).to_u128().unwrap_or(0);
    let delta = &q_bfv / &k_second_big;

    let benc = BigUint::from(config.b);
    let term_d_bb_chi = BigUint::from(d) * BigUint::from(config.b) * BigUint::from(config.b_chi);
    let b_fresh = &benc + &term_d_bb_chi + &term_d_bb_chi;
    // Include q mod t in the fresh-noise bound. The remainder is part of the
    // centered-RNS scaling error and must not be discarded in the second set.
    let b_c = &b_fresh + BigUint::from(rkq);

    // Correctness: 2·B_C < Δ.
    let lhs = &b_c << 1;
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);

    let margin = rhs_log2 - lhs_log2;
    let ok = lhs < delta && margin >= config.min_margin;

    if verbose {
        println!(
            "    Detailed: log2(2·B_C)={lhs_log2:.2}, log2(Δ)={rhs_log2:.2} => {}",
            if ok { "PASS" } else { "FAIL" }
        );
    }

    if !ok {
        return None;
    }

    Some(BfvSearchResult {
        d,
        k_plain_eff: k_plain,
        q_bfv,
        selected_primes: chosen,
        rkq,
        delta,
        benc_min: benc,
        b_fresh,
        b_c: b_c.clone(),
        b_c_final: b_c,
        b_sm_min: BigUint::zero(),
        b_relin: BigUint::zero(),
        mult_depth: 0,
        lhs_log2,
        rhs_log2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    fn create_test_config() -> BfvSearchConfig {
        BfvSearchConfig {
            n: 20,
            z: 3,
            k: 1000,
            lambda: 31,
            mult_depth: 3,
            b: 20,
            b_chi: 1,
            min_margin: 2.0,
            verbose: false,
        }
    }

    #[test]
    fn test_bfv_search_result_qi_values() {
        let primes = build_prime_items();
        assert!(!primes.is_empty());

        let test_primes = primes.iter().take(3).cloned().collect::<Vec<_>>();
        let result = BfvSearchResult {
            d: 512,
            k_plain_eff: 1000,
            q_bfv: product(test_primes.iter().map(|p| p.value.clone())),
            selected_primes: test_primes.clone(),
            rkq: 0,
            delta: BigUint::one(),
            benc_min: BigUint::one(),
            b_fresh: BigUint::one(),
            b_c: BigUint::one(),
            b_c_final: BigUint::one(),
            b_sm_min: BigUint::one(),
            b_relin: BigUint::one(),
            mult_depth: 0,
            lhs_log2: 0.0,
            rhs_log2: 0.0,
        };

        let qi_vals = result.qi_values();
        assert_eq!(qi_vals.len(), test_primes.len());
        for (i, val) in qi_vals.iter().enumerate() {
            assert_eq!(*val, test_primes[i].value.to_u64().unwrap());
        }
    }

    #[test]
    fn test_bfv_search_invalid_z_zero() {
        let mut config = create_test_config();
        config.z = 0;
        assert!(bfv_search(&config).is_err());
    }

    #[test]
    fn test_bfv_search_invalid_z_too_large() {
        let mut config = create_test_config();
        config.z = K_MAX + 1;
        assert!(bfv_search(&config).is_err());
    }

    #[test]
    fn test_bfv_search_mult_depth_3_feasible() {
        let config = create_test_config();
        let res = bfv_search(&config).expect("search succeeds for n=20 m=3 mult_depth=3 λ=31");
        assert_eq!(res.d, 16384);
        assert_eq!(res.mult_depth, 3);
        assert_eq!(res.selected_primes.len(), 5);
    }

    #[test]
    fn test_finalize_second_param_qi_gap() {
        let config = create_test_config();
        let primes = build_prime_items_for_second();
        assert!(!primes.is_empty());

        let k_plain = 1u128 << 50; // 2^50, requires primes > 2^51
        let d = 16384;
        let small = primes
            .iter()
            .filter(|p| p.bitlen == 50)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        if !small.is_empty() {
            let expected = small
                .iter()
                .all(|p| p.value > (BigUint::from(k_plain) << 1));
            let res = finalize_second_param(&config, d, small, k_plain, false);
            assert_eq!(res.is_some(), expected);
        }
    }
}
