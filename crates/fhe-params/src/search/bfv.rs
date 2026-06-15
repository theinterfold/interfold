// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Search Library
//!
//! This library provides functionality to search for optimal BFV (Brakerski-Fan-Vercauteren)
//! parameters using NTT-friendly primes. It implements exact arithmetic for security analysis
//! and parameter validation.
use std::collections::BTreeMap;

use crate::search::constants::{D_POW2_MAX, K_MAX};
use crate::search::errors::{BfvParamsResult, SearchError, ValidationError};
use crate::search::prime::PrimeItem;
use crate::search::prime::{
    build_prime_items, build_prime_items_for_second, select_max_q_under_cap,
};
use crate::search::utils::{approx_bits_from_log2, big_shift_pow2, log2_big, product};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::collections::HashSet;

/// Fixed ring dimension used for both parameter sets.
const RING_DIM: u64 = 8192;

/// First-set prime bit-size bounds. The 50-bit floor avoids the <0.2-bit
/// correctness margin of 49-bit primes; the 60-bit cap leaves 61/62-bit primes
/// for the second set (centered-RNS gap requirement).
const FIRST_MIN_PRIME_BITS: u8 = 50;
const FIRST_MAX_PRIME_BITS: u8 = 60;
const FIRST_TARGET_NUM_PRIMES: usize = 3;
const FIRST_MAX_NUM_PRIMES: usize = 6;

/// Second-set search bounds.
const SECOND_MIN_PRIME_BITS: u8 = 50;
const SECOND_MAX_PRIME_BITS: u8 = 62;
const SECOND_TARGET_NUM_PRIMES: usize = 2;
const SECOND_MAX_NUM_PRIMES: usize = 8;

/// Configuration for BFV parameter search
#[derive(Debug, Clone)]
pub struct BfvSearchConfig {
    /// Number of parties n (e.g. ciphernodes)
    pub n: u128,
    /// Number of fresh ciphertext additions z (number of votes) - equal to k_plain_eff.
    pub z: u128,
    /// Plaintext modulus k (plaintext space).
    pub k: u128,
    /// Statistical Security parameter λ (negl(λ)=2^{-λ})
    pub lambda: u32,
    /// Bound B on the error distribution ψ used generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    pub b: u128,
    /// Bound B_{\chi} on the distribution \chi used generate the secret key sk_i of each party i.
    pub b_chi: u128,
    /// Min supported margin.
    pub min_margin: f64,
    /// Verbose output showing detailed parameter search process
    pub verbose: bool,
}

/// Result of BFV parameter search
#[derive(Debug, Clone)]
pub struct BfvSearchResult {
    /// Chosen degree and primes
    pub d: u64,
    pub k_plain_eff: u128, // = z
    pub q_bfv: BigUint,
    pub selected_primes: Vec<PrimeItem>,
    pub rkq: u128,
    pub delta: BigUint,

    /// Noise budgets
    pub benc_min: BigUint,
    pub b_fresh: BigUint,
    pub b_c: BigUint,
    pub b_sm_min: BigUint,

    /// Validation logs
    pub lhs_log2: f64,
    pub rhs_log2: f64,
}

impl BfvSearchResult {
    /// Extract prime values as u64 for BFV parameter construction
    pub fn qi_values(&self) -> Vec<u64> {
        self.selected_primes
            .iter()
            .map(|p| p.value.to_u64().expect("Prime value too large for u64"))
            .collect()
    }
}

/// Search for optimal BFV parameters that satisfy all security constraints.
///
/// This function implements a search algorithm that:
/// 1. Iterates through polynomial degrees d (powers of 2)
/// 2. For each d, finds the maximum q under the Eq4 constraint
/// 3. Validates the candidate against Eq1 (noise bound)
/// 4. Refines the result by decreasing q to find the minimal valid parameters
///
/// Returns the first feasible parameter set found, or an error if none exist.
///
/// Note: Some resulting parameter sets from this search are hardcoded as presets
/// in the `presets.rs` file for production use (e.g., `BfvPreset::SecureThreshold8192`).
pub fn bfv_search(bfv_search_config: &BfvSearchConfig) -> BfvParamsResult<BfvSearchResult> {
    // Quick checks on k := z
    if bfv_search_config.z == 0 || bfv_search_config.z > K_MAX {
        return Err(ValidationError::InvalidVotes {
            z: bfv_search_config.z,
            reason: "z must be positive and less than 2^25".to_string(),
        }
        .into());
    }

    let verbose = bfv_search_config.verbose;
    let prime_items = build_prime_items();
    let log2_b = (bfv_search_config.b as f64).log2();

    // Buckets sorted DESCENDING within each bit-length (largest prime first), so
    // taking the first `num_primes` of a bucket maximises q for that prime size.
    let by_bits = group_by_bits_desc(&prime_items);

    // Show available buckets (pool is independent of d, so print once).
    if verbose {
        for bb in FIRST_MIN_PRIME_BITS..=FIRST_MAX_PRIME_BITS {
            if let Some(bucket) = by_bits.get(&bb) {
                let max_log2 = bucket.first().map(|p| p.log2).unwrap_or(0.0);
                let min_log2 = bucket.last().map(|p| p.log2).unwrap_or(0.0);
                println!(
                    "  {}-bit bucket: {} primes, log2 range [{:.2}, {:.2}]",
                    bb,
                    bucket.len(),
                    min_log2,
                    max_log2
                );
            }
        }
    }

    // Search increasing ring dimensions: start at RING_DIM and only step up when
    // no q satisfies both correctness (lower) and Eq4 security (upper) bounds at
    // the current d. A larger d raises the security limit far faster than the
    // correctness requirement, so high-λ requests resolve at a bigger ring.
    let mut d = RING_DIM;
    while d <= D_POW2_MAX {
        // Minimum log2(q) for correctness (Eq1); exact margin check is in finalize.
        let min_log2_q = calculate_min_q_bits(bfv_search_config, d);
        // Eq4 security upper bound: log2(q) <= log2(B) + (d-75)/37.5.
        let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

        if verbose {
            println!("\n[BFV-1st] d={d}");
            println!("  Security limit: log2(q) <= {log2_q_limit:.1}");
            println!("  Correctness requires: log2(q) >= {min_log2_q:.1}");
        }

        // Try the fewest primes first, then the smallest prime bit-size that
        // meets the correctness bound. This mirrors the reference bucket scan.
        for num_primes in FIRST_TARGET_NUM_PRIMES..=FIRST_MAX_NUM_PRIMES {
            if verbose {
                println!("\n  === Trying {num_primes} primes ===");
            }

            for bb in FIRST_MIN_PRIME_BITS..=FIRST_MAX_PRIME_BITS {
                let bucket = match by_bits.get(&bb) {
                    Some(b) => b,
                    None => continue,
                };

                if bucket.len() < num_primes {
                    if verbose {
                        println!(
                            "  {} × {}-bit: only {} primes available (need {})",
                            num_primes,
                            bb,
                            bucket.len(),
                            num_primes
                        );
                    }
                    continue;
                }

                // Take the largest `num_primes` primes in this bucket to maximise q.
                let sel: Vec<PrimeItem> = bucket.iter().take(num_primes).cloned().collect();
                let q = product(sel.iter().map(|pi| pi.value.clone()));
                let q_bits = log2_big(&q);
                let max_qi_log2 = sel.iter().map(|p| p.log2).fold(0.0_f64, f64::max);

                if q_bits < min_log2_q {
                    if verbose {
                        println!(
                            "  {} × {}-bit: log2(q)={:.2} < {:.1} needed, skipping",
                            num_primes, bb, q_bits, min_log2_q
                        );
                    }
                    continue;
                }

                // Eq4 security upper bound: reject any q exceeding the security limit.
                if q_bits > log2_q_limit {
                    if verbose {
                        println!(
                            "  {} × {}-bit: log2(q)={:.2} > {:.1} security limit, skipping",
                            num_primes, bb, q_bits, log2_q_limit
                        );
                    }
                    continue;
                }

                if let Some(res) = finalize_bfv_candidate(bfv_search_config, d, sel) {
                    if verbose {
                        println!(
                            "\n✓ Found first set: {} × {}-bit primes, d={}, log2(q)={:.2}, max_qi={:.2} bits",
                            num_primes, bb, d, q_bits, max_qi_log2
                        );
                    }
                    return Ok(res);
                } else if verbose {
                    println!(
                        "  {} × {}-bit: log2(q)={:.2} ❌ fails correctness or margin < {:.1} bits",
                        num_primes, bb, q_bits, bfv_search_config.min_margin
                    );
                }
            }
        }

        if verbose {
            println!("\n  no feasible set at d={d}; increasing ring dimension…");
        }
        d <<= 1;
    }

    if verbose {
        eprintln!("\nERROR: No valid first parameter set found");
    }
    Err(SearchError::NoFeasibleParameters.into())
}

/// Minimum log2(q) needed for correctness (Eq1), ignoring r_k(q).
///
/// finalize_bfv_candidate performs the exact check (including r_k(q) and the
/// margin); this is only used to prune prime selections that are too small.
fn calculate_min_q_bits(bfv_search_config: &BfvSearchConfig, d: u64) -> f64 {
    let two_pow_lambda = big_shift_pow2(bfv_search_config.lambda);

    let benc_min = (BigUint::from(2u32)
        * BigUint::from(d)
        * BigUint::from(bfv_search_config.n)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi))
        * &two_pow_lambda;

    let term_d_b_b_chi_n = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi)
        * BigUint::from(bfv_search_config.n);
    let b_fresh = &benc_min + &term_d_b_b_chi_n + &term_d_b_b_chi_n;

    let b_c = BigUint::from(bfv_search_config.z) * &b_fresh;
    let b_sm_min = &b_c * &two_pow_lambda;

    let lhs = (&b_c + BigUint::from(bfv_search_config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);

    let log2_k = (bfv_search_config.k.max(bfv_search_config.z) as f64).log2();
    lhs_log2 + log2_k
}

/// Group primes by bit-length, sorting each bucket descending by value.
fn group_by_bits_desc(prime_items: &[PrimeItem]) -> BTreeMap<u8, Vec<PrimeItem>> {
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in prime_items {
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }
    by_bits
}

/// Validate a candidate parameter set and compute all noise bounds.
///
/// Computes noise budgets (B_Enc, B_fresh, B_C, B_sm) and checks if Eq1 is satisfied:
/// 2*(B_C + n*B_sm) < Δ
///
/// Returns None if validation fails, otherwise returns the complete result.
pub fn finalize_bfv_candidate(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
) -> Option<BfvSearchResult> {
    let q_bfv = product(chosen.iter().map(|pi| pi.value.clone()));

    // Compute plaintext space: max of user-defined k and z
    let k_plain_eff: u128 = bfv_search_config.k.max(bfv_search_config.z);

    // r_k(q) = q mod k
    let k_big = BigUint::from(k_plain_eff);
    let rkq_big = &q_bfv % &k_big;
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);

    // Δ = floor(q / k)
    let delta = &q_bfv / &k_big;

    // Eq2: 2 d n B B_chi ≤ B_Enc * 2^{-λ}  =>  B_Enc ≥ (2 d n B B_chi) * 2^{λ}
    let two_pow_lambda = big_shift_pow2(bfv_search_config.lambda);
    let benc_min = (BigUint::from(2u32)
        * BigUint::from(d)
        * BigUint::from(bfv_search_config.n)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi))
        * &two_pow_lambda;

    // B_fresh ≤ B_Enc + d B B_chi n+ d B B_chi n
    let term_d_b_b_chi_n = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi)
        * BigUint::from(bfv_search_config.n);
    let b_fresh = &benc_min + &term_d_b_b_chi_n + &term_d_b_b_chi_n;

    // B_C = z (B_fresh + r_k(q))
    let b_c = BigUint::from(bfv_search_config.z) * (&b_fresh + BigUint::from(rkq));

    // Eq3: B_C ≤ B_sm * 2^{-λ}  =>  B_sm ≥ B_C * 2^{λ}
    let b_sm_min = &b_c * &two_pow_lambda;

    // Eq1: 2*(B_C + n*B_sm) < Δ
    let lhs = (&b_c + BigUint::from(bfv_search_config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);
    let margin = rhs_log2 - lhs_log2;

    if lhs >= delta || margin < bfv_search_config.min_margin {
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
        b_c,
        b_sm_min,
        lhs_log2,
        rhs_log2,
    })
}

/// Refine parameters by decreasing q in 2-bit steps from an initial feasible set.
///
/// Starting from a valid parameter set, this function decreases the bit size of q
/// by 2 bits per iteration, keeping the last passing configuration before the first failure.
/// This finds the minimal valid q for the given degree d.
pub fn refine_from_initial(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    initial_sel: Vec<PrimeItem>,
) -> Option<BfvSearchResult> {
    // Determine initial bits and then decrease by 2 bits per step.
    let initial_q = product(initial_sel.iter().map(|pi| pi.value.clone()));
    let mut current_bits = approx_bits_from_log2(log2_big(&initial_q));

    // Start with the initial feasible result
    let mut last_passing = finalize_bfv_candidate(bfv_search_config, d, initial_sel.clone())?;

    // Walk down in steps of 2 bits, keeping the last passing set before the first failure
    while current_bits > 40 {
        let target_bits = current_bits.saturating_sub(2);
        if let Some(res) =
            construct_qi_for_target_bits(bfv_search_config, d, prime_items, target_bits)
        {
            // Update last_passing to this new passing result
            last_passing = res;
            current_bits = target_bits;
            continue;
        } else {
            // Stop at the first failure; return the last passing result
            break;
        }
    }

    Some(last_passing)
}

/// Construct a CRT prime selection targeting a specific bit size for q.
///
/// Uses a greedy packing strategy: divides target bits by number of primes needed,
/// then tries combinations of floor/ceil bit-length buckets to get closest to target.
/// Validates the selection and returns a result if it passes Eq1.
pub fn construct_qi_for_target_bits(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    target_bits: u64,
) -> Option<BfvSearchResult> {
    // Build buckets sorted ascending (smallest first) to allow tight packing
    let mut by_bits_small: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    let mut by_bits_large: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in prime_items.iter() {
        by_bits_small.entry(p.bitlen).or_default().push(p.clone());
        by_bits_large.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits_small.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }
    for v in by_bits_large.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let target_f = target_bits as f64;

    // Compute the actual maximum bit length available in the prime buckets
    let max_bit = by_bits_small.keys().max().cloned().unwrap_or(61);

    // Fewest primes first: start from minimal s needed to reach target with max_bit primes
    let s = target_bits.div_ceil(max_bit as u64).max(2) as usize;

    let r_float = target_f / (s as f64);
    let floor_r = r_float.floor().clamp(40.0, max_bit as f64) as u8;
    let ceil_r = r_float.ceil().clamp(40.0, max_bit as f64) as u8;

    // Build candidate selections mixing floor/ceil buckets; choose best by closeness once
    let mut tried: Vec<Vec<PrimeItem>> = Vec::new();
    for k in 0..=s {
        let take_ceil = k;
        let take_floor = s - k;
        let mut sel: Vec<PrimeItem> = Vec::new();
        if take_floor > 0 {
            if let Some(b) = by_bits_small.get(&floor_r) {
                if b.len() < take_floor {
                    continue;
                }
                sel.extend(b.iter().take(take_floor).cloned());
            } else {
                continue;
            }
        }
        if take_ceil > 0 {
            if let Some(b) = by_bits_small.get(&ceil_r) {
                if b.len() < take_ceil {
                    continue;
                }
                sel.extend(b.iter().take(take_ceil).cloned());
            } else {
                continue;
            }
        }
        if sel.len() == s {
            tried.push(sel);
        }
    }
    // Also consider pure buckets
    if let Some(b) = by_bits_large.get(&floor_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }
    if let Some(b) = by_bits_large.get(&ceil_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }

    // Pick selection closest to target bits and test exactly once
    let mut best: Option<(f64, Vec<PrimeItem>)> = None;
    for sel in tried {
        let q = product(sel.iter().map(|pi| pi.value.clone()));
        let qbits = log2_big(&q);
        let diff = (qbits - target_f).abs();
        if let Some((best_diff, _)) = &best {
            if diff < *best_diff {
                best = Some((diff, sel));
            }
        } else {
            best = Some((diff, sel));
        }
    }
    if let Some((_, sel)) = best {
        // During decreasing, use plaintext from qi (not max with user k)
        return finalize_bfv_candidate(bfv_search_config, d, sel.clone());
    }

    None
}

/// Search for a second BFV parameter set with plaintext space derived from the first set.
///
/// The plaintext modulus k is set to the actual maximum qi value of the first set.
/// fhe.rs centered RNS requires every second-set qi > 2*k (the "large gap" rule),
/// and second-set primes must be disjoint from the first set. The smallest valid
/// primes (fewest and smallest) that satisfy correctness are chosen. Uses a
/// separate prime pool that includes 62-bit primes.
pub fn bfv_search_second_param(
    bfv_search_config: &BfvSearchConfig,
    first: &BfvSearchResult,
) -> Option<BfvSearchResult> {
    let d = first.d;

    // Plaintext space for second set: k = max qi of first set (actual value).
    let max_qi_first: BigUint = first
        .selected_primes
        .iter()
        .map(|pi| pi.value.clone())
        .max()
        .expect("first set has at least one prime");
    let k_second: u128 = max_qi_first.to_u128().unwrap_or(u128::MAX);

    let verbose = bfv_search_config.verbose;

    // Centered-RNS gap rule: qi > 2*k.
    let min_qi_second = &max_qi_first << 1;

    // Eq4 security upper bound: log2(q) <= log2(B) + (d-75)/37.5.
    let log2_b = (bfv_search_config.b as f64).log2();
    let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

    if verbose {
        println!(
            "\n[BFV-2nd] Fixed d={d}, k = max_qi_first = {k_second} ({:.2} bits)",
            log2_big(&max_qi_first)
        );
        println!(
            "  Minimum qi required: {:.2} bits (fhe.rs centered RNS: qi > 2*k)",
            log2_big(&min_qi_second)
        );
        println!("  Security limit: log2(q) <= {log2_q_limit:.1}");
    }

    let prime_items = build_prime_items_for_second();

    // Exclude primes already used by the first set.
    let first_set_primes: HashSet<String> = first
        .selected_primes
        .iter()
        .map(|p| p.hex.clone())
        .collect();

    // Buckets sorted ASCENDING within each bit-length (smallest prime first), so
    // taking the first valid `num_primes` minimises prime size.
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in &prime_items {
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }

    // Show available primes per bit-length (gap rule applied, first-set excluded).
    if verbose {
        for bb in SECOND_MIN_PRIME_BITS..=SECOND_MAX_PRIME_BITS {
            if let Some(bucket) = by_bits.get(&bb) {
                let available: Vec<&PrimeItem> = bucket
                    .iter()
                    .filter(|p| p.value > min_qi_second && !first_set_primes.contains(&p.hex))
                    .collect();
                if !available.is_empty() {
                    let min_log2 = available.first().map(|p| p.log2).unwrap_or(0.0);
                    let max_log2 = available.last().map(|p| p.log2).unwrap_or(0.0);
                    println!(
                        "  {}-bit bucket: {} primes with qi > 2k, log2 range [{:.2}, {:.2}]",
                        bb,
                        available.len(),
                        min_log2,
                        max_log2
                    );
                }
            }
        }
    }

    // Fewest primes first, then smallest prime bit-size.
    for num_primes in SECOND_TARGET_NUM_PRIMES..=SECOND_MAX_NUM_PRIMES {
        if verbose {
            println!("\n  === Trying {num_primes} primes ===");
        }

        for bb in SECOND_MIN_PRIME_BITS..=SECOND_MAX_PRIME_BITS {
            let bucket = match by_bits.get(&bb) {
                Some(b) => b,
                None => continue,
            };

            // Valid primes: satisfy the gap rule and not used by the first set.
            let valid: Vec<PrimeItem> = bucket
                .iter()
                .filter(|pi| pi.value > min_qi_second && !first_set_primes.contains(&pi.hex))
                .cloned()
                .collect();

            if valid.len() < num_primes {
                if verbose {
                    println!(
                        "  {} × {}-bit: only {} valid primes with large gap (need {})",
                        num_primes,
                        bb,
                        valid.len(),
                        num_primes
                    );
                }
                continue;
            }

            // Slide a window of `num_primes` over the ascending valid primes,
            // starting from the smallest (to minimise prime size). If the
            // smallest window fails the correctness/margin check, larger primes
            // in the same bucket give a larger Δ and may still pass with the
            // same CRT count, so keep trying before abandoning the bucket.
            for start in 0..=(valid.len() - num_primes) {
                let sel: Vec<PrimeItem> = valid[start..start + num_primes].to_vec();
                let q = product(sel.iter().map(|pi| pi.value.clone()));
                let q_bits = log2_big(&q);
                let min_selected = sel.iter().map(|p| &p.value).min().unwrap();
                let gap_bits = log2_big(&(min_selected - &max_qi_first));

                if verbose {
                    println!(
                        "  {} × {}-bit: log2(q) = {:.2}, min gap = 2^{:.1}",
                        num_primes, bb, q_bits, gap_bits
                    );
                }

                // Eq4 security upper bound: q grows monotonically with `start`,
                // so once it exceeds the security limit no later window can pass.
                if q_bits > log2_q_limit {
                    if verbose {
                        println!(
                            "    log2(q)={:.2} > {:.1} security limit, abandoning bucket",
                            q_bits, log2_q_limit
                        );
                    }
                    break;
                }

                if let Some(res) = finalize_second_param(bfv_search_config, d, sel, k_second) {
                    if verbose {
                        println!(
                            "\n✓ Found second set: {} × {}-bit, log2(q)={:.2}, gap=2^{:.1}",
                            num_primes, bb, q_bits, gap_bits
                        );
                    }
                    return Some(res);
                } else if verbose {
                    println!("    ❌ Fails correctness check");
                }
            }
        }
    }

    if verbose {
        eprintln!("\nWARNING: No valid second parameter set found");
    }
    None
}

/// Refine second parameter set at a fixed degree d by decreasing q.
///
/// Collects all passing candidates as q decreases, then selects the one with
/// the fewest primes (minimizing CRT overhead).
pub fn refine_second_param_at_d(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    log2_q_limit: f64,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    // Start from largest q under cap at this d and decrease by 2 bits, collecting all passing
    let initial_sel = select_max_q_under_cap(log2_q_limit, prime_items);
    if initial_sel.is_empty() {
        return None;
    }

    let initial_q = product(initial_sel.iter().map(|pi| pi.value.clone()));
    let mut current_bits = approx_bits_from_log2(log2_big(&initial_q));
    let mut all_passing: Vec<BfvSearchResult> = Vec::new();

    // Try the initial selection
    if let Some(res) = finalize_second_param(bfv_search_config, d, initial_sel.clone(), k_plain) {
        all_passing.push(res);
    }

    // Decrease by 2 bits at a time, continue even if some fail (don't stop at first failure)
    while current_bits > 40 {
        let target_bits = current_bits.saturating_sub(2);
        if let Some(res) =
            construct_qi_second_param(bfv_search_config, d, prime_items, target_bits, k_plain)
        {
            all_passing.push(res);
        }
        // Continue decreasing regardless of whether this target passed or failed
        current_bits = target_bits;
    }

    // Pick the one with fewest qi's among all passing at this d
    if all_passing.is_empty() {
        return None;
    }
    all_passing.sort_by(|a, b| {
        a.selected_primes.len().cmp(&b.selected_primes.len()).then(
            log2_big(&a.q_bfv)
                .partial_cmp(&log2_big(&b.q_bfv))
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    Some(all_passing.into_iter().next().unwrap())
}

/// Construct CRT prime selection for second parameter set targeting specific bit size.
///
/// Similar to `construct_qi_for_target_bits` but uses 62-bit primes and validates
/// that all qi are more than one bit larger than k_plain.
pub fn construct_qi_second_param(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    target_bits: u64,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    let mut by_bits_small: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    let mut by_bits_large: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in prime_items.iter() {
        by_bits_small.entry(p.bitlen).or_default().push(p.clone());
        by_bits_large.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits_small.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }
    for v in by_bits_large.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let target_f = target_bits as f64;
    let s = target_bits.div_ceil(62).max(2) as usize;
    let r_float = target_f / (s as f64);
    let floor_r = r_float.floor().clamp(40.0, 62.0) as u8;
    let ceil_r = r_float.ceil().clamp(40.0, 62.0) as u8;

    let mut tried: Vec<Vec<PrimeItem>> = Vec::new();
    for k in 0..=s {
        let take_ceil = k;
        let take_floor = s - k;
        let mut sel: Vec<PrimeItem> = Vec::new();
        if take_floor > 0 {
            if let Some(b) = by_bits_small.get(&floor_r) {
                if b.len() < take_floor {
                    continue;
                }
                sel.extend(b.iter().take(take_floor).cloned());
            } else {
                continue;
            }
        }
        if take_ceil > 0 {
            if let Some(b) = by_bits_small.get(&ceil_r) {
                if b.len() < take_ceil {
                    continue;
                }
                sel.extend(b.iter().take(take_ceil).cloned());
            } else {
                continue;
            }
        }
        if sel.len() == s {
            tried.push(sel);
        }
    }
    if let Some(b) = by_bits_large.get(&floor_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }
    if let Some(b) = by_bits_large.get(&ceil_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }

    // Prefer the smallest qualifying primes (minimise prime size), matching the
    // old behaviour of taking the smallest valid primes in the smallest bucket.
    let mut best: Option<(f64, Vec<PrimeItem>)> = None;
    for sel in tried {
        let q = product(sel.iter().map(|pi| pi.value.clone()));
        let qbits = log2_big(&q);
        if let Some((best_qbits, _)) = &best {
            if qbits < *best_qbits {
                best = Some((qbits, sel));
            }
        } else {
            best = Some((qbits, sel));
        }
    }
    if let Some((_, sel)) = best {
        return finalize_second_param(bfv_search_config, d, sel.clone(), k_plain);
    }
    None
}

/// Validate second parameter set with simplified noise bounds.
///
/// For the second set, uses B_Enc = B (simpler bound) and checks 2*B_C < Δ.
/// Also validates that all qi are more than one bit larger than k_plain.
pub fn finalize_second_param(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    // fhe.rs centered RNS requires qi > 2*k to avoid sign-flip errors in the
    // centered representation scaler (the "large gap" rule).
    let k_big = BigUint::from(k_plain);
    let min_qi_threshold = &k_big << 1; // 2 * k

    for pi in &chosen {
        if pi.value <= min_qi_threshold {
            return None;
        }
    }

    let q_bfv = product(chosen.iter().map(|pi| pi.value.clone()));
    let rkq_big = &q_bfv % &k_big;
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);
    let delta = &q_bfv / &k_big;

    // For second set: B_Enc = B (simpler), B_fresh = B_Enc + d*B*B_chi + d*B*B_chi
    let benc = BigUint::from(bfv_search_config.b);
    let term_d_bbchi = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi);
    let b_fresh = &benc + &term_d_bbchi + &term_d_bbchi;
    let b_c = b_fresh.clone(); // B_C = B_fresh

    let lhs = &b_c << 1; // 2*B_C
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);

    let margin = rhs_log2 - lhs_log2;
    if lhs >= delta || margin < bfv_search_config.min_margin {
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
        b_c,
        b_sm_min: BigUint::zero(), // not used in second set
        lhs_log2,
        rhs_log2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::prime::build_prime_items;
    use crate::search::prime::build_prime_items_for_second;
    use num_bigint::BigUint;
    use num_traits::One;

    fn create_test_config() -> BfvSearchConfig {
        BfvSearchConfig {
            n: 10,
            z: 1000,
            k: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            min_margin: 1.0,
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
            b_sm_min: BigUint::one(),
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

        let result = bfv_search(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_bfv_search_invalid_z_too_large() {
        let mut config = create_test_config();
        config.z = K_MAX + 1;

        let result = bfv_search(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_bfv_candidate_with_valid_primes() {
        let config = create_test_config();
        let primes = build_prime_items();
        assert!(!primes.is_empty());

        let test_primes = primes.iter().take(2).cloned().collect::<Vec<_>>();
        let d = 512;

        let result = finalize_bfv_candidate(&config, d, test_primes.clone());

        if let Some(res) = result {
            assert_eq!(res.d, d);
            assert_eq!(res.selected_primes.len(), test_primes.len());
            assert_eq!(res.k_plain_eff, config.z.max(config.k));
        }
    }

    #[test]
    fn test_finalize_bfv_candidate_empty_primes() {
        let config = create_test_config();
        let empty_primes = vec![];
        let d = 512;

        let result = finalize_bfv_candidate(&config, d, empty_primes);
        assert!(result.is_none());
    }

    #[test]
    fn test_finalize_second_param_qi_validation() {
        let config = create_test_config();
        let primes = build_prime_items_for_second();
        assert!(!primes.is_empty());

        // Test invalid case: primes too small for k_plain
        let small_primes = primes
            .iter()
            .filter(|p| p.bitlen <= 40)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();

        if !small_primes.is_empty() {
            let k_plain = 1u128 << 50; // 2^50, requires primes > 2^51
            let d = 512;
            let result = finalize_second_param(&config, d, small_primes, k_plain);
            // Primes with bitlen <= 40 are < 2^40 < 2^51, so should be rejected
            assert!(result.is_none());
        }

        // Test valid case: primes large enough for k_plain
        let large_primes = primes
            .iter()
            .filter(|p| p.bitlen > 50) // Large primes that can satisfy various k_plain values
            .take(2)
            .cloned()
            .collect::<Vec<_>>();

        if !large_primes.is_empty() {
            let k_plain = 1u128 << 30; // 2^30, requires primes > 2^31
            let d = 512;
            let result = finalize_second_param(&config, d, large_primes.clone(), k_plain);
            assert!(result.is_some());
            let res = result.unwrap();

            // Validate returned properties
            assert_eq!(res.d, d);
            assert_eq!(res.k_plain_eff, k_plain);
            assert_eq!(res.selected_primes.len(), large_primes.len());
            // Compare primes by their values since PrimeItem doesn't implement PartialEq
            for (returned, expected) in res.selected_primes.iter().zip(large_primes.iter()) {
                assert_eq!(returned.value, expected.value);
            }

            // Validate q_bfv is product of selected primes
            let expected_q = product(res.selected_primes.iter().map(|p| p.value.clone()));
            assert_eq!(res.q_bfv, expected_q);

            // Validate delta = q_bfv / k_plain
            let expected_delta = &res.q_bfv / &BigUint::from(k_plain);
            assert_eq!(res.delta, expected_delta);
        }
    }

    #[test]
    fn test_construct_qi_for_target_bits() {
        let config = create_test_config();
        let primes = build_prime_items();
        assert!(!primes.is_empty());

        let d = 512;
        let target_bits = 100;

        let result = construct_qi_for_target_bits(&config, d, &primes, target_bits);
        if let Some(res) = result {
            assert_eq!(res.d, d);
            assert!(!res.selected_primes.is_empty());
        }
    }
}
