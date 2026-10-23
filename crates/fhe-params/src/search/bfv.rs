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
    build_prime_items, build_prime_items_for_second, generate_prime_items, is_ntt_friendly,
    select_max_q_under_cap,
};
use crate::search::security::max_log2_q;
use crate::search::utils::{approx_bits_from_log2, big_shift_pow2, log2_big};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::collections::HashSet;

/// Smallest ring dimension served by the prime table, and the first d that the search tries
/// when `BfvSearchConfig::d` is `None`. Smaller ring dimensions generate their primes.
const RING_DIM: u64 = 8192;

/// First-set largest prime bit-size. The 60-bit cap leaves 61/62-bit primes for the second set
/// (centered-RNS gap requirement). `BfvSearchConfig::min_prime_bits` sets the floor of both sets.
const FIRST_MAX_PRIME_BITS: u8 = 60;
const FIRST_TARGET_NUM_PRIMES: usize = 3;
const FIRST_MAX_NUM_PRIMES: usize = 6;

/// Second-set search bounds.
const SECOND_MAX_PRIME_BITS: u8 = 62;
const SECOND_TARGET_NUM_PRIMES: usize = 2;
const SECOND_MAX_NUM_PRIMES: usize = 8;

/// Primes generated per bit-length for ring dimensions below `RING_DIM`: the 12 largest of each
/// bit-length. The insecure presets were searched with this pool. The second set takes the
/// smallest primes of the pool, so InsecureDkg64 is the 11th and 12th largest 29-bit primes, and a
/// different count changes it.
const GENERATED_PRIMES_PER_BITS: usize = 12;

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
    /// Ring dimension. `None` searches d = 8192, 16384 and 32768, and returns the first feasible set.
    pub d: Option<u64>,
    /// Skip the RLWE security limit (Eq4). Only for insecure test presets such as
    /// `InsecureThreshold64`. The search still checks correctness (Eq1).
    pub insecure: bool,
    /// Levels of BFV multiplication and relinearization after the `z` additions. 0 is summation
    /// only. Each level applies the Prop. 20 noise recursion with the Eq. 30 relinearization noise.
    /// The security limit on q assumes m = 2d LWE samples (`search::security`). The relinearization
    /// keys expose more samples under the same secret, so estimate a set with `mult_depth > 0`
    /// for its real key exposure before you use it.
    pub mult_depth: u32,
    /// Smallest prime bit-length for both parameter sets (10..=60). Ring dimensions below
    /// `RING_DIM` generate their primes, so a toy preset can use primes from 10 bits. For
    /// d >= `RING_DIM` the table pool starts at 50 bits, so a value below 50 has no effect there.
    pub min_prime_bits: u8,
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
    /// B_C after the z additions
    pub b_c: BigUint,
    /// B_C after `mult_depth` levels of multiplication; equal to `b_c` when `mult_depth` is 0
    pub b_c_final: BigUint,
    /// Smudging bound, from `b_c_final`
    pub b_sm_min: BigUint,
    /// Multiplication levels and the Eq. 30 relinearization noise (zero when `mult_depth` is 0)
    pub mult_depth: u32,
    pub b_relin: BigUint,

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
/// 1. Iterates through polynomial degrees d (powers of 2), or uses `BfvSearchConfig::d`
/// 2. For each prime count from 3 to 6, scans the prime bit-lengths from smallest to largest
/// 3. Pass 1 takes the largest primes of each bit-length under the Eq4 limit and validates them
///    against Eq1. Pass 2, only when pass 1 finds nothing, tries every window under the limit
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

    if let Some(d) = bfv_search_config.d {
        // fhe.rs builds BFV parameters only for degree >= 8.
        if !d.is_power_of_two() || !(8..=D_POW2_MAX).contains(&d) {
            return Err(ValidationError::InvalidRingDimension { d }.into());
        }
    }
    let min_prime_bits = bfv_search_config.min_prime_bits;
    if !(10..=FIRST_MAX_PRIME_BITS).contains(&min_prime_bits) {
        return Err(ValidationError::InvalidPrimeBits {
            bits: min_prime_bits,
            reason: format!("must be in 10..={FIRST_MAX_PRIME_BITS}"),
        }
        .into());
    }

    let verbose = bfv_search_config.verbose;

    // Buckets sorted DESCENDING within each bit-length (largest prime first), so
    // taking the first `num_primes` of a bucket maximises q for that prime size.
    let by_bits = group_by_bits_desc(&build_prime_items());

    // Search increasing ring dimensions: start at RING_DIM and only step up when
    // no q satisfies both correctness (lower) and Eq4 security (upper) bounds at
    // the current d. A larger d raises the security limit far faster than the
    // correctness requirement, so high-λ requests resolve at a bigger ring.
    // A fixed `d` searches that ring dimension only.
    let ring_dims: Vec<u64> = match bfv_search_config.d {
        Some(d) => vec![d],
        None => std::iter::successors(Some(RING_DIM), |d| Some(d << 1))
            .take_while(|d| *d <= D_POW2_MAX)
            .collect(),
    };
    for d in ring_dims {
        // Keep only primes that are NTT-friendly for this ring dimension
        // (p ≡ 1 mod 2d). At d == RING_DIM every table entry already qualifies,
        // but doubling d below can exclude primes (e.g. 60-bit) that only
        // satisfy the smaller modulus. Below RING_DIM the primes are generated.
        let by_bits_d: BTreeMap<u8, Vec<PrimeItem>> = if d < RING_DIM {
            group_by_bits_desc(&generate_prime_items(
                d,
                min_prime_bits,
                FIRST_MAX_PRIME_BITS,
                GENERATED_PRIMES_PER_BITS,
            ))
        } else {
            by_bits
                .iter()
                .filter_map(|(&bb, bucket)| {
                    let filtered: Vec<PrimeItem> = bucket
                        .iter()
                        .filter(|p| is_ntt_friendly(&p.value, d))
                        .cloned()
                        .collect();
                    (!filtered.is_empty()).then_some((bb, filtered))
                })
                .collect()
        };

        if verbose {
            for bb in min_prime_bits..=FIRST_MAX_PRIME_BITS {
                if let Some(bucket) = by_bits_d.get(&bb) {
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

        // Minimum log2(q) for correctness (Eq1); exact margin check is in finalize.
        let min_log2_q = calculate_min_q_bits(bfv_search_config, d);
        // Eq4 security upper bound: 128-bit ceiling on log2(q) for this d.
        let (log2_q_limit, limit_source) =
            max_log2_q(bfv_search_config.b, bfv_search_config.b_chi, d);

        if verbose {
            println!("\n[BFV-1st] d={d}");
            let ignored = if bfv_search_config.insecure {
                "  [IGNORED: insecure]"
            } else {
                ""
            };
            println!("  Security limit: log2(q) <= {log2_q_limit:.1} ({limit_source:?}){ignored}");
            println!("  Correctness requires: log2(q) >= {min_log2_q:.1}");
        }

        // Try the fewest primes first, then the smallest prime bit-size that
        // meets the correctness bound. This mirrors the reference bucket scan.
        for num_primes in FIRST_TARGET_NUM_PRIMES..=FIRST_MAX_NUM_PRIMES {
            // Two passes per prime count. Pass 1 takes, in each bucket, the largest primes under
            // the security cap, as the presets do. Pass 2 runs only when pass 1 finds nothing and
            // scans every window, so a smaller window whose r_k(q) = q mod k passes still counts
            // before the search adds a prime.
            for full_scan in [false, true] {
                if verbose {
                    let pass = if full_scan { " (all windows)" } else { "" };
                    println!("\n  === Trying {num_primes} primes{pass} ===");
                }

                for bb in min_prime_bits..=FIRST_MAX_PRIME_BITS {
                    let bucket = match by_bits_d.get(&bb) {
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

                    // Slide a window of `num_primes` over the descending bucket. The
                    // largest window is tried first; if it exceeds the security cap,
                    // smaller windows in the same bucket may still fit
                    // [min_log2_q, log2_q_limit]. In pass 1 the first window under the cap
                    // decides the bucket; in pass 2 the search keeps sliding.
                    for start in 0..=(bucket.len() - num_primes) {
                        let sel: Vec<PrimeItem> = bucket[start..start + num_primes].to_vec();
                        let q = sel.iter().map(|pi| &pi.value).product::<BigUint>();
                        let q_bits = log2_big(&q);
                        let max_qi_log2 = sel.iter().map(|p| p.log2).fold(0.0_f64, f64::max);

                        // Because the bucket is descending, later windows only get smaller.
                        if q_bits < min_log2_q {
                            if verbose {
                                println!(
                                "  {} × {}-bit: log2(q)={:.2} < {:.1} needed, abandoning bucket",
                                num_primes, bb, q_bits, min_log2_q
                            );
                            }
                            break;
                        }

                        if q_bits > log2_q_limit && !bfv_search_config.insecure {
                            if verbose {
                                println!(
                                "  {} × {}-bit: log2(q)={:.2} > {:.1} security limit, trying smaller primes",
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
                        }
                        if verbose {
                            println!(
                            "  {} × {}-bit: log2(q)={:.2} ❌ fails correctness or margin < {:.1} bits",
                            num_primes, bb, q_bits, bfv_search_config.min_margin
                        );
                        }
                        if !full_scan {
                            break;
                        }
                    }
                }
            }
        }

        if verbose {
            println!("\n  no feasible set at d={d}");
        }
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

    // Lower bound for pruning: the fewest moduli and the smallest B_g give the least
    // multiplication noise, so no feasible candidate is pruned.
    let k_plain_eff = bfv_search_config.k.max(bfv_search_config.z);
    let b_g_min = big_shift_pow2(bfv_search_config.min_prime_bits as u32 - 1);
    let (b_c_final, _) = mult_noise(
        bfv_search_config,
        d,
        &b_c,
        k_plain_eff,
        FIRST_TARGET_NUM_PRIMES as u64,
        &b_g_min,
    );
    let b_sm_min = smudging_bound(&b_c_final, bfv_search_config.lambda, d);

    let lhs = (&b_c_final + BigUint::from(bfv_search_config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);

    let log2_k = (k_plain_eff as f64).log2();
    lhs_log2 + log2_k
}

/// Smudging noise bound `B_sm = 2^(λ+1) · d · B_C`.
///
/// fhe.rs derives the additive smudging bound with this formula, and the C1 circuit config
/// (`circuits/bin/config/src/main.nr`, `verify_e_sm_bound`) checks `PK_GENERATION_E_SM_BOUND`
/// against it. The search must use the same bound, or it sizes q for less noise than the
/// protocol adds.
fn smudging_bound(b_c: &BigUint, lambda: u32, d: u64) -> BigUint {
    b_c * big_shift_pow2(lambda + 1) * BigUint::from(d)
}

/// Relinearization noise bound (Eq. 30):
/// `N·l·‖sk‖·B_g·B_agg + 2·N²·l²·‖sk‖²·B_g·B_agg`, with `‖sk‖ = n·B_χ` and `B_agg = n·B`.
///
/// The n ciphernodes produce the relinearization key together, so its error is a sum of n terms
/// and its bound is `n·B`, as for the `e^(ek)` term of B_fresh. fhe.rs enforces this bound as
/// `accepted_participant_count * b_e` (`crates/fhe/src/trbfv/smudging.rs` in fhe.rs).
fn relin_bound(config: &BfvSearchConfig, d: u64, l: u64, b_g: &BigUint) -> BigUint {
    let d_big = BigUint::from(d);
    let l_big = BigUint::from(l);
    let sk_norm = BigUint::from(config.n) * BigUint::from(config.b_chi);
    let b_agg = BigUint::from(config.n) * BigUint::from(config.b);
    let term1 = &d_big * &l_big * &sk_norm * b_g * &b_agg;
    let term2 = BigUint::from(2u32)
        * &d_big
        * &d_big
        * &l_big
        * &l_big
        * &sk_norm
        * &sk_norm
        * b_g
        * &b_agg;
    term1 + term2
}

/// B_C after `config.mult_depth` levels of multiplication and relinearization (Prop. 20):
/// `B_C(i+1) = 2·k·N²·‖sk‖·B_C(i) + B_relin`. Returns `(b_c_final, b_relin)`; with depth 0 the
/// noise is `b_c` and `b_relin` is zero.
fn mult_noise(
    config: &BfvSearchConfig,
    d: u64,
    b_c: &BigUint,
    k: u128,
    l: u64,
    b_g: &BigUint,
) -> (BigUint, BigUint) {
    if config.mult_depth == 0 {
        return (b_c.clone(), BigUint::zero());
    }
    let b_relin = relin_bound(config, d, l, b_g);
    let coeff = BigUint::from(2u32)
        * BigUint::from(k)
        * BigUint::from(d)
        * BigUint::from(d)
        * BigUint::from(config.n)
        * BigUint::from(config.b_chi);
    let mut b_c_final = b_c.clone();
    for _ in 0..config.mult_depth {
        b_c_final = &coeff * &b_c_final + &b_relin;
    }
    (b_c_final, b_relin)
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
    let q_bfv = chosen.iter().map(|pi| &pi.value).product::<BigUint>();

    // Compute plaintext space: max of user-defined k and z
    let k_plain_eff: u128 = bfv_search_config.k.max(bfv_search_config.z);

    // Compute delta = floor(q / k) and r_k(q) without repeating the division.
    let (delta, rkq_big) = q_bfv.div_rem(&BigUint::from(k_plain_eff));
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);

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

    // Multiplication: l = number of moduli, RNS gadget base B_g = largest modulus.
    let b_g = chosen
        .iter()
        .map(|pi| pi.value.clone())
        .max()
        .unwrap_or_default();
    let (b_c_final, b_relin) = mult_noise(
        bfv_search_config,
        d,
        &b_c,
        k_plain_eff,
        chosen.len() as u64,
        &b_g,
    );

    let b_sm_min = smudging_bound(&b_c_final, bfv_search_config.lambda, d);

    // Eq1: 2*(B_C + n*B_sm) < Δ
    let lhs = (&b_c_final + BigUint::from(bfv_search_config.n) * &b_sm_min) << 1;
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
        b_c_final,
        b_sm_min,
        mult_depth: bfv_search_config.mult_depth,
        b_relin,
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
    let initial_q = initial_sel.iter().map(|pi| &pi.value).product::<BigUint>();
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
        let q = sel.iter().map(|pi| &pi.value).product::<BigUint>();
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
/// and second-set primes must be disjoint from the first set. The fewest and smallest
/// primes of the pool that satisfy correctness are chosen. For d >= 8192 the pool is the
/// table, which includes 62-bit primes. For a smaller d it holds the 12 largest generated
/// primes of each bit-length, so the choice is the smallest of those 12, not the smallest
/// valid prime overall.
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

    // Eq4 security upper bound: 128-bit ceiling on log2(q) for this d.
    let (log2_q_limit, limit_source) = max_log2_q(bfv_search_config.b, bfv_search_config.b_chi, d);

    if verbose {
        println!(
            "\n[BFV-2nd] Fixed d={d}, k = max_qi_first = {k_second} ({:.2} bits)",
            log2_big(&max_qi_first)
        );
        println!(
            "  Minimum qi required: {:.2} bits (fhe.rs centered RNS: qi > 2*k)",
            log2_big(&min_qi_second)
        );
        println!("  Security limit: log2(q) <= {log2_q_limit:.1} ({limit_source:?})");
    }

    // Ring dimensions below RING_DIM use generated primes (see `generate_prime_items`).
    let prime_items = if d < RING_DIM {
        generate_prime_items(
            d,
            bfv_search_config.min_prime_bits,
            SECOND_MAX_PRIME_BITS,
            GENERATED_PRIMES_PER_BITS,
        )
    } else {
        build_prime_items_for_second()
    };

    // Exclude primes already used by the first set.
    let first_set_primes: HashSet<String> = first
        .selected_primes
        .iter()
        .map(|p| p.hex.clone())
        .collect();

    // Buckets sorted ASCENDING within each bit-length (smallest prime first), so
    // taking the first valid `num_primes` minimises prime size. Only primes that
    // are NTT-friendly for this ring dimension (p ≡ 1 mod 2d) are eligible: at
    // d == RING_DIM every entry qualifies, but a larger d (from bfv_search)
    // excludes some 62-bit primes that only satisfy the smaller modulus.
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in &prime_items {
        if !is_ntt_friendly(&p.value, d) {
            continue;
        }
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }

    // Show available primes per bit-length (gap rule applied, first-set excluded).
    if verbose {
        for bb in bfv_search_config.min_prime_bits..=SECOND_MAX_PRIME_BITS {
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

        for bb in bfv_search_config.min_prime_bits..=SECOND_MAX_PRIME_BITS {
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
                let q = sel.iter().map(|pi| &pi.value).product::<BigUint>();
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
                if q_bits > log2_q_limit && !bfv_search_config.insecure {
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

    let initial_q = initial_sel.iter().map(|pi| &pi.value).product::<BigUint>();
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
        let q = sel.iter().map(|pi| &pi.value).product::<BigUint>();
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

    let q_bfv = chosen.iter().map(|pi| &pi.value).product::<BigUint>();
    let (delta, rkq_big) = q_bfv.div_rem(&k_big);
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);

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
        b_c_final: b_c.clone(),
        b_c,
        b_sm_min: BigUint::zero(), // not used in second set
        mult_depth: 0,
        b_relin: BigUint::zero(),
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

    /// Search inputs of a preset, with the margin the presets were searched with.
    fn preset_config(preset: crate::presets::BfvPreset) -> BfvSearchConfig {
        let sd = preset
            .search_defaults()
            .expect("threshold preset has search inputs");
        BfvSearchConfig {
            n: sd.n,
            z: sd.z,
            k: sd.k,
            lambda: sd.lambda,
            b: sd.b,
            b_chi: sd.b_chi,
            min_margin: crate::search::constants::MIN_MARGIN_BITS,
            d: None,
            insecure: false,
            mult_depth: 0,
            min_prime_bits: crate::search::constants::DEFAULT_MIN_PRIME_BITS,
            verbose: false,
        }
    }

    #[test]
    fn search_reproduces_insecure_presets() {
        use crate::constants::insecure_64;
        use crate::search::utils::{variance_cbd_str, variance_uniform_sym};

        let mut config = preset_config(crate::presets::BfvPreset::InsecureThreshold64);
        config.d = Some(insecure_64::DEGREE as u64);
        config.insecure = true;
        config.min_prime_bits = 12;

        let first = bfv_search(&config).expect("insecure threshold set must be feasible");
        assert_eq!(first.d, insecure_64::DEGREE as u64);
        assert_eq!(first.qi_values(), insecure_64::threshold::MODULI);
        assert_eq!(
            first.k_plain_eff,
            insecure_64::threshold::PLAINTEXT_MODULUS as u128
        );
        assert_eq!(
            variance_uniform_sym(&first.benc_min).to_str_radix(10),
            insecure_64::threshold::ERROR1_VARIANCE
        );

        let second =
            bfv_search_second_param(&config, &first).expect("insecure DKG set must be feasible");
        assert_eq!(second.qi_values(), insecure_64::dkg::MODULI);
        assert_eq!(
            second.k_plain_eff,
            insecure_64::dkg::PLAINTEXT_MODULUS as u128
        );
        assert_eq!(
            variance_cbd_str(config.b),
            insecure_64::dkg::ERROR1_VARIANCE
        );

        // The security limit rejects every q at d = 64.
        config.insecure = false;
        assert!(bfv_search(&config).is_err());
    }

    #[test]
    fn search_reproduces_secure_presets() {
        use crate::constants::secure_8192;
        use crate::search::utils::{variance_cbd_str, variance_uniform_sym};

        let config = preset_config(crate::presets::BfvPreset::SecureThreshold8192);
        let first = bfv_search(&config).expect("secure threshold set must be feasible");
        assert_eq!(first.d, secure_8192::DEGREE as u64);
        assert_eq!(first.qi_values(), secure_8192::threshold::MODULI);
        assert_eq!(
            first.k_plain_eff,
            secure_8192::threshold::PLAINTEXT_MODULUS as u128
        );
        assert_eq!(
            variance_uniform_sym(&first.benc_min).to_str_radix(10),
            secure_8192::threshold::ERROR1_VARIANCE
        );

        let second =
            bfv_search_second_param(&config, &first).expect("secure DKG set must be feasible");
        assert_eq!(second.qi_values(), secure_8192::dkg::MODULI);
        assert_eq!(
            second.k_plain_eff,
            secure_8192::dkg::PLAINTEXT_MODULUS as u128
        );
        assert_eq!(
            variance_cbd_str(config.b),
            secure_8192::dkg::ERROR1_VARIANCE
        );

        // The search's smudging bound is the one fhe.rs computes for the built preset.
        let preset = crate::presets::BfvPreset::SecureThreshold8192;
        let sm_config = fhe::trbfv::SmudgingBoundCalculatorConfig::new(
            crate::presets::BfvParamSet::from(preset).build_arc(),
            config.n as usize,
            config.z as usize,
            preset.lambda().unwrap(),
        )
        .unwrap();
        let fhe_b_sm = fhe::trbfv::SmudgingBoundCalculator::new(sm_config)
            .calculate_sm_bound()
            .unwrap();
        assert_eq!(first.b_sm_min, fhe_b_sm);
    }

    #[test]
    fn search_keeps_q_under_the_estimator_limit() {
        // At λ = 66 the smallest correct q at d = 8192 has log2(q) = 220. The formula
        // log2(B) + (d-75)/37.5 accepts it (limit 220.8), but it has about 124 bits of
        // security. The estimator limit (213.9) rejects it, so the search moves to d = 16384.
        let mut config = preset_config(crate::presets::BfvPreset::SecureThreshold8192);
        config.lambda = 66;
        let result = bfv_search(&config).expect("a set exists at d = 16384");
        let (limit, source) = crate::search::security::max_log2_q(config.b, config.b_chi, result.d);
        assert_eq!(source, crate::search::security::LimitSource::Estimator);
        assert_eq!(result.d, 16384);
        assert!(log2_big(&result.q_bfv) <= limit);
    }

    #[test]
    fn mult_depth_zero_is_summation_only() {
        let config = preset_config(crate::presets::BfvPreset::SecureThreshold8192);
        let result = bfv_search(&config).expect("secure threshold set must be feasible");
        assert_eq!(result.mult_depth, 0);
        assert_eq!(result.b_c_final, result.b_c);
        assert!(result.b_relin.is_zero());
    }

    #[test]
    fn mult_depth_three_secure_set() {
        // n = 20, k = 1000, z = 3 additions, then depth 3, λ = 50. No q at d = 8192 is both
        // correct and under the 128-bit limit, so the search moves to d = 16384.
        let mut config = preset_config(crate::presets::BfvPreset::SecureThreshold8192);
        config.k = 1000;
        config.z = 3;
        config.lambda = 50;
        config.mult_depth = 3;
        let result = bfv_search(&config).expect("depth-3 set must be feasible");
        assert_eq!(result.d, 16384);
        assert_eq!(
            result.qi_values(),
            [
                0x0400000000c00001,
                0x0400000000a40001,
                0x0400000000990001,
                0x0400000000980001,
                0x0400000000920001
            ]
        );
        assert_eq!(result.mult_depth, 3);
        assert!((result.lhs_log2 - 275.4157).abs() < 1e-3);
        assert!((result.rhs_log2 - 280.0342).abs() < 1e-3);
    }

    #[test]
    fn mult_depth_three_insecure_set() {
        // d = 128, n = 19, k = 100, z = 3 additions, then depth 3, λ = 2.
        let mut config = preset_config(crate::presets::BfvPreset::InsecureThreshold64);
        config.d = Some(128);
        config.insecure = true;
        config.min_prime_bits = 12;
        config.k = 100;
        config.z = 3;
        config.mult_depth = 3;
        let result = bfv_search(&config).expect("toy depth-3 set must be feasible");
        assert_eq!(
            result.qi_values(),
            [72057594037913089, 72057594037912321, 72057594037904641]
        );
        // B_relin carries the aggregate relinearization-key error n·B, not B.
        assert_eq!(
            result.b_relin.to_str_radix(10),
            "2915363831777978269497576960"
        );
        assert!(result.lhs_log2 + config.min_margin <= result.rhs_log2);
    }

    #[test]
    fn search_scans_every_window_before_adding_a_prime() {
        // At this k, the largest 3 × 60-bit window misses the 2-bit margin by about 5e-6 bits,
        // and the next window passes. Pass 1 rejects the bucket; pass 2 must find the 3-prime
        // set before the search moves to 4 primes.
        let mut config = preset_config(crate::presets::BfvPreset::SecureThreshold8192);
        config.n = 1;
        config.z = 1;
        config.k = 3_601_790_000_000_000;
        for min_prime_bits in [60, 50] {
            config.min_prime_bits = min_prime_bits;
            let result = bfv_search(&config).expect("a 3-prime set exists");
            assert_eq!(result.selected_primes.len(), 3);
            assert!(result.selected_primes.iter().all(|p| p.bitlen == 60));
        }
    }

    #[test]
    fn search_rejects_ring_dimensions_fhe_rs_cannot_build() {
        let mut config = preset_config(crate::presets::BfvPreset::InsecureThreshold64);
        config.insecure = true;
        config.min_prime_bits = 12;
        config.d = Some(4);
        assert!(bfv_search(&config).is_err());
        config.d = Some(8);
        assert!(bfv_search(&config).is_ok());
    }

    fn create_test_config() -> BfvSearchConfig {
        BfvSearchConfig {
            n: 10,
            z: 1000,
            k: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            min_margin: 1.0,
            d: None,
            insecure: false,
            mult_depth: 0,
            min_prime_bits: crate::search::constants::DEFAULT_MIN_PRIME_BITS,
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
            q_bfv: test_primes.iter().map(|p| &p.value).product(),
            selected_primes: test_primes.clone(),
            rkq: 0,
            delta: BigUint::one(),
            benc_min: BigUint::one(),
            b_fresh: BigUint::one(),
            b_c: BigUint::one(),
            b_c_final: BigUint::one(),
            b_sm_min: BigUint::one(),
            mult_depth: 0,
            b_relin: BigUint::zero(),
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
            let expected_q = res
                .selected_primes
                .iter()
                .map(|p| &p.value)
                .product::<BigUint>();
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
