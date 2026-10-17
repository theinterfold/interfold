// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Search CLI
//!
//! Standalone command-line tool for searching BFV parameters using NTT-friendly primes.

use clap::Parser;
use e3_fhe_params::constants::defaults::DEFAULT_SECURE_LAMBDA;
use e3_fhe_params::constants::search_defaults::{B, B_CHI, SEARCH_K, SEARCH_N, SEARCH_Z};
use e3_fhe_params::search::bfv::{
    bfv_search, bfv_search_second_param, BfvSearchConfig, BfvSearchResult,
};
use e3_fhe_params::search::constants::{DEFAULT_MIN_PRIME_BITS, K_MAX, MIN_MARGIN_BITS};
use e3_fhe_params::search::prime::{build_prime_items, build_prime_items_for_second};
use e3_fhe_params::search::security::{max_log2_q, LimitSource};
use e3_fhe_params::search::utils::{approx_bits_from_log2, fmt_big_summary, variance_uniform_sym};
use num_bigint::BigUint;

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Search BFV params with NTT-friendly CRT primes (40..63 bits)"
)]
struct Args {
    /// Number of parties n (ciphernodes). Defaults to the SecureThreshold8192 search inputs.
    #[arg(long, default_value_t = SEARCH_N)]
    n: u128,

    /// Number of fresh ciphertexts z summed (number of votes).
    #[arg(long, default_value_t = SEARCH_Z)]
    z: u128,

    /// Plaintext modulus k (plaintext space). The search uses max(k, z).
    #[arg(long, default_value_t = SEARCH_K)]
    k: u128,

    /// Statistical security parameter λ (negl(λ)=2^{-λ}).
    #[arg(long, default_value_t = DEFAULT_SECURE_LAMBDA as u32)]
    lambda: u32,

    /// Bound B on the error distribution ψ used to generate e1 when encrypting (20 for CBD with σ≈3.2).
    #[arg(long, default_value_t = B)]
    b: u128,

    /// Bound B_χ on the distribution χ used to generate the secret key sk_i of each party i.
    #[arg(long, default_value_t = B_CHI)]
    b_chi: u128,

    /// Minimum correctness margin in bits, log2(Δ) - log2(LHS).
    #[arg(long, default_value_t = MIN_MARGIN_BITS)]
    min_margin: f64,

    /// Ring dimension d (power of two). Without it, the search tries d = 8192, 16384, 32768.
    #[arg(long)]
    d: Option<u64>,

    /// Skip the RLWE security limit. Only for insecure test presets; correctness is still checked.
    #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
    insecure: bool,

    /// Smallest prime bit-length for both parameter sets (10..=60).
    #[arg(long, default_value_t = DEFAULT_MIN_PRIME_BITS)]
    min_prime_bits: u8,

    /// Levels of multiplication and relinearization after the z additions (0 = summation only).
    #[arg(long, default_value_t = 0u32)]
    mult_depth: u32,

    /// Verbose per-candidate logging
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

fn variance_cbd_str(b: u128) -> String {
    if b.is_multiple_of(2) {
        (b / 2).to_string()
    } else {
        format!("{}/2", b)
    }
}

fn variance_uniform_str(b: u128) -> String {
    let b_big = BigUint::from(b);
    let var = (&b_big * (b + 1)) / 3u32;
    var.to_str_radix(10)
}

fn variance_uniform_big_str(b: &BigUint) -> String {
    variance_uniform_sym(b).to_str_radix(10)
}

#[allow(clippy::too_many_arguments)]
fn print_param_set(
    title: &str,
    config: &BfvSearchConfig,
    result: &BfvSearchResult,
    dist_b: &str,
    var_b: &str,
    var_chi: &str,
    var_enc: Option<&str>,
    show_common: bool,
) {
    println!();
    println!("=== {} ===", title);
    println!();
    if show_common {
        println!("  n (ciphernodes)       = {}", config.n);
        println!("  z (votes)             = {}", config.z);
    }
    println!(
        "  k (plaintext space)   = {} ({} bits)",
        result.k_plain_eff,
        approx_bits_from_log2((result.k_plain_eff as f64).log2())
    );
    println!("  λ (statistical sec)   = {}", config.lambda);
    println!(
        "  B (error bound)       = {}  [Dist: {}, Var = {}]",
        config.b, dist_b, var_b
    );
    println!(
        "  B_χ (secret bound)    = {}  [Dist: CBD, Var = {}]",
        config.b_chi, var_chi
    );
    println!();
    println!("  d (ring dimension)    = {}", result.d);
    println!(
        "  q (ciphertext mod)    = {}",
        result.q_bfv.to_str_radix(10)
    );
    println!(
        "  |q|                   = {}",
        fmt_big_summary(&result.q_bfv)
    );
    println!(
        "  Δ = ⌊q/k⌋             = {}",
        result.delta.to_str_radix(10)
    );
    println!("  r_k(q) = q mod k      = {}", result.rkq);
    println!();
    if let Some(var) = var_enc {
        println!(
            "  B_Enc                 = {}",
            result.benc_min.to_str_radix(10)
        );
        println!("  Var(e_1)              = {}", var);
        println!(
            "  B_fresh               = {}",
            result.b_fresh.to_str_radix(10)
        );
        println!("  B_C                   = {}", result.b_c.to_str_radix(10));
        if result.mult_depth > 0 {
            println!("  mult depth            = {}", result.mult_depth);
            println!(
                "  B_relin (Eq. 30)      = {}",
                result.b_relin.to_str_radix(10)
            );
            println!(
                "  B_C (after mult)      = {}",
                result.b_c_final.to_str_radix(10)
            );
        }
        println!(
            "  B_sm                  = {}",
            result.b_sm_min.to_str_radix(10)
        );
        println!();
        println!("  log₂(LHS)             = {:.6}", result.lhs_log2);
    } else {
        println!(
            "  B_Enc (= B)           = {}",
            result.benc_min.to_str_radix(10)
        );
        println!(
            "  B_fresh               = {}",
            result.b_fresh.to_str_radix(10)
        );
        println!("  B_C (= B_fresh)       = {}", result.b_c.to_str_radix(10));
        println!();
        println!("  log₂(2·B_C)           = {:.6}", result.lhs_log2);
    }
    println!("  log₂(Δ)               = {:.6}", result.rhs_log2);
    println!(
        "  Correctness check     = {} < {} ✓",
        result.lhs_log2, result.rhs_log2
    );
    println!();
    println!("  q_i ({} primes):", result.selected_primes.len());
    for (i, p) in result.selected_primes.iter().enumerate() {
        println!("    [{}] {} ({} bits)", i + 1, p.hex, p.bitlen);
    }
}

fn main() {
    let args = Args::parse();

    println!("================================================================================");
    println!("                    BFV Parameter Search (NTT-friendly primes)");
    println!("================================================================================");
    println!();
    println!("Inputs:");
    println!("  n (ciphernodes)     = {}", args.n);
    println!("  z (votes)           = {}", args.z);
    println!("  mult depth          = {}", args.mult_depth);
    println!("  k (plaintext space) = {}", args.k);
    println!("  λ (statistical sec) = {}", args.lambda);
    println!("  B (error bound)     = {}", args.b);
    println!("  B_χ (secret bound)  = {}", args.b_chi);
    if let Some(d) = args.d {
        println!("  d (ring dimension)  = {d}");
    }
    println!();
    if args.insecure {
        println!("WARNING: --insecure skips the RLWE security limit. Use the result for test presets only.");
        println!();
    }

    // Enforce constraints on z and k
    if args.z == 0 {
        eprintln!("ERROR: z must be positive.");
        std::process::exit(1);
    }
    if args.z > K_MAX {
        eprintln!(
            "ERROR: too many votes — z = {} exceeds 2^25 = {}.",
            args.z, K_MAX
        );
        std::process::exit(1);
    }
    if args.k == 0 {
        eprintln!("ERROR: user-supplied plaintext space k must be positive.");
        std::process::exit(1);
    }

    if !args.min_margin.is_finite() || args.min_margin < 0.0 {
        eprintln!("ERROR: --min-margin must be a finite, non-negative number.");
        std::process::exit(1);
    }

    let config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        k: args.k,
        lambda: args.lambda,
        b: args.b,
        b_chi: args.b_chi,
        min_margin: args.min_margin,
        d: args.d,
        insecure: args.insecure,
        mult_depth: args.mult_depth,
        min_prime_bits: args.min_prime_bits,
        verbose: args.verbose,
    };

    println!("Prime pools:");
    println!("  First set:  {} primes", build_prime_items().len());
    println!(
        "  Second set: {} primes",
        build_prime_items_for_second().len()
    );

    // Search for first parameter set
    if args.verbose {
        println!();
        println!(
            "================================================================================"
        );
        println!("                         Searching First Parameter Set");
        println!(
            "================================================================================"
        );
    }

    let bfv = match bfv_search(&config) {
        Ok(bfv) => bfv,
        Err(e) => {
            eprintln!("\nERROR: {e}");
            eprintln!("Try reducing n, z, k, λ, B, B_χ or min_margin.");
            std::process::exit(1);
        }
    };

    if !args.insecure && max_log2_q(args.b, args.b_chi, bfv.d).1 == LimitSource::Formula {
        println!();
        println!(
            "WARNING: no lattice-estimator limit for d = {}, B = {}, B_χ = {}.",
            bfv.d, args.b, args.b_chi
        );
        println!("  The security limit is the formula log2(B) + (d-75)/37.5, which can allow");
        println!("  q with less than 128 bits of security. Estimate this set before you use it.");
    }

    // Decide distributions: CBD for B ≤ 32, otherwise Uniform
    let (dist_b, var_b) = if args.b <= 32 {
        ("CBD", variance_cbd_str(args.b))
    } else {
        ("Uniform", variance_uniform_str(args.b))
    };

    let var_chi = variance_cbd_str(args.b_chi);
    let var_enc = variance_uniform_big_str(&bfv.benc_min);

    // Search for second parameter set
    if args.verbose {
        println!();
        println!(
            "================================================================================"
        );
        println!("                         Searching Second Parameter Set");
        println!(
            "================================================================================"
        );
    }

    let bfv2_opt = bfv_search_second_param(&config, &bfv);

    println!();
    println!();
    println!("================================================================================");
    println!("                            FINAL PARAMETER SETS");
    println!("================================================================================");

    print_param_set(
        "FIRST BFV PARAMETER SET",
        &config,
        &bfv,
        dist_b,
        &var_b,
        &var_chi,
        Some(&var_enc),
        true,
    );

    if let Some(bfv2) = &bfv2_opt {
        print_param_set(
            "SECOND BFV PARAMETER SET",
            &config,
            bfv2,
            dist_b,
            &var_b,
            &var_chi,
            None,
            false,
        );
    } else {
        println!("\n=== SECOND BFV PARAMETER SET ===");
        println!("No second BFV parameter set found.");
    }

    println!();
    println!("================================================================================");
}
