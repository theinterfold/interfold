// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Search CLI
//!
//! Standalone command-line tool for searching BFV parameters using NTT-friendly primes.

use clap::Parser;
use e3_fhe_params::search::bfv::{
    bfv_search, bfv_search_second_param, BfvSearchConfig, BfvSearchResult,
};
use e3_fhe_params::search::constants::K_MAX;
use e3_fhe_params::search::prime::{build_prime_items, build_prime_items_for_second};
use e3_fhe_params::search::utils::{approx_bits_from_log2, fmt_big_summary};
use num_bigint::BigUint;

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Search BFV params with NTT-friendly CRT primes (40..63 bits)"
)]
struct Args {
    /// Number of parties n (e.g. ciphernodes, default is 1000)
    #[arg(long, default_value_t = 1000u128)]
    n: u128,

    /// Number of fresh ciphertext z, i.e. number of votes. Note that the BFV plaintext modulus k will be defined as k = z
    #[arg(long, default_value_t = 1000u128)]
    z: u128,

    /// Plaintext modulus k (plaintext space).
    #[arg(long, default_value_t = 1000u128)]
    k: u128,

    /// Statistical Security parameter λ (negl(λ)=2^{-λ}).
    #[arg(long, default_value_t = 80u32)]
    lambda: u32,

    /// Bound B on the error distribution \psi (see pdf) used generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    #[arg(long, default_value_t = 20u128)]
    b: u128,

    /// Bound B_{\chi} on the distribution \chi (see pdf) used generate the secret key sk_i of each party i.
    /// By default, it is fixed to be 20 (that is the case when \chi is CBD with with σ≈3.2, which
    /// is the distribution by default in fhe.rs).
    #[arg(long, default_value_t = 1u128)]
    b_chi: u128,

    /// Min margin.
    #[arg(long, default_value_t = 1f64)]
    min_margin: f64,

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
    // Variance for Uniform(-B..B): Var = B^2 / 3
    let var = (b * b) / 3u32;
    var.to_str_radix(10)
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
    println!("  k (plaintext space) = {}", args.k);
    println!("  λ (statistical sec) = {}", args.lambda);
    println!("  B (error bound)     = {}", args.b);
    println!("  B_χ (secret bound)  = {}", args.b_chi);
    println!();

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

    let config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        k: args.k,
        lambda: args.lambda,
        b: args.b,
        b_chi: args.b_chi,
        min_margin: args.min_margin,
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

    let Ok(bfv) = bfv_search(&config) else {
        eprintln!("\nERROR: No feasible first parameter set found.");
        eprintln!("Try increasing d, or reducing n, z, λ, or B.");
        std::process::exit(1);
    };

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
