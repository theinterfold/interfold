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
use e3_fhe_params::search::utils::{approx_bits_from_log2, fmt_big_summary, log2_big};
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
    let b_plus_one = b + BigUint::from(1u32);
    let var = (b * &b_plus_one) / 3u32;
    var.to_str_radix(10)
}

#[allow(clippy::too_many_arguments)]
fn print_param_set(
    title: &str,
    config: &BfvSearchConfig,
    result: &BfvSearchResult,
    dist_b: &str,
    var_b: &str,
    dist_b_chi: &str,
    var_chi: &str,
    dist_benc: Option<(&str, &str)>,
    show_common: bool,
) {
    println!("\n=== {} ===", title);
    if show_common {
        println!("n (number of ciphernodes)                = {}", config.n);
        println!("z (number of votes)                      = {}", config.z);
    }
    println!(
        "k (plaintext space)                      = {} ({} bits)",
        result.k_plain_eff,
        approx_bits_from_log2((result.k_plain_eff as f64).log2())
    );
    if show_common {
        println!(
            "λ (Statistical security parameter)       = {}",
            config.lambda
        );
        println!(
            "B (bound on e2)     = {}   [Dist: {}, Var = {}]",
            config.b, dist_b, var_b
        );
        println!(
            "B_chi (bound on sk) = {}   [Dist: {}, Var = {}]",
            config.b_chi, dist_b_chi, var_chi
        );
    }
    println!("d (LWE dimension)               = {}", result.d);
    println!("q_BFV (decimal)  = {}", result.q_bfv.to_str_radix(10));
    println!("|q_BFV|          = {}", fmt_big_summary(&result.q_bfv));
    println!("Δ (decimal)      = {}", result.delta.to_str_radix(10));
    println!("r_k(q)           = {}", result.rkq);
    if let Some((dist, var)) = dist_benc {
        println!(
            "BEnc (bound on e1)  = {}   [Dist: {}, Var = {}]",
            result.benc_min.to_str_radix(10),
            dist,
            var
        );
    } else {
        println!(
            "BEnc (bound on e1, taken as B)  = {}   [Dist: {}, Var = {}]",
            config.b, dist_b, var_b
        );
    }
    println!("B_fresh          = {}", result.b_fresh.to_str_radix(10));
    println!("B_C              = {}", result.b_c.to_str_radix(10));
    if show_common {
        println!("B_sm         = {}", result.b_sm_min.to_str_radix(10));
        println!("log2(LHS)        = {:.6}", result.lhs_log2);
    } else {
        println!("log2(2*B_C)      = {:.6}", log2_big(&(&result.b_c << 1)));
    }
    println!("log2(Δ)          = {:.6}", result.rhs_log2);
    println!(
        "q_i used ({}): {}",
        result.selected_primes.len(),
        result
            .selected_primes
            .iter()
            .map(|p| format!("{} ({} bits)", p.hex, p.bitlen))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        println!(
            "== BFV parameter search (NTT-friendly primes 40..60 bits; 61-, 62- and 63-bit primes are excluded) =="
        );
        println!(
            "Inputs: n={}  z={} k(user)={}  λ={}  B={} B_chi={}",
            args.n, args.z, args.k, args.lambda, args.b, args.b_chi
        );
        println!("Constraint: z ≤ k(effective) and z ≤ 2^25 (≈33.5M)\n");
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

    let config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        k: args.k,
        lambda: args.lambda,
        b: args.b,
        b_chi: args.b_chi,
        verbose: args.verbose,
    };

    // Search across all powers of two; stop at the first feasible candidate
    let Ok(bfv) = bfv_search(&config) else {
        eprintln!(
            "\nNo feasible BFV parameter set found across d∈{{256, 512, 1024,2048,4096,8192,16384,32768}}."
        );
        eprintln!("Try increasing d, or reducing n, z, λ, or B.");
        std::process::exit(1);
    };

    // Decide distributions: CBD for B ≤ 32, otherwise Uniform
    let (dist_b, var_b) = if args.b <= 32 {
        ("CBD", variance_cbd_str(args.b))
    } else {
        ("Uniform", variance_uniform_str(args.b))
    };

    let (dist_b_chi, var_chi) = ("CBD", variance_cbd_str(args.b_chi));
    let (dist_benc, var_benc) = ("Uniform", variance_uniform_big_str(&bfv.benc_min));

    let bfv2_opt = bfv_search_second_param(&config, &bfv);

    println!("\n\n");
    println!("================================================================================");
    println!("                         FINAL BFV PARAMETER SETS");
    println!("================================================================================");

    print_param_set(
        "FIRST BFV PARAMETER SET",
        &config,
        &bfv,
        dist_b,
        &var_b,
        dist_b_chi,
        &var_chi,
        Some((dist_benc, &var_benc)),
        true,
    );

    if let Some(bfv2) = &bfv2_opt {
        print_param_set(
            "SECOND BFV PARAMETER SET",
            &config,
            bfv2,
            dist_b,
            &var_b,
            dist_b_chi,
            &var_chi,
            None,
            false,
        );
    } else {
        println!("\n=== SECOND BFV PARAMETER SET ===");
        println!("No second BFV parameter set found.");
    }

    println!("\n================================================================================");
}
