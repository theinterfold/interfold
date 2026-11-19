// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! BFV Parameter Search CLI
//!
//! Standalone command-line tool for searching BFV parameters using NTT-friendly primes.
//!
//! With `--bidders`, `--levels` and `--failure-bits` it searches the parameters of the
//! second-price auction of `examples/auction-e2e` (see `e3_fhe_params::search::auction`):
//!
//! ```text
//! cargo run -p e3-fhe-params --bin search_params -- --bidders 8 --levels 16 --failure-bits 40
//! ```

use clap::Parser;
use e3_fhe_params::constants::defaults::{DEFAULT_SECURE_16384_LAMBDA, DEFAULT_SECURE_LAMBDA};
use e3_fhe_params::constants::search_defaults::{B, B_CHI, SEARCH_K, SEARCH_N, SEARCH_Z};
use e3_fhe_params::search::auction::{auction_search, AuctionSearchConfig, AuctionSearchResult};
use e3_fhe_params::search::bfv::{
    bfv_search, bfv_search_second_param, BfvSearchConfig, BfvSearchResult,
};
use e3_fhe_params::search::constants::{DEFAULT_MIN_PRIME_BITS, K_MAX, MIN_MARGIN_BITS};
use e3_fhe_params::search::errors::{BfvParamsError, SearchError};
use e3_fhe_params::search::prime::{build_prime_items, build_prime_items_for_second};
use e3_fhe_params::search::security::{max_log2_q, LimitSource};
use e3_fhe_params::search::utils::{
    approx_bits_from_log2, fmt_big_summary, variance_cbd_str, variance_uniform_sym,
};
use num_bigint::BigUint;

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Search BFV params with NTT-friendly CRT primes")]
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

    /// Statistical security parameter λ (negl(λ)=2^{-λ}). Defaults to 45, and in auction mode
    /// to 31, the λ of the depth-3 preset SecureThreshold16384.
    #[arg(long)]
    lambda: Option<u32>,

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

    /// Smallest prime bit-length for both parameter sets (10..=60). For d >= 8192 the prime
    /// table starts at 50 bits, so a value below 50 has no effect there.
    #[arg(long, default_value_t = DEFAULT_MIN_PRIME_BITS)]
    min_prime_bits: u8,

    /// Levels of multiplication and relinearization after the z additions (0 = summation only).
    #[arg(long, default_value_t = 0u32)]
    mult_depth: u32,

    /// Verbose per-candidate logging
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Auction mode: the most bidders of an auction. With --levels and --failure-bits, the
    /// search derives k, z and the depth of the auction program, and ignores --k, --z and
    /// --mult-depth.
    #[arg(long, requires_all = ["levels", "failure_bits"])]
    bidders: Option<u32>,

    /// Auction mode: the number of price levels (a bid is in 0..levels).
    #[arg(long, requires_all = ["bidders", "failure_bits"])]
    levels: Option<u32>,

    /// Auction mode: the auction may fail with probability at most 2^-failure_bits.
    #[arg(long, requires_all = ["bidders", "levels"])]
    failure_bits: Option<u32>,
}

/// The inputs of the auction search, when the three auction arguments are present.
fn auction_config(args: &Args, lambda: u32) -> Option<AuctionSearchConfig> {
    Some(AuctionSearchConfig {
        bidders: args.bidders?,
        levels: args.levels?,
        failure_bits: args.failure_bits?,
        n: args.n,
        lambda,
        b: args.b,
        b_chi: args.b_chi,
        min_margin: args.min_margin,
        d: args.d,
        insecure: args.insecure,
        min_prime_bits: args.min_prime_bits,
        verbose: args.verbose,
    })
}

/// What the auction search derived, and what the auction program and fhe.rs need from it.
fn print_auction(config: &AuctionSearchConfig, result: &AuctionSearchResult) {
    println!();
    println!("=== AUCTION ===");
    println!();
    println!("  bidders (most)        = {}", config.bidders);
    println!("  levels                = {}", config.levels);
    println!("  slots used            = {}", result.slots);
    println!("  failure target        = 2^-{}", config.failure_bits);
    println!(
        "  failure bound         = slots / k^2 = 2^{:.2}",
        result.failure_log2
    );
    println!();
    println!(
        "  k (plaintext modulus) = {} ({:.2} bits)",
        result.plaintext_modulus,
        (result.plaintext_modulus as f64).log2()
    );
    println!(
        "  c (non-residue)       = {}  [mask = S1^2 - c S2^2]",
        result.non_residue
    );
    println!(
        "  mult depth            = {}  [smudging: mult_depth]",
        result.mult_depth
    );
    println!(
        "  z                     = {}  [smudging: num_ciphertexts]",
        result.z
    );
    println!();
    println!(
        "  B_C of the auction    = {}",
        fmt_big_summary(&result.b_c_auction)
    );
    println!(
        "  B_C of fhe.rs (z)     = {}",
        fmt_big_summary(&result.bfv.b_c_final)
    );
}

fn variance_uniform_str(b: u128) -> String {
    variance_uniform_sym(&BigUint::from(b)).to_str_radix(10)
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
    let auction_mode = args.bidders.is_some();
    let lambda = args.lambda.unwrap_or(if auction_mode {
        DEFAULT_SECURE_16384_LAMBDA as u32
    } else {
        DEFAULT_SECURE_LAMBDA as u32
    });
    let auction = auction_config(&args, lambda);

    println!("================================================================================");
    println!("                    BFV Parameter Search (NTT-friendly primes)");
    println!("================================================================================");
    println!();
    println!("Inputs:");
    println!("  n (ciphernodes)     = {}", args.n);
    if let Some(auction) = &auction {
        println!("  bidders (most)      = {}", auction.bidders);
        println!("  levels              = {}", auction.levels);
        println!("  failure target      = 2^-{}", auction.failure_bits);
    } else {
        println!("  z (votes)           = {}", args.z);
        println!("  mult depth          = {}", args.mult_depth);
        println!("  k (plaintext space) = {}", args.k);
    }
    println!("  λ (statistical sec) = {}", lambda);
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

    // Enforce constraints on z and k. The auction search derives both.
    if !auction_mode {
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
    }

    if !args.min_margin.is_finite() || args.min_margin < 0.0 {
        eprintln!("ERROR: --min-margin must be a finite, non-negative number.");
        std::process::exit(1);
    }

    let mut config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        k: args.k,
        lambda,
        b: args.b,
        b_chi: args.b_chi,
        min_margin: args.min_margin,
        d: args.d,
        insecure: args.insecure,
        mult_depth: args.mult_depth,
        min_prime_bits: args.min_prime_bits,
        verbose: args.verbose,
    };

    if args.d.is_none_or(|d| d >= 8192) {
        println!("Prime pools (table, d >= 8192):");
        println!("  First set:  {} primes", build_prime_items().len());
        println!(
            "  Second set: {} primes",
            build_prime_items_for_second().len()
        );
    } else {
        println!(
            "Prime pools: generated for d = {} (p ≡ 1 mod 2d)",
            args.d.unwrap_or_default()
        );
    }

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

    let mut auction_result = None;
    let bfv = if let Some(auction) = &auction {
        match auction_search(auction) {
            Ok(result) => {
                // The first set is the one `bfv_search` returns for the derived k, z and depth.
                config = result.bfv_config.clone();
                let bfv = result.bfv.clone();
                auction_result = Some(result);
                bfv
            }
            Err(e) => {
                eprintln!("\nERROR: {e}");
                // The other errors say what to change.
                let no_set: BfvParamsError = SearchError::NoFeasibleParameters.into();
                if e.to_string() == no_set.to_string() {
                    eprintln!("Try fewer bidders or levels, fewer failure bits, or a smaller n.");
                }
                std::process::exit(1);
            }
        }
    } else {
        match bfv_search(&config) {
            Ok(bfv) => bfv,
            Err(e) => {
                eprintln!("\nERROR: {e}");
                eprintln!("Try reducing n, z, k, λ, B, B_χ or min_margin.");
                std::process::exit(1);
            }
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

    if let (Some(auction), Some(result)) = (&auction, &auction_result) {
        print_auction(auction, result);
    }

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
