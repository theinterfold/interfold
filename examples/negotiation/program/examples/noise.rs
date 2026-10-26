// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Measures the noise budget of the real negotiation program.
//!
//! For each random negotiation it encrypts the two offers under the committee key (the key
//! generation of the real committee, with `--parties` members), runs `fhe_processor`, and measures
//! the noise of the six fresh ciphertexts and of the output with `SecretKey::measure_noise`. The
//! budget is `log2(q / t) - 1 - noise`, in bits. A decryption fails when the budget is below 0.
//!
//! The real decryption adds one smudging noise for each committee member. The example prints the
//! smudging bound of the preset, so the margin that is left for it is visible.
//!
//! ```text
//! cargo run --release -p e3-user-program --example noise -- --negotiations 20 --parties 3
//! ```

mod common;

use anyhow::{Result, ensure};
use clap::Parser;
use common::{Committee, PRESET};
use e3_fhe_params::calculate_smudging_bound;
use e3_user_program::layout::{LEVELS, LANES, Role, expected_outcome, read_output};
use rand::Rng;

#[derive(Parser)]
#[command(about = "Noise budget of the negotiation program")]
struct Args {
    /// How many random negotiations to run.
    #[arg(long, default_value_t = 20)]
    negotiations: usize,
    /// The members of the local committee. They sum their key contributions.
    #[arg(long, default_value_t = 3)]
    parties: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.negotiations > 0, "at least one negotiation");
    let committee = Committee::generate(args.parties)?;
    let limit = committee.noise_limit_bits();
    let mut rng = rand::rng();

    println!(
        "preset {PRESET:?}: degree {}, t {}, log2(q) {:.1}, parties {}",
        committee.params.degree(),
        committee.params.plaintext(),
        committee.params.moduli().iter().map(|&q| (q as f64).log2()).sum::<f64>(),
        args.parties
    );
    println!("decryption limit: {limit:.1} bits of noise (log2(q/t) - 1)");
    println!("negotiation   s   b  match  fresh(max of 6)  output  output budget");

    let mut fresh_max = 0usize;
    let mut output_max = 0usize;
    let mut fresh_min = usize::MAX;
    let mut output_min = usize::MAX;
    let mut matches = 0;
    for n in 0..args.negotiations {
        // Half the negotiations match; the extremes are in the sample.
        let (s, b) = match n {
            0 => (0, 15),
            1 => (15, 0),
            _ => (rng.random_range(0..LEVELS), rng.random_range(0..LEVELS)),
        };
        let (a, c) = (rng.random_range(0..LANES), rng.random_range(0..LANES));
        let seller = committee.offer(Role::Seller, s, a, &mut rng)?;
        let buyer = committee.offer(Role::Buyer, b, c, &mut rng)?;
        let fresh = seller.iter().chain(&buyer).map(|ct| committee.noise_bits(ct)).max().unwrap();
        let output = committee.run_program(&seller, &buyer)?;
        let noise = committee.noise_bits(&output);
        let outcome = read_output(&committee.decrypt(&output)?).expect("a valid output");
        ensure!(outcome == expected_outcome(s, b, a, c), "the output of negotiation {n} is wrong");
        matches += usize::from(outcome.is_some());
        println!(
            "{n:>11} {s:>3} {b:>3}  {:<5}  {fresh:>15}  {noise:>6}  {:>13.1}",
            outcome.is_some(),
            limit - noise as f64
        );
        fresh_max = fresh_max.max(fresh);
        fresh_min = fresh_min.min(fresh);
        output_max = output_max.max(noise);
        output_min = output_min.min(noise);
    }

    println!();
    println!("negotiations {} ({matches} matched), every output decrypted to the expected outcome", args.negotiations);
    println!("fresh noise:  min {fresh_min} max {fresh_max} bits, budget {:.1} bits at the worst", limit - fresh_max as f64);
    println!(
        "output noise: min {output_min} max {output_max} bits, budget {:.1} bits at the worst",
        limit - output_max as f64
    );

    let defaults = PRESET.search_defaults().expect("the preset has search defaults");
    let bound = calculate_smudging_bound(
        committee.params.clone(),
        defaults.n as usize,
        1,
        defaults.mult_depth,
        defaults.lambda as usize,
    )?;
    // `bits()` rounds the logarithm up, so the figures below are upper bounds of the noise.
    let smudging_bits = bound.bits() as f64;
    let summed_smudging_bits = smudging_bits + (defaults.n as f64).log2();
    println!(
        "smudging bound of the preset: 2^{smudging_bits:.0} for each of {} members (n of the preset, mult depth {}, lambda {}), at most 2^{summed_smudging_bits:.1} summed",
        defaults.n, defaults.mult_depth, defaults.lambda
    );
    let total_bits = (2f64.powf(summed_smudging_bits - output_max as f64) + 1.0).log2() + output_max as f64;
    println!(
        "worst output noise plus summed smudging: 2^{total_bits:.1}; margin to the limit: {:.1} bits",
        limit - total_bits
    );
    Ok(())
}
