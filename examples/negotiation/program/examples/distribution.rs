// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Measures the law of the agreed level of the real negotiation program.
//!
//! For each run it draws independent uniform shares and masks, builds the two offers with the
//! layout rules, encrypts them under a local committee key, runs `fhe_processor`, decrypts, and
//! applies the contract decode rule (the sum of the 8 groups of each level). It prints the
//! histogram of the agreed level and compares it with the exact law, with a chi-square test and the
//! total variation distance.
//!
//! ```text
//! cargo run --release -p e3-user-program --example distribution -- --seller-step 2 --buyer-step 12 --runs 300
//! ```

mod common;

use anyhow::{Result, ensure};
use clap::Parser;
use common::Committee;
use e3_user_program::layout::{LANES, LEVELS, Role, law, read_output};
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Parser)]
#[command(about = "Distribution of the agreed level of the negotiation program")]
struct Args {
    /// The private minimum step of the seller.
    #[arg(long)]
    seller_step: usize,
    /// The private maximum step of the buyer.
    #[arg(long)]
    buyer_step: usize,
    /// How many independent negotiations to run.
    #[arg(long, default_value_t = 300)]
    runs: usize,
    /// The members of the local committee. They sum their key contributions.
    #[arg(long, default_value_t = 3)]
    parties: usize,
    /// The worker threads. Default: all cores.
    #[arg(long)]
    threads: Option<usize>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.seller_step < LEVELS && args.buyer_step < LEVELS, "steps are below {LEVELS}");
    ensure!(args.runs > 0, "at least one run");
    let threads = args
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
        .clamp(1, args.runs);
    let committee = Committee::generate(args.parties)?;

    let next = AtomicUsize::new(0);
    let runs: Vec<Option<usize>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| -> Result<Vec<Option<usize>>> {
                    let mut rng = rand::rng();
                    let mut done = Vec::new();
                    while next.fetch_add(1, Ordering::Relaxed) < args.runs {
                        let a = rng.random_range(0..LANES);
                        let c = rng.random_range(0..LANES);
                        let seller = committee.offer(Role::Seller, args.seller_step, a, &mut rng)?;
                        let buyer = committee.offer(Role::Buyer, args.buyer_step, c, &mut rng)?;
                        let output = committee.run_program(&seller, &buyer)?;
                        let slots = committee.decrypt(&output)?;
                        let outcome = read_output(&slots).expect("the level sums are a valid outcome");
                        done.push(outcome);
                    }
                    Ok(done)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("a worker panicked"))
            .collect::<Result<Vec<_>>>()
            .map(|all| all.into_iter().flatten().collect())
    })?;
    assert_eq!(runs.len(), args.runs);

    let exact = law(args.seller_step, args.buyer_step);
    let matched = runs.iter().filter(|run| run.is_some()).count();
    println!(
        "seller step {}, buyer step {}, runs {}, committee {} members, threads {threads}",
        args.seller_step, args.buyer_step, args.runs, args.parties
    );

    if args.seller_step > args.buyer_step {
        ensure!(matched == 0, "{matched} runs matched although the buyer maximum is below the seller minimum");
        println!("no match in {} of {} runs (expected: all)", args.runs - matched, args.runs);
        return Ok(());
    }
    ensure!(matched == args.runs, "{} runs did not match although the steps overlap", args.runs - matched);

    let mut counts = [0usize; LEVELS];
    for level in runs.iter().copied().flatten() {
        counts[level] += 1;
    }
    let n = args.runs as f64;
    println!("level  count  observed  exact (sixteenths)  exact");
    let mut chi2 = 0.0;
    let mut support = 0;
    let mut tv = 0.0;
    for level in 0..LEVELS {
        let probability = f64::from(exact[level]) / LANES as f64;
        tv += (counts[level] as f64 / n - probability).abs();
        if exact[level] == 0 {
            ensure!(counts[level] == 0, "level {level} is outside [s, b] but was agreed {} times", counts[level]);
            continue;
        }
        support += 1;
        let expected = n * probability;
        chi2 += (counts[level] as f64 - expected).powi(2) / expected;
        println!(
            "{level:>5}  {:>5}  {:>8.4}  {:>18}  {probability:.4}",
            counts[level],
            counts[level] as f64 / n,
            exact[level]
        );
    }
    let degrees = support - 1;
    println!("chi-square {chi2:.2} with {degrees} degrees of freedom, p-value {:.3}", chi_square_survival(chi2, degrees));
    println!("total variation distance to the exact law: {:.4}", tv / 2.0);
    let uniform = 1.0 / support as f64;
    let tv_uniform: f64 = (0..LEVELS)
        .map(|level| {
            let ideal = if exact[level] > 0 { uniform } else { 0.0 };
            (counts[level] as f64 / n - ideal).abs()
        })
        .sum::<f64>()
        / 2.0;
    let exact_tv_uniform: f64 = (0..LEVELS)
        .map(|level| {
            let ideal = if exact[level] > 0 { uniform } else { 0.0 };
            (f64::from(exact[level]) / LANES as f64 - ideal).abs()
        })
        .sum::<f64>()
        / 2.0;
    println!(
        "total variation distance to the uniform law on [s, b]: observed {tv_uniform:.4}, exact law {exact_tv_uniform:.4}"
    );
    Ok(())
}

/// `P(X >= x)` for a chi-square variable with `k` degrees of freedom: the regularised upper
/// incomplete gamma function `Q(k / 2, x / 2)`.
fn chi_square_survival(x: f64, k: usize) -> f64 {
    if k == 0 {
        return if x > 0.0 { 0.0 } else { 1.0 };
    }
    let a = k as f64 / 2.0;
    let x = x / 2.0;
    if x <= 0.0 {
        return 1.0;
    }
    let ln_gamma_a = ln_gamma(a);
    if x < a + 1.0 {
        // The series of the lower function.
        let mut term = 1.0 / a;
        let mut sum = term;
        let mut n = a;
        for _ in 0..500 {
            n += 1.0;
            term *= x / n;
            sum += term;
            if term.abs() < sum.abs() * 1e-15 {
                break;
            }
        }
        1.0 - sum * (-x + a * x.ln() - ln_gamma_a).exp()
    } else {
        // The continued fraction of the upper function (modified Lentz).
        let tiny = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / tiny;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..500 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < tiny {
                d = tiny;
            }
            c = b + an / c;
            if c.abs() < tiny {
                c = tiny;
            }
            d = 1.0 / d;
            let delta = d * c;
            h *= delta;
            if (delta - 1.0).abs() < 1e-15 {
                break;
            }
        }
        (-x + a * x.ln() - ln_gamma_a).exp() * h
    }
}

/// `ln Gamma(x)` by the Lanczos approximation.
fn ln_gamma(x: f64) -> f64 {
    const G: [f64; 6] = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut y = x;
    let tmp = x + 5.5;
    let tmp = tmp - (x + 0.5) * tmp.ln();
    let mut series = 1.000000000190015;
    for g in G {
        y += 1.0;
        series += g / y;
    }
    -tmp + (2.5066282746310005 * series / x).ln()
}
