// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use auction_designs::{
    run, Design, FirstPrice, FirstPriceBlind, Profile, Rank, RankBatched, RatioFirstPrice,
    RatioSecondPrice, Report, SecondPrice, SecondPriceBlind, Vickrey, VickreyCompact,
};
use clap::{Parser, ValueEnum};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::process::ExitCode;

#[derive(Parser)]
#[command(about = "Run sealed-bid auction designs over l-BFV encrypted bids")]
struct Cli {
    /// Design to run.
    #[arg(long, value_enum, default_value_t = DesignArg::All)]
    design: DesignArg,
    /// Parameter profile. `toy` is fast and not secure.
    #[arg(long, value_enum, default_value_t = ProfileArg::Toy)]
    params: ProfileArg,
    /// Comma-separated bids, one for each bidder. Random bids when not set.
    #[arg(long, value_delimiter = ',')]
    bids: Option<Vec<u64>>,
    /// Number of bidders for random bids.
    #[arg(long, default_value_t = 4)]
    bidders: usize,
    /// Bids are in 0..levels.
    #[arg(long, default_value_t = 16)]
    levels: usize,
    /// Seed for keys, bids, and masks. Random when not set.
    #[arg(long)]
    seed: Option<u64>,
    /// Comma-separated bidder counts. Runs the selected designs on random bids for each count
    /// and prints one table, to show how the cost grows with the number of bidders.
    #[arg(long, value_delimiter = ',', conflicts_with = "bids")]
    sweep: Option<Vec<usize>>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DesignArg {
    All,
    Rank,
    RankBatched,
    FirstPrice,
    FirstPriceBlind,
    SecondPrice,
    SecondPriceBlind,
    Vickrey,
    VickreyCompact,
    RlFirstPrice,
    RlSecondPrice,
}

/// Runs `$body` with `$design` bound to each design that `$selected` accepts, in table order.
macro_rules! for_each_selected {
    ($selected:expr, $design:ident => $body:expr) => {{
        if $selected(DesignArg::Rank) {
            let $design = &Rank;
            $body;
        }
        if $selected(DesignArg::RankBatched) {
            let $design = &RankBatched;
            $body;
        }
        if $selected(DesignArg::FirstPrice) {
            let $design = &FirstPrice;
            $body;
        }
        if $selected(DesignArg::FirstPriceBlind) {
            let $design = &FirstPriceBlind;
            $body;
        }
        if $selected(DesignArg::SecondPrice) {
            let $design = &SecondPrice;
            $body;
        }
        if $selected(DesignArg::SecondPriceBlind) {
            let $design = &SecondPriceBlind;
            $body;
        }
        if $selected(DesignArg::Vickrey) {
            let $design = &Vickrey;
            $body;
        }
        if $selected(DesignArg::VickreyCompact) {
            let $design = &VickreyCompact;
            $body;
        }
        if $selected(DesignArg::RlFirstPrice) {
            let $design = &RatioFirstPrice;
            $body;
        }
        if $selected(DesignArg::RlSecondPrice) {
            let $design = &RatioSecondPrice;
            $body;
        }
    }};
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Toy,
    Demo,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let seed = cli.seed.unwrap_or_else(rand::random);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let profile = match cli.params {
        ProfileArg::Toy => Profile::Toy,
        ProfileArg::Demo => Profile::Demo,
    };
    let selected = |design: DesignArg| cli.design == DesignArg::All || cli.design == design;
    if let Some(counts) = &cli.sweep {
        println!("seed {seed}, {profile:?} profile, {} levels", cli.levels);
        return if sweep(counts, &selected, profile, cli.levels, &mut rng) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let bids = cli.bids.clone().unwrap_or_else(|| {
        (0..cli.bidders)
            .map(|_| rng.random_range(0..cli.levels as u64))
            .collect()
    });
    println!("seed {seed}, {profile:?} profile, {} levels", cli.levels);
    println!("bids {}", list(&bids));

    let mut reports = Vec::new();
    let mut failed = false;
    for_each_selected!(selected, design => {
        failed |= !show(design, profile, &bids, cli.levels, &mut rng, &mut reports);
    });
    if reports.len() > 1 {
        summary(&reports);
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Runs the selected designs for each bidder count and prints one table. Returns false when a
/// run gives a wrong result. A design that does not fit a count is shown as not run.
fn sweep(
    counts: &[usize],
    selected: &dyn Fn(DesignArg) -> bool,
    profile: Profile,
    levels: usize,
    rng: &mut ChaCha20Rng,
) -> bool {
    println!(
        "\n| bidders | design | depth | moduli | ct×ct | ct×pt | bytes/bidder | program | result |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    let mut correct = true;
    for &count in counts {
        let bids: Vec<u64> = (0..count)
            .map(|_| rng.random_range(0..levels as u64))
            .collect();
        for_each_selected!(selected, design => {
            match run(design, profile, &bids, levels, rng) {
                Ok(report) => {
                    let s = &report.stats;
                    let ok = report.is_correct();
                    correct &= ok;
                    println!(
                        "| {count} | {} | {} | {} | {} | {} | {} | {:.2?} | {} |",
                        report.design,
                        s.depth,
                        s.moduli,
                        s.ciphertext_products,
                        s.plaintext_products,
                        bytes(s.bytes_per_bidder),
                        s.evaluate,
                        if ok { "OK" } else { "WRONG" }
                    );
                }
                Err(error) => println!(
                    "| {count} | {} | - | - | - | - | - | - | not run: {error} |",
                    design.name()
                ),
            }
        });
    }
    correct
}

/// Runs and prints one design. Returns false when the run fails or gives a wrong result.
fn show<D: Design>(
    design: &D,
    profile: Profile,
    bids: &[u64],
    levels: usize,
    rng: &mut ChaCha20Rng,
    reports: &mut Vec<Report>,
) -> bool {
    println!("\n== {} ==", design.name());
    let report = match run(design, profile, bids, levels, rng) {
        Ok(report) => report,
        Err(error) => {
            println!("not run: {error}");
            return false;
        }
    };
    let s = &report.stats;
    println!("reveals      {}", report.disclosure);
    println!("readout      {}", report.readout);
    println!(
        "parameters   N={} t={} moduli={} log2(q)={:.0} depth={}",
        s.degree, s.plaintext_modulus, s.moduli, s.log2_q, s.depth
    );
    println!(
        "keys         relinearization key {}",
        bytes(s.relinearization_key_bytes)
    );
    println!(
        "bidder       ciphertexts {}, {}, encrypt all {:.2?}",
        s.ciphertexts_per_bidder,
        bytes(s.bytes_per_bidder),
        s.encrypt
    );
    println!(
        "program      {} ct×ct, {} ct×pt, {:.2?}",
        s.ciphertext_products, s.plaintext_products, s.evaluate
    );
    println!(
        "decryption   {:.2?}, {:.0} bits of noise budget left",
        s.decrypt, s.noise_budget_bits
    );
    println!(
        "public       winner {}, price {}",
        option(report.public.winner),
        option(report.public.price)
    );
    if design.random_tie_order() {
        println!(
            "ties         random priority {:?} (higher wins a tie)",
            report.setup.tie_priority
        );
    }
    if let Some(ties) = &report.ties {
        println!("ties         {ties}");
    }
    if let Some(own) = &report.own_ranks {
        let ranks: Vec<String> = own
            .iter()
            .enumerate()
            .map(|(index, rank)| format!("{index}: {}", option(*rank)))
            .collect();
        println!("private      own rank {}", ranks.join(", "));
    }
    let correct = report.is_correct();
    println!(
        "check        {} (expected winner {}, price {})",
        if correct { "OK" } else { "WRONG" },
        option(report.expected.winner),
        option(report.expected.price)
    );
    reports.push(report);
    correct
}

fn summary(reports: &[Report]) {
    println!("\n| design | depth | moduli | ct×ct | ct×pt | ciphertexts/bidder | bytes/bidder | relinearization key | program | noise left |");
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for report in reports {
        let s = &report.stats;
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.2?} | {:.0} bits |",
            report.design,
            s.depth,
            s.moduli,
            s.ciphertext_products,
            s.plaintext_products,
            s.ciphertexts_per_bidder,
            bytes(s.bytes_per_bidder),
            bytes(s.relinearization_key_bytes),
            s.evaluate,
            s.noise_budget_bits
        );
    }
}

fn list(values: &[u64]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}: {value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn option<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_string(), |value| value.to_string())
}

fn bytes(count: usize) -> String {
    match count {
        0..1_000 => format!("{count} B"),
        1_000..1_000_000 => format!("{:.1} kB", count as f64 / 1e3),
        _ => format!("{:.2} MB", count as f64 / 1e6),
    }
}
