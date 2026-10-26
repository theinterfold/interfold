// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Writes the shared layout vectors, `sdk/test-vectors/layout.json`, to the standard output.
//!
//! Each case has a round, a bid, an output of the program on the plaintext bids (with random masks),
//! and what [`e3_user_program::layout::decode_round`] reads from it. `sdk/src/layout.vectors.test.ts`
//! checks that the TypeScript layout produces the same bid slots and decodes the same outputs. The
//! seed is fixed, so the file only changes when the layout changes.
//!
//! ```text
//! cargo run --release -p e3-user-program --example layout_vectors > sdk/test-vectors/layout.json
//! ```

use e3_user_program::layout::{
    COPIES, GATE_BASE, GATE_COPIES, MAX_BIDDERS, MAX_LOTS, Outcome, RoundParams, SLOTS,
    VERSION_BASE, bid_slots, decode_round, price_slot, zero_set,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const T: u64 = 257;

fn list(values: &[u64]) -> String {
    let items: Vec<String> = values.iter().map(u64::to_string).collect();
    format!("[{}]", items.join(","))
}

/// The output of the program on plaintext bids: `R * prod_j (c - z_j)` in the lane slots, the
/// versions in the version slots, 0 elsewhere.
fn output(round: &RoundParams, bids: &[usize], versions: &[u64], rng: &mut StdRng) -> Vec<u64> {
    let n = bids.len();
    let price_zeros = zero_set(round.lots, n);
    let gate_zeros = zero_set(round.min_lots, n);
    let factors = price_zeros.len().max(gate_zeros.len());
    let slots: Vec<Vec<u64>> = bids
        .iter()
        .enumerate()
        .map(|(i, &b)| bid_slots(SLOTS, round, b, i, versions[i]))
        .collect();
    let mut out = vec![0u64; SLOTS];
    let mut lane = |slot: usize, zeros: &[u64]| {
        let c = slots.iter().map(|s| s[slot]).sum::<u64>() % T;
        let mask: u64 = (0..n).map(|_| rng.random_range(0..T)).sum::<u64>() % T;
        out[slot] = (0..factors).fold(mask, |acc, j| {
            let z = if zeros.is_empty() {
                n as u64 + 1
            } else {
                zeros[j % zeros.len()]
            };
            acc * ((c + T - z % T) % T) % T
        });
    };
    for copy in 0..COPIES {
        for level in round.reserve_step..round.levels {
            lane(price_slot(copy, level), &price_zeros);
        }
    }
    for slot in GATE_BASE..GATE_BASE + GATE_COPIES {
        lane(slot, &gate_zeros);
    }
    for (i, &v) in versions.iter().enumerate() {
        out[VERSION_BASE + i] = v;
    }
    out
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::NotMet => "NotMet",
        Outcome::Undersubscribed => "Undersubscribed",
        Outcome::SoldOut => "SoldOut",
        Outcome::Aborted => "Aborted",
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(20260101);
    let mut cases = Vec::new();
    for case in 0..80 {
        let levels = rng.random_range(2..=16usize);
        let lots = rng.random_range(1..=MAX_LOTS);
        let round = RoundParams {
            levels,
            reserve_step: rng.random_range(0..levels),
            lots,
            min_lots: rng.random_range(1..=lots),
        };
        let n = rng.random_range(1..=MAX_BIDDERS);
        let bids: Vec<usize> = (0..n).map(|_| rng.random_range(0..levels)).collect();
        let versions: Vec<u64> = (0..n).map(|_| rng.random_range(1..=3)).collect();
        let mut slots = output(&round, &bids, &versions, &mut rng);
        // Every fourth case breaks one rule, so the vectors cover the decoder's aborts.
        if case % 4 == 3 {
            let target = rng.random_range(0..VERSION_BASE);
            slots[target] = rng.random_range(1..T);
        }
        let decoded = decode_round(&slots, &round);
        let bid = bid_slots(SLOTS, &round, bids[0], 0, versions[0]);
        cases.push(format!(
            concat!(
                "    {{\"levels\":{},\"reserveStep\":{},\"lots\":{},\"minLots\":{},",
                "\"firstBid\":{{\"level\":{},\"bidderIndex\":0,\"version\":{},\"slots\":{}}},",
                "\"slots\":{},\"outcome\":\"{}\",\"step\":{},\"counted\":{},\"versions\":{}}}"
            ),
            round.levels,
            round.reserve_step,
            round.lots,
            round.min_lots,
            bids[0],
            versions[0],
            list(&bid),
            list(&slots),
            outcome_name(decoded.outcome),
            decoded.step.map_or("null".to_string(), |s| s.to_string()),
            decoded.counted,
            list(&decoded.versions),
        ));
    }
    println!("{{\n  \"cases\": [\n{}\n  ]\n}}", cases.join(",\n"));
}
