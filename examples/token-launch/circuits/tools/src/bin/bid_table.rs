// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generator of `circuits/bid/src/constants.nr`: the layout of the bid plaintext and the `k1` of
//! the plaintext of every slot a bid can set.
//!
//! The bid circuit proves that `k1` is `reverse([Q_MOD_T * m]_t)` for the SIMD plaintext `m` of a
//! token-launch bid (`sdk/src/layout.ts`): the cell `(l, j)` at slot `l * LANES + j` holds the
//! digit `j` of the budget when `l <= b` and 0 otherwise, and the flag cell `FLAG_BASE + i / 8`
//! holds `2^(i % 8)` for the bidder index `i`. Every other slot is 0.
//!
//! The SIMD map is linear, so `m` is the combination of the plaintexts of the indicators of the
//! slots. This reads those plaintexts from fhe.rs: it encodes an indicator, encrypts and decrypts
//! it under a throwaway key, and takes the polynomial coefficients of the decrypted plaintext,
//! which carries no encoding. `TABLE_UNIT[s]` is `k1` of the indicator of the slot `s`; only the
//! `CELLS` slots a bid can set are emitted. The generator also derives the bit size of the
//! quotient of the circuit's integer plaintext equation from the worst case of the table, and
//! checks the table against a direct encoding of a bid.
//!
//! ```text
//! cargo run --release --manifest-path circuits/tools/Cargo.toml --bin bid_table > circuits/bid/src/constants.nr
//! ```

use anyhow::{Result, ensure};
use e3_fhe_params::{BfvPreset, build_pair_for_preset};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

// The layout of `program/src/lib.rs` (`layout`), mirrored by `sdk/src/layout.ts`.
/// The price steps of the slot layout.
const LEVELS_MAX: usize = 16;
/// The base-4 digits of a budget.
const LANES: usize = 6;
/// The largest digit: `2^DIGIT_BITS - 1`.
const DIGIT_MAX: u64 = 3;
/// The bidders of a sale.
const MAX_BIDDERS: usize = 85;
/// The counted flags packed in one cell.
const FLAGS_PER_CELL: usize = 8;
/// The first flag cell: `LEVELS_MAX * LANES`.
const FLAG_BASE: usize = LEVELS_MAX * LANES;
/// `ceil(MAX_BIDDERS / FLAGS_PER_CELL)`.
const FLAG_CELLS: usize = MAX_BIDDERS.div_ceil(FLAGS_PER_CELL);
/// The slots a bid can set.
const CELLS: usize = FLAG_BASE + FLAG_CELLS;

/// The slots of the plaintext of a bid: step `b`, budget `budget`, bidder index `index`.
fn bid_slots(degree: usize, b: usize, budget: u64, index: usize) -> Vec<u64> {
    let mut slots = vec![0u64; degree];
    for l in 0..=b {
        for j in 0..LANES {
            slots[l * LANES + j] = (budget >> (2 * j)) & DIGIT_MAX;
        }
    }
    slots[FLAG_BASE + index / FLAGS_PER_CELL] = 1 << (index % FLAGS_PER_CELL);
    slots
}

fn main() -> Result<()> {
    let (params, _) = build_pair_for_preset(PRESET)?;
    let (degree, t) = (params.degree(), params.plaintext());
    ensure!(degree >= CELLS, "the layout needs {CELLS} slots, the preset has {degree}");
    let mut rng = rand::rng();
    let secret_key = SecretKey::random(&params, &mut rng);

    // The polynomial of a SIMD plaintext with these slots.
    let mut polynomial = |slots: &[u64]| -> Result<Vec<u64>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &params)?;
        let ciphertext: Ciphertext = secret_key.try_encrypt(&plaintext, &mut rng)?;
        let decrypted = secret_key.try_decrypt(&ciphertext)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::poly())?)
    };

    let indicator =
        |slot: usize| -> Vec<u64> { (0..degree).map(|i| u64::from(i == slot)).collect() };
    let slot_polynomials = (0..CELLS)
        .map(|slot| polynomial(&indicator(slot)))
        .collect::<Result<Vec<_>>>()?;

    // [q]_t, with q the product of the ciphertext moduli.
    let q_mod_t = params
        .moduli()
        .iter()
        .fold(1u128, |acc, &qi| acc * u128::from(qi % t) % u128::from(t)) as u64;

    // k1 of the plaintext polynomial `m`: reverse([q * m]_t).
    let to_k1 = |m: &Vec<u64>| -> Vec<u64> {
        let mut k1: Vec<u64> = m
            .iter()
            .map(|&c| (u128::from(c) * u128::from(q_mod_t) % u128::from(t)) as u64)
            .collect();
        k1.reverse();
        k1
    };
    let unit: Vec<Vec<u64>> = slot_polynomials.iter().map(to_k1).collect();

    // A combination of units must equal a direct encoding, or the SIMD map is not linear here.
    for (b, budget, index) in [(5, 3000, 83), (15, 4095, 84), (0, 1, 0)] {
        let slots = bid_slots(degree, b, budget, index);
        let combined: Vec<u64> = (0..degree)
            .map(|j| {
                (0..CELLS).fold(0u64, |acc, s| (acc + slots[s] * unit[s][j]) % t)
            })
            .collect();
        ensure!(
            to_k1(&polynomial(&slots)?) == combined,
            "the slot units do not combine to a direct encoding"
        );
    }

    // The largest integer `sum_s v_s * unit_s[j]` of any bid: every cell at most `DIGIT_MAX`, and
    // one flag cell at most `2^(FLAGS_PER_CELL - 1)`. It bounds the quotient by `t` of the circuit.
    let largest_sum = (0..degree)
        .map(|j| {
            let cells: u64 = (0..FLAG_BASE).map(|s| DIGIT_MAX * unit[s][j]).sum();
            let flag = (FLAG_BASE..CELLS)
                .map(|s| (1u64 << (FLAGS_PER_CELL - 1)) * unit[s][j])
                .max()
                .unwrap_or(0);
            cells + flag
        })
        .max()
        .unwrap_or(0);
    let largest_quotient = largest_sum / t;
    let quotient_bits = u64::BITS - largest_quotient.leading_zeros();

    println!("// SPDX-License-Identifier: LGPL-3.0-only");
    println!("//");
    println!("// This file is provided WITHOUT ANY WARRANTY;");
    println!("// without even the implied warranty of MERCHANTABILITY");
    println!("// or FITNESS FOR A PARTICULAR PURPOSE.");
    println!();
    println!("// Constants of the bid circuit.");
    println!(
        "// GENERATED by examples/token-launch/circuits/tools/src/bin/bid_table.rs. Do not edit it."
    );
    println!("// Regenerate it from examples/token-launch with:");
    println!(
        "//   cargo run --release --manifest-path circuits/tools/Cargo.toml --bin bid_table > circuits/bid/src/constants.nr"
    );
    println!();
    println!("/// The price steps of the slot layout.");
    println!("pub global LEVELS_MAX: u32 = {LEVELS_MAX};");
    println!("/// The base-4 digits of a budget.");
    println!("pub global LANES: u32 = {LANES};");
    println!("/// The bidders of a sale.");
    println!("pub global MAX_BIDDERS: u32 = {MAX_BIDDERS};");
    println!("/// The counted flags packed in one cell: bidder `i` adds `2^(i % FLAGS_PER_CELL)`.");
    println!("pub global FLAGS_PER_CELL: u32 = {FLAGS_PER_CELL};");
    println!("/// The first flag cell.");
    println!("pub global FLAG_BASE: u32 = {FLAG_BASE};");
    println!("pub global FLAG_CELLS: u32 = {FLAG_CELLS};");
    println!("/// The slots a bid can set: the cells and the flag cells.");
    println!("pub global CELLS: u32 = {CELLS};");
    println!("pub global TABLE_N: u32 = {degree};");
    println!("pub global TABLE_PLAINTEXT_MODULUS: Field = {t};");
    println!("pub global TABLE_Q_MOD_T: Field = {q_mod_t};");
    println!(
        "/// The sum `sum_s v_s * TABLE_UNIT[s][j]` of a bid is at most {largest_sum} (every cell 3, the largest flag cell 128), so its quotient by `t` is at most {largest_quotient}, below 2^{quotient_bits}."
    );
    println!("pub global QUOTIENT_BITS: u32 = {quotient_bits};");
    println!(
        "/// `TABLE_UNIT[s]` is `k1` of the SIMD plaintext with 1 in the slot `s` and 0 elsewhere."
    );
    println!("pub global TABLE_UNIT: [[Field; TABLE_N]; CELLS] = [");
    for row in &unit {
        let cells: Vec<String> = row.iter().map(u64::to_string).collect();
        println!("    [{}],", cells.join(", "));
    }
    println!("];");
    Ok(())
}
