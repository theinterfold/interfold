// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generator of `circuits/record/src/constants.nr`: the `k1` of every honest bid.
//!
//! The record circuit proves that `k1` is `reverse([Q_MOD_T * m]_t)` for a plaintext `m` whose SIMD
//! slots have a known shape: the period-`LEVELS` thermometer of a bid `b` (roles 0 and 1), or a
//! pair-equal mask (role 3). The SIMD map is linear, so `m` is a sum of the plaintexts of the
//! indicators of the slots. This reads those plaintexts from fhe.rs: it encodes an indicator,
//! encrypts and decrypts it under a throwaway key, and takes the polynomial coefficients of the
//! decrypted plaintext, which carries no encoding.
//!
//! A pair-equal mask has one free value for each level `l` of each pair of groups `(2c, 2c + 1)`:
//! the slots `2c * LEVELS + l` and `(2c + 1) * LEVELS + l` hold the same value. Its unit
//! `c * LEVELS + l` has 1 in those two slots and 0 elsewhere.
//!
//! Run it from `examples/auction-e2e`:
//!
//! ```text
//! cargo run -p e3-user-program --example bid_table > circuits/record/src/constants.nr
//! ```

use anyhow::{Result, ensure};
use e3_fhe_params::{BfvPreset, build_pair_for_preset};
use e3_user_program::LEVELS;
use fhe::bfv::{Ciphertext, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

const PRESET: BfvPreset = BfvPreset::InsecureThresholdSimd;

fn main() -> Result<()> {
    let (params, _) = build_pair_for_preset(PRESET)?;
    let (degree, t) = (params.degree(), params.plaintext());
    let mut rng = rand::rng();
    let secret_key = SecretKey::random(&params, &mut rng);

    // The polynomial of a SIMD plaintext with these slots.
    let mut polynomial = |slots: &[u64]| -> Result<Vec<u64>> {
        let plaintext = Plaintext::try_encode(slots, Encoding::simd(), &params)?;
        let ciphertext: Ciphertext = secret_key.try_encrypt(&plaintext, &mut rng)?;
        let decrypted = secret_key.try_decrypt(&ciphertext)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::poly())?)
    };

    let indicator = |level: usize| -> Vec<u64> {
        (0..degree).map(|i| u64::from(i % LEVELS == level)).collect()
    };
    let level_polynomials = (0..LEVELS)
        .map(|level| polynomial(&indicator(level)))
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
    // k1 for a bid whose thermometer includes the levels `levels`.
    let k1 = |levels: std::ops::Range<usize>| -> Vec<u64> {
        let mut m = vec![0u64; degree];
        for level in levels {
            for (sum, &c) in m.iter_mut().zip(&level_polynomials[level]) {
                *sum = (*sum + c) % t;
            }
        }
        to_k1(&m)
    };
    // `ge[b]` is the thermometer `[b >= l]`, `gt[b]` is `[b > l]`.
    let ge: Vec<Vec<u64>> = (0..LEVELS).map(|b| k1(0..b + 1)).collect();
    let gt: Vec<Vec<u64>> = (0..LEVELS).map(|b| k1(0..b)).collect();

    // The pair-equal units, one per (pair of groups, level).
    let groups = degree / LEVELS;
    ensure!(groups % 2 == 0, "the slots do not split into pairs of groups");
    let pair_units = groups / 2 * LEVELS;
    let unit_slots = |unit: usize| -> Vec<u64> {
        let (pair, level) = (unit / LEVELS, unit % LEVELS);
        (0..degree)
            .map(|i| {
                let (group, slot_level) = (i / LEVELS, i % LEVELS);
                u64::from(slot_level == level && group / 2 == pair)
            })
            .collect()
    };
    let pair_unit_polynomials = (0..pair_units)
        .map(|unit| polynomial(&unit_slots(unit)))
        .collect::<Result<Vec<_>>>()?;
    let pair_unit: Vec<Vec<u64>> = pair_unit_polynomials.iter().map(to_k1).collect();

    // The sums of indicators must equal a direct encoding, or the SIMD map is not linear here.
    for b in 0..LEVELS {
        let slots: Vec<u64> = (0..degree).map(|i| u64::from(b >= i % LEVELS)).collect();
        ensure!(to_k1(&polynomial(&slots)?) == ge[b], "the table of bid {b} does not match a direct encoding");
    }
    // A pair-equal mask from arbitrary values: the combination of the units mod t is its k1.
    let values: Vec<u64> = (0..pair_units).map(|u| (u as u64 * 97 + 31) % t).collect();
    let mask_slots: Vec<u64> = (0..degree)
        .map(|i| values[(i / LEVELS / 2) * LEVELS + i % LEVELS])
        .collect();
    let combined: Vec<u64> = (0..degree)
        .map(|i| {
            values
                .iter()
                .zip(&pair_unit)
                .fold(0u64, |acc, (&v, row)| (acc + v * row[i]) % t)
        })
        .collect();
    ensure!(
        to_k1(&polynomial(&mask_slots)?) == combined,
        "the pair units do not combine to a direct encoding"
    );

    println!("// SPDX-License-Identifier: LGPL-3.0-only");
    println!("//");
    println!("// This file is provided WITHOUT ANY WARRANTY;");
    println!("// without even the implied warranty of MERCHANTABILITY");
    println!("// or FITNESS FOR A PARTICULAR PURPOSE.");
    println!();
    println!("// Constants of the auction_bid circuit.");
    println!("// GENERATED by examples/auction-e2e/program/examples/bid_table.rs. Do not edit it.");
    println!("// Regenerate it from examples/auction-e2e with:");
    println!(
        "//   cargo run -p e3-user-program --example bid_table > circuits/record/src/constants.nr"
    );
    println!();
    println!("pub global LEVELS: u32 = {LEVELS};");
    println!("pub global PAIR_UNITS: u32 = {pair_units};");
    println!("pub global TABLE_N: u32 = {degree};");
    println!("pub global TABLE_PLAINTEXT_MODULUS: Field = {t};");
    println!("pub global TABLE_Q_MOD_T: Field = {q_mod_t};");
    for (name, doc, table) in [
        ("TABLE_GE", "[b >= l]", &ge),
        ("TABLE_GT", "[b > l]", &gt),
    ] {
        println!("/// `{name}[b]` is `k1` of the SIMD plaintext `{doc}`, for the bid `b`.");
        println!("pub global {name}: [[Field; TABLE_N]; LEVELS] = [");
        for row in table {
            let cells: Vec<String> = row.iter().map(u64::to_string).collect();
            println!("    [{}],", cells.join(", "));
        }
        println!("];");
    }
    println!("/// `TABLE_PAIR_UNIT[c * LEVELS + l]` is `k1` of the SIMD plaintext that is 1 at level `l` of");
    println!("/// the groups `2c` and `2c + 1`, and 0 elsewhere.");
    println!("pub global TABLE_PAIR_UNIT: [[Field; TABLE_N]; PAIR_UNITS] = [");
    for row in &pair_unit {
        let cells: Vec<String> = row.iter().map(u64::to_string).collect();
        println!("    [{}],", cells.join(", "));
    }
    println!("];");
    Ok(())
}
