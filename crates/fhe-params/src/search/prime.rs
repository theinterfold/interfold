// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use num_bigint::BigUint;
use std::collections::BTreeMap;

use crate::search::constants::NTT_PRIMES_BY_BITS;
use crate::search::utils::{log2_big, parse_hex_big};

/// Represents an NTT-friendly prime with precomputed metadata.
#[derive(Debug, Clone)]
pub struct PrimeItem {
    /// Bit length of the prime
    pub bitlen: u8,
    /// Prime value as BigUint
    pub value: BigUint,
    /// Precomputed log2(value) for efficiency
    pub log2: f64,
    /// Hexadecimal representation
    pub hex: String,
}

/// Build the prime pool for the first parameter set (49–62 bits).
///
/// The ring dimension is fixed at 16384, so every table entry already satisfies
/// `p ≡ 1 (mod 32768)`; the search only needs the 49–62-bit working pool.
pub fn build_prime_items() -> Vec<PrimeItem> {
    build_in_range(49, 62)
}

/// Build the prime pool for the second parameter set (50–62 bits).
///
/// The plaintext modulus is `2 * max(q_i)` of the first set, and each prime
/// must exceed twice that modulus. The 50-bit floor is the start of the scan.
/// The search drops every prime that is too small.
pub fn build_prime_items_for_second() -> Vec<PrimeItem> {
    build_in_range(50, 62)
}

/// Build a flat list of primes with bit-length in `[lo, hi]`, precomputing
/// log2 and hex strings.
fn build_in_range(lo: u8, hi: u8) -> Vec<PrimeItem> {
    let mut vec = Vec::new();
    for (bits, arr) in NTT_PRIMES_BY_BITS.iter() {
        if *bits < lo || *bits > hi {
            continue;
        }
        for &phex in arr.iter() {
            let v = parse_hex_big(phex);
            vec.push(PrimeItem {
                bitlen: *bits,
                log2: log2_big(&v),
                hex: phex.to_string(),
                value: v,
            });
        }
    }
    vec
}

/// Group primes by bit-length, sorting each bucket ascending or descending.
pub fn group_by_bits(primes: &[PrimeItem], ascending: bool) -> BTreeMap<u8, Vec<PrimeItem>> {
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in primes {
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        if ascending {
            v.sort_by(|a, b| a.value.cmp(&b.value));
        } else {
            v.sort_by(|a, b| b.value.cmp(&a.value));
        }
    }
    by_bits
}

/// Whether any two primes in the selection share the same value.
pub fn has_duplicate_primes(sel: &[PrimeItem]) -> bool {
    for i in 0..sel.len() {
        for j in (i + 1)..sel.len() {
            if sel[i].value == sel[j].value {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::utils::parse_hex_big;

    #[test]
    fn test_build_prime_items() {
        let items = build_prime_items();
        assert!(!items.is_empty());

        // First-set pool covers 49..=62 bits.
        for item in &items {
            assert!((49..=62).contains(&item.bitlen));
        }

        // Verify items have correct structure.
        for item in &items {
            assert_eq!(parse_hex_big(&item.hex), item.value);
            assert!(item.log2 > 0.0);
        }
    }

    #[test]
    fn test_build_prime_items_for_second() {
        let items = build_prime_items_for_second();
        assert!(!items.is_empty());

        // Second-set pool covers 50..=62 bits.
        for item in &items {
            assert!((50..=62).contains(&item.bitlen));
        }

        // Verify items have correct structure.
        for item in &items {
            assert_eq!(parse_hex_big(&item.hex), item.value);
            assert!(item.log2 > 0.0);
        }
    }
}
