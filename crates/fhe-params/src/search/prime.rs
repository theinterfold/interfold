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

/// Filter function type for excluding specific bit lengths
type BitFilter = fn(u8) -> bool;

/// Build a flat list of primes with precomputed log2 and hex strings.
/// Excludes primes whose bit length matches the filter predicate.
fn build_prime_items_with_filter(filter: BitFilter) -> Vec<PrimeItem> {
    let mut vec = Vec::new();
    for (bits, arr) in NTT_PRIMES_BY_BITS.iter() {
        if filter(*bits) {
            continue;
        }
        for &phex in arr.into_iter() {
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

/// Build the prime pool for the first parameter set.
/// Restricted to 50..=60 bit primes: the floor of 50 bits avoids the <0.2-bit
/// correctness margin of 49-bit primes for worst-case inputs, and 61/62/63-bit
/// primes are reserved for the second set (centered-RNS gap requirement).
pub fn build_prime_items() -> Vec<PrimeItem> {
    build_prime_items_with_filter(|bits| bits < 50 || bits == 61 || bits == 62 || bits == 63)
}

/// Build prime items for second parameter set (includes 62-bit primes, excludes 61 and 63-bit)
pub fn build_prime_items_for_second() -> Vec<PrimeItem> {
    build_prime_items_with_filter(|bits| bits == 63 || bits == 61)
}

/// Greedily select the maximum q under a log2 cap by taking largest primes first.
///
/// Iterates through bit lengths from largest to smallest (60 down to 40),
/// adding primes as long as the cumulative log2(q) stays under the limit.
pub fn select_max_q_under_cap(limit_log2: f64, all: &[PrimeItem]) -> Vec<PrimeItem> {
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in all {
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let mut sel: Vec<PrimeItem> = Vec::new();
    let mut qlog = 0.0f64;

    for bb in (40u8..=60u8).rev() {
        if let Some(bucket) = by_bits.get_mut(&bb) {
            for pi in bucket.iter() {
                let new_qlog = qlog + pi.log2;
                if new_qlog <= limit_log2 + 1e-12 {
                    sel.push(pi.clone());
                    qlog = new_qlog;
                }
            }
        }
    }

    sel
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::utils::parse_hex_big;

    #[test]
    fn test_build_prime_items() {
        let items = build_prime_items();
        assert!(!items.is_empty());

        // Verify no 61, 62, or 63-bit primes are included
        for item in &items {
            assert_ne!(item.bitlen, 61);
            assert_ne!(item.bitlen, 62);
            assert_ne!(item.bitlen, 63);
        }

        // Verify items have correct structure
        for item in &items {
            assert_eq!(parse_hex_big(&item.hex), item.value);
            assert!(item.log2 > 0.0);
        }
    }

    #[test]
    fn test_build_prime_items_for_second() {
        let items = build_prime_items_for_second();
        assert!(!items.is_empty());

        // Verify no 61 or 63-bit primes are included, but 62-bit should be included
        assert!(items.iter().any(|item| item.bitlen == 62));
        for item in &items {
            assert_ne!(item.bitlen, 61);
            assert_ne!(item.bitlen, 63);
        }

        // Verify items have correct structure
        for item in &items {
            assert_eq!(parse_hex_big(&item.hex), item.value);
            assert!(item.log2 > 0.0);
        }
    }

    #[test]
    fn test_select_max_q_under_cap() {
        let all = build_prime_items();
        assert!(!all.is_empty());

        // Test with a reasonable cap
        let limit_log2 = 100.0;
        let selected = select_max_q_under_cap(limit_log2, &all);

        // Verify selected items are under the cap
        let mut total_log2 = 0.0;
        for item in &selected {
            total_log2 += item.log2;
        }
        assert!(total_log2 <= limit_log2 + 1e-12);

        // Verify selected items are from the input
        for sel_item in &selected {
            assert!(all.iter().any(|item| item.hex == sel_item.hex));
        }
    }

    #[test]
    fn test_select_max_q_under_cap_small_limit() {
        let all = build_prime_items();
        let limit_log2 = 50.0;
        let selected = select_max_q_under_cap(limit_log2, &all);

        // With a small limit, we should get fewer items
        let mut total_log2 = 0.0;
        for item in &selected {
            total_log2 += item.log2;
        }
        assert!(total_log2 <= limit_log2 + 1e-12);
    }

    #[test]
    fn test_select_max_q_under_cap_empty_input() {
        let empty: Vec<PrimeItem> = vec![];
        let selected = select_max_q_under_cap(100.0, &empty);
        assert!(selected.is_empty());
    }
}
