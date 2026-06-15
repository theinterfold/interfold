// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use num_bigint::BigUint;
use num_traits::{One, Zero};

pub fn parse_hex_big(s: &str) -> BigUint {
    let t = s.trim_start_matches("0x");
    BigUint::parse_bytes(t.as_bytes(), 16).expect("invalid hex prime")
}

pub fn product<I>(xs: I) -> BigUint
where
    I: IntoIterator<Item = BigUint>,
{
    xs.into_iter().fold(BigUint::one(), |acc, x| acc * x)
}

/// Compute approximate log2 of a BigUint efficiently.
///
/// Uses the bit length and top 8 bytes to compute a fractional approximation:
/// log2(x) ≈ (total_bits - 64) + log2(top_8_bytes)
pub fn log2_big(x: &BigUint) -> f64 {
    if x.is_zero() {
        return f64::NEG_INFINITY;
    }
    let bytes = x.to_bytes_be();

    // Take up to 8 bytes for f64 precision (53 mantissa bits)
    let take = bytes.len().min(8);
    let mut top: u64 = 0;
    for &byte in bytes.iter().take(take) {
        top = (top << 8) | byte as u64;
    }

    // log2(x) = log2(top * 2^((bytes.len() - take) * 8))
    //         = log2(top) + (bytes.len() - take) * 8
    let shift = ((bytes.len() - take) * 8) as f64;
    (top as f64).log2() + shift
}

pub fn approx_bits_from_log2(log2x: f64) -> u64 {
    if log2x <= 0.0 {
        1
    } else {
        log2x.floor() as u64 + 1
    }
}

pub fn fmt_big_summary(x: &BigUint) -> String {
    let bits = approx_bits_from_log2(log2_big(x));
    format!("≈ 2^{bits} ({bits} bits)")
}

pub fn big_shift_pow2(exp: u32) -> BigUint {
    BigUint::one() << exp
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_parse_hex_big() {
        assert_eq!(parse_hex_big("0xff"), BigUint::from(255u64));
        assert_eq!(parse_hex_big("ff"), BigUint::from(255u64));
        assert_eq!(parse_hex_big("0x100"), BigUint::from(256u64));
        assert_eq!(parse_hex_big("0x1a2b3c"), BigUint::from(1715004u64));
    }

    #[test]
    fn test_product() {
        let nums = vec![
            BigUint::from(2u64),
            BigUint::from(3u64),
            BigUint::from(4u64),
        ];
        assert_eq!(product(nums), BigUint::from(24u64));

        let empty: Vec<BigUint> = vec![];
        assert_eq!(product(empty), BigUint::one());
    }

    #[test]
    fn test_log2_big() {
        assert_eq!(log2_big(&BigUint::zero()), f64::NEG_INFINITY);

        // Function returns approximation, just verify it's positive for non-zero values
        assert!(log2_big(&BigUint::from(256u64)) > 0.0);
        assert!(log2_big(&BigUint::from(1024u64)) > 0.0);
        assert!(log2_big(&BigUint::from(1024u64)) > log2_big(&BigUint::from(256u64)));
    }

    #[test]
    fn test_approx_bits_from_log2() {
        assert_eq!(approx_bits_from_log2(0.0), 1);
        assert_eq!(approx_bits_from_log2(1.0), 2);
        assert_eq!(approx_bits_from_log2(8.0), 9);
        assert_eq!(approx_bits_from_log2(-1.0), 1);
    }

    #[test]
    fn test_fmt_big_summary() {
        let x = BigUint::from(256u64);
        let summary = fmt_big_summary(&x);
        assert!(summary.contains("2^"));
        assert!(summary.contains("bits"));
    }

    #[test]
    fn test_big_shift_pow2() {
        assert_eq!(big_shift_pow2(0), BigUint::one());
        assert_eq!(big_shift_pow2(1), BigUint::from(2u64));
        assert_eq!(big_shift_pow2(8), BigUint::from(256u64));
        assert_eq!(big_shift_pow2(10), BigUint::from(1024u64));
    }
}
