// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// NTT-friendly primes by bit-length (49..62), the working pool for the search.
///
/// Every entry is a proven prime satisfying `p ≡ 1 (mod 32768)`, i.e.
/// `p ≡ 1 (mod 2·N)` with ring dimension `N = 16384` (the fixed ring dimension of
/// the first parameter set). Valid primes end in `...0001` or `...8001` in hex;
/// posts ending `...4001`/`...c001` satisfy `mod 16384` only and are excluded.
/// Buckets below 49 bits are deliberately absent: an earlier auto-generated pool
/// contained composite entries, so the search only consumes bit-lengths 49..62.
pub const NTT_PRIMES_BY_BITS: &[(u8, &[&str])] = &[
    (
        49u8,
        &[
            "0x00010000001a0001",
            "0x00010000001e0001",
            "0x0001000000320001",
            "0x0001000000380001",
            "0x00010000004d0001",
            "0x0001000000500001",
            "0x0001000000570001",
            "0x0001000000690001",
            "0x00010000006b0001",
            "0x0001000000720001",
            "0x0001000000ba0001",
            "0x0001000000c00001",
        ],
    ),
    (
        50u8,
        &[
            "0x00020000000b0001",
            "0x00020000001a0001",
            "0x00020000003b0001",
            "0x00020000005e0001",
            "0x00020000006d0001",
            "0x0002000000860001",
            "0x00020000008b0001",
            "0x0002000000b00001",
            "0x0002000000ce0001",
            "0x0002000001090001",
            "0x00020000013a0001",
            "0x00020000013c0001",
        ],
    ),
    (
        51u8,
        &[
            "0x0004000000120001",
            "0x00040000001b0001",
            "0x0004000000270001",
            "0x0004000000350001",
            "0x0004000000420001",
            "0x0004000000450001",
            "0x0004000000660001",
            "0x0004000000750001",
            "0x00040000007e0001",
            "0x0004000000800001",
            "0x00040000008a0001",
            "0x00040000009f0001",
        ],
    ),
    (
        52u8,
        &[
            "0x0008000000110001",
            "0x0008000000130001",
            "0x00080000001c0001",
            "0x00080000002c0001",
            "0x00080000004d0001",
            "0x00080000004f0001",
            "0x0008000000500001",
            "0x0008000000590001",
            "0x0008000000820001",
            "0x0008000000940001",
            "0x0008000000a30001",
            "0x0008000000bb0001",
        ],
    ),
    (
        53u8,
        &[
            "0x0010000000060001",
            "0x00100000000f0001",
            "0x0010000000150001",
            "0x0010000000180001",
            "0x0010000000200001",
            "0x00100000003e0001",
            "0x0010000000500001",
            "0x0010000000650001",
            "0x00100000006e0001",
            "0x00100000006f0001",
            "0x00100000007e0001",
            "0x0010000000960001",
        ],
    ),
    (
        54u8,
        &[
            "0x00200000000e0001",
            "0x0020000000140001",
            "0x0020000000170001",
            "0x0020000000280001",
            "0x0020000000640001",
            "0x00200000007c0001",
            "0x0020000000820001",
            "0x0020000000970001",
            "0x0020000000b30001",
            "0x0020000000bf0001",
            "0x0020000000c10001",
            "0x0020000000c70001",
        ],
    ),
    (
        55u8,
        &[
            "0x0040000000120001",
            "0x00400000001d0001",
            "0x00400000002c0001",
            "0x0040000000480001",
            "0x0040000000540001",
            "0x00400000005c0001",
            "0x00400000006c0001",
            "0x00400000007b0001",
            "0x0040000000890001",
            "0x0040000000b00001",
            "0x0040000000e40001",
            "0x0040000000f60001",
        ],
    ),
    (
        56u8,
        &[
            "0x0080000000080001",
            "0x0080000000130001",
            "0x0080000000190001",
            "0x00800000001d0001",
            "0x0080000000440001",
            "0x0080000000490001",
            "0x0080000000500001",
            "0x00800000005e0001",
            "0x0080000000730001",
            "0x0080000000770001",
            "0x0080000000850001",
            "0x00800000009d0001",
        ],
    ),
    (
        57u8,
        &[
            "0x0100000000060001",
            "0x01000000002a0001",
            "0x0100000000450001",
            "0x0100000000480001",
            "0x01000000005f0001",
            "0x0100000000650001",
            "0x0100000000980001",
            "0x0100000000ab0001",
            "0x0100000000bf0001",
            "0x0100000000cf0001",
            "0x0100000000dd0001",
            "0x0100000000ed0001",
        ],
    ),
    (
        58u8,
        &[
            "0x02000000002b0001",
            "0x02000000003a0001",
            "0x02000000005b0001",
            "0x0200000000640001",
            "0x02000000006d0001",
            "0x0200000000910001",
            "0x0200000000b90001",
            "0x0200000000ef0001",
            "0x0200000000f80001",
            "0x0200000001210001",
            "0x0200000001460001",
            "0x02000000015a0001",
        ],
    ),
    (
        59u8,
        &[
            "0x0400000000270001",
            "0x0400000000350001",
            "0x0400000000360001",
            "0x04000000004d0001",
            "0x0400000000570001",
            "0x0400000000660001",
            "0x04000000008a0001",
            "0x0400000000920001",
            "0x0400000000980001",
            "0x0400000000990001",
            "0x0400000000a40001",
            "0x0400000000c00001",
        ],
    ),
    (
        61u8,
        &[
            // Valid negacyclic primes near top of 61-bit range (q ≡ 1 mod 32768).
            "0x1fffffffffe10001", // log2 ≈ 60.9999, ends 0001
            "0x1fffffffffe00001", // log2 ≈ 60.9999, ends 0001
            "0x1fffffffffdd0001", // log2 ≈ 60.9999, ends 0001
            "0x1fffffffffd08001", // log2 ≈ 60.9998, ends 8001
        ],
    ),
    (
        62u8,
        &[
            // Mid range — entries ending 0001 / 8001 only.
            "0x260dfc1463740001", // log2 = 61.25, ends 0001
            "0x28c9335e63610001", // log2 = 61.35, ends 0001
            "0x2a3968a772a88001", // log2 = 61.40, ends 8001
            "0x2ed9ca3ed4188001", // log2 = 61.55, ends 8001
            "0x3080c00765628001", // log2 = 61.60, ends 8001
            "0x3460000000000001", // ends 0001
            "0x3630000000000001", // ends 0001
            "0x37f0000000000001", // ends 0001
            "0x3810000000000001", // ends 0001
            "0x3820000000000001", // ends 0001
            "0x3960000000000001", // ends 0001
            "0x39ae166b9acc8001", // log2 = 61.85, ends 8001
            "0x3a00000000000001", // ends 0001
            "0x3a90000000000001", // ends 0001
            "0x3ae0000000000001", // ends 0001
            "0x3c8c355f344d0001", // log2 = 61.92, ends 0001
            "0x3d6495552e9c0001", // log2 = 61.94, ends 0001
            "0x3e10000000000001", // ends 0001
            "0x3ea0000000000001", // ends 0001
            "0x3f18000000000001", // ends 0001
            "0x3f1e6fc702dc8001", // log2 = 61.98, ends 8001
            "0x3fffffffffff0001", // ends 0001
            "0x3ffffffffffe8001", // ends 8001
            "0x3fffffffffe80001", // ends 0001
            "0x3fffffffffd78001", // ends 8001
        ],
    ),
];

/// Fixed ring dimension for the first parameter set.
pub const RING_DIM: u64 = 16384;
/// Fewest CRT primes the first parameter set tries; the search takes the smallest count that works.
pub const TARGET_NUM_PRIMES: usize = 5;
/// Most CRT primes the first parameter set tries. Six 53-bit primes give `Q` about 2^312, which the
/// l-BFV circuits carry in two field limbs (C2b smudging lift) or in U384 (wide C7).
pub const MAX_NUM_PRIMES: usize = 6;
/// Maximum polynomial degree (power of 2) supported.
pub const D_POW2_MAX: u64 = 16384;
/// Maximum number of multiplications (total circuit depth) supported.
pub const K_MAX: u128 = 1_000_000; // 1M multiplications

#[cfg(test)]
mod tests {
    use super::NTT_PRIMES_BY_BITS;
    use std::collections::HashSet;

    /// NTT compatibility modulus: primes must satisfy p ≡ 1 (mod 2*RING_DIM),
    /// i.e. p % 32768 == 1 for the 16384-degree ring used by the search.
    const NTT_MODULUS: u64 = 32768;

    /// Deterministic Miller-Rabin primality test, exact for all u64.
    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        for p in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            if n.is_multiple_of(p) {
                return n == p;
            }
        }
        let mut d = n - 1;
        let mut r = 0;
        while d.is_multiple_of(2) {
            d /= 2;
            r += 1;
        }
        let mulmod = |a: u64, b: u64| -> u64 { ((a as u128 * b as u128) % n as u128) as u64 };
        let powmod = |mut base: u64, mut exp: u64| -> u64 {
            let mut acc = 1u64;
            base %= n;
            while exp > 0 {
                if exp & 1 == 1 {
                    acc = mulmod(acc, base);
                }
                base = mulmod(base, base);
                exp >>= 1;
            }
            acc
        };
        'witness: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            let mut x = powmod(a, d);
            if x == 1 || x == n - 1 {
                continue;
            }
            for _ in 0..r - 1 {
                x = mulmod(x, x);
                if x == n - 1 {
                    continue 'witness;
                }
            }
            return false;
        }
        true
    }

    /// Guard: every hardcoded NTT prime must be an actual prime, NTT-compatible,
    /// match its declared bit-length, and be globally unique. Prevents composite
    /// or mislabelled entries from silently re-entering the table.
    #[test]
    fn ntt_primes_table_is_valid() {
        let mut seen: HashSet<u64> = HashSet::new();
        for (bits, primes) in NTT_PRIMES_BY_BITS {
            for hex in *primes {
                let v = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("invalid hex literal {hex}"));
                assert!(is_prime(v), "{hex} ({bits}-bit) is not prime");
                assert_eq!(
                    v % NTT_MODULUS,
                    1,
                    "{hex} is not NTT-compatible (p % 32768 != 1)"
                );
                assert_eq!(
                    v.checked_ilog2().unwrap() + 1,
                    *bits as u32,
                    "{hex} bit-length does not match declared {bits} bits"
                );
                assert!(seen.insert(v), "{hex} is a duplicate entry");
            }
        }
    }
}
