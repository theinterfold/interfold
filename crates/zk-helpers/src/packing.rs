// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Polynomial packing utilities for zero-knowledge circuits
//!
//! This module provides functions to pack polynomial coefficients into field elements
//! using a nibble-aligned layout, matching the Noir implementation exactly.

use ark_bn254::Fr as Field;
use ark_ff::{BigInt as FieldInteger, BigInteger, PrimeField};
use e3_polynomial::Polynomial;
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};

/// Compute hex-aligned packing parameters for a given `BIT`.
/// Matches the Noir `packing_layout` function exactly.
///
/// # Arguments
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// A tuple of (nibble_bits, group) where:
/// - `nibble_bits`: The bit width rounded up to the next multiple of 4
/// - `group`: Maximum number of limbs that fit in one BN254 field element
fn packing_layout(bit: u32) -> (u32, u32) {
    // Ceil BIT up to the next multiple of 4 (nibble alignment).
    let nibble_bits = bit.div_ceil(4) * 4;

    // Each stored limb uses an extra nibble because negative coefficients
    // will be shifted to positive, so radix = 2^(nibble_bits+4).
    assert!(nibble_bits + 4 <= 254);

    // Maximum limbs that fit in one BN254 element without wrap.
    let group = 254 / (nibble_bits + 4);
    assert!(group >= 1);
    (nibble_bits, group)
}

/// Pack a polynomial's coefficients into a Vec<Field> of carriers using the shared hex-aligned layout.
///
/// Matches the Noir `packer` function exactly.
/// Packs multiple coefficients into each field element using nibble-aligned layout.
///
/// # Arguments
/// * `poly` - Polynomial whose coefficients to pack
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// A vector of field elements containing the packed coefficients.
/// The number of field elements is `ceil(poly.coefficients().len() / group)` where `group` is
/// determined by the packing layout.
fn packer(polynomial: &Polynomial, bit: u32) -> Vec<Field> {
    packer_fixed_width(polynomial, bit).unwrap_or_else(|| packer_bigint(polynomial, bit))
}

/// Uses four machine words when each shifted coefficient fits its allocated digit.
/// Other values use the original arbitrary-precision path.
fn packer_fixed_width(polynomial: &Polynomial, bit: u32) -> Option<Vec<Field>> {
    let (nibble_bits, group) = packing_layout(bit);
    if nibble_bits > 120 {
        return None;
    }
    let digit_bits = nibble_bits + 4;
    let base = 1i128 << nibble_bits;
    let radix = 1u128 << digit_bits;
    let values = polynomial.coefficients();
    let mut output = Vec::with_capacity(values.len().div_ceil(group as usize));
    for chunk in values.chunks(group as usize) {
        let mut accumulator = FieldInteger::<4>::from(0u64);
        for index in 0..group as usize {
            let value = match chunk.get(index) {
                Some(value) => value.to_i128()?,
                None => 0,
            };
            let digit = u128::try_from(value.checked_add(base)?).ok()?;
            if digit >= radix {
                return None;
            }
            accumulator <<= digit_bits;
            let carry = accumulator.add_with_carry(&FieldInteger([
                digit as u64,
                (digit >> 64) as u64,
                0,
                0,
            ]));
            debug_assert!(!carry);
        }
        // The nibble-aligned layout uses at most 252 bits, below the field modulus.
        output.push(Field::from_bigint(accumulator)?);
    }
    Some(output)
}

fn packer_bigint(polynomial: &Polynomial, bit: u32) -> Vec<Field> {
    let values = polynomial.coefficients();
    let (nibble_bits, group) = packing_layout(bit);

    let base = BigInt::from(2).pow(nibble_bits);
    let radix = BigInt::from(2).pow(nibble_bits + 4);

    let a = values.len() as u32;
    let num_chunks = a.div_ceil(group);
    let mut out = Vec::new();

    // Process in fixed-size chunks of `group` limbs.
    for chunk in 0..num_chunks {
        // How many real values go into this chunk.
        let remain = a - (chunk * group);
        let take = if remain < group { remain } else { group };

        // Build field element accumulator (big-endian concatenation in `radix`).
        let mut acc = BigInt::zero();
        for i in 0..take {
            let v = &values[(chunk * group + i) as usize];
            acc = acc * &radix + (v + &base);
        }

        // Pad remaining limb slots with the canonical zero-limb `digit = base`.
        for _ in 0..(group - take) {
            acc = acc * &radix + &base;
        }

        // Convert BigInt to Field element
        let acc_biguint = if acc < BigInt::zero() {
            // Should not happen with our packing scheme, but handle it
            panic!("Negative accumulator in packer");
        } else {
            acc.to_biguint().unwrap()
        };

        // Convert to Field via bytes
        let bytes = acc_biguint.to_bytes_le();
        let field_elem = Field::from_le_bytes_mod_order(&bytes);
        out.push(field_elem);
    }
    out
}

/// Flatten a slice of polynomials into a single linear stream of packed `Field` carriers.
///
/// Matches the Noir `flatten` function exactly.
/// Packs each polynomial's coefficients using the same bit width and appends them sequentially.
///
/// # Arguments
/// * `inputs` - Initial vector of field elements to append to
/// * `polys` - Slice of polynomials to pack
/// * `bit` - The bit width for coefficient bounds
///
/// # Returns
/// Extended vector with packed polynomial coefficients appended in order.
/// The polynomials are packed sequentially, maintaining a stable transcript layout.
pub fn flatten(mut inputs: Vec<Field>, polynomials: &[Polynomial], bit: u32) -> Vec<Field> {
    for polynomial in polynomials {
        let packed = packer(polynomial, bit);
        inputs.extend(packed);
    }
    inputs
}

/// Reverses, centers, and packs one canonical RNS row without per-coefficient allocations.
/// Returns `None` if the row cannot use the fixed-width path.
pub fn pack_centered_rns_row(coefficients: &[u64], modulus: u64, bit: u32) -> Option<Vec<Field>> {
    let (nibble_bits, group) = packing_layout(bit);
    if modulus == 0 || nibble_bits > 120 || coefficients.iter().any(|value| *value >= modulus) {
        return None;
    }
    let base = 1i128 << nibble_bits;
    let digit_bits = nibble_bits + 4;
    let radix = 1u128 << digit_bits;
    let group = group as usize;
    let mut values = coefficients.iter().rev();
    let mut output = Vec::with_capacity(coefficients.len().div_ceil(group));
    for _ in 0..coefficients.len().div_ceil(group) {
        let mut accumulator = FieldInteger::<4>::from(0u64);
        for _ in 0..group {
            let value = values.next().copied().unwrap_or(0);
            let negative = if modulus % 2 == 0 {
                value >= modulus / 2
            } else {
                value > modulus / 2
            };
            let centered = i128::from(value) - if negative { i128::from(modulus) } else { 0 };
            let digit = u128::try_from(centered.checked_add(base)?).ok()?;
            if digit >= radix {
                return None;
            }
            accumulator <<= digit_bits;
            if accumulator.add_with_carry(&FieldInteger([digit as u64, (digit >> 64) as u64, 0, 0]))
            {
                return None;
            }
        }
        output.push(Field::from_bigint(accumulator)?);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_rns_packing_matches_reverse_center_and_bigint_packing() {
        for modulus in [
            2u64,
            3,
            16,
            17,
            65537,
            (1 << 51) - 1,
            (1 << 62) - 57,
            u64::MAX,
        ] {
            let bit = 64 - (modulus / 2).leading_zeros();
            for length in [0, 1, 3, 4, 7, 16, 31, 512] {
                let edges = [0, 1, modulus / 2, modulus - 1];
                let coefficients: Vec<_> = edges.into_iter().cycle().take(length).collect();
                let mut reference = Polynomial::from_u64_vector(coefficients.clone());
                reference.reverse();
                reference.center(&BigInt::from(modulus));
                assert_eq!(
                    pack_centered_rns_row(&coefficients, modulus, bit).unwrap(),
                    packer_bigint(&reference, bit)
                );
            }
        }
        assert!(pack_centered_rns_row(&[17], 17, 5).is_none());
        assert!(pack_centered_rns_row(&[0], 0, 5).is_none());
    }

    #[test]
    fn fixed_width_packing_matches_bigint_at_boundaries() {
        for bit in [0, 1, 4, 5, 8, 31, 32, 51, 53, 60, 64, 100, 120] {
            let (nibble_bits, group) = packing_layout(bit);
            let base = BigInt::from(1) << nibble_bits;
            let edge = vec![
                -&base,
                -&base + 1,
                BigInt::from(-1),
                BigInt::zero(),
                &base - 1,
                base,
            ];
            for length in [
                0,
                1,
                group as usize - 1,
                group as usize,
                group as usize + 1,
                100,
            ] {
                let polynomial =
                    Polynomial::new(edge.iter().cycle().take(length).cloned().collect());
                assert_eq!(
                    packer_fixed_width(&polynomial, bit).unwrap(),
                    packer_bigint(&polynomial, bit)
                );
            }
        }
    }

    #[test]
    fn fixed_width_packing_matches_bigint_for_deterministic_samples() {
        let mut state = 7u64;
        for bit in 1..=64 {
            let values = (0..131)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let magnitude = u128::from(state) & ((1u128 << bit) - 1);
                    let value = BigInt::from(magnitude);
                    if state & 1 == 0 {
                        value
                    } else {
                        -value
                    }
                })
                .collect();
            let polynomial = Polynomial::new(values);
            assert_eq!(
                packer_fixed_width(&polynomial, bit).unwrap(),
                packer_bigint(&polynomial, bit)
            );
        }
    }

    #[test]
    fn packing_retains_bigint_fallback() {
        for (bit, value) in [(8, BigInt::from(1) << 40), (200, BigInt::from(1) << 199)] {
            let polynomial = Polynomial::new(vec![value]);
            assert!(packer_fixed_width(&polynomial, bit).is_none());
            assert_eq!(packer(&polynomial, bit), packer_bigint(&polynomial, bit));
        }
    }

    #[test]
    fn test_packing_layout() {
        // Test nibble alignment
        // For bit=1 or 4: nibble_bits=4, radix uses 4+4=8 bits, so group=254/8=31
        assert_eq!(packing_layout(1), (4, 31));
        assert_eq!(packing_layout(4), (4, 31));
        // For bit=5 or 8: nibble_bits=8, radix uses 8+4=12 bits, so group=254/12=21
        assert_eq!(packing_layout(5), (8, 21));
        assert_eq!(packing_layout(8), (8, 21));
        // For bit=51: nibble_bits=52, radix uses 52+4=56 bits, so group=254/56=4
        assert_eq!(packing_layout(51), (52, 4));
    }

    #[test]
    fn test_packer_single_value() {
        let poly = Polynomial::new(vec![BigInt::from(42)]);
        let packed = packer(&poly, 8);
        assert!(!packed.is_empty());
    }

    #[test]
    fn test_flatten_empty() {
        let inputs = Vec::new();
        let polys: Vec<Polynomial> = vec![];
        let result = flatten(inputs, &polys, 8);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_flatten_single_poly() {
        let inputs = Vec::new();
        let poly = Polynomial::new(vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)]);
        let polys = vec![poly];
        let result = flatten(inputs, &polys, 8);
        assert!(!result.is_empty());
    }
}
