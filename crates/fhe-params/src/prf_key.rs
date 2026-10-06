// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pack a PRF key into one limb of an encrypted secret share.
//!
//! The share-encryption plaintext modulus is `2 * q`, where `q` is the largest
//! threshold modulus. Coefficient `i` stores `residue + bit_i * q`. Bit 0 is
//! the least significant bit of the first key byte. Only the first
//! [`prf_key_bit_len`] coefficients carry key bits.

use crate::constants::{insecure, secure_16384, secure_8192};
use crate::BfvPreset;
use thiserror::Error;

/// Failure while packing or unpacking a PRF key in a share limb.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrfKeyPackError {
    /// The modulus is zero.
    #[error("modulus must be positive")]
    ZeroModulus,
    /// A share residue is outside `[0, q)`.
    #[error("share residue {residue} must be less than modulus {modulus}")]
    ResidueOutOfRange { residue: u64, modulus: u64 },
    /// The key bit is not 0 or 1.
    #[error("key bit {bit} must be 0 or 1")]
    BitOutOfRange { bit: u8 },
    /// The key length does not match the preset.
    #[error("PRF key has {actual_bits} bits, the preset requires {expected_bits} bits")]
    KeyLength {
        expected_bits: usize,
        actual_bits: usize,
    },
    /// The limb has fewer coefficients than the key.
    #[error("limb has {available} coefficients, the PRF key requires {needed}")]
    NotEnoughCoefficients { needed: usize, available: usize },
    /// A packed coefficient is outside `[0, 2q)`.
    #[error("packed coefficient {packed} must be less than twice modulus {modulus}")]
    PackedOutOfRange { packed: u64, modulus: u64 },
    /// A coefficient past the key prefix carries a key bit.
    #[error("coefficient {index} must not carry a key bit")]
    UnexpectedKeyBit { index: usize },
}

/// Return the number of PRF-key bits stored in one encrypted share.
///
/// The insecure preset stores 32 bits because its polynomial degree is 128.
/// Both secure presets store 256 bits.
#[must_use]
pub const fn prf_key_bit_len(preset: BfvPreset) -> usize {
    match preset {
        BfvPreset::InsecureThreshold | BfvPreset::InsecureDkg => insecure::dkg::PRF_KEY_BITS,
        BfvPreset::SecureThreshold8192 | BfvPreset::SecureDkg8192 => secure_8192::dkg::PRF_KEY_BITS,
        BfvPreset::SecureThreshold16384 | BfvPreset::SecureDkg16384 => {
            secure_16384::dkg::PRF_KEY_BITS
        }
    }
}

/// Return a key of the preset length whose bits are all zero.
#[must_use]
pub fn zero_prf_key(preset: BfvPreset) -> Vec<u8> {
    vec![0u8; prf_key_bit_len(preset) / 8]
}

/// Expand a key into bits. Bit 0 is the least significant bit of the first byte.
#[must_use]
pub fn prf_key_bits(key: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(key.len() * 8);
    for byte in key {
        for shift in 0..8 {
            bits.push((byte >> shift) & 1);
        }
    }
    bits
}

/// Return the largest threshold modulus. The PRF key is packed into this limb.
#[must_use]
pub fn prf_key_modulus(preset: BfvPreset) -> u64 {
    let threshold = preset.threshold_counterpart().unwrap_or(preset);
    crate::BfvParamSet::from(threshold)
        .moduli
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
}

/// Pack one key bit into a share residue.
///
/// The result is `residue + bit * q`.
pub fn pack_share_coefficient(residue: u64, bit: u8, q: u64) -> Result<u64, PrfKeyPackError> {
    if q == 0 {
        return Err(PrfKeyPackError::ZeroModulus);
    }
    if bit > 1 {
        return Err(PrfKeyPackError::BitOutOfRange { bit });
    }
    if residue >= q {
        return Err(PrfKeyPackError::ResidueOutOfRange {
            residue,
            modulus: q,
        });
    }
    let packed = u128::from(residue) + u128::from(bit) * u128::from(q);
    u64::try_from(packed).map_err(|_| PrfKeyPackError::PackedOutOfRange {
        packed: u64::MAX,
        modulus: q,
    })
}

/// Split a packed coefficient into the share residue and the key bit.
pub fn unpack_share_coefficient(packed: u64, q: u64) -> Result<(u64, u8), PrfKeyPackError> {
    if q == 0 {
        return Err(PrfKeyPackError::ZeroModulus);
    }
    let limit = u128::from(q) * 2;
    if u128::from(packed) >= limit {
        return Err(PrfKeyPackError::PackedOutOfRange { packed, modulus: q });
    }
    if packed >= q {
        Ok((packed - q, 1))
    } else {
        Ok((packed, 0))
    }
}

/// Write the key into the first coefficients of one share limb.
///
/// Coefficients after the key are copied unchanged. Each of those residues
/// must already lie in `[0, q)`.
pub fn pack_prf_key(
    preset: BfvPreset,
    residues: &[u64],
    key: &[u8],
    q: u64,
) -> Result<Vec<u64>, PrfKeyPackError> {
    let expected_bits = prf_key_bit_len(preset);
    let actual_bits = key.len().checked_mul(8).ok_or(PrfKeyPackError::KeyLength {
        expected_bits,
        actual_bits: usize::MAX,
    })?;
    if actual_bits != expected_bits {
        return Err(PrfKeyPackError::KeyLength {
            expected_bits,
            actual_bits,
        });
    }
    if residues.len() < expected_bits {
        return Err(PrfKeyPackError::NotEnoughCoefficients {
            needed: expected_bits,
            available: residues.len(),
        });
    }

    let mut packed = Vec::with_capacity(residues.len());
    for (index, &residue) in residues.iter().enumerate() {
        let bit = if index < expected_bits {
            key_bit(key, index)
        } else {
            0
        };
        packed.push(pack_share_coefficient(residue, bit, q)?);
    }
    Ok(packed)
}

/// Recover the share residues and the PRF key from one packed limb.
///
/// A coefficient after the key prefix must have key bit 0.
pub fn unpack_prf_key(
    preset: BfvPreset,
    packed: &[u64],
    q: u64,
) -> Result<(Vec<u64>, Vec<u8>), PrfKeyPackError> {
    let expected_bits = prf_key_bit_len(preset);
    if packed.len() < expected_bits {
        return Err(PrfKeyPackError::NotEnoughCoefficients {
            needed: expected_bits,
            available: packed.len(),
        });
    }

    let mut residues = Vec::with_capacity(packed.len());
    let mut key = vec![0u8; expected_bits / 8];
    for (index, &value) in packed.iter().enumerate() {
        let (residue, bit) = unpack_share_coefficient(value, q)?;
        if index < expected_bits {
            key[index / 8] |= bit << (index % 8);
        } else if bit != 0 {
            return Err(PrfKeyPackError::UnexpectedKeyBit { index });
        }
        residues.push(residue);
    }
    Ok((residues, key))
}

/// Return bit `index` of `key`. Bit 0 is the least significant bit of `key[0]`.
fn key_bit(key: &[u8], index: usize) -> u8 {
    (key[index / 8] >> (index % 8)) & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_pair_for_preset;

    #[test]
    fn share_plaintext_is_one_bit_wider_than_the_largest_threshold_modulus() {
        for preset in BfvPreset::PAIR_PRESETS {
            let (threshold, dkg) = build_pair_for_preset(preset).unwrap();
            let max_q = threshold.moduli().iter().copied().max().unwrap();
            assert_eq!(u128::from(dkg.plaintext()), u128::from(max_q) * 2);
            let two_t = u128::from(dkg.plaintext()) * 2;
            assert!(dkg.moduli().iter().all(|qi| u128::from(*qi) > two_t));
            assert!(prf_key_bit_len(preset) <= threshold.degree());
            assert_eq!(prf_key_modulus(preset), max_q);
        }
    }

    #[test]
    fn insecure_key_is_32_bits_and_secure_keys_are_256_bits() {
        assert_eq!(prf_key_bit_len(BfvPreset::InsecureDkg), 32);
        assert_eq!(prf_key_bit_len(BfvPreset::SecureDkg8192), 256);
        assert_eq!(prf_key_bit_len(BfvPreset::SecureDkg16384), 256);
    }

    #[test]
    fn packed_coefficient_round_trips_the_residue_and_the_bit() {
        let q = prf_key_modulus(BfvPreset::SecureThreshold16384);
        assert_eq!(pack_share_coefficient(7, 0, q).unwrap(), 7);
        assert_eq!(pack_share_coefficient(7, 1, q).unwrap(), 7 + q);
        assert_eq!(unpack_share_coefficient(7 + q, q).unwrap(), (7, 1));
        assert!(pack_share_coefficient(q, 0, q).is_err());
        assert!(unpack_share_coefficient(q * 2, q).is_err());
    }

    #[test]
    fn prf_key_round_trips_in_the_first_coefficients() {
        for (preset, key) in [
            (BfvPreset::InsecureThreshold, vec![0xA5u8, 0x11, 0x00, 0xFF]),
            (
                BfvPreset::SecureThreshold8192,
                (0u8..32).collect::<Vec<_>>(),
            ),
            (
                BfvPreset::SecureThreshold16384,
                (0u8..32).rev().collect::<Vec<_>>(),
            ),
        ] {
            let q = prf_key_modulus(preset);
            let bits = prf_key_bit_len(preset);
            let residues: Vec<u64> = (0..bits as u64 + 3).map(|index| index % q).collect();
            let packed = pack_prf_key(preset, &residues, &key, q).unwrap();
            let plaintext = u128::from(q) * 2;
            assert!(packed.iter().all(|value| u128::from(*value) < plaintext));
            let (unpacked, recovered) = unpack_prf_key(preset, &packed, q).unwrap();
            assert_eq!(unpacked, residues);
            assert_eq!(recovered, key);
        }
    }

    #[test]
    fn pack_rejects_a_key_of_the_wrong_length() {
        let q = prf_key_modulus(BfvPreset::InsecureDkg);
        let residues = vec![1u64; 32];
        assert!(pack_prf_key(BfvPreset::InsecureDkg, &residues, &[0u8; 32], q).is_err());
    }
}
