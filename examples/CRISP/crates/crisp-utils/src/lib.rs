// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_bfv_client::decode_bytes_to_vec_u64;
use eyre::Result;
use num_bigint::BigUint;

/// Number of leading polynomial coefficients that carry the tally (must match `@crisp-e3/sdk` / circuits).
///
/// Coefficient `o` holds option `o`'s total; the rest, up to the BFV polynomial degree, is zero
/// padding.
pub const MAX_MSG_NON_ZERO_COEFFS: usize = 50;

/// Represents decoded vote counts from a tally
#[derive(Debug, Clone)]
pub struct VoteCounts {
    pub yes: BigUint,
    pub no: BigUint,
}

/// Decode an FHE-encrypted tally result into the total for each choice.
///
/// # Layout
///
/// Coefficient `o` of the decrypted polynomial is option `o`'s total weight, for `o < num_choices`,
/// because homomorphic addition is coefficient-wise. Later coefficients are ignored.
///
/// # Arguments
///
/// * `tally_bytes` - Raw bytes from the FHE decryption, encoding u64 values
///   in little-endian format (8 bytes per coefficient). At least [`MAX_MSG_NON_ZERO_COEFFS`]
///   coefficients are required.
/// * `num_choices` - Number of voting options, from 1 to [`MAX_MSG_NON_ZERO_COEFFS`].
///
/// # Returns
///
/// A `Vec<BigUint>` of length `num_choices`, where `results[i]` is the
/// total vote weight for choice `i`.
pub fn decode_tally(tally_bytes: &[u8], num_choices: usize) -> Result<Vec<BigUint>> {
    if num_choices == 0 {
        return Err(eyre::eyre!("Number of choices must be positive"));
    }

    if num_choices > MAX_MSG_NON_ZERO_COEFFS {
        return Err(eyre::eyre!(
            "Number of choices ({num_choices}) exceeds MAX_MSG_NON_ZERO_COEFFS ({MAX_MSG_NON_ZERO_COEFFS})"
        ));
    }

    let values = decode_bytes_to_vec_u64(tally_bytes)?;

    if values.len() < MAX_MSG_NON_ZERO_COEFFS {
        return Err(eyre::eyre!(
            "decoded coefficient count ({}) is less than MAX_MSG_NON_ZERO_COEFFS ({})",
            values.len(),
            MAX_MSG_NON_ZERO_COEFFS
        ));
    }

    Ok(values[..num_choices]
        .iter()
        .map(|&v| BigUint::from(v))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le_bytes(coeffs: &[u64]) -> Vec<u8> {
        coeffs.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn decode_tally_reads_coefficient_per_option_and_ignores_the_rest() {
        let mut coeffs = vec![99u64; 512];
        coeffs[..4].copy_from_slice(&[3, 0, 17_000_000, u64::MAX]);
        let expected: Vec<BigUint> = coeffs[..4].iter().map(|&t| BigUint::from(t)).collect();

        assert_eq!(decode_tally(&le_bytes(&coeffs), 4).unwrap(), expected);
    }

    #[test]
    fn decode_tally_bounds() {
        let min = le_bytes(&[7; MAX_MSG_NON_ZERO_COEFFS]);

        let all = decode_tally(&min, MAX_MSG_NON_ZERO_COEFFS).unwrap();
        assert_eq!(all.len(), MAX_MSG_NON_ZERO_COEFFS);
        assert!(decode_tally(&min, 0).is_err());
        assert!(decode_tally(&min, MAX_MSG_NON_ZERO_COEFFS + 1).is_err());
        assert!(decode_tally(&min[8..], 2).is_err());
    }
}
