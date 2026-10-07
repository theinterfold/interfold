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
/// Coefficient `o` holds option `o`'s total, so a round has at most this many options. The remaining
/// coefficients up to the BFV polynomial degree are zero padding.
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
/// Coefficient `o` of the decrypted polynomial is the total weight on option `o`, for
/// `o < num_choices`. Homomorphic addition is coefficient-wise, so the sum of the ballots holds the sum
/// of each option's weights in that option's coefficient. Coefficients at or after `num_choices` are
/// ignored.
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

    fn coeffs_to_le_bytes(coeffs: &[u64]) -> Vec<u8> {
        coeffs.iter().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// A tally polynomial of `degree` coefficients with `totals` in the leading coefficients and
    /// `noise` in every coefficient from `totals.len()` through the message region and the padding.
    fn tally_bytes(totals: &[u64], noise: u64, degree: usize) -> Vec<u8> {
        let mut coeffs = vec![noise; degree];
        coeffs[..totals.len()].copy_from_slice(totals);
        coeffs_to_le_bytes(&coeffs)
    }

    #[test]
    fn decode_tally_reads_coefficient_per_option_and_ignores_the_rest() {
        let totals = [3u64, 0, 17_000_000, u64::MAX];
        let bytes = tally_bytes(&totals, 99, 512);
        let result = decode_tally(&bytes, totals.len()).unwrap();

        let expected: Vec<BigUint> = totals.iter().map(|&t| BigUint::from(t)).collect();
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_tally_accepts_exactly_max_choices_at_minimum_length() {
        let totals: Vec<u64> = (1..=MAX_MSG_NON_ZERO_COEFFS as u64).collect();
        let bytes = coeffs_to_le_bytes(&totals);
        let result = decode_tally(&bytes, MAX_MSG_NON_ZERO_COEFFS).unwrap();

        assert_eq!(result.len(), MAX_MSG_NON_ZERO_COEFFS);
        assert_eq!(
            result[MAX_MSG_NON_ZERO_COEFFS - 1],
            BigUint::from(MAX_MSG_NON_ZERO_COEFFS as u64)
        );
    }

    #[test]
    fn decode_tally_rejects_invalid_arguments() {
        let bytes = tally_bytes(&[1, 2], 0, 512);
        assert!(decode_tally(&bytes, 0).is_err());
        assert!(decode_tally(&bytes, MAX_MSG_NON_ZERO_COEFFS + 1).is_err());

        let short = coeffs_to_le_bytes(&vec![0u64; MAX_MSG_NON_ZERO_COEFFS - 1]);
        assert!(decode_tally(&short, 2).is_err());
    }
}
