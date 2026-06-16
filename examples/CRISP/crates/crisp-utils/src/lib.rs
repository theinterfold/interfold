// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_bfv_client::decode_bytes_to_vec_u64;
use eyre::Result;
use num_bigint::BigUint;

/// Number of polynomial coefficients used for the vote payload (must match `@crisp-e3/sdk` / circuits).
///
/// Splits evenly across options: `segment_size = MAX_MSG_NON_ZERO_COEFFS / num_choices` (e.g. 2 → 50 bits each).
pub const MAX_MSG_NON_ZERO_COEFFS: usize = 100;

/// Represents decoded vote counts from a tally
#[derive(Debug, Clone)]
pub struct VoteCounts {
    pub yes: BigUint,
    pub no: BigUint,
}

/// Decode an FHE-encrypted tally result into vote counts for each choice.
///
/// # Encoding scheme
///
/// Only the first [`MAX_MSG_NON_ZERO_COEFFS`] coefficients carry the vote; the rest are zero padding
/// to the BFV polynomial degree. With `n` choices, each choice uses
/// `segment_size = floor(MAX_MSG_NON_ZERO_COEFFS / n)` binary coefficients (MSB at the start of the segment).
///
///   |-- choice 0 --|-- choice 1 --| ... | unused in msg region |-- degree padding --|
///
/// Homomorphic addition is coefficient-wise, so summed ciphertexts yield per-coefficient sums and this
/// decode recovers each option’s total.
///
/// # Arguments
///
/// * `tally_bytes` - Raw bytes from the FHE decryption, encoding u64 values
///   in little-endian format (8 bytes per coefficient).
/// * `num_choices` - Number of voting options (must match what was used to encode).
///
/// # Returns
///
/// A `Vec<BigUint>` of length `num_choices`, where `results[i]` is the
/// total vote weight for choice `i`.
///
pub fn decode_tally(tally_bytes: &[u8], num_choices: usize) -> Result<Vec<BigUint>> {
    if num_choices == 0 {
        return Err(eyre::eyre!("Number of choices must be positive"));
    }

    let values = decode_bytes_to_vec_u64(tally_bytes)?;

    if values.len() < MAX_MSG_NON_ZERO_COEFFS {
        return Err(eyre::eyre!(
            "decoded coefficient count ({}) is less than MAX_MSG_NON_ZERO_COEFFS ({})",
            values.len(),
            MAX_MSG_NON_ZERO_COEFFS
        ));
    }

    let segment_size = MAX_MSG_NON_ZERO_COEFFS / num_choices;
    let mut results = Vec::with_capacity(num_choices);

    for choice_idx in 0..num_choices {
        let segment_start = choice_idx * segment_size;
        let segment = &values[segment_start..segment_start + segment_size];

        let mut value = BigUint::from(0u64);
        for (i, &v) in segment.iter().enumerate() {
            let weight = BigUint::from(2u64).pow((segment.len() - 1 - i) as u32);
            value += BigUint::from(v) * weight;
        }

        results.push(value);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `@crisp-e3/sdk` `encodeVote` (binary coeffs, first `MAX_MSG_NON_ZERO_COEFFS`, then zeros).
    fn encode_vote_like_sdk(vote: &[u64], degree: usize) -> Vec<u64> {
        assert!(vote.len() >= 2);
        assert!(degree >= MAX_MSG_NON_ZERO_COEFFS);

        let n = vote.len();
        let segment_size = MAX_MSG_NON_ZERO_COEFFS / n;
        let max_val = (1u128 << segment_size) - 1;

        let mut out = vec![0u64; degree];
        let mut idx = 0;

        for &value in vote {
            assert!(
                (value as u128) <= max_val,
                "value {value} exceeds max for segment_size {segment_size}"
            );
            let bits = format!("{value:b}");
            let bin_len = bits.len();
            for i in 0..segment_size {
                let offset = segment_size.saturating_sub(bin_len);
                out[idx] = if i < offset {
                    0
                } else {
                    u64::from(bits.as_bytes()[i - offset] - b'0')
                };
                idx += 1;
            }
        }

        while idx < MAX_MSG_NON_ZERO_COEFFS {
            out[idx] = 0;
            idx += 1;
        }

        out
    }

    fn coeffs_to_le_bytes(coeffs: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(coeffs.len() * 8);
        for c in coeffs {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn test_decode_tally_matches_sdk_layout() {
        let degree = 512;
        let coeffs = encode_vote_like_sdk(&[10_000_000_000u64, 30_000_000_000u64], degree);
        let bytes = coeffs_to_le_bytes(&coeffs);
        let result = decode_tally(&bytes, 2).unwrap();

        assert_eq!(result[0], BigUint::from(10_000_000_000u64));
        assert_eq!(result[1], BigUint::from(30_000_000_000u64));
    }

    #[test]
    fn test_decode_tally_wrong_num_options_differs() {
        let degree = 512;
        let coeffs = encode_vote_like_sdk(&[10_000_000_000u64, 30_000_000_000u64], degree);
        let bytes = coeffs_to_le_bytes(&coeffs);
        let result = decode_tally(&bytes, 3).unwrap();

        assert_ne!(result[0], BigUint::from(10_000_000_000u64));
        assert_ne!(result[1], BigUint::from(30_000_000_000u64));
    }
}
