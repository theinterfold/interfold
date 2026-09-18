// SPDX-License-Identifier: LGPL-3.0-only

/// Computes the protocol Keccak-256 digest without changing its input encoding.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    #[cfg(feature = "openvm-hashes")]
    {
        openvm_keccak256::keccak256(input)
    }
    #[cfg(not(feature = "openvm-hashes"))]
    {
        use sha3::{Digest, Keccak256};
        Keccak256::digest(input).into()
    }
}

#[cfg(test)]
mod tests {
    use super::keccak256;
    use sha3::{Digest, Keccak256};

    #[test]
    fn keccak_matches_reference_at_block_boundaries_and_unaligned_offsets() {
        for len in [0, 1, 31, 32, 63, 64, 135, 136, 137, 271, 272, 273, 356_469] {
            let bytes: Vec<u8> = (0..len + 4).map(|index| (index * 71 + 13) as u8).collect();
            for offset in 0..4 {
                let input = &bytes[offset..offset + len];
                let expected: [u8; 32] = Keccak256::digest(input).into();
                assert_eq!(keccak256(input), expected, "length {len}, offset {offset}");
            }
        }
    }
}
