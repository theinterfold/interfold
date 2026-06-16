// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! SAFE (Sponge API for Field Elements)
//!
//! This module provides a complete implementation of the SAFE API in Rust as defined in:
//! "SAFE (Sponge API for Field Elements) - A Toolbox for ZK Hash Applications"
//! see https://hackmd.io/bHgsH6mMStCVibM_wYvb2w#22-Sponge-state for more details.
//!
//! SAFE provides a unified interface for cryptographic sponge functions that can be
//! instantiated with various permutations to create hash functions, MACs, authenticated
//! encryption schemes, and other cryptographic primitives for ZK proof systems.
//!
//! This implementation follows the SAFE specification exactly, providing:
//! - Complete API: START, ABSORB, SQUEEZE, FINISH operations.
//! - Full security: Domain separation, tag computation, IO pattern validation.
//! - Poseidon2 integration: Field-friendly permutation for ZK systems.
//! - Specification compliance: All operations follow SAFE spec 2.4 exactly.
//! - Natural API design: Variable-length inputs, automatic length detection from IO patterns.

use ark_bn254::Fr;
use ark_ff::Zero;
use sha3::{Digest, Keccak256};
use taceo_poseidon2::bn254::t4::permutation as poseidon2_permutation;

/// Field type used throughout the SAFE implementation (BN254 scalar field)
pub type Field = Fr;

/// Rate parameter for the sponge construction (number of field elements that can be absorbed per permutation call).
pub const RATE: usize = 3;

/// Capacity parameter for the sponge construction (security parameter, typically 1-2 field elements).
pub const CAPACITY: usize = 1;

/// Total state size (rate + capacity) in field elements.
pub const STATE_SIZE: usize = RATE + CAPACITY;

// IO Pattern encoding constants (from SAFE spec 2.3).
//
// These constants are used for encoding operation types in the 32-bit word format:
// - MSB set to 1 for ABSORB operations
// - MSB set to 0 for SQUEEZE operations

/// Flag for ABSORB operations (MSB = 1)
pub const ABSORB_FLAG: u32 = 0x80000000;

/// Flag for SQUEEZE operations (MSB = 0)
pub const SQUEEZE_FLAG: u32 = 0x00000000;

/// SAFE Sponge State (following spec 2.2)
///
/// The sponge state consists of the permutation state, tag, position counters,
/// and IO pattern tracking as defined in the SAFE specification.
///
/// # Generic Parameters
/// - `L`: The length of the IO pattern array
///
/// # Fields
/// - `state`: Permutation state V in F^n (rate + capacity elements)
/// - `tag`: Parameter tag T used for instance differentiation
/// - `absorb_pos`: Current absorb position (<= n-c)
/// - `squeeze_pos`: Current squeeze position (<= n-c)
/// - `io_pattern`: Expected IO pattern for validation (encoded 32-bit words)
/// - `io_count`: Current operation count for pattern tracking
#[derive(Clone, Debug)]
pub struct SafeSponge<const L: usize> {
    /// Permutation state V in F^n (rate + capacity elements).
    state: [Field; STATE_SIZE],
    /// Parameter tag T used for instance differentiation.
    #[allow(dead_code)]
    tag: Field,
    /// Current absorb position (<= n-c).
    absorb_pos: usize,
    /// Current squeeze position (<= n-c).
    squeeze_pos: usize,
    /// Expected IO pattern for validation.
    io_pattern: [u32; L],
    /// Current operation count for pattern tracking (spec 2.4: io_count).
    io_count: usize,
}

impl<const L: usize> SafeSponge<L> {
    /// Initializes a new SAFE sponge instance with the given IO pattern and domain separator (following spec 2.4).
    ///
    /// # Arguments
    /// - `io_pattern`: Array of 32-bit encoded operations defining the expected sequence of ABSORB/SQUEEZE calls.
    ///   Each word has MSB=1 for ABSORB operations, MSB=0 for SQUEEZE operations.
    /// - `domain_separator`: 64-byte domain separator for cross-protocol security.
    ///
    /// # Returns
    /// A new `SafeSponge` instance with initialized state
    pub fn start(io_pattern: [u32; L], domain_separator: [u8; 64]) -> SafeSponge<L> {
        // Compute tag from IO pattern and domain separator (spec 2.3).
        let tag = compute_tag(io_pattern, domain_separator);

        let mut state = [Field::zero(); STATE_SIZE];
        // Initialize capacity with tag (spec 2.4).
        // Add T to the first 128 bits of the state.
        state[0] = tag;

        SafeSponge {
            state,
            tag,
            absorb_pos: 0,
            squeeze_pos: 0,
            io_pattern,
            io_count: 0,
        }
    }

    /// Absorbs field elements into the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// The number of elements to absorb is automatically validated against the IO pattern.
    /// This method accepts variable-length slices, making it natural to use without padding.
    ///
    /// # Arguments
    /// - `input`: Slice of field elements to absorb (variable length, must match IO pattern)
    ///
    /// # Panics
    /// Panics if the operation doesn't match the expected IO pattern.
    pub fn absorb(&mut self, input: Vec<Field>) {
        let length = input.len() as u32;

        // Validate against IO pattern.
        assert!(self.io_count < L, "IO pattern exhausted");

        // Parse expected operation from io_pattern (encoded word)
        let expected_encoded_word = self.io_pattern[self.io_count];
        let is_expected_absorb = (expected_encoded_word & ABSORB_FLAG) != 0;
        let expected_length = expected_encoded_word & 0x7FFFFFFF;

        // Validate operation type and length
        assert!(is_expected_absorb, "Expected ABSORB operation");
        assert!(expected_length == length, "Length mismatch");

        // Process each element naturally (no unnecessary iterations).
        for input in &input {
            // If absorb_pos == (n-c) then permute and reset (spec 2.4).
            if self.absorb_pos == RATE {
                // n-c = RATE.
                self.state = self.permute();
                self.absorb_pos = 0;
            }

            // Add X[i] to state at absorb_pos (spec 2.4).
            // Note: absorb_pos is the rate position, not capacity position.
            self.state[self.absorb_pos + CAPACITY] += input;
            self.absorb_pos += 1;
        }

        // Verify that the encoded word matches the expected pattern.
        let encoded_word = ABSORB_FLAG | length;
        assert!(encoded_word == expected_encoded_word);

        self.io_count += 1;

        // Force permute at start of next SQUEEZE (spec 2.4).
        self.squeeze_pos = RATE;
    }

    /// Extracts field elements from the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// The number of elements to squeeze is automatically determined from the IO pattern.
    ///
    /// # Returns
    /// A vector of field elements squeezed from the sponge state.
    ///
    /// # Panics
    /// Panics if the operation doesn't match the expected IO pattern.
    pub fn squeeze(&mut self) -> Vec<Field> {
        // Validate against IO pattern.
        assert!(self.io_count < L, "IO pattern exhausted");

        // Parse expected operation from io_pattern (encoded word)
        let expected_encoded_word = self.io_pattern[self.io_count];
        let is_expected_squeeze = (expected_encoded_word & ABSORB_FLAG) == 0;
        let length = (expected_encoded_word & 0x7FFFFFFF) as usize;

        // Validate operation type
        assert!(is_expected_squeeze, "Expected SQUEEZE operation");

        let mut output = Vec::with_capacity(length);

        // SQUEEZE implementation following spec 2.4.
        // If length==0, loop won't execute (spec 2.4).
        for _ in 0..length {
            // If squeeze_pos==(n-c) then permute and reset (spec 2.4).
            if self.squeeze_pos == RATE {
                // n-c = RATE.
                self.state = self.permute();
                self.squeeze_pos = 0;
                self.absorb_pos = 0;
            }
            // Set Y[i] to state element at squeeze_pos (spec 2.4).
            output.push(self.state[self.squeeze_pos + CAPACITY]);
            self.squeeze_pos += 1;
        }

        // Verify that the encoded word matches the expected pattern.
        let encoded_word = SQUEEZE_FLAG | (length as u32);
        assert!(encoded_word == expected_encoded_word);

        self.io_count += 1;
        output
    }

    /// Finalizes the sponge instance, verifying that all expected operations have been performed
    /// and clearing the internal state for security (following spec 2.4).
    ///
    /// This function is used to ensure that the sponge instance has been used correctly
    /// and to prevent information leakage.
    ///
    /// # Panics
    /// Panics if not all operations in the IO pattern have been performed.
    pub fn finish(&mut self) {
        // Check that io_count equals the length of the IO pattern expected (spec 2.4).
        assert!(self.io_count == L, "IO pattern not completed");

        // Erase the state and its variables (spec 2.4).
        self.state = [Field::zero(); STATE_SIZE];
        self.absorb_pos = 0;
        self.squeeze_pos = 0;
        self.io_count = 0;
    }

    /// Permute the state using Poseidon2 (following spec 2.4).
    ///
    /// Applies the Poseidon2 permutation to the current state.
    /// This is the core cryptographic primitive of the sponge construction.
    ///
    /// # Returns
    /// New state after permutation
    fn permute(&self) -> [Field; STATE_SIZE] {
        poseidon2_permutation(&self.state)
    }
}

/// Computes a unique tag for a sponge instance based on its IO pattern and domain separator.
/// The tag is used to ensure that distinct instances behave like distinct functions.
///
/// # Generic Parameters
/// - `L`: The length of the IO pattern array
///
/// # Arguments
/// - `io_pattern`: Array of 32-bit encoded operations defining the sponge's usage pattern.
///   Each word has MSB=1 for ABSORB operations, MSB=0 for SQUEEZE operations.
/// - `domain_separator`: 64-byte domain separator for cross-protocol security.
///
/// # Returns
/// A field element representing the 128-bit tag.
pub fn compute_tag<const L: usize>(io_pattern: [u32; L], domain_separator: [u8; 64]) -> Field {
    // Step 1: Parse and aggregate consecutive operations of the same type
    let mut encoded_words = [0; L]; // Support up to L operations.
    let mut word_count = 0;
    let mut current_absorb_sum = 0;
    let mut current_squeeze_sum = 0;
    let mut last_was_absorb = false;

    for item in io_pattern.iter().take(L) {
        if *item > 0 {
            // Parse operation type from MSB and length from lower 31 bits
            let is_absorb = (*item & ABSORB_FLAG) != 0;
            let length = *item & 0x7FFFFFFF; // Clear MSB to get length

            if is_absorb {
                if last_was_absorb {
                    // Aggregate consecutive ABSORB operations
                    current_absorb_sum += length;
                } else {
                    // Start new ABSORB sequence
                    if current_squeeze_sum > 0 {
                        // Flush previous SQUEEZE sequence
                        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum;
                        word_count += 1;
                        current_squeeze_sum = 0;
                    }
                    current_absorb_sum = length;
                }
                last_was_absorb = true;
            } else {
                if !last_was_absorb {
                    // Aggregate consecutive SQUEEZE operations
                    current_squeeze_sum += length;
                } else {
                    // Start new SQUEEZE sequence
                    if current_absorb_sum > 0 {
                        // Flush previous ABSORB sequence
                        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum;
                        word_count += 1;
                        current_absorb_sum = 0;
                    }
                    current_squeeze_sum = length;
                }
                last_was_absorb = false;
            }
        }
    }

    // Flush remaining operations
    if current_absorb_sum > 0 {
        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum;
        word_count += 1;
    }
    if current_squeeze_sum > 0 {
        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum;
        word_count += 1;
    }

    // Step 2: Serialize to byte string and append domain separator (following SAFE spec 2.3).
    // Buffer is 256 bytes: max 192 bytes for IO pattern (48 words) + 64 bytes for domain separator.
    // Note: We use a fixed-size array to match Noir's implementation exactly.
    let max_io_pattern_bytes = 192; // 256 - 64 (domain separator)
    let io_pattern_bytes = word_count * 4;
    assert!(
        io_pattern_bytes <= max_io_pattern_bytes,
        "IO pattern too large: max 48 aggregated words supported"
    );

    let mut input_bytes = [0u8; 256];
    let mut byte_count = 0;

    // Serialize encoded words to bytes (big-endian as per SAFE spec).
    for word in encoded_words.iter().take(word_count) {
        let word = *word;
        input_bytes[byte_count] = (word >> 24) as u8;
        input_bytes[byte_count + 1] = (word >> 16) as u8;
        input_bytes[byte_count + 2] = (word >> 8) as u8;
        input_bytes[byte_count + 3] = word as u8;
        byte_count += 4;
    }

    // Append full 64-byte domain separator.
    for ds_val in domain_separator {
        input_bytes[byte_count] = ds_val;
        byte_count += 1;
    }

    // Step 3: Hash with Keccak-256 and truncate to 128 bits.
    // Note: Using Keccak-256 (Ethereum's hash) for compatibility with Noir's keccak256.
    // The SAFE spec mentions SHA3-256, but Keccak-256 is used here for cross-implementation consistency.
    // Hash only the first byte_count bytes to match Noir's keccak256(input_bytes, byte_count).
    let mut hasher = Keccak256::new();
    hasher.update(&input_bytes[..byte_count]);
    let hash_bytes = hasher.finalize();

    // Convert first 128 bits (16 bytes) to field element.
    let mut tag_value: Field = Field::zero();
    for i in 0..16 {
        tag_value = tag_value * Field::from(256) + Field::from(hash_bytes[i]);
    }

    tag_value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a field element from a u64 value
    fn field_from_u64(val: u64) -> Field {
        Field::from(val)
    }

    fn test_domain_separator() -> [u8; 64] {
        let mut ds = [0u8; 64];
        ds[0] = 0x41; // 'A'
        ds[1] = 0x42; // 'B'
        ds[2] = 0x43; // 'C'
        ds[3] = 0x44; // 'D'
        ds
    }

    #[test]
    fn test_safe_hashing() {
        // Verifies basic hash functionality with a simple ABSORB(3) + SQUEEZE(1) pattern.
        let domain_separator = test_domain_separator();
        let elements = vec![field_from_u64(1), field_from_u64(2), field_from_u64(3)];

        // Pattern: ABSORB(3), SQUEEZE(1)
        let io_pattern = [0x80000003, 0x00000001];
        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(elements.clone());
        let output = sponge.squeeze();
        sponge.finish();

        assert_eq!(output.len(), 1);
        assert!(output[0] != Field::zero());

        // Test determinism
        let mut sponge2 = SafeSponge::start(io_pattern, domain_separator);
        sponge2.absorb(elements.clone());
        let output2 = sponge2.squeeze();
        sponge2.finish();

        assert_eq!(output2.len(), 1);
        assert_eq!(output[0], output2[0]);
    }

    #[test]
    fn test_merkle_node() {
        // Verifies SAFE can be used for Merkle tree node hashing with pattern ABSORB(1) + ABSORB(1) + SQUEEZE(1).
        let domain_separator = test_domain_separator();
        let left = vec![field_from_u64(123)];
        let right = vec![field_from_u64(456)];

        // Pattern: ABSORB(1), ABSORB(1), SQUEEZE(1)
        let io_pattern = [0x80000001, 0x80000001, 0x00000001];
        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(left.clone());
        sponge.absorb(right.clone());
        let output = sponge.squeeze();
        sponge.finish();

        assert_eq!(output.len(), 1);
        assert!(output[0] != Field::zero());

        // Test determinism
        let mut sponge2 = SafeSponge::start(io_pattern, domain_separator);
        sponge2.absorb(left.clone());
        sponge2.absorb(right.clone());
        let output2 = sponge2.squeeze();
        sponge2.finish();

        assert_eq!(output[0], output2[0]);
    }

    #[test]
    fn test_commitment_scheme() {
        // Verifies SAFE can be used for commitment schemes with pattern ABSORB(3) + SQUEEZE(1).
        let domain_separator = test_domain_separator();
        let values = vec![field_from_u64(10), field_from_u64(20), field_from_u64(30)];

        // Pattern: ABSORB(3), SQUEEZE(1)
        let io_pattern = [0x80000003, 0x00000001];
        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(values.clone());
        let output = sponge.squeeze();
        sponge.finish();

        assert_eq!(output.len(), 1);
        assert!(output[0] != Field::zero());

        // Test determinism
        let mut sponge2 = SafeSponge::start(io_pattern, domain_separator);
        sponge2.absorb(values.clone());
        let output2 = sponge2.squeeze();
        sponge2.finish();

        assert_eq!(output[0], output2[0]);
    }

    #[test]
    fn test_domain_separation() {
        // Verifies that different domain separators produce different outputs for the same input.
        let elements = vec![field_from_u64(1), field_from_u64(2), field_from_u64(3)];

        let mut domain1 = [0u8; 64];
        domain1[0] = 0x41;
        domain1[1] = 0x42;
        domain1[2] = 0x43;
        domain1[3] = 0x44;

        let mut domain2 = [0u8; 64];
        domain2[0] = 0x41;
        domain2[1] = 0x42;
        domain2[2] = 0x43;
        domain2[3] = 0x45; // Different!

        // Pattern: ABSORB(3), SQUEEZE(1)
        let io_pattern = [0x80000003, 0x00000001];

        let mut sponge1 = SafeSponge::start(io_pattern, domain1);
        sponge1.absorb(elements.clone());
        let output1 = sponge1.squeeze();
        sponge1.finish();

        let mut sponge2 = SafeSponge::start(io_pattern, domain2);
        sponge2.absorb(elements.clone());
        let output2 = sponge2.squeeze();
        sponge2.finish();

        assert_eq!(output1.len(), 1);
        assert_eq!(output2.len(), 1);
        assert!(output1[0] != output2[0]); // Different domain separators should produce different outputs
    }

    #[test]
    fn test_multiple_squeeze() {
        // Verifies that multiple field elements can be squeezed in a single operation.
        let domain_separator = test_domain_separator();
        let elements = vec![field_from_u64(1), field_from_u64(2), field_from_u64(3)];

        // Pattern: ABSORB(3), SQUEEZE(2)
        let io_pattern = [0x80000003, 0x00000002];
        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(elements.clone());
        let output = sponge.squeeze();
        sponge.finish();

        assert_eq!(output.len(), 2);
        assert!(output[0] != Field::zero());
        assert!(output[1] != Field::zero());
        assert!(output[0] != output[1]); // Different squeeze outputs should be different
    }

    #[test]
    fn test_zero_length_operations() {
        // Verifies that zero-length ABSORB and SQUEEZE operations are handled correctly.
        let domain_separator = test_domain_separator();

        // Pattern: ABSORB(0), SQUEEZE(1)
        let io_pattern = [0x80000000, 0x00000001];
        let mut sponge = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(vec![]);
        let output = sponge.squeeze();
        sponge.finish();

        assert_eq!(output.len(), 1);
        assert!(output[0] != Field::zero());
    }

    #[test]
    fn test_tag_computation() {
        // Verifies the tag computation algorithm.
        // Pattern: ABSORB(3), ABSORB(3), SQUEEZE(3)
        // Should aggregate to: ABSORB(6), SQUEEZE(3)
        let io_pattern = [0x80000003, 0x80000003, 0x00000003];
        let domain_separator = test_domain_separator();

        let tag = compute_tag(io_pattern, domain_separator);

        // Test determinism
        let tag2 = compute_tag(io_pattern, domain_separator);
        assert_eq!(tag, tag2);

        // Test that different patterns produce different tags
        let io_pattern2 = [0x80000003, 0x00000003]; // ABSORB(3), SQUEEZE(3) - different pattern
        let tag3 = compute_tag(io_pattern2, domain_separator);
        assert!(tag != tag3);
    }

    #[test]
    fn test_consecutive_absorb_aggregation() {
        // Test that consecutive ABSORB operations are properly aggregated
        // Pattern: ABSORB(1), ABSORB(1), SQUEEZE(1) should aggregate to ABSORB(2), SQUEEZE(1)
        let domain_separator = test_domain_separator();

        // Test pattern: ABSORB(1), ABSORB(1), SQUEEZE(1)
        let io_pattern = [0x80000001, 0x80000001, 0x00000001];

        // This should aggregate to: ABSORB(2), SQUEEZE(1) = [0x80000002, 0x00000001]
        let tag = compute_tag(io_pattern, domain_separator);

        // Test that the aggregated pattern produces the same tag ABSORB(2), SQUEEZE(1)
        let aggregated_pattern = [0x80000002, 0x00000001];
        let aggregated_tag = compute_tag(aggregated_pattern, domain_separator);

        // The tags should be identical because the patterns are equivalent after aggregation
        assert_eq!(
            tag, aggregated_tag,
            "Consecutive ABSORB operations should aggregate to the same tag"
        );

        // Test that a different pattern produces a different tag
        let different_pattern = [0x80000001, 0x00000001, 0x80000001]; // ABSORB(1), SQUEEZE(1), ABSORB(1)
        let different_tag = compute_tag(different_pattern, domain_separator);

        // This should be different because it doesn't have consecutive ABSORB operations
        assert!(
            tag != different_tag,
            "Different patterns should produce different tags"
        );
    }

    #[test]
    fn test_consecutive_squeeze_aggregation() {
        // Test that consecutive SQUEEZE operations are properly aggregated
        // Pattern: ABSORB(1), SQUEEZE(1), SQUEEZE(1) should aggregate to ABSORB(1), SQUEEZE(2)
        let domain_separator = test_domain_separator();

        // Test pattern: ABSORB(1), SQUEEZE(1), SQUEEZE(1)
        let io_pattern = [0x80000001, 0x00000001, 0x00000001];

        // This should aggregate to: ABSORB(1), SQUEEZE(2) = [0x80000001, 0x00000002]
        let tag = compute_tag(io_pattern, domain_separator);

        // Test that the aggregated pattern produces the same tag ABSORB(1), SQUEEZE(2)
        let aggregated_pattern = [0x80000001, 0x00000002];
        let aggregated_tag = compute_tag(aggregated_pattern, domain_separator);

        // The tags should be identical because the patterns are equivalent after aggregation
        assert_eq!(
            tag, aggregated_tag,
            "Consecutive SQUEEZE operations should aggregate to the same tag"
        );

        // Test that a different pattern produces a different tag
        let different_pattern = [0x80000001, 0x00000001, 0x80000001]; // ABSORB(1), SQUEEZE(1), ABSORB(1)
        let different_tag = compute_tag(different_pattern, domain_separator);

        // This should be different because it doesn't have consecutive SQUEEZE operations
        assert!(
            tag != different_tag,
            "Different patterns should produce different tags"
        );
    }

    #[test]
    fn test_mixed_consecutive_aggregation() {
        // Test that both consecutive ABSORB and SQUEEZE operations are properly aggregated
        // Pattern: ABSORB(1), ABSORB(1), SQUEEZE(1), SQUEEZE(1), ABSORB(1)
        // Should aggregate to: ABSORB(2), SQUEEZE(2), ABSORB(1)
        let domain_separator = test_domain_separator();

        // Test pattern: ABSORB(1), ABSORB(1), SQUEEZE(1), SQUEEZE(1), ABSORB(1)
        let io_pattern = [0x80000001, 0x80000001, 0x00000001, 0x00000001, 0x80000001];

        // This should aggregate to: ABSORB(2), SQUEEZE(2), ABSORB(1) = [0x80000002, 0x00000002, 0x80000001]
        let tag = compute_tag(io_pattern, domain_separator);

        // Test that the aggregated pattern produces the same tag
        let aggregated_pattern = [0x80000002, 0x00000002, 0x80000001]; // ABSORB(2), SQUEEZE(2), ABSORB(1)
        let aggregated_tag = compute_tag(aggregated_pattern, domain_separator);

        // The tags should be identical because the patterns are equivalent after aggregation
        assert_eq!(
            tag, aggregated_tag,
            "Mixed consecutive operations should aggregate to the same tag"
        );
    }
    #[test]
    fn test_large_io_pattern() {
        let domain_separator = test_domain_separator();

        // Create pattern with 48 alternating ABSORB(1) and SQUEEZE(1) operations
        // This is the maximum supported (48 words * 4 bytes = 192 bytes, leaving 64 for domain separator)
        let mut io_pattern = [0u32; 48];
        for (i, slot) in io_pattern.iter_mut().enumerate() {
            if i % 2 == 0 {
                *slot = ABSORB_FLAG | 1; // ABSORB(1)
            } else {
                *slot = SQUEEZE_FLAG | 1; // SQUEEZE(1)
            }
        }

        let tag = compute_tag(io_pattern, domain_separator);
        assert!(tag != Field::zero());
    }

    #[test]
    fn test_domain_separator_not_truncated() {
        // This test verifies that the domain separator is always included in the tag computation,
        // even for large IO patterns. If the domain separator were truncated, different domain
        // separators would produce the same tag for large patterns.

        let domain_separator_a = [0x41u8; 64]; // All 'A's
        let domain_separator_b = [0x42u8; 64]; // All 'B's

        // Create pattern with 48 alternating operations (max supported: 192 bytes of IO pattern)
        let mut io_pattern = [0u32; 48];
        for (i, slot) in io_pattern.iter_mut().enumerate() {
            if i % 2 == 0 {
                *slot = ABSORB_FLAG | 1;
            } else {
                *slot = SQUEEZE_FLAG | 1;
            }
        }

        let tag_a = compute_tag(io_pattern, domain_separator_a);
        let tag_b = compute_tag(io_pattern, domain_separator_b);

        // Tags MUST be different because domain separators are different.
        // If they were the same, it would mean the domain separator was truncated/ignored.
        assert_ne!(
            tag_a, tag_b,
            "Domain separator must affect tag even for large IO patterns"
        );
    }

    #[test]
    #[should_panic(expected = "IO pattern exhausted")]
    fn test_squeeze_io_pattern_exhausted() {
        // This test verifies that squeeze properly checks for IO pattern exhaustion
        // and provides a clear error message instead of an index-out-of-bounds panic.

        let domain_separator = test_domain_separator();

        // Create a sponge with exactly one operation (L=1)
        let io_pattern: [u32; 1] = [ABSORB_FLAG | 1]; // Only ABSORB(1)

        let mut sponge: SafeSponge<1> = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(vec![field_from_u64(42)]);

        // io_count is now 1, which equals L=1, so this should panic with "IO pattern exhausted"
        let _ = sponge.squeeze();
    }

    #[test]
    #[should_panic(expected = "IO pattern exhausted")]
    fn test_absorb_io_pattern_exhausted() {
        // This test verifies that absorb properly checks for IO pattern exhaustion.

        let domain_separator = test_domain_separator();

        // Create a sponge with exactly one operation (L=1)
        let io_pattern: [u32; 1] = [ABSORB_FLAG | 1]; // Only ABSORB(1)

        let mut sponge: SafeSponge<1> = SafeSponge::start(io_pattern, domain_separator);
        sponge.absorb(vec![field_from_u64(42)]);

        // io_count is now 1, which equals L=1, so this should panic with "IO pattern exhausted"
        sponge.absorb(vec![field_from_u64(43)]);
    }
}
