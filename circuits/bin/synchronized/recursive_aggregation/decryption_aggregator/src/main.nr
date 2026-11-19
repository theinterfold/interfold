// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use lib::configs::protocol::MAX_MSG_NON_ZERO_COEFFS;
use lib::configs::synchronized::sync_insecure_64::{C6_PUBLIC_FIELDS, T};
use poseidon::poseidon2::Poseidon2;

// Minimum verifies the two private C6 leaves directly. The public pins must be compared
// with the independently selected synchronized artifacts by the final verifier.
fn main(
    c6_vk: UltraHonkVerificationKey,
    c6_proofs: [UltraHonkZKProof; T + 1],
    c7_vk: UltraHonkVerificationKey,
    c7_proof: UltraHonkZKProof,
    c6_key_hash: pub Field,
    c7_key_hash: pub Field,
    c7_public: pub [Field; (T + 1) * C6_PUBLIC_FIELDS + MAX_MSG_NON_ZERO_COEFFS],
) {
    assert(Poseidon2::hash(c6_vk, c6_vk.len()) == c6_key_hash, "Wrong synchronized C6 VK");
    assert(Poseidon2::hash(c7_vk, c7_vk.len()) == c7_key_hash, "Wrong synchronized C7 VK");
    for s in 0..T + 1 {
        let mut row = [0; C6_PUBLIC_FIELDS];
        for j in 0..C6_PUBLIC_FIELDS {
            row[j] = c7_public[s * C6_PUBLIC_FIELDS + j];
        }
        verify_honk_proof(c6_vk, c6_proofs[s], row, c6_key_hash);
    }
    verify_honk_proof(c7_vk, c7_proof, c7_public, c7_key_hash);
}
