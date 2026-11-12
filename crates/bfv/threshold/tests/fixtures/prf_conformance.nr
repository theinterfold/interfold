// SPDX-License-Identifier: LGPL-3.0-only

use lib::math::prf::decryption_mask;

// Standalone primitive conformance, not a C6 statement or a deployed verifier interface.
fn main(
    owner: u32,
    ids: [u32; 2],
    level: u32,
    ciphertext: [[[u64; 64]; 3]; 2],
    outgoing: [[u8; 32]; 3],
    incoming: [[u8; 32]; 3],
    moduli: [u64; 3],
    expected: pub [[u64; 64]; 3],
) {
    assert(
        decryption_mask::<64, 3, 3, 2>(owner, ids, level, ciphertext, outgoing, incoming, moduli)
            == expected,
    );
}
