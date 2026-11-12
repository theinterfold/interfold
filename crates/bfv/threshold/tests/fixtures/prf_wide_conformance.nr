// SPDX-License-Identifier: LGPL-3.0-only

use lib::math::prf::decryption_mask;

// Private secure-width residues in an insecure small ring, not secure-profile qualification.
fn main(
    owner: u32,
    ids: [u32; 3],
    level: u32,
    ciphertext: [[[u64; 8]; 3]; 2],
    outgoing: [[u8; 32]; 5],
    incoming: [[u8; 32]; 5],
    moduli: [u64; 3],
    expected: pub [[u64; 8]; 3],
) {
    assert(
        decryption_mask::<8, 3, 5, 3>(owner, ids, level, ciphertext, outgoing, incoming, moduli)
            == expected,
    );
}
