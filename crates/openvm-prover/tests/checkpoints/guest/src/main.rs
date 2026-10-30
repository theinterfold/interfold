// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

fn main() {
    // A public digest fixture exercises the worker's proof/identity/journal boundaries only.
    let digest = openvm::io::read_vec();
    assert_eq!(digest.len(), 32);
    for (index, word) in digest.chunks_exact(4).enumerate() {
        openvm::io::reveal_u32(u32::from_le_bytes(word.try_into().unwrap()), index);
    }
}
