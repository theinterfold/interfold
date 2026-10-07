// SPDX-License-Identifier: LGPL-3.0-only

openvm::init!();

use bincode::Options;
use e3_support_types::{ComputeGuestInput, ComputeJournal};
use sha2::Digest;

fn main() {
    let bytes = openvm::io::read_vec();
    const MAX_BYTES: usize = 512 * 1024 * 1024 - 16;
    assert!(bytes.len() <= MAX_BYTES, "The input exceeds the byte limit");
    let input: ComputeGuestInput = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .expect("Invalid compute input");
    assert!(
        input.input.fhe_inputs.ciphertexts.len() <= 1024,
        "Too many inputs"
    );
    let (result, _) = input
        .input
        .run(e3_user_program::fhe_processor, e3_user_program::policy())
        .expect("Ciphertext aggregation failed");
    let journal = ComputeJournal::new(input.domain, result)
        .expect("Invalid compute journal")
        .abi_bytes()
        .expect("Invalid journal encoding");
    let digest = openvm_sha2::Sha256::digest(&journal);
    for (index, word) in digest.chunks_exact(4).enumerate() {
        openvm::io::reveal_u32(u32::from_le_bytes(word.try_into().unwrap()), index);
    }
}
