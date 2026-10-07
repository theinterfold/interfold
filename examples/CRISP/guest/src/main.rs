// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The OpenVM guest that proves this project's Secure Process.
//!
//! It reads the round one item at a time: a header, every ciphertext in index order, then the
//! ciphertexts the program's policy selected, again in index order. Only one ciphertext is held at
//! a time, so the round can be larger than the guest's memory. It reveals the SHA-256 digest of the
//! nine-word journal, which the receipt verifier recomputes on chain.

openvm::init!();

use e3_compute_provider::SecureProcess;
use e3_openvm_types::{ComputeJournal, GuestHeader};
use sha2::Digest;

fn main() {
    let header = GuestHeader::decode(&openvm::io::read_vec()).expect("Invalid guest header");
    let inputs = header.indices.len();
    let mut process = SecureProcess::new(
        &header.params,
        header.indices,
        header.published,
        e3_user_program::policy(),
    )
    .expect("Invalid round");
    for _ in 0..inputs {
        process
            .absorb(&openvm::io::read_vec())
            .expect("Invalid input");
    }
    let (result, _) = process
        .select()
        .expect("Input selection failed")
        .finish(e3_user_program::fhe_processor, |_| {
            Ok(openvm::io::read_vec())
        })
        .expect("Ciphertext aggregation failed");

    let journal = ComputeJournal::new(&header.domain, &result)
        .expect("Invalid compute journal")
        .abi_bytes();
    let digest = openvm_sha2::Sha256::digest(&journal);
    for (index, word) in digest.chunks_exact(4).enumerate() {
        openvm::io::reveal_u32(u32::from_le_bytes(word.try_into().unwrap()), index);
    }
}
