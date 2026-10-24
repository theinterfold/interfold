// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifies `SHARE_COMPUTATION_CHUNKS_PER_BATCH` consecutive chunks of chunked C2 (either C2a or
//! C2b), links them and pins each chunk's key by its place in the chain.
//!
//! Public: `[batch_idx, full_key_hash, last_key_hash, h_in, h_out]`. The final C2 circuit
//! checks the indices, the links between batches and that every batch used the same chunk keys.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk};
use lib::configs::default::dkg::{SHARE_COMPUTATION_CHUNKS_PER_BATCH, SHARE_COMPUTATION_N_CHUNKS};
use lib::core::dkg::share_computation_chain::link_chunk_batch;

fn main(
    chunk_vks: [UltraHonkVerificationKey; SHARE_COMPUTATION_CHUNKS_PER_BATCH],
    chunk_proofs: [UltraHonkProof; SHARE_COMPUTATION_CHUNKS_PER_BATCH],
    chunk_publics: [[Field; 2]; SHARE_COMPUTATION_CHUNKS_PER_BATCH],
    chunk_key_hashes: [Field; SHARE_COMPUTATION_CHUNKS_PER_BATCH],
    batch_idx: pub u32,
    full_key_hash: pub Field,
    last_key_hash: pub Field,
) -> pub (Field, Field) {
    for i in 0..SHARE_COMPUTATION_CHUNKS_PER_BATCH {
        verify_honk_proof_non_zk(
            chunk_vks[i],
            chunk_proofs[i],
            chunk_publics[i],
            chunk_key_hashes[i],
        );
    }
    link_chunk_batch::<SHARE_COMPUTATION_CHUNKS_PER_BATCH, SHARE_COMPUTATION_N_CHUNKS>(
        batch_idx,
        chunk_publics,
        chunk_key_hashes,
        full_key_hash,
        last_key_hash,
    )
}
