// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::error::ZkError;

/// Default chunk count per C2 batch in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNKS_PER_BATCH: usize = 4;

pub use e3_zk_config::chunks::c2_chunk_size;

// The derived layout (`chunk_count`, `chunks_per_batch`, `batch_count`) is
// computed by `c2_chunk_layout::C2ChunkLayout` from `c2_chunk_size`.

/// How many C2 chunk or batch proofs one chunked C2 call proves at once
/// (`E3_C2_CHUNK_PROOF_CONCURRENCY`, default 2).
///
/// Each proof runs its own `bb prove`, which uses every core, so proving many at once buys little
/// speed but multiplies memory: at secure-16384 with the small committee, all 8 leaves at once
/// exceed a 32 GB node. The bound applies per call; concurrent C2a and C2b requests each get their
/// own pool.
fn c2_chunk_proof_concurrency() -> usize {
    std::env::var("E3_C2_CHUNK_PROOF_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&jobs| jobs > 0)
        .unwrap_or(2)
}

/// Dedicated pool that bounds the concurrent chunk and batch proofs of one chunked C2 call.
pub(crate) fn c2_proof_pool() -> Result<rayon::ThreadPool, ZkError> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(c2_chunk_proof_concurrency())
        .build()
        .map_err(|error| ZkError::ProveFailed(format!("C2 proof pool: {error}")))
}

#[cfg(test)]
mod tests {
    use crate::circuits::aggregation::c2_chunk_layout::C2ChunkLayout;

    #[test]
    fn secure_16384_layout_depends_on_the_committee() {
        let minimum = C2ChunkLayout::compiled(16384, 3).unwrap();
        assert_eq!((minimum.chunk_size, minimum.chunk_count), (8192, 2));
        assert_eq!((minimum.chunks_per_batch, minimum.batch_count), (2, 1));
        let micro = C2ChunkLayout::compiled(16384, 9).unwrap();
        assert_eq!(
            (micro.chunk_size, micro.chunk_count, micro.batch_count),
            (2048, 8, 2)
        );
        let small = C2ChunkLayout::compiled(16384, 19).unwrap();
        assert_eq!(
            (small.chunk_size, small.chunk_count, small.batch_count),
            (2048, 8, 2)
        );
    }
}
