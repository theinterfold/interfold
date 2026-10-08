// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Default coefficient count per C2 chunk in the compiled Noir artifacts.
pub use e3_zk_helpers::circuits::dkg::share_computation::DEFAULT_C2_CHUNK_SIZE;
/// Default chunk count per C2 batch in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNKS_PER_BATCH: usize = 4;

pub use e3_zk_helpers::circuits::dkg::share_computation::c2_chunk_size;

// The derived layout (`chunk_count`, `chunks_per_batch`, `batch_count`) is
// computed by `c2_chunk_layout::C2ChunkLayout` from `c2_chunk_size`.

#[cfg(test)]
mod tests {
    use crate::circuits::aggregation::c2_chunk_layout::C2ChunkLayout;

    #[test]
    fn insecure_artifacts_use_one_chunk_and_batch() {
        let layout = C2ChunkLayout::compiled(128, 3).unwrap();
        assert_eq!(layout.chunk_count, 1);
        assert_eq!(layout.chunks_per_batch, 1);
        assert_eq!(layout.batch_count, 1);
    }

    #[test]
    fn secure_artifacts_use_sixteen_chunks_and_four_batches() {
        let layout = C2ChunkLayout::compiled(8192, 3).unwrap();
        assert_eq!(layout.chunk_count, 16);
        assert_eq!(layout.chunks_per_batch, 4);
        assert_eq!(layout.batch_count, 4);
    }

    #[test]
    fn secure_16384_layout_depends_on_the_committee() {
        let minimum = C2ChunkLayout::compiled(16384, 3).unwrap();
        assert_eq!((minimum.chunk_size, minimum.chunk_count), (4096, 4));
        assert_eq!((minimum.chunks_per_batch, minimum.batch_count), (4, 1));
        let micro = C2ChunkLayout::compiled(16384, 9).unwrap();
        assert_eq!(
            (micro.chunk_size, micro.chunk_count, micro.batch_count),
            (1024, 16, 4)
        );
        let small = C2ChunkLayout::compiled(16384, 19).unwrap();
        assert_eq!(
            (small.chunk_size, small.chunk_count, small.batch_count),
            (512, 32, 8)
        );
    }
}
