// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Default coefficient count per C2 chunk in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNK_SIZE: usize = 512;
/// Default chunk count per C2 batch in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNKS_PER_BATCH: usize = 4;

// The derived layout (`chunk_count`, `chunks_per_batch`, `batch_count`) is
// computed by `c2_chunk_layout::C2ChunkLayout` from these two constants.

#[cfg(test)]
mod tests {
    use crate::circuits::aggregation::c2_chunk_layout::C2ChunkLayout;

    #[test]
    fn insecure_artifacts_use_one_chunk_and_batch() {
        let layout = C2ChunkLayout::compiled(512).unwrap();
        assert_eq!(layout.chunk_count, 1);
        assert_eq!(layout.chunks_per_batch, 1);
        assert_eq!(layout.batch_count, 1);
    }

    #[test]
    fn secure_artifacts_use_sixteen_chunks_and_four_batches() {
        let layout = C2ChunkLayout::compiled(8192).unwrap();
        assert_eq!(layout.chunk_count, 16);
        assert_eq!(layout.chunks_per_batch, 4);
        assert_eq!(layout.batch_count, 4);
    }
}
