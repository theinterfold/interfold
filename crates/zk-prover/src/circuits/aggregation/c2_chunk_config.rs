// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Default coefficient count per C2 chunk in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNK_SIZE: usize = 512;
/// Default chunk count per C2 batch in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNKS_PER_BATCH: usize = 4;

pub fn chunks_per_batch(degree: usize) -> usize {
    if degree <= DEFAULT_C2_CHUNK_SIZE {
        1
    } else {
        DEFAULT_C2_CHUNKS_PER_BATCH
    }
}

pub fn compiled_chunk_count(degree: usize) -> usize {
    degree / DEFAULT_C2_CHUNK_SIZE
}

pub fn compiled_batch_count(degree: usize) -> usize {
    compiled_chunk_count(degree) / chunks_per_batch(degree)
}

#[cfg(test)]
mod tests {
    use super::{chunks_per_batch, compiled_batch_count, compiled_chunk_count};

    #[test]
    fn insecure_artifacts_use_one_chunk_and_batch() {
        assert_eq!(compiled_chunk_count(512), 1);
        assert_eq!(chunks_per_batch(512), 1);
        assert_eq!(compiled_batch_count(512), 1);
    }

    #[test]
    fn secure_artifacts_use_sixteen_chunks_and_four_batches() {
        assert_eq!(compiled_chunk_count(8192), 16);
        assert_eq!(chunks_per_batch(8192), 4);
        assert_eq!(compiled_batch_count(8192), 4);
    }
}
