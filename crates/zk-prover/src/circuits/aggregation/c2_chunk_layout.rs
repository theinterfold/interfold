// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Versioned C2 chunk layout — the single derivation point for how a compiled
//! artifact set slices a polynomial degree into chunk and batch counts.
//!
//! Runtime code must not re-derive `chunk_count`, `chunks_per_batch`, or
//! `batch_count` from independent constants; use [`C2ChunkLayout`] instead.

use crate::circuits::aggregation::c2_chunk_config::{
    DEFAULT_C2_CHUNKS_PER_BATCH, DEFAULT_C2_CHUNK_SIZE,
};
use crate::error::ZkError;

/// The complete C2 chunk layout implied by a compiled artifact set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct C2ChunkLayout {
    /// Polynomial degree of the preset (`N`).
    pub degree: usize,
    /// Coefficients per C2 leaf proof.
    pub chunk_size: usize,
    /// Number of leaf proofs per degree: `degree / chunk_size`.
    pub chunk_count: usize,
    /// Number of leaf proofs grouped into one `C2ChunkBatch` proof.
    pub chunks_per_batch: usize,
    /// Number of batch proofs: `chunk_count / chunks_per_batch`.
    pub batch_count: usize,
}

impl C2ChunkLayout {
    /// Builds the layout for the compiled default chunk size (512).
    pub fn compiled(degree: usize) -> Result<Self, ZkError> {
        Self::from_degree_chunk_size(degree, DEFAULT_C2_CHUNK_SIZE)
    }

    /// Builds a layout with the compiled `chunks_per_batch` rule: a degree that
    /// fits in a single chunk uses one batch; larger degrees use the compiled
    /// constant batch width.
    pub fn from_degree_chunk_size(degree: usize, chunk_size: usize) -> Result<Self, ZkError> {
        let chunks_per_batch = if degree <= chunk_size {
            1
        } else {
            DEFAULT_C2_CHUNKS_PER_BATCH
        };
        Self::new(degree, chunk_size, chunks_per_batch)
    }

    /// Validates and builds a layout. Enforces every structural invariant the
    /// C2 chunk pipeline depends on.
    pub fn new(degree: usize, chunk_size: usize, chunks_per_batch: usize) -> Result<Self, ZkError> {
        if degree == 0 {
            return Err(ZkError::InvalidInput(
                "C2 chunk layout requires degree > 0".into(),
            ));
        }
        if chunk_size == 0 {
            return Err(ZkError::InvalidInput(
                "C2 chunk layout requires chunk_size > 0".into(),
            ));
        }
        if !degree.is_multiple_of(chunk_size) {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk size {chunk_size} must divide polynomial degree {degree}"
            )));
        }
        let chunk_count = degree / chunk_size;
        if chunks_per_batch == 0 {
            return Err(ZkError::InvalidInput(
                "C2 chunk layout requires chunks_per_batch > 0".into(),
            ));
        }
        if !chunk_count.is_multiple_of(chunks_per_batch) {
            return Err(ZkError::InvalidInput(format!(
                "C2 chunk count {chunk_count} is not divisible by chunks_per_batch {chunks_per_batch}"
            )));
        }
        Ok(Self {
            degree,
            chunk_size,
            chunk_count,
            chunks_per_batch,
            batch_count: chunk_count / chunks_per_batch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::C2ChunkLayout;

    #[test]
    fn insecure_compiled_layout_is_one_chunk_one_batch() {
        let layout = C2ChunkLayout::compiled(512).unwrap();
        assert_eq!(
            layout,
            C2ChunkLayout {
                degree: 512,
                chunk_size: 512,
                chunk_count: 1,
                chunks_per_batch: 1,
                batch_count: 1,
            }
        );
    }

    #[test]
    fn secure_compiled_layout_is_sixteen_chunks_four_batches() {
        let layout = C2ChunkLayout::compiled(8192).unwrap();
        assert_eq!(layout.chunk_count, 16);
        assert_eq!(layout.chunks_per_batch, 4);
        assert_eq!(layout.batch_count, 4);
    }

    #[test]
    fn rejects_zero_degree() {
        assert!(C2ChunkLayout::new(0, 512, 4).is_err());
    }

    #[test]
    fn rejects_zero_chunk_size() {
        assert!(C2ChunkLayout::new(512, 0, 4).is_err());
    }

    #[test]
    fn rejects_chunk_size_not_dividing_degree() {
        assert!(C2ChunkLayout::new(8192, 1000, 4).is_err());
    }

    #[test]
    fn rejects_zero_chunks_per_batch() {
        assert!(C2ChunkLayout::new(512, 512, 0).is_err());
    }

    #[test]
    fn rejects_chunk_count_not_dividing_batch_width() {
        assert!(C2ChunkLayout::new(8192, 512, 3).is_err());
    }

    #[test]
    fn single_chunk_degree_uses_single_batch() {
        let layout = C2ChunkLayout::from_degree_chunk_size(512, 512).unwrap();
        assert_eq!(layout.chunks_per_batch, 1);
        assert_eq!(layout.batch_count, 1);
    }
}
