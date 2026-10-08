// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// Default coefficient count per C2 chunk in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNK_SIZE: usize = 512;
/// Default chunk count per C2 batch in the compiled Noir artifacts.
pub const DEFAULT_C2_CHUNKS_PER_BATCH: usize = 4;

/// Coefficients per C2 chunk for a polynomial degree and committee size.
///
/// A C2 leaf proves every party's share of its coefficients, so its cost grows with
/// `chunk_size * n_parties`. At degree 16384 the size is chosen so the leaves stay near 2^21
/// gates (measured: chunk 4096 with 3 parties gives 1.29M for sk, 2.19M for e_sm), which cuts the
/// leaf and batch count and keeps the finalizer at one or a few recursive verifications. Other
/// degrees keep the default. Mirrored by the `SHARE_COMPUTATION_CHUNK_SIZE` expression the config
/// generator writes into each preset's `dkg.nr`.
pub fn c2_chunk_size(degree: usize, n_parties: usize) -> usize {
    let size = if degree >= 16384 {
        if n_parties <= 4 {
            4096
        } else if n_parties <= 12 {
            1024
        } else {
            DEFAULT_C2_CHUNK_SIZE
        }
    } else {
        DEFAULT_C2_CHUNK_SIZE
    };
    size.min(degree)
}

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
