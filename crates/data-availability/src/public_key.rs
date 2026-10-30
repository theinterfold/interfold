// SPDX-License-Identifier: LGPL-3.0-only

//! Committee-public-key chunk mechanics. Shape validity is not key or publication authority.

use anyhow::{ensure, Result};
use std::ops::{Deref, Range};

pub const PUBLIC_KEY_CHUNK_BYTES: usize = 90 * 1024;
// Matches `CiphernodeRegistryOwnable.MAX_COMMITTEE_PUBLIC_KEY_BYTES`; a secure-16384 l-BFV key
// envelope is about 7.8 MB.
pub const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024 * 1024;

/// An ephemeral layout, never a replacement for a consumer's persisted assembly record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkLayout {
    total_length: u32,
    chunk_count: u16,
}

impl ChunkLayout {
    pub fn new(total_length: usize) -> Result<Self> {
        ensure!(total_length != 0, "committee public key is empty");
        ensure!(
            total_length <= MAX_PUBLIC_KEY_BYTES,
            "committee public key is {total_length} bytes; maximum is {MAX_PUBLIC_KEY_BYTES}"
        );
        Ok(Self {
            total_length: total_length.try_into()?,
            chunk_count: total_length.div_ceil(PUBLIC_KEY_CHUNK_BYTES).try_into()?,
        })
    }

    pub fn total_length(self) -> u32 {
        self.total_length
    }

    pub fn chunk_count(self) -> u16 {
        self.chunk_count
    }

    pub fn range(self, index: u16) -> Option<Range<usize>> {
        if index >= self.chunk_count {
            return None;
        }
        let start = usize::from(index) * PUBLIC_KEY_CHUNK_BYTES;
        Some(start..(start + PUBLIC_KEY_CHUNK_BYTES).min(self.total_length as usize))
    }

    pub fn accepts(self, index: u16, count: u16, length: usize) -> bool {
        count == self.chunk_count && self.range(index).is_some_and(|range| range.len() == length)
    }
}

/// Insert into a consumer-owned slot, accepting only byte-identical duplicates.
/// Metadata/shape validation and the response to a conflict remain with the caller.
pub fn insert_chunk<B: Deref<Target = [u8]>>(
    chunks: &mut [Option<B>],
    index: u16,
    bytes: &[u8],
    own: impl FnOnce() -> B,
) -> bool {
    let Some(slot) = chunks.get_mut(usize::from(index)) else {
        return false;
    };
    if let Some(existing) = slot {
        return &existing[..] == bytes;
    }
    *slot = Some(own());
    true
}

/// Assemble already-admitted slots in index order, without owning their storage or validity flags.
pub fn assemble_chunks<B: Deref<Target = [u8]>>(
    total_length: u32,
    chunks: &[Option<B>],
) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(total_length as usize);
    for chunk in chunks {
        bytes.extend_from_slice(chunk.as_ref()?);
    }
    (bytes.len() == total_length as usize).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ChunkCase {
        name: String,
        total_length: u32,
        chunk_index: u16,
        chunk_count: u16,
        chunk_length: usize,
        valid: bool,
    }

    #[test]
    fn layout_matches_independent_solidity_boundary_vectors() {
        // The Solidity registry test executes these same literal cases against the real library.
        let cases: Vec<ChunkCase> =
            serde_json::from_str(include_str!("../tests/fixtures/public_key_chunks.json")).unwrap();
        for case in cases {
            let valid = ChunkLayout::new(case.total_length as usize).is_ok_and(|layout| {
                layout.accepts(case.chunk_index, case.chunk_count, case.chunk_length)
            });
            assert_eq!(valid, case.valid, "{}", case.name);
        }
    }

    #[test]
    fn layout_preserves_exact_offsets_and_wire_metadata() {
        let layout = ChunkLayout::new(184_337).unwrap();
        assert_eq!(layout.total_length(), 184_337);
        assert_eq!(layout.chunk_count(), 3);
        assert_eq!(layout.range(0), Some(0..92_160));
        assert_eq!(layout.range(1), Some(92_160..184_320));
        assert_eq!(layout.range(2), Some(184_320..184_337));
        assert_eq!(layout.range(3), None);
        assert_eq!(
            ChunkLayout::new(524_288).unwrap().range(5),
            Some(460_800..524_288)
        );
        assert!(ChunkLayout::new(usize::MAX).is_err());
    }

    #[test]
    fn reordered_chunks_duplicates_conflicts_and_incomplete_assemblies() {
        let bytes = (0..184_337)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let layout = ChunkLayout::new(bytes.len()).unwrap();
        let mut chunks: Vec<Option<Vec<u8>>> = vec![None; 3];
        for index in [2, 0] {
            let chunk = &bytes[layout.range(index).unwrap()];
            assert!(insert_chunk(&mut chunks, index, chunk, || chunk.to_vec()));
        }
        assert!(assemble_chunks(layout.total_length(), &chunks).is_none());
        assert!(insert_chunk(&mut chunks, 2, &bytes[184_320..], || panic!(
            "duplicate allocated"
        )));
        assert!(!insert_chunk(&mut chunks, 2, &[0xff; 17], || panic!(
            "conflict allocated"
        )));
        assert!(!insert_chunk(&mut chunks, 3, &[0], || panic!(
            "invalid index allocated"
        )));
        let middle = &bytes[92_160..184_320];
        assert!(insert_chunk(&mut chunks, 1, middle, || middle.to_vec()));
        assert_eq!(assemble_chunks(layout.total_length(), &chunks), Some(bytes));
        assert!(assemble_chunks(1, &chunks).is_none());
    }
}
