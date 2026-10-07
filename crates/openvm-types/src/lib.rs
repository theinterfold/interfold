// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the OpenVM guest reads and reveals, shared by the guest, the host and the worker.
//!
//! The guest reads a round as a sequence of items: a [`GuestHeader`], then every ciphertext in
//! index order, then the selected ciphertexts in index order (see `e3_compute_provider::SecureProcess`).
//! It reveals the SHA-256 digest of the nine-word [`ComputeJournal`].

use bincode::Options;
use e3_compute_provider::{ComputeResult, PublishedData};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// The largest single item the guest reads.
///
/// The guest reads each item into memory whole, and its address space is 512 MiB. The bound applies
/// to each item rather than to the round, because the round is read one item at a time.
pub const MAX_ITEM_BYTES: usize = 512 * 1024 * 1024 - 16;

/// The length of the journal: nine 32-byte ABI words.
pub const JOURNAL_BYTES: usize = 9 * 32;

/// The E3 a computation belongs to. Every field is revealed in the journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeDomain {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    pub e3_id: [u8; 32],
    pub encryption_scheme_id: [u8; 32],
    pub committee_public_key_hash: [u8; 32],
}

/// The first item the guest reads: everything about the round except the ciphertexts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestHeader {
    pub domain: ComputeDomain,
    /// The encoded BFV parameters.
    pub params: Vec<u8>,
    /// Each input's on-chain index, in tree order. Its length is the round's input count.
    pub indices: Vec<u64>,
    /// What the E3 program published with each input: empty, or one entry per input.
    pub published: Vec<PublishedData>,
}

fn header_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ITEM_BYTES as u64)
        .reject_trailing_bytes()
}

impl GuestHeader {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        header_options()
            .serialize(self)
            .map_err(|error| format!("cannot encode the guest header: {error}"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        header_options()
            .deserialize(bytes)
            .map_err(|error| format!("invalid guest header: {error}"))
    }
}

/// The nine words the guest reveals, as the receipt verifier reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeJournal {
    pub chain_id: [u8; 32],
    pub verifying_contract: [u8; 32],
    pub e3_id: [u8; 32],
    pub encryption_scheme_id: [u8; 32],
    pub committee_public_key_hash: [u8; 32],
    pub ciphertext_hash: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub params_hash: [u8; 32],
    pub merkle_root: [u8; 32],
}

fn word(value: &[u8], name: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("the {name} must be 32 bytes"))
}

impl ComputeJournal {
    pub fn new(domain: &ComputeDomain, result: &ComputeResult) -> Result<Self, String> {
        let mut chain_id = [0; 32];
        chain_id[24..].copy_from_slice(&domain.chain_id.to_be_bytes());
        let mut verifying_contract = [0; 32];
        verifying_contract[12..].copy_from_slice(&domain.verifying_contract);

        Ok(Self {
            chain_id,
            verifying_contract,
            e3_id: domain.e3_id,
            encryption_scheme_id: domain.encryption_scheme_id,
            committee_public_key_hash: domain.committee_public_key_hash,
            ciphertext_hash: word(&result.ciphertext_hash, "ciphertext hash")?,
            ciphertext_commitment: word(&result.ciphertext_commitment, "ciphertext commitment")?,
            params_hash: word(&result.params_hash, "parameter hash")?,
            merkle_root: word(&result.merkle_root, "input root")?,
        })
    }

    /// The nine words in order, as Solidity ABI-encodes them.
    pub fn abi_bytes(&self) -> Vec<u8> {
        [
            self.chain_id,
            self.verifying_contract,
            self.e3_id,
            self.encryption_scheme_id,
            self.committee_public_key_hash,
            self.ciphertext_hash,
            self.ciphertext_commitment,
            self.params_hash,
            self.merkle_root,
        ]
        .concat()
    }
}

/// Writes the guest's input items for the worker: a little-endian `u32` item count, then each item
/// as a little-endian `u64` length followed by its bytes.
pub fn write_items<'a, W: Write>(
    mut writer: W,
    items: impl ExactSizeIterator<Item = &'a [u8]>,
) -> io::Result<()> {
    let count = u32::try_from(items.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many guest input items"))?;
    writer.write_all(&count.to_le_bytes())?;
    for item in items {
        if item.len() > MAX_ITEM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a guest input item exceeds the guest memory limit",
            ));
        }
        writer.write_all(&(item.len() as u64).to_le_bytes())?;
        writer.write_all(item)?;
    }
    writer.flush()
}

/// Reads the items [`write_items`] wrote, one at a time, so a reader never holds more than one.
pub struct ItemReader<R> {
    reader: R,
    remaining: u32,
}

impl<R: Read> ItemReader<R> {
    pub fn new(mut reader: R) -> io::Result<Self> {
        let mut count = [0; 4];
        reader.read_exact(&mut count)?;
        Ok(Self {
            reader,
            remaining: u32::from_le_bytes(count),
        })
    }

    /// The items not yet read.
    pub fn remaining(&self) -> usize {
        self.remaining as usize
    }

    /// Reads the next item, or `None` after the last. Trailing bytes after the last item are an
    /// error, because they mean the file is not the one the host wrote.
    pub fn next_item(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.remaining == 0 {
            let mut trailing = [0; 1];
            return match self.reader.read(&mut trailing)? {
                0 => Ok(None),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected bytes after the last guest input item",
                )),
            };
        }
        let mut length = [0; 8];
        self.reader.read_exact(&mut length)?;
        let length = u64::from_le_bytes(length);
        if length > MAX_ITEM_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a guest input item exceeds the guest memory limit",
            ));
        }
        let mut item = vec![0; length as usize];
        self.reader.read_exact(&mut item)?;
        self.remaining -= 1;
        Ok(Some(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> ComputeDomain {
        ComputeDomain {
            chain_id: 1,
            verifying_contract: [2; 20],
            e3_id: [3; 32],
            encryption_scheme_id: [4; 32],
            committee_public_key_hash: [5; 32],
        }
    }

    #[test]
    fn the_journal_is_nine_words_in_verifier_order() {
        let result = ComputeResult {
            ciphertext_hash: vec![6; 32],
            ciphertext_commitment: vec![7; 32],
            params_hash: vec![8; 32],
            merkle_root: vec![9; 32],
        };
        let bytes = ComputeJournal::new(&domain(), &result).unwrap().abi_bytes();

        assert_eq!(bytes.len(), JOURNAL_BYTES);
        assert_eq!(&bytes[..24], &[0; 24]);
        assert_eq!(bytes[31], 1);
        assert_eq!(&bytes[32..44], &[0; 12]);
        assert_eq!(&bytes[44..64], &[2; 20]);
        for (index, field) in bytes[64..].chunks_exact(32).enumerate() {
            assert_eq!(field, &[index as u8 + 3; 32]);
        }

        let short = ComputeResult {
            merkle_root: vec![9; 31],
            ..result
        };
        assert!(ComputeJournal::new(&domain(), &short).is_err());
    }

    #[test]
    fn the_header_round_trips_and_refuses_trailing_bytes() {
        let header = GuestHeader {
            domain: domain(),
            params: vec![1, 2, 3],
            indices: vec![10, 11],
            published: vec![
                PublishedData {
                    commitment: Some([7; 32]),
                    metadata: vec![1; 25],
                },
                PublishedData::default(),
            ],
        };
        let mut bytes = header.encode().unwrap();
        let decoded = GuestHeader::decode(&bytes).unwrap();
        assert_eq!(decoded.domain, header.domain);
        assert_eq!(decoded.indices, header.indices);
        assert_eq!(decoded.published.len(), 2);

        bytes.push(0);
        assert!(GuestHeader::decode(&bytes).is_err());
    }

    /// The worker reads this format; `interfold-openvm-prover` pins the same bytes.
    #[test]
    fn the_item_format_is_pinned() {
        let mut file = Vec::new();
        write_items(&mut file, [&[1u8, 2, 3][..], &[][..]].into_iter()).unwrap();
        assert_eq!(
            file,
            [2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn items_round_trip_one_at_a_time() {
        let items: Vec<Vec<u8>> = vec![vec![1, 2, 3], Vec::new(), vec![9; 1000]];
        let mut file = Vec::new();
        write_items(&mut file, items.iter().map(Vec::as_slice)).unwrap();

        let mut reader = ItemReader::new(file.as_slice()).unwrap();
        assert_eq!(reader.remaining(), 3);
        for item in &items {
            assert_eq!(reader.next_item().unwrap().as_ref(), Some(item));
        }
        assert_eq!(reader.next_item().unwrap(), None);
    }

    #[test]
    fn a_truncated_or_padded_file_is_refused() {
        let mut file = Vec::new();
        write_items(&mut file, [&[1u8, 2, 3][..]].into_iter()).unwrap();

        let mut truncated = ItemReader::new(&file[..file.len() - 1]).unwrap();
        assert!(truncated.next_item().is_err());

        let mut padded_file = file.clone();
        padded_file.push(0);
        let mut padded = ItemReader::new(padded_file.as_slice()).unwrap();
        padded.next_item().unwrap();
        assert!(padded.next_item().is_err());

        let mut oversized = 1u32.to_le_bytes().to_vec();
        oversized.extend_from_slice(&(MAX_ITEM_BYTES as u64 + 1).to_le_bytes());
        assert!(ItemReader::new(oversized.as_slice())
            .unwrap()
            .next_item()
            .is_err());
    }
}
