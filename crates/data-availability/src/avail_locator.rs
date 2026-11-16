// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Where Avail holds an object: the block and the blob leaf that the Interfold contract's
//! `CiphertextOutputReferencePublished` event and its Avail verifier name. The chain reader writes
//! this locator and the Avail reader reads it; no other code looks inside.

use anyhow::{ensure, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvailLocator {
    pub block_number: u32,
    pub leaf_index: u128,
}

impl AvailLocator {
    const LEN: usize = 4 + 16;

    pub fn encode(&self) -> Vec<u8> {
        [
            self.block_number.to_be_bytes().as_slice(),
            &self.leaf_index.to_be_bytes(),
        ]
        .concat()
    }

    pub fn decode(locator: &[u8]) -> Result<Self> {
        ensure!(
            locator.len() == Self::LEN,
            "an Avail locator has {} bytes, not {}",
            Self::LEN,
            locator.len()
        );
        let (block, leaf) = locator.split_at(4);
        Ok(Self {
            block_number: u32::from_be_bytes(block.try_into()?),
            leaf_index: u128::from_be_bytes(leaf.try_into()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locator_reads_back_as_written_and_refuses_other_lengths() {
        let at = AvailLocator {
            block_number: 7,
            leaf_index: u128::MAX - 3,
        };
        assert_eq!(AvailLocator::decode(&at.encode()).unwrap(), at);
        assert!(AvailLocator::decode(&[]).is_err());
        assert!(AvailLocator::decode(&[0; 21]).is_err());
    }
}
