// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{keccak256, B256, U256};
use serde::{Deserialize, Serialize};
use std::fmt;

/// An E3 as the contracts number it: per requesting chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct E3Id {
    pub chain_id: u64,
    pub number: U256,
}

impl fmt::Display for E3Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.chain_id, self.number)
    }
}

/// A large payload, stored once by the node and referenced by the Keccak-256 hash of its bytes,
/// which is also the hash the contracts take of such bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlobRef {
    pub hash: B256,
    pub len: u64,
}

impl BlobRef {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            hash: keccak256(bytes),
            len: bytes.len() as u64,
        }
    }
}

/// A secret this node stored, sealed with its cipher. It is a different type from [`BlobRef`], and
/// a different space in the store, so no peer message can name one and no peer can fetch one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SealedRef {
    pub hash: B256,
    pub len: u64,
}

impl SealedRef {
    pub fn of(bytes: &[u8]) -> Self {
        Self {
            hash: keccak256(bytes),
            len: bytes.len() as u64,
        }
    }
}
