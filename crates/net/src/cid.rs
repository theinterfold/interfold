// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::{Deref, DerefMut};

#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct ContentHash(
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))] pub Vec<u8>,
);

impl ContentHash {
    pub fn from_content(content: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hashed = hasher.finalize();
        Self(hashed.to_vec())
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for ContentHash {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for ContentHash {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for ContentHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
