// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use core::fmt;
use std::{
    cmp::Ordering,
    ops::Deref,
    sync::{Arc, Mutex},
};

use e3_utils_derive::BytesSerde;
use rand_chacha::ChaCha20Rng;

use crate::{formatters::hexf, AsBytesSerde};

pub type SharedRng = Arc<Mutex<ChaCha20Rng>>;

#[derive(BytesSerde, Clone, Default, PartialEq, Eq, Hash)]
pub struct ArcBytes(Arc<Vec<u8>>);

impl ArcBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Arc::new(bytes.to_vec()))
    }

    pub fn extract_bytes(&self) -> Vec<u8> {
        (*self.0).clone()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl Deref for ArcBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for ArcBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hexf(self, f)
    }
}

impl AsBytesSerde for ArcBytes {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        // Shared bytes retain no spare capacity after their source vector is dropped.
        Ok(ArcBytes(Arc::new(bytes.into_boxed_slice().into_vec())))
    }
}

impl PartialOrd for ArcBytes {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArcBytes {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_slice().cmp(other.0.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_bytes_release_spare_capacity() {
        let mut bytes = vec![0x5a; 1024 * 1024];
        bytes.truncate(1);
        let shared = ArcBytes::try_from_bytes(bytes).unwrap();

        assert_eq!(shared.as_bytes(), [0x5a]);
        assert_eq!(shared.0.capacity(), shared.size());
        assert_eq!(shared.clone().0.capacity(), shared.size());
    }
}
