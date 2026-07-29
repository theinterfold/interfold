// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bincode::Options;
use derivative::Derivative;
use e3_utils::{AsBytesSerde, BytesSerde};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

const EVENT_ID_DOMAIN: &[u8] = b"interfold:event-id:v1\0";

#[derive(Derivative, BytesSerde, Clone, Copy, PartialEq, Eq, Hash)]
#[derivative(Debug)]
pub struct EventId(#[derivative(Debug(format_with = "e3_utils::formatters::hexf"))] pub [u8; 32]);

impl EventId {
    /// Hash a deterministic, versioned bincode representation of an event payload.
    ///
    /// Fixed-width little-endian encoding makes the byte representation independent
    /// of the target architecture. Production callers hash `InterfoldEventData`, whose
    /// enum discriminant provides the event type domain and whose payload includes its
    /// chain/E3 identifiers.
    pub fn hash<T: Serialize>(value: T) -> Self {
        let canonical = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .serialize(&value)
            .expect("event identity values must support deterministic bincode serialization");
        let mut hasher = Sha256::new();
        hasher.update(EVENT_ID_DOMAIN);
        hasher.update((canonical.len() as u64).to_le_bytes());
        hasher.update(canonical);
        let result = hasher.finalize();
        EventId(result.into())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base58_string = bs58::encode(&self.0).into_string();
        write!(f, "evt:{}", &base58_string[0..8])
    }
}

impl AsBytesSerde for EventId {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        Ok(EventId(
            bytes.try_into().map_err(|_| "EventId requires 32 bytes")?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_format() {
        let event_id = EventId::hash("test");
        println!("{:?}", event_id);
    }

    #[test]
    fn canonical_hash_has_a_stable_golden_vector() {
        assert_eq!(
            EventId::hash("test").0,
            [
                0xef, 0x64, 0x93, 0xab, 0x8b, 0x80, 0xe4, 0xa2, 0xe1, 0x35, 0x8f, 0xb3, 0xf1, 0x2e,
                0x40, 0x73, 0x91, 0x4c, 0x78, 0xb6, 0xcc, 0x81, 0x71, 0xf2, 0xf0, 0x44, 0xdf, 0x7e,
                0x98, 0x24, 0x42, 0x8d,
            ]
        );
    }
}
