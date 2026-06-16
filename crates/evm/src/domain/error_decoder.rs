// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure decoding of raw EVM revert data into human-readable contract errors.

use crate::contracts::{ICiphernodeRegistry, IInterfold, ISlashingManager};
use alloy::sol_types::SolInterface;

/// Try to decode raw revert data into a human-readable error string.
pub fn decode_error(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    if let Ok(err) = IInterfold::IInterfoldErrors::abi_decode(data) {
        return Some(format!("{err:?}"));
    }
    if let Ok(err) = ICiphernodeRegistry::ICiphernodeRegistryErrors::abi_decode(data) {
        return Some(format!("{err:?}"));
    }
    if let Ok(err) = ISlashingManager::ISlashingManagerErrors::abi_decode(data) {
        return Some(format!("{err:?}"));
    }

    None
}

/// Extract hex revert data from an error string and try to decode it.
/// Tries all hex blobs found in the string, returning the first that decodes
/// as a known contract error.
pub fn decode_error_from_str(error_str: &str) -> Option<String> {
    for data in extract_all_hex_blobs(error_str) {
        if let Some(decoded) = decode_error(&data) {
            return Some(decoded);
        }
    }
    None
}

/// Format an anyhow error, replacing raw hex revert data with decoded error if possible.
/// Returns the decoded error string if decoding succeeds, otherwise the original error.
pub fn format_evm_error(err: &anyhow::Error) -> String {
    let error_str = format!("{err:?}");
    decode_error_from_str(&error_str).unwrap_or(error_str)
}

/// Extract all hex blobs (0x...) with at least 4 bytes (8 hex chars) from a string.
fn extract_all_hex_blobs(error_str: &str) -> Vec<Vec<u8>> {
    error_str
        .match_indices("0x")
        .filter_map(|(idx, _)| {
            let rest = &error_str[idx + 2..];
            let hex_end = rest
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(rest.len());
            let hex_str = &rest[..hex_end];
            if hex_str.len() >= 8 {
                hex::decode(hex_str).ok()
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolError;

    #[test]
    fn test_decode_known_errors() {
        // CiphertextOutputNotPublished(uint256 e3Id) with e3Id = 1
        let mut data = IInterfold::CiphertextOutputNotPublished::SELECTOR.to_vec();
        data.extend_from_slice(&[0u8; 31]);
        data.push(1); // e3Id = 1
        let decoded = decode_error(&data).unwrap();
        assert!(
            decoded.contains("CiphertextOutputNotPublished"),
            "got: {decoded}"
        );
    }

    #[test]
    fn test_decode_parameterless_error() {
        // CommitteeNotRequested()
        let data = ICiphernodeRegistry::CommitteeNotRequested::SELECTOR.to_vec();
        let decoded = decode_error(&data).unwrap();
        assert!(decoded.contains("CommitteeNotRequested"), "got: {decoded}");
    }

    #[test]
    fn test_decode_from_error_string() {
        // Simulate an alloy error string containing hex revert data
        let selector = hex::encode(IInterfold::CiphertextOutputNotPublished::SELECTOR);
        let param = "0000000000000000000000000000000000000000000000000000000000000001";
        let error_str = format!(
            "server returned an error response: error code 3: execution reverted, data: \"0x{selector}{param}\""
        );
        let decoded = decode_error_from_str(&error_str).unwrap();
        assert!(
            decoded.contains("CiphertextOutputNotPublished"),
            "got: {decoded}"
        );
    }

    #[test]
    fn test_decode_unknown_error() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(decode_error(&data).is_none());
    }

    #[test]
    fn test_extract_hex_blobs_too_short() {
        assert!(extract_all_hex_blobs("0x1234").is_empty());
    }

    #[test]
    fn test_short_selector_found_despite_longer_hex() {
        // Error string contains a tx hash (32 bytes) AND a short 4-byte selector.
        // The decoder must find the selector even though the tx hash is longer.
        let selector = hex::encode(ICiphernodeRegistry::CommitteeNotRequested::SELECTOR);
        let tx_hash = "aabbccddee11223344556677889900aabbccddee11223344556677889900aabb";
        let error_str = format!("tx 0x{tx_hash} reverted with data: 0x{selector}");
        let decoded = decode_error_from_str(&error_str).unwrap();
        assert!(decoded.contains("CommitteeNotRequested"), "got: {decoded}");
    }
}
