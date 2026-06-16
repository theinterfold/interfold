// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub mod client;

use fhe::bfv::{Encoding, Plaintext};
use fhe_traits::FheDecoder;
use thiserror::Error as ThisError;

pub use client::VerifiableEncryptionResult;
pub use client::{
    bfv_encrypt, bfv_verifiable_encrypt, compute_ct_commitment, compute_pk_commitment,
};

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Plaintext decoding failed")]
    PlaintextDecodeFailed,
    #[error("Input was not encoded correctly")]
    BadEncoding,
}

/// Result that returns a type T or a BfvClientError
type Result<T> = std::result::Result<T, Error>;

/// Decode Plaintext to a Vec<u64>
pub fn decode_plaintext_to_vec_u64(value: &Plaintext) -> Result<Vec<u64>> {
    let decoded = Vec::<u64>::try_decode(value, Encoding::poly())
        .map_err(|_| Error::PlaintextDecodeFailed)?;

    Ok(decoded)
}

/// Convert from a Vec<u64> to Vec<u8>
pub fn encode_vec_u64_to_bytes(value: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for num in &value.to_vec() {
        bytes.extend_from_slice(&num.to_le_bytes());
    }
    bytes
}

/// Decode bytes to Vec<u64>
pub fn decode_bytes_to_vec_u64(bytes: &[u8]) -> Result<Vec<u64>> {
    if !bytes.len().is_multiple_of(8) {
        return Err(Error::BadEncoding);
    }

    Ok(bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect())
}
