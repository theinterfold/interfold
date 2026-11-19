// SPDX-License-Identifier: LGPL-3.0-only

//! Directed PRF-key packing for synchronized DKG, not ciphertext decryption.
//! Callers authenticate the E3/profile and dealer/recipient identities and retain successful
//! randomized outputs. These helpers do not enable the disabled synchronized profile.

mod keys;
mod sealed_keys;

pub use keys::{pack_key, unpack_key, PrfKey};
pub use sealed_keys::SealedPrfKeys;
