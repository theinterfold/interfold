// SPDX-License-Identifier: LGPL-3.0-only

//! Directed PRF-key packing and local noise for synchronized decryption.
//! Callers authenticate the E3/profile and dealer/recipient identities and retain successful
//! randomized outputs. These helpers do not enable the disabled synchronized profile.

mod keys;
mod noise;
mod sealed_keys;

pub use keys::{pack_key, unpack_key, PrfKey};
pub use noise::contribution_noise_v1;
pub use sealed_keys::SealedPrfKeys;
