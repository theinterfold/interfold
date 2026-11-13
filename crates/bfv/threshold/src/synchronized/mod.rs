// SPDX-License-Identifier: LGPL-3.0-only

//! Native synchronized primitives, not actor admission or authorization to retry decryption.
//! Callers authenticate the E3/profile, DKG keys and ciphertext, and persist successful randomized
//! outputs before exposure. These helpers do not enable the disabled synchronized profile.

mod decryption;
mod keys;

pub use decryption::{create_share, reconstruct, select_designated_set, SynchronizedShare};
pub use keys::{assemble_party_keys, pack_key, unpack_key, PrfKey};
