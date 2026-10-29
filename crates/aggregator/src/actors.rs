// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of the thin actors stored with their capabilities.
//!
//! New implementation belongs in the referenced capability directory, not here.

#[path = "plaintext_aggregation/decryption_share_buffer.rs"]
mod decryptionshare_created_buffer;
#[path = "public_key_aggregation/keyshare_buffer.rs"]
mod keyshare_created_filter_buffer;
#[path = "public_key_aggregation/actor.rs"]
mod publickey_aggregator;
#[path = "plaintext_aggregation/actor.rs"]
mod threshold_plaintext_aggregator;

pub use decryptionshare_created_buffer::*;
pub use keyshare_created_filter_buffer::*;
pub use publickey_aggregator::*;
pub use threshold_plaintext_aggregator::*;
