// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure threshold-keyshare modules.
//!
//! Nothing in this module depends on actix, persistence, the event bus or
//! timers. Implementation is physically co-located under `threshold_keyshare`.

#[path = "threshold_keyshare/generate_encryption_key.rs"]
mod bfv_keygen;
#[path = "threshold_keyshare/derive_decryption_key.rs"]
mod decryption_key_calculation;
#[path = "threshold_keyshare/collect_decryption_keys.rs"]
mod decryption_key_shared_collection;
#[path = "threshold_keyshare/collect_encryption_keys.rs"]
mod encryption_key_collection;
#[path = "threshold_keyshare/state.rs"]
mod keyshare_state;
#[path = "threshold_keyshare/lbfv_generation_state.rs"]
mod lbfv_generation_state;
#[path = "threshold_keyshare/generate_shares.rs"]
mod share_generation;
#[path = "threshold_keyshare/collect_threshold_shares.rs"]
mod threshold_share_collection;
#[path = "threshold_keyshare/timeout_policy.rs"]
pub(crate) mod timeout_policy;

// Public (re-exported at the crate root): the persisted state machine and its
// per-phase data types.
pub use keyshare_state::*;
pub use lbfv_generation_state::*;

// Crate-internal pure services consumed by the actor shells.
pub(crate) use bfv_keygen::*;
pub(crate) use decryption_key_calculation::*;
pub(crate) use decryption_key_shared_collection::*;
pub(crate) use encryption_key_collection::*;
pub(crate) use share_generation::*;
pub(crate) use threshold_share_collection::*;
