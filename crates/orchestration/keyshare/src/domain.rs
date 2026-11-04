// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure threshold-keyshare modules.
//!
//! Nothing in this module depends on actix, persistence, the event bus or
//! timers. Implementation files sit beside the actors in `src/`.

#[path = "generate_encryption_key.rs"]
mod bfv_keygen;
#[path = "derive_decryption_key.rs"]
mod decryption_key_calculation;
#[path = "collect_decryption_keys.rs"]
mod decryption_key_shared_collection;
#[path = "ready_summary.rs"]
mod dkg_ready_summary;
#[path = "roster.rs"]
mod dkg_roster;
#[path = "collect_encryption_keys.rs"]
mod encryption_key_collection;
#[path = "state.rs"]
mod keyshare_state;
#[path = "generate_shares.rs"]
mod share_generation;
#[path = "collect_threshold_shares.rs"]
mod threshold_share_collection;
#[path = "timeout_policy.rs"]
pub(crate) mod timeout_policy;

// Public (re-exported at the crate root): the persisted state machine and its
// per-phase data types.
pub use keyshare_state::*;

// Crate-internal pure services consumed by the actor shells.
pub(crate) use bfv_keygen::*;
pub(crate) use decryption_key_calculation::*;
pub(crate) use decryption_key_shared_collection::*;
pub(crate) use dkg_ready_summary::*;
pub(crate) use dkg_roster::*;
pub(crate) use encryption_key_collection::*;
pub(crate) use share_generation::*;
pub(crate) use threshold_share_collection::*;
