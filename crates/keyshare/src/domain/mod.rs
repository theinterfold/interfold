// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous domain logic for the threshold keyshare DKG flow.
//!
//! Nothing in this module depends on actix, persistence, the event bus or
//! timers. The actors in [`crate::actors`] are thin message-passing shells that
//! delegate all decision-making to these unit-testable services.

mod bfv_keygen;
mod decryption_key_calculation;
mod decryption_key_shared_collection;
mod encryption_key_collection;
mod keyshare_state;
mod share_generation;
mod threshold_share_collection;
pub(crate) mod timeout_policy;

// Public (re-exported at the crate root): the persisted state machine and its
// per-phase data types.
pub use keyshare_state::*;

// Crate-internal pure services consumed by the actor shells.
pub(crate) use bfv_keygen::*;
pub(crate) use decryption_key_calculation::*;
pub(crate) use decryption_key_shared_collection::*;
pub(crate) use encryption_key_collection::*;
pub(crate) use share_generation::*;
pub(crate) use threshold_share_collection::*;
