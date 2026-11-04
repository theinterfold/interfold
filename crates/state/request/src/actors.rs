// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of actors stored with the routing and lifecycle capabilities.

#[path = "lifecycle/actor.rs"]
mod lifecycle_coordinator;
#[path = "routing/actor.rs"]
mod router;

pub use lifecycle_coordinator::*;
pub use router::*;
