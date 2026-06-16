// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Public-key and threshold-plaintext aggregation.
//!
//! The crate is organised into two layers:
//! - [`actors`] — thin actix actors that own persistence and the event bus and
//!   route messages between the protocol and the domain services.
//! - [`domain`] — pure, synchronous services holding the aggregation state
//!   machines and cryptographic combination logic, unit-tested in isolation.

mod actors;
mod domain;
pub mod ext;
mod repo;

pub use actors::*;
pub use domain::committee_hash;
pub use repo::*;
