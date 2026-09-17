// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! EVM integration for Interfold.
//!
//! - [`domain`] holds pure, synchronous, unit-testable services (no actix /
//!   `BusHandle` / provider types in their cores).
//! - [`actors`] holds the thin actix message-passing shells.
//! - `adapters` holds concrete EVM/provider I/O.
//! - [`messages`] holds the actix message and event types exchanged between them.

mod actors;
mod adapters;
mod contracts;
mod dkg_timing;
mod domain;
mod messages;
mod node_release;
mod operator_status;
mod repo;

pub mod helpers;

// `error_decoder` remains part of the public API (`e3_evm::error_decoder`).
pub use domain::error_decoder;

pub use actors::*;
pub use dkg_timing::{read_canonical_dkg_timing, CanonicalDkgTiming};
pub use domain::encode_attestation_evidence;
pub use helpers::*;
pub use messages::*;
pub use node_release::*;
pub use operator_status::*;
pub use repo::*;
