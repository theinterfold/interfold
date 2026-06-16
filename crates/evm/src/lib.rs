// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! EVM integration for Interfold.
//!
//! - [`domain`] holds pure, synchronous, unit-testable services (no actix /
//!   `BusHandle` / provider types in their cores).
//! - [`actors`] holds the thin actix message-passing shells that wire those
//!   services together and perform the EVM/provider I/O.
//! - [`messages`] holds the actix message and event types exchanged between them.

mod actors;
mod contracts;
mod domain;
mod messages;
mod repo;

pub mod helpers;

// `error_decoder` remains part of the public API (`e3_evm::error_decoder`).
pub use domain::error_decoder;

pub use actors::*;
pub use domain::encode_attestation_evidence;
pub use helpers::*;
pub use messages::*;
pub use repo::*;
