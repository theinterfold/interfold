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
pub mod canonical_key;
mod contracts;
mod dkg_timing;
mod domain;
mod finalized_lifecycle;
mod messages;
mod node_release;
mod operator_status;
mod repo;

pub mod helpers;

// `error_decoder` remains part of the public API (`e3_evm::error_decoder`).
pub use domain::error_decoder;

pub use actors::*;
pub use adapters::ingestion_progress::{
    heartbeat_file_name, ingestion_heartbeat_files, write_ingestion_expectation,
    write_ingestion_expectation_at, IngestionProgress, IngestionProgressSink,
    INGESTION_EXPECTATION_FILE,
};
pub use contracts::ICiphernodeRegistry;
pub use dkg_timing::{read_canonical_dkg_timing, CanonicalDkgTiming};
pub use domain::encode_attestation_evidence;
pub use finalized_lifecycle::{read_finalized_e3_lifecycles, FinalizedE3Lifecycle};
pub use helpers::*;
pub use messages::*;
pub use node_release::*;
pub use operator_status::*;
pub use repo::*;
