// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous, unit-testable business logic for the EVM integration.
//!
//! Nothing in this module depends on the actix runtime, `BusHandle`, or actor
//! addresses; the `actors` module wires these services into message-passing
//! shells and performs the actual EVM/provider I/O.

// `error_decoder` is part of the crate's public surface (`e3_evm::error_decoder`).
pub mod error_decoder;

pub(crate) mod attestation_evidence;
pub(crate) mod backoff;
pub(crate) mod bonding_registry_events;
pub(crate) mod chain_sync_state;
pub(crate) mod ciphernode_registry_events;
pub(crate) mod historical_order_fixer;
pub(crate) mod interfold_events;
pub(crate) mod log_timestamp;
pub(crate) mod plaintext_publication;
pub(crate) mod reorg;
pub(crate) mod slash_submission;
pub(crate) mod slashing_events;

pub use attestation_evidence::encode_attestation_evidence;
