// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure EVM integration logic stored by capability.
//!
//! Nothing in this module depends on the actix runtime, `BusHandle`, or actor
//! addresses; the `actors` module wires these services into message-passing
//! shells and performs the actual EVM/provider I/O.

// `error_decoder` is part of the crate's public surface (`e3_evm::error_decoder`).
#[path = "event_decoding/error.rs"]
pub mod error_decoder;

#[path = "slashing/evidence.rs"]
pub(crate) mod attestation_evidence;
#[path = "chain_reader/backoff.rs"]
pub(crate) mod backoff;
#[path = "bonding_registry/events.rs"]
pub(crate) mod bonding_registry_events;
#[path = "chain_gateway/state.rs"]
pub(crate) mod chain_sync_state;
#[path = "ciphernode_registry/events.rs"]
pub(crate) mod ciphernode_registry_events;
#[path = "event_decoding/catalog.rs"]
pub(crate) mod evm_event_catalog;
#[path = "event_decoding/observation.rs"]
pub(crate) mod evm_log_observation;
#[path = "historical_order/workflow.rs"]
pub(crate) mod historical_order_fixer;
#[path = "interfold/events.rs"]
pub(crate) mod interfold_events;
#[path = "chain_reader/log_timestamp.rs"]
pub(crate) mod log_timestamp;
#[path = "log_fetching/window.rs"]
pub(crate) mod log_window;
#[path = "interfold_writing/workflow.rs"]
pub(crate) mod plaintext_publication;
#[path = "publication_writing/workflow.rs"]
pub(crate) mod publication_replay;
#[path = "randomness_provider/events.rs"]
pub(crate) mod randomness_provider_events;
#[path = "chain_reader/reorg.rs"]
pub(crate) mod reorg;
#[path = "slashing_writing/workflow.rs"]
pub(crate) mod slash_submission;
#[path = "slashing/events.rs"]
pub(crate) mod slashing_events;

pub use attestation_evidence::encode_attestation_evidence;
