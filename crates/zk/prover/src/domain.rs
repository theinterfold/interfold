// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of pure ZK protocol calculations and validation.
//!
//! These modules contain NO actix / `BusHandle` / `Addr` / signing concerns.
//! The actors in [`crate::actors`] are thin transport shells that drive these
//! state machines and perform all I/O (publishing, signing, persistence).

#[path = "commitment_links/mod.rs"]
pub(crate) mod commitment_links;
#[path = "node_proof_aggregation/workflow.rs"]
pub(crate) mod node_dkg_fold;
#[path = "proof_verification/workflow.rs"]
pub(crate) mod proof_verification;
