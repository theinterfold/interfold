// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, synchronous, unit-testable domain services for ZK proof orchestration.
//!
//! These modules contain NO actix / `BusHandle` / `Addr` / signing concerns.
//! The actors in [`crate::actors`] are thin transport shells that drive these
//! state machines and perform all I/O (publishing, signing, persistence).

pub(crate) mod node_dkg_fold;
pub(crate) mod proof_request;
pub(crate) mod proof_verification;
pub(crate) mod share_verification;
