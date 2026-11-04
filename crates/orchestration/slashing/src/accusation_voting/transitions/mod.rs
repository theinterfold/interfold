// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic accusation transitions grouped by protocol input.

use super::*;

mod admission;
#[path = "incoming_accusations.rs"]
mod incoming;
#[path = "initiate_accusation.rs"]
mod initiation;
#[path = "reverify_proofs.rs"]
mod reverification;
mod setup;
#[path = "vote.rs"]
mod voting;
