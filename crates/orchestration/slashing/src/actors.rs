// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of thin actors stored with their slashing capabilities.

#[path = "accusation_voting/actor.rs"]
pub mod accusation_manager;
#[path = "commitment_consistency/actor.rs"]
pub mod commitment_consistency_checker;
