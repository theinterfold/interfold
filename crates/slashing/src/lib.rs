// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! E3 fault attribution and accusation quorum protocol.
//!
//! Extracted from `e3-zk-prover` — accusation management is protocol-level
//! fault-handling, not ZK infrastructure.

mod actors;
mod domain;

pub mod accusation_manager_ext;
pub mod commitment_consistency_checker_ext;

// Re-export the actor module paths so downstream glob imports
// (`e3_slashing::accusation_manager::*`, `e3_slashing::commitment_consistency_checker::*`)
// keep resolving after the internal move into `actors/`.
pub use actors::accusation_manager;
pub use actors::commitment_consistency_checker;

pub use accusation_manager::AccusationManager;
pub use accusation_manager_ext::AccusationManagerExtension;
pub use commitment_consistency_checker::CommitmentConsistencyChecker;
pub use commitment_consistency_checker_ext::CommitmentConsistencyCheckerExtension;
