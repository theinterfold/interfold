// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compatibility view of actors stored with their ZK capabilities.
//!
//! Startup composition lives in [`crate::actor_system`].

#[path = "accusation_manager.rs"]
pub mod accusation_manager;
#[path = "accusation_manager_ext.rs"]
pub mod accusation_manager_ext;
#[path = "commitment_consistency_checker.rs"]
pub mod commitment_consistency_checker;
#[path = "commitment_consistency_checker_ext.rs"]
pub mod commitment_consistency_checker_ext;
#[path = "node_proof_aggregation/actor.rs"]
pub mod node_proof_aggregator;
#[path = "proof_request/actor.rs"]
pub mod proof_request;
#[path = "proof_verification/actor.rs"]
pub mod proof_verification;
#[path = "share_verification/actor.rs"]
pub mod share_verification;
#[path = "zk_actor.rs"]
pub mod zk_actor;

// Re-export accusation types from their canonical home in e3-slashing.
pub use e3_slashing::CommitmentConsistencyCheckerExtension;
pub use node_proof_aggregator::NodeProofAggregator;
pub use proof_request::ProofRequestActor;
pub use proof_verification::{
    ProofVerificationActor, ZkVerificationOutcome, ZkVerificationRequest, ZkVerificationResponse,
};
pub use share_verification::ShareVerificationActor;
pub use zk_actor::ZkActor;
