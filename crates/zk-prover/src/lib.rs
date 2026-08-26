// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod actor_system;
mod actors;
mod backend;
mod circuits;
mod config;
mod dkg_attestation_bundle;
mod domain;
mod error;
mod node_fold_public;
mod prover;
pub mod test_utils;
mod traits;
mod witness;
mod workflow;

pub use actor_system::{setup_zk_actors, ZkActorRecovery, ZkActors};
pub use actors::{
    CommitmentConsistencyCheckerExtension, ProofRequestActor, ProofVerificationActor,
    ShareVerificationActor, ZkVerificationRequest, ZkVerificationResponse,
};
pub use domain::commitment_links::default_links;

pub use backend::{SetupStatus, ZkBackend};
pub use circuits::aggregation::c3_accumulator::{
    generate_batched_c3_fold, generate_batched_c3_fold_b10, generate_batched_c3_fold_b2,
    generate_batched_c3_fold_b3, generate_c3_merge_m1, generate_c3_merge_m7,
    generate_sequential_c3_fold,
};
pub use circuits::aggregation::c6_accumulator::generate_sequential_c6_fold;
pub use circuits::aggregation::node_dkg_fold::{
    prove_decryption_aggregation_jobs, prove_dkg_aggregation, prove_node_dkg_fold,
    DecryptionAggregationJob, DkgAggregationInput, FoldProveStepTiming, NodeDkgFoldInput,
    NodeDkgFoldProveResult,
};
pub use circuits::aggregation::nodes_fold_accumulator::{
    generate_nodes_fold_step, generate_sequential_nodes_fold,
};
pub use config::{verify_checksum, BbTarget, CircuitInfo, VersionInfo, ZkConfig};
pub use dkg_attestation_bundle::encode_dkg_attestation_bundle;
pub use e3_events::CircuitVariant;
pub use e3_zk_helpers::circuits::dkg::pk::circuit::PkCircuit;
pub use error::ZkError;
pub use node_fold_public::extract_node_fold_agg_commits;
pub use prover::ZkProver;
pub use traits::Provable;
pub use witness::{input_map, CompiledCircuit, WitnessGenerator};
