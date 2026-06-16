// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

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

pub use actors::commitment_links::default_links;
pub use actors::{
    setup_zk_actors, CommitmentConsistencyCheckerExtension, ProofRequestActor,
    ProofVerificationActor, ShareVerificationActor, ZkActors, ZkVerificationRequest,
    ZkVerificationResponse,
};

pub use backend::{SetupStatus, ZkBackend};
pub use circuits::aggregation::c3_accumulator::generate_sequential_c3_fold;
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
