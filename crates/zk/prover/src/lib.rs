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
mod request_execution;
pub mod test_utils;
mod traits;
mod utils;
mod witness;
mod workflow;

pub use actor_system::{setup_zk_actors, ZkActorRecovery, ZkActors};
pub use actors::{
    CommitmentConsistencyCheckerExtension, ProofRequestActor, ProofVerificationActor,
    ShareVerificationActor, ZkVerificationOutcome, ZkVerificationRequest, ZkVerificationResponse,
};
pub use domain::commitment_links::default_links;

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
pub use circuits::dkg::pk::PkCircuit;
pub use circuits::dkg::share_computation::ShareComputationCircuit;
pub use circuits::dkg::share_decryption::ShareDecryptionCircuit as DkgShareDecryptionCircuit;
pub use circuits::dkg::share_encryption::ShareEncryptionCircuit;
pub use circuits::threshold::decrypted_shares_aggregation::DecryptedSharesAggregationCircuit;
pub use circuits::threshold::pk_aggregation::PkAggregationCircuit;
pub use circuits::threshold::pk_generation::PkGenerationCircuit;
pub use circuits::threshold::share_decryption::ShareDecryptionCircuit as ThresholdShareDecryptionCircuit;
pub use circuits::utils::inputs_json_to_input_map;
pub use config::{verify_checksum, BbTarget, CircuitInfo, VersionInfo, ZkConfig};
pub use dkg_attestation_bundle::encode_dkg_attestation_bundle;
pub use e3_events::CircuitVariant;
pub use error::ZkError;
pub use node_fold_public::extract_node_fold_agg_commits;
pub use prover::ZkProver;
pub use request_execution::{execute_zk_request, zk_operation_name};
pub use traits::Provable;
pub use witness::{input_map, CompiledCircuit, WitnessGenerator};
