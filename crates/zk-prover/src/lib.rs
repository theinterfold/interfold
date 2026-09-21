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
pub use domain::commitment_links::lbfv_share_transport::{
    validate_lbfv_key_share_document_commitments,
    validate_lbfv_key_share_document_commitments_dynamic,
};

pub use backend::{SetupStatus, ZkBackend};
pub use circuits::aggregation::c2_terminal_validation::{
    validate_c2_terminal_proof, C2TerminalAnchors,
};
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
pub use circuits::aggregation::v2::{
    prove_dkg_aggregation_v2, prove_lbfv_aggregation_fold_step,
    prove_lbfv_aggregation_fold_step_for_preset, prove_lbfv_generation_fold_step,
    prove_lbfv_generation_fold_step_for_preset, prove_node_dkg_fold_v2,
    prove_node_dkg_fold_v2_for_preset, prove_nodes_fold_v2_step,
    prove_nodes_fold_v2_step_for_preset,
};
pub use circuits::dkg::share_computation::{
    prove_chunked_share_computation, prove_chunked_share_computation_with_chunk_size,
    ChunkedShareComputationProofs, DEFAULT_C2_CHUNK_SIZE,
};
pub use circuits::threshold::lbfv_pk_generation::{
    finalize_lbfv_pk_generation_row, load_staged_lbfv_pk_generation_limb_vk_hash,
    prove_lbfv_pk_generation_row, validate_lbfv_pk_generation_terminal_proof,
    LbfvPkGenerationRowProof,
};
pub use circuits::threshold::rlk_generation::{
    finalize_rlk_generation_row, load_staged_rlk_generation_limb_vk_hash, prove_rlk_generation_row,
    validate_rlk_generation_terminal_proof, RlkGenerationRowProof,
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
