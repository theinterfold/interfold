// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use common::{
    compiled_circuit_artifacts_available, find_bb, recursive_circuit_artifacts_available,
    require_minimum_circuits_for_preset, setup_compiled_circuit_for_preset,
    setup_recursive_aggregation_fold_circuit_for_preset, setup_test_prover,
};
use e3_events::{CircuitName, CircuitVariant, Proof, ProofType};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuitData;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, fold_witness_input_map, load_vk_artifacts,
};
use e3_zk_prover::{
    validate_c2_terminal_proof, C2TerminalAnchors, CompiledCircuit, WitnessGenerator, ZkProver,
};
use serde_json::{json, Value};

fn c2ab_input(
    c2a_vk: &[String],
    c2a_proof: &Proof,
    c2a_key_hash: &str,
    c2b_vk: &[String],
    c2b_proof: &Proof,
    c2b_key_hash: &str,
) -> Value {
    json!({
        "c2a_vk": c2a_vk,
        "c2a_proof": fold_witness_field_strings(&c2a_proof.data).expect("C2a proof fields"),
        "c2a_public": fold_witness_field_strings(&c2a_proof.public_signals)
            .expect("C2a public fields"),
        "c2b_vk": c2b_vk,
        "c2b_proof": fold_witness_field_strings(&c2b_proof.data).expect("C2b proof fields"),
        "c2b_public": fold_witness_field_strings(&c2b_proof.public_signals)
            .expect("C2b public fields"),
        "c2a_key_hash": c2a_key_hash,
        "c2b_key_hash": c2b_key_hash,
    })
}

fn replace_public_signal(proof: &Proof, index: usize, value: &str) -> Proof {
    let bytes = hex::decode(value.trim_start_matches("0x")).expect("VK hash hex");
    assert_eq!(bytes.len(), 32, "VK hash must be one field");
    let mut public_signals = proof.public_signals.extract_bytes();
    let start = index.checked_mul(32).expect("public signal index");
    public_signals[start..start + 32].copy_from_slice(&bytes);
    Proof::new(
        proof.circuit,
        proof.data.clone(),
        ArcBytes::from_bytes(&public_signals),
    )
}

fn with_circuit(proof: &Proof, circuit: CircuitName) -> Proof {
    let mut substituted = proof.clone();
    substituted.circuit = circuit;
    substituted
}

fn assert_finalizer_vk_rejected(
    prover: &ZkProver,
    proof: &Proof,
    substituted_circuit: CircuitName,
    e3_id: &str,
    artifacts_dir: &str,
    label: &str,
) {
    let substituted = with_circuit(proof, substituted_circuit);
    let result = prover.verify_proof_with_variant(
        &substituted,
        e3_id,
        0,
        CircuitVariant::Recursive,
        artifacts_dir,
    );
    assert!(
        !matches!(result, Ok(true)),
        "{label} VK substitution must be rejected"
    );
}

fn assert_terminal_vk_rejected(
    preset: BfvPreset,
    proof_type: ProofType,
    proof: &Proof,
    anchors: &C2TerminalAnchors,
    label: &str,
) {
    let result = validate_c2_terminal_proof(
        preset,
        CiphernodesCommitteeSize::Minimum,
        proof_type,
        proof,
        anchors,
    );
    assert!(result.is_err(), "{label} VK substitution must be rejected");
}

#[tokio::test]
async fn chunked_c2_chain_rejects_artifact_vk_substitution() {
    let preset = BfvPreset::InsecureThreshold512;
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    if require_minimum_circuits_for_preset(preset).is_none() {
        return;
    }

    let dkg_circuits = ["sk_share_computation_chunk", "esm_share_computation_chunk"];
    let fold_circuits = [
        CircuitName::C2ChunkBatch,
        CircuitName::SkC2ChunkFinalize,
        CircuitName::ESmC2ChunkFinalize,
        CircuitName::C2abChunkFold,
    ];
    if dkg_circuits
        .iter()
        .any(|circuit| !compiled_circuit_artifacts_available("dkg", circuit))
        || fold_circuits
            .iter()
            .any(|circuit| !recursive_circuit_artifacts_available(*circuit))
    {
        println!("skipping: chunked C2 circuit artifacts are not available");
        return;
    }

    let (backend, temp) = setup_test_prover(&bb).await;
    for circuit in dkg_circuits {
        setup_compiled_circuit_for_preset(&backend, "dkg", circuit, preset, "minimum").await;
    }
    for circuit in fold_circuits {
        setup_recursive_aggregation_fold_circuit_for_preset(&backend, circuit, preset, "minimum")
            .await;
    }

    let prover = ZkProver::new(&backend);
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let c2a_data = ShareComputationCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .expect("canonical C2a sample");
    let c2b_data = ShareComputationCircuitData::generate_sample(
        preset,
        committee,
        DkgInputType::SmudgingNoise,
    )
    .expect("canonical C2b sample");

    let c2a = e3_zk_prover::prove_chunked_share_computation(
        &prover,
        preset,
        &c2a_data,
        "fold-vk-c2a",
        &artifacts_dir,
    )
    .expect("canonical chunked C2a proof");
    let c2b = e3_zk_prover::prove_chunked_share_computation(
        &prover,
        preset,
        &c2b_data,
        "fold-vk-c2b",
        &artifacts_dir,
    )
    .expect("canonical chunked C2b proof");
    assert_eq!(c2a.chunk_count, 1);
    assert_eq!(c2b.chunk_count, 1);
    assert_eq!(c2a.proof.circuit, CircuitName::SkC2ChunkFinalize);
    assert_eq!(c2b.proof.circuit, CircuitName::ESmC2ChunkFinalize);

    let recursive_dir = prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir);
    let default_dir = prover.circuits_dir(CircuitVariant::Default, &artifacts_dir);
    let c2a_chunk_vk = load_vk_artifacts(&recursive_dir, CircuitName::SkShareComputationChunk)
        .expect("compiled C2a chunk VK");
    let c2b_chunk_vk = load_vk_artifacts(&recursive_dir, CircuitName::ESmShareComputationChunk)
        .expect("compiled C2b chunk VK");
    let c2_batch_vk =
        load_vk_artifacts(&default_dir, CircuitName::C2ChunkBatch).expect("compiled C2 batch VK");
    let c2a_finalize_vk = load_vk_artifacts(&recursive_dir, CircuitName::SkC2ChunkFinalize)
        .expect("compiled C2a finalizer VK");
    let c2b_finalize_vk = load_vk_artifacts(&recursive_dir, CircuitName::ESmC2ChunkFinalize)
        .expect("compiled C2b finalizer VK");
    let c2ab_vk =
        load_vk_artifacts(&default_dir, CircuitName::C2abChunkFold).expect("compiled C2AB VK");

    let c2a_public =
        fold_witness_field_strings(&c2a.proof.public_signals).expect("C2a public fields");
    let c2b_public =
        fold_witness_field_strings(&c2b.proof.public_signals).expect("C2b public fields");
    assert_eq!(c2a_public.first(), Some(&c2a_chunk_vk.key_hash));
    assert_eq!(c2b_public.first(), Some(&c2b_chunk_vk.key_hash));
    assert_eq!(c2a_public.last(), Some(&c2_batch_vk.key_hash));
    assert_eq!(c2b_public.last(), Some(&c2_batch_vk.key_hash));

    let canonical_input = c2ab_input(
        &c2a_finalize_vk.verification_key,
        &c2a.proof,
        &c2a_finalize_vk.key_hash,
        &c2b_finalize_vk.verification_key,
        &c2b.proof,
        &c2b_finalize_vk.key_hash,
    );
    let c2ab_compiled = CompiledCircuit::from_file(
        &default_dir
            .join(CircuitName::C2abChunkFold.dir_path())
            .join(format!("{}.json", CircuitName::C2abChunkFold.as_str())),
    )
    .expect("compiled C2AB circuit");
    let canonical_witness = WitnessGenerator::new()
        .generate_witness(
            &c2ab_compiled,
            fold_witness_input_map(&canonical_input).expect("canonical C2AB input map"),
        )
        .expect("canonical C2AB witness");
    let c2ab_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C2abChunkFold,
            &canonical_witness,
            "fold-vk-c2ab",
            &artifacts_dir,
        )
        .expect("canonical C2AB proof");
    assert!(
        prover
            .verify_fold_proof(&c2ab_proof, "fold-vk-c2ab", 0, &artifacts_dir)
            .expect("canonical C2AB verification"),
        "canonical C2AB proof must verify"
    );

    let c2a_anchors =
        C2TerminalAnchors::load(&prover, ProofType::C2aSkShareComputation, &artifacts_dir)
            .expect("C2a terminal VK anchors");
    let c2b_anchors =
        C2TerminalAnchors::load(&prover, ProofType::C2bESmShareComputation, &artifacts_dir)
            .expect("C2b terminal VK anchors");
    validate_c2_terminal_proof(
        preset,
        CiphernodesCommitteeSize::Minimum,
        ProofType::C2aSkShareComputation,
        &c2a.proof,
        &c2a_anchors,
    )
    .expect("canonical C2a terminal proof validation");
    validate_c2_terminal_proof(
        preset,
        CiphernodesCommitteeSize::Minimum,
        ProofType::C2bESmShareComputation,
        &c2b.proof,
        &c2b_anchors,
    )
    .expect("canonical C2b terminal proof validation");

    assert_finalizer_vk_rejected(
        &prover,
        &c2a.proof,
        CircuitName::ESmC2ChunkFinalize,
        "fold-vk-c2a-as-c2b",
        &artifacts_dir,
        "C2a finalizer",
    );
    assert_finalizer_vk_rejected(
        &prover,
        &c2b.proof,
        CircuitName::SkC2ChunkFinalize,
        "fold-vk-c2b-as-c2a",
        &artifacts_dir,
        "C2b finalizer",
    );

    assert_terminal_vk_rejected(
        preset,
        ProofType::C2aSkShareComputation,
        &replace_public_signal(&c2a.proof, c2a_public.len() - 1, &c2ab_vk.key_hash),
        &c2a_anchors,
        "C2a batch",
    );
    assert_terminal_vk_rejected(
        preset,
        ProofType::C2bESmShareComputation,
        &replace_public_signal(&c2b.proof, c2b_public.len() - 1, &c2ab_vk.key_hash),
        &c2b_anchors,
        "C2b batch",
    );

    assert_terminal_vk_rejected(
        preset,
        ProofType::C2aSkShareComputation,
        &replace_public_signal(&c2a.proof, 0, &c2b_chunk_vk.key_hash),
        &c2a_anchors,
        "C2a chunk",
    );
    assert_terminal_vk_rejected(
        preset,
        ProofType::C2bESmShareComputation,
        &replace_public_signal(&c2b.proof, 0, &c2a_chunk_vk.key_hash),
        &c2b_anchors,
        "C2b chunk",
    );

    drop(temp);
}
