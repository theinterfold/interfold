// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Correlated `node_fold` proof: one [`PkGenerationCircuitData`] drives C1 and both C2 chains; C3
//! inner proofs use [`node_fold_witness::share_encryption_for_slot`] (`tests/common/node_fold_witness.rs`); C4 reuses one honest row for
//! all `H` senders so decryption witnesses stay self-consistent.
//!
//! Requires `bb`, `pnpm build:circuits --group recursive_aggregation`, and DKG/threshold bins.

mod common;
#[path = "common/node_fold_witness.rs"]
mod node_fold_witness;

use std::path::PathBuf;

use common::{
    active_bin_preset, compiled_circuit_artifacts_available, find_bb,
    recursive_circuit_artifacts_available, require_minimum_circuits_for_preset,
    setup_compiled_circuit_for_preset, setup_recursive_aggregation_fold_circuit_for_preset,
    setup_test_prover,
};
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::Computation;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::Inputs as ShareComputationInputs;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuit;
use e3_zk_helpers::threshold::pk_generation::PkGenerationCircuit;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{CircuitVariant, NodeDkgFoldInput, Provable, ZkProver};
use node_fold_witness::{
    pk_generation_sample_with_esi, share_computation_esm_from_esi, share_computation_sk_from_pk,
    share_encryption_for_slot,
};

fn recursive_aggregation_compiled_json_path(circuit: CircuitName) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin")
        .join(circuit.group())
        .join(circuit.as_str())
        .join("target")
        .join(format!("{}.json", circuit.as_str()))
}

fn c3_fold_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json")
}

fn c3_fold_total_slots_from_compiled_json() -> usize {
    let path = c3_fold_json_path();
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let len = v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| {
                    p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into()))
                })
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c3_fold acc_public_inputs length") as usize;
    assert!(
        len >= 6 && (len - 6).is_multiple_of(3),
        "unexpected acc_public_inputs length {len} (expected 6 + 3 * slots)"
    );
    (len - 6) / 3
}

fn triplicate_honest_rows(mut d: ShareDecryptionCircuitData) -> ShareDecryptionCircuitData {
    let row0 = d.honest_ciphertexts[0].clone();
    d.honest_ciphertexts = (0..d.honest_ciphertexts.len())
        .map(|_| row0.clone())
        .collect();
    d
}

async fn run_node_fold_correlated_sparse_self_slot(preset: BfvPreset) {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };

    if require_minimum_circuits_for_preset(preset).is_none() {
        return;
    }

    let gate = recursive_aggregation_compiled_json_path(CircuitName::NodeFold);
    if !gate.exists() {
        println!(
            "skipping: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            gate.display()
        );
        return;
    }
    if !c3_fold_json_path().exists() {
        println!("skipping: c3_fold.json not found");
        return;
    }

    let committee = CiphernodesCommitteeSize::Minimum.values();

    let (backend, temp) = setup_test_prover(&bb).await;
    let prover = ZkProver::new(&backend);
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());

    for g in [
        "pk",
        "sk_share_computation_chunk",
        "esm_share_computation_chunk",
        "share_encryption",
        "share_decryption",
    ] {
        setup_compiled_circuit_for_preset(&backend, "dkg", g, preset, "minimum").await;
    }
    setup_compiled_circuit_for_preset(&backend, "threshold", "pk_generation", preset, "minimum")
        .await;

    for c in [
        CircuitName::C2ChunkBatch,
        CircuitName::SkC2ChunkFinalize,
        CircuitName::ESmC2ChunkFinalize,
        CircuitName::C2abChunkFold,
        CircuitName::C3Fold,
        CircuitName::C3FoldKernel,
        CircuitName::C3abFold,
        CircuitName::C4abFold,
        CircuitName::NodeFold,
    ] {
        setup_recursive_aggregation_fold_circuit_for_preset(&backend, c, preset, "minimum").await;
    }

    let (pk_gen, esi, pk_secret_key) = pk_generation_sample_with_esi(preset, committee.clone())
        .expect("pk + esi correlated sample");
    let share_sk = share_computation_sk_from_pk(preset, committee.clone(), &pk_gen, &pk_secret_key)
        .expect("correlated C2a data");
    let share_esm = share_computation_esm_from_esi(preset, committee.clone(), &pk_gen, &esi)
        .expect("correlated C2b data");

    let sk_inputs = ShareComputationInputs::compute(preset, &share_sk).expect("C2a inputs");
    let esm_inputs = ShareComputationInputs::compute(preset, &share_esm).expect("C2b inputs");

    let pk_bfv_data = PkCircuitData::generate_sample(preset).expect("C0 pk sample");
    let c0_e3 = "e3-nf-c0";
    let c1_e3 = "e3-nf-c1";

    let c0_proof = PkCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &pk_bfv_data,
            c0_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C0 pk proof");
    let c1_proof = PkGenerationCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &pk_gen,
            c1_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C1 pk_generation proof");

    let (_dkg_th, dkg_dkg) = e3_fhe_params::build_pair_for_preset(preset).expect("pair");
    let mut rng = rand::rng();
    let dkg_sk = fhe::bfv::SecretKey::random(&dkg_dkg, &mut rng);
    let dkg_pk = fhe::bfv::PublicKey::new(&dkg_sk, &mut rng);

    let total_slots = c3_fold_total_slots_from_compiled_json();
    let expected_slots = committee.n * preset.metadata().num_moduli;
    assert_eq!(total_slots, expected_slots);
    let slots_per_party = total_slots / committee.n;
    let own_party_id = 0usize;

    let mut c3a_inners = Vec::new();
    let mut c3b_inners = Vec::new();
    let mut slot_indices = Vec::new();
    for slot in 0..total_slots {
        if slot / slots_per_party == own_party_id {
            continue;
        }

        let da = share_encryption_for_slot(
            preset,
            &dkg_sk,
            &dkg_pk,
            &sk_inputs,
            slot,
            DkgInputType::SecretKey,
            committee.clone(),
        )
        .expect("C3a slot encrypt");
        let db = share_encryption_for_slot(
            preset,
            &dkg_sk,
            &dkg_pk,
            &esm_inputs,
            slot,
            DkgInputType::SmudgingNoise,
            committee.clone(),
        )
        .expect("C3b slot encrypt");

        c3a_inners.push(
            ShareEncryptionCircuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &da,
                    &format!("e3-nf-c3a-{slot}"),
                    CircuitVariant::Recursive,
                    &artifacts_dir,
                )
                .expect("C3a inner"),
        );
        c3b_inners.push(
            ShareEncryptionCircuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &db,
                    &format!("e3-nf-c3b-{slot}"),
                    CircuitVariant::Recursive,
                    &artifacts_dir,
                )
                .expect("C3b inner"),
        );
        slot_indices.push(slot as u32);
    }
    let expected_slot_indices: Vec<u32> = (slots_per_party..total_slots)
        .map(|slot| slot as u32)
        .collect();
    assert_eq!(slot_indices, expected_slot_indices);

    let c4a_sample = ShareDecryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .expect("c4a sample");
    let c4b_sample = ShareDecryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SmudgingNoise,
    )
    .expect("c4b sample");
    let c4a_data = triplicate_honest_rows(c4a_sample);
    let c4b_data = triplicate_honest_rows(c4b_sample);

    let c4a_e3 = "e3-nf-c4a";
    let c4b_e3 = "e3-nf-c4b";
    let c4a_proof = ShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &c4a_data,
            c4a_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C4a");
    let c4b_proof = ShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &c4b_data,
            c4b_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C4b");

    let c2a_chunked = e3_zk_prover::prove_chunked_share_computation(
        &prover,
        preset,
        &share_sk,
        "e3-nf-c2a-chunked",
        &artifacts_dir,
    )
    .expect("chunked C2a proof");
    let c2b_chunked = e3_zk_prover::prove_chunked_share_computation(
        &prover,
        preset,
        &share_esm,
        "e3-nf-c2b-chunked",
        &artifacts_dir,
    )
    .expect("chunked C2b proof");
    assert_eq!(c2a_chunked.proof.circuit, CircuitName::SkC2ChunkFinalize);
    assert_eq!(c2b_chunked.proof.circuit, CircuitName::ESmC2ChunkFinalize);
    let expected_chunk_count = preset.metadata().degree / 512;
    assert_eq!(c2a_chunked.chunk_count, expected_chunk_count);
    assert_eq!(c2b_chunked.chunk_count, expected_chunk_count);

    let chunked_node = e3_zk_prover::prove_node_dkg_fold(
        &prover,
        &NodeDkgFoldInput {
            c0_proof: &c0_proof,
            c1_proof: &c1_proof,
            c2a_proof: &c2a_chunked.proof,
            c2b_proof: &c2b_chunked.proof,
            c3a_inner_proofs: &c3a_inners,
            c3b_inner_proofs: &c3b_inners,
            c3_slot_indices_a: &slot_indices,
            c3_slot_indices_b: &slot_indices,
            c3_total_slots: total_slots,
            c4a_proof: &c4a_proof,
            c4b_proof: &c4b_proof,
            party_id: own_party_id as u64,
        },
        "e3-nf-node-chunked",
        &artifacts_dir,
    )
    .expect("chunked node fold proof");
    assert!(chunked_node
        .step_timings
        .iter()
        .any(|step| step.step == CircuitName::C2abChunkFold.as_str()));
    assert!(prover
        .verify_fold_proof(
            &chunked_node.proof,
            "e3-nf-node-chunked-nodefold",
            0,
            &artifacts_dir,
        )
        .expect("verify chunked node_fold"));

    drop(temp);
}

#[tokio::test]
async fn node_fold_correlated_sparse_self_slot_proves_and_verifies() {
    run_node_fold_correlated_sparse_self_slot(BfvPreset::InsecureThreshold512).await;
}

#[tokio::test]
async fn node_fold_correlated_secure_multi_chunk_proves_and_verifies() {
    if active_bin_preset().as_deref() != Some("secure-8192") {
        println!("skipping: secure-8192 circuit artifacts are not active");
        return;
    }
    let dkg_circuits = [
        "pk",
        "sk_share_computation_chunk",
        "esm_share_computation_chunk",
        "share_encryption",
        "share_decryption",
    ];
    let recursive_circuits = [
        CircuitName::C2ChunkBatch,
        CircuitName::SkC2ChunkFinalize,
        CircuitName::ESmC2ChunkFinalize,
        CircuitName::C2abChunkFold,
        CircuitName::C3Fold,
        CircuitName::C3FoldKernel,
        CircuitName::C3abFold,
        CircuitName::C4abFold,
        CircuitName::NodeFold,
    ];
    if dkg_circuits
        .iter()
        .any(|circuit| !compiled_circuit_artifacts_available("dkg", circuit))
        || !compiled_circuit_artifacts_available("threshold", "pk_generation")
        || recursive_circuits
            .iter()
            .any(|circuit| !recursive_circuit_artifacts_available(*circuit))
    {
        println!("skipping: secure-8192 circuit artifacts are not staged");
        return;
    }
    run_node_fold_correlated_sparse_self_slot(BfvPreset::SecureThreshold8192).await;
}
