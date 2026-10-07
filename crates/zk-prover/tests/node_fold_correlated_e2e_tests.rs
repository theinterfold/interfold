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
#[path = "common/recursive_vk_substitution.rs"]
mod recursive_vk_substitution;

use std::path::PathBuf;

use common::{
    active_bin_preset, compiled_circuit_artifacts_available, find_bb,
    recursive_circuit_artifacts_available, require_minimum_circuits_for_preset,
    setup_compiled_circuit_for_preset, setup_recursive_aggregation_fold_circuit_for_preset,
    setup_test_prover,
};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::Computation;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::Inputs as ShareComputationInputs;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuit;
use e3_zk_helpers::threshold::pk_generation::PkGenerationCircuit;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::{fold_witness_field_strings, load_vk_artifacts};
use e3_zk_prover::{
    generate_sequential_c3_fold, CircuitVariant, NodeDkgFoldInput, Provable, ZkProver,
};
use node_fold_witness::{
    pk_generation_sample_with_esi, share_computation_esm_from_esi, share_computation_sk_from_pk,
    share_encryption_for_slot,
};
use recursive_vk_substitution::{fields, substitute_proof, vk_hash, witness};
use serde_json::json;

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
    (len - 5) / 3
}

fn field_str_zero() -> String {
    format!("0x{}", hex::encode([0u8; 32]))
}

fn proof_public_fields(proof: &Proof) -> Vec<String> {
    fold_witness_field_strings(proof.public_signals.as_ref()).expect("public_signals as fields")
}

fn triplicate_honest_rows(mut d: ShareDecryptionCircuitData) -> ShareDecryptionCircuitData {
    let row0 = d.honest_ciphertexts[0].clone();
    d.honest_ciphertexts = (0..d.honest_ciphertexts.len())
        .map(|_| row0.clone())
        .collect();
    d
}

fn assert_final_dkg_tree_binding(
    prover: &ZkProver,
    node: &Proof,
    changed_node: &Proof,
    artifacts_dir: &str,
) {
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let fold_vk = load_vk_artifacts(&default_dir, CircuitName::NodesFold).unwrap();
    let kernel_vk = load_vk_artifacts(&default_dir, CircuitName::NodesFoldKernel).unwrap();
    let fold_path = default_dir.join("recursive_aggregation/nodes_fold/nodes_fold.json");
    let kernel_path =
        default_dir.join("recursive_aggregation/nodes_fold_kernel/nodes_fold_kernel.json");
    let final_path = default_dir.join("recursive_aggregation/dkg_aggregator/dkg_aggregator.json");
    let canonical_tree = format!(
        "0x{}",
        hex::encode(
            std::fs::read(
                default_dir.join("recursive_aggregation/nodes_fold/nodes_fold.vk_tree_hash")
            )
            .unwrap()
        )
    );

    // Alternate node and C5 relations isolate tree binding from the DKG commitment-link checks.
    let mut row = vec![field_str_zero(); fields(node).len()];
    row[6] = fields(node)[6].clone();
    let first_node = substitute_proof(
        prover,
        CircuitName::NodeFold,
        CircuitVariant::Default,
        &row,
        None,
        "dkg-tree-node0",
    );
    let c5 = substitute_proof(
        prover,
        CircuitName::PkAggregation,
        CircuitVariant::Default,
        &vec![field_str_zero(); 3],
        None,
        "dkg-tree-c5",
    );
    let mut step = json!({
        "inner_vk": first_node.vk,
        "inner_proof": fold_witness_field_strings(&first_node.proof.data).unwrap(),
        "node_fold_public_inputs": fields(&first_node.proof),
        "acc_vk": kernel_vk.verification_key,
        "acc_proof": vec!["0"; 410],
        "acc_public_inputs": vec!["0"; 5 + 2 * row.len()],
        "inner_key_hash": first_node.key_hash,
        "fold_key_hash": fold_vk.key_hash,
        "kernel_key_hash": kernel_vk.key_hash,
        "is_first_step": true,
        "slot_index": 0,
    });
    let genesis_witness = witness(&kernel_path, &step).unwrap();
    let genesis = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::NodesFoldKernel,
            &genesis_witness,
            "dkg-tree-genesis",
            artifacts_dir,
        )
        .unwrap();
    step["acc_proof"] = json!(fold_witness_field_strings(&genesis.data).unwrap());
    step["acc_public_inputs"] = json!(fields(&genesis));
    let first_witness = witness(&fold_path, &step).unwrap();
    let first = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::NodesFold,
            &first_witness,
            "dkg-tree-first",
            artifacts_dir,
        )
        .unwrap();
    let fake_prior = substitute_proof(
        prover,
        CircuitName::NodesFold,
        CircuitVariant::Default,
        &fields(&first),
        None,
        "dkg-tree-prior",
    );
    let mut changed_genesis = step.clone();
    changed_genesis["acc_vk"] = json!(fake_prior.vk);
    changed_genesis["acc_proof"] =
        json!(fold_witness_field_strings(&fake_prior.proof.data).unwrap());
    changed_genesis["acc_public_inputs"] = json!(fields(&fake_prior.proof));
    recursive_vk_substitution::assert_fold_rejected(
        prover,
        CircuitName::NodesFold,
        &fold_path,
        &changed_genesis,
        artifacts_dir,
        "nodes-substituted-genesis",
    );

    let addresses: Vec<_> = (1..=3)
        .map(|i| alloy::primitives::Address::from_word(alloy::primitives::U256::from(i).into()))
        .collect();
    let (committee_hi, committee_lo) = e3_committee_hash::committee_hash_field_hex(&addresses);
    for mixed_tree in [false, true] {
        row[0] = "1".into();
        row[6] = fields(if mixed_tree { changed_node } else { node })[6].clone();
        let second_node = substitute_proof(
            prover,
            CircuitName::NodeFold,
            CircuitVariant::Default,
            &row,
            None,
            "dkg-tree-node1",
        );
        assert_eq!(second_node.key_hash, first_node.key_hash);
        step["inner_proof"] = json!(fold_witness_field_strings(&second_node.proof.data).unwrap());
        step["node_fold_public_inputs"] = json!(fields(&second_node.proof));
        step["acc_vk"] = json!(fold_vk.verification_key);
        step["acc_proof"] = json!(fold_witness_field_strings(&first.data).unwrap());
        step["acc_public_inputs"] = json!(fields(&first));
        step["is_first_step"] = json!(false);
        step["slot_index"] = json!(1);
        let second_witness = witness(&fold_path, &step).unwrap();
        let folded = prover
            .generate_recursive_aggregation_bin_proof(
                CircuitName::NodesFold,
                &second_witness,
                "dkg-tree-second",
                artifacts_dir,
            )
            .unwrap();
        assert!(prover
            .verify_fold_proof(&folded, "dkg-tree-second", 0, artifacts_dir)
            .unwrap());
        if !mixed_tree {
            let mut changed_prior = step.clone();
            changed_prior["acc_vk"] = json!(fake_prior.vk);
            changed_prior["acc_proof"] =
                json!(fold_witness_field_strings(&fake_prior.proof.data).unwrap());
            changed_prior["acc_public_inputs"] = json!(fields(&fake_prior.proof));
            recursive_vk_substitution::assert_fold_rejected(
                prover,
                CircuitName::NodesFold,
                &fold_path,
                &changed_prior,
                artifacts_dir,
                "nodes-substituted-predecessor",
            );
            for key in ["inner_key_hash", "fold_key_hash", "kernel_key_hash"] {
                let mut changed_key = step.clone();
                changed_key[key] = json!(fake_prior.key_hash);
                assert!(
                    witness(&fold_path, &changed_key).is_err(),
                    "nodes continuation must retain {key}"
                );
            }
        }
        let tree = vk_hash(&[
            fold_vk.key_hash.clone(),
            kernel_vk.key_hash.clone(),
            first_node.key_hash.clone(),
            fields(node)[6].clone(),
        ]);
        let mut final_input = json!({
            "nodes_fold_vk": fold_vk.verification_key,
            "nodes_fold_vk_hash": fold_vk.key_hash,
            "nodes_fold_proof": fold_witness_field_strings(&folded.data).unwrap(),
            "nodes_fold_public": fields(&folded),
            "c5_vk": c5.vk,
            "c5_proof": fold_witness_field_strings(&c5.proof.data).unwrap(),
            "c5_public": fields(&c5.proof),
            "nodes_fold_key_hash": tree,
            "c5_key_hash": c5.key_hash,
            "party_ids": ["0", "1"],
            "committee_members": ["1", "2", "3"],
            "committee_hash_hi": committee_hi,
            "committee_hash_lo": committee_lo,
        });
        if mixed_tree {
            assert!(
                witness(&final_path, &final_input).is_err(),
                "every DKG node row must use the same nested VK tree"
            );
        } else {
            let final_witness =
                witness(&final_path, &final_input).expect("consistent alternate DKG tree");
            let control = prover
                .generate_recursive_aggregation_bin_proof(
                    CircuitName::DkgAggregator,
                    &final_witness,
                    "dkg-tree-final",
                    artifacts_dir,
                )
                .unwrap();
            assert!(prover
                .verify_fold_proof(&control, "dkg-tree-final", 0, artifacts_dir)
                .unwrap());
            final_input["nodes_fold_key_hash"] = json!(canonical_tree);
            assert!(
                witness(&final_path, &final_input).is_err(),
                "an alternate DKG tree must not claim the deployment's canonical anchor"
            );
        }
    }
}

async fn run_node_fold_correlated_sparse_self_slot(preset: BfvPreset) {
    let Some(bb) = find_bb().await else {
        panic!("missing required test prerequisite: bb not found");
    };

    if require_minimum_circuits_for_preset(preset).is_none() {
        return;
    }

    let gate = recursive_aggregation_compiled_json_path(CircuitName::NodeFold);
    if !gate.exists() {
        panic!(
            "missing required test prerequisite: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            gate.display()
        );
    }
    if !c3_fold_json_path().exists() {
        panic!("missing required test prerequisite: c3_fold.json not found");
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
        CircuitName::NodesFold,
        CircuitName::NodesFoldKernel,
        CircuitName::DkgAggregator,
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

    let c3a_folded = generate_sequential_c3_fold(
        &prover,
        &c3a_inners,
        &slot_indices,
        total_slots,
        "e3-nf-c3fold-a",
        &artifacts_dir,
    )
    .expect("c3 fold sk chain");
    let c3b_folded = generate_sequential_c3_fold(
        &prover,
        &c3b_inners,
        &slot_indices,
        total_slots,
        "e3-nf-c3fold-b",
        &artifacts_dir,
    )
    .expect("c3 fold e_sm chain");

    let c3a_pub = proof_public_fields(&c3a_folded);
    let c3b_pub = proof_public_fields(&c3b_folded);
    let c3_prefix_len = c3a_pub.len() - (3 * total_slots);
    for slot in 0..slots_per_party {
        assert_eq!(c3a_pub[c3_prefix_len + slot], field_str_zero());
        assert_eq!(
            c3a_pub[c3_prefix_len + total_slots + slot],
            field_str_zero()
        );
        assert_eq!(c3b_pub[c3_prefix_len + slot], field_str_zero());
        assert_eq!(
            c3b_pub[c3_prefix_len + total_slots + slot],
            field_str_zero()
        );
    }
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

    // The final DKG aggregator must accept rows under one nested VK tree only. A node row under a
    // different tree anchor (public field 6) stands in for a node built from substituted leaves.
    let node_proof = &chunked_node.proof;
    let mut changed_row = fields(node_proof);
    changed_row[6] = vk_hash(&[changed_row[6].clone()]);
    let changed_node = substitute_proof(
        &prover,
        CircuitName::NodeFold,
        CircuitVariant::Default,
        &changed_row,
        None,
        "nested-vk-node",
    );
    assert_ne!(fields(&changed_node.proof)[6], fields(node_proof)[6]);
    assert_final_dkg_tree_binding(&prover, node_proof, &changed_node.proof, &artifacts_dir);

    drop(temp);
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn node_fold_correlated_sparse_self_slot_proves_and_verifies() {
    run_node_fold_correlated_sparse_self_slot(BfvPreset::InsecureThreshold).await;
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
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
