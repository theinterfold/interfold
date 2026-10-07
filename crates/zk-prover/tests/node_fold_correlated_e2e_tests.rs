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
    find_bb, require_minimum_circuits, setup_compiled_circuit,
    setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::Computation;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::dkg::share_computation::{
    Inputs as ShareComputationInputs, ShareComputationCircuit,
};
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::dkg::share_encryption::ShareEncryptionCircuit;
use e3_zk_helpers::threshold::pk_generation::PkGenerationCircuit;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, fold_witness_input_map, load_vk_artifacts,
};
use e3_zk_prover::{generate_sequential_c3_fold, CircuitVariant, Provable, ZkProver};
use e3_zk_prover::{CompiledCircuit, WitnessGenerator};
use node_fold_witness::{
    pk_generation_sample_with_esi, share_computation_esm_from_esi, share_computation_sk_from_pk,
    share_encryption_for_slot,
};
use recursive_vk_substitution::{fields, substitute_proof, vk_hash, witness};
use serde::Serialize;
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

#[derive(Serialize)]
struct C2abFoldWitness {
    c2a_vk: Vec<String>,
    c2a_proof: Vec<String>,
    c2a_public: Vec<String>,
    c2b_vk: Vec<String>,
    c2b_proof: Vec<String>,
    c2b_public: Vec<String>,
    c2a_key_hash: String,
    c2b_key_hash: String,
}

#[derive(Serialize)]
struct C3abFoldWitness {
    c3a_vk: Vec<String>,
    c3a_proof: Vec<String>,
    c3a_public: Vec<String>,
    c3b_vk: Vec<String>,
    c3b_proof: Vec<String>,
    c3b_public: Vec<String>,
    c3a_key_hash: String,
    c3b_key_hash: String,
}

#[derive(Serialize)]
struct C4abFoldWitness {
    c4a_vk: Vec<String>,
    c4a_proof: Vec<String>,
    c4a_public: Vec<String>,
    c4b_vk: Vec<String>,
    c4b_proof: Vec<String>,
    c4b_public: Vec<String>,
    c4a_key_hash: String,
    c4b_key_hash: String,
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

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn node_fold_correlated_sparse_self_slot_proves_and_verifies() {
    let Some(bb) = find_bb().await else {
        panic!("missing required test prerequisite: bb not found");
    };

    require_minimum_circuits()
        .expect("rebuild required circuits with pnpm build:circuits --committee minimum");

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
    let preset = BfvPreset::InsecureThreshold;

    let (backend, temp) = setup_test_prover(&bb).await;
    let prover = ZkProver::new(&backend);
    let artifacts_dir =
        preset.artifacts_dir_for_committee(CiphernodesCommitteeSize::Minimum.as_str());

    for g in [
        "pk",
        "sk_share_computation",
        "e_sm_share_computation",
        "share_encryption",
        "share_decryption",
    ] {
        let name = match g {
            "pk" => "pk",
            "sk_share_computation" => "sk_share_computation",
            "e_sm_share_computation" => "e_sm_share_computation",
            "share_encryption" => "share_encryption",
            "share_decryption" => "share_decryption",
            _ => unreachable!(),
        };
        setup_compiled_circuit(&backend, "dkg", name).await;
    }
    setup_compiled_circuit(&backend, "threshold", "pk_generation").await;

    for c in [
        CircuitName::C2abFold,
        CircuitName::C3Fold,
        CircuitName::C3FoldKernel,
        CircuitName::C3abFold,
        CircuitName::C4abFold,
        CircuitName::NodeFold,
        CircuitName::NodesFold,
        CircuitName::NodesFoldKernel,
        CircuitName::DkgAggregator,
    ] {
        setup_recursive_aggregation_fold_circuit(&backend, c).await;
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
    let c2a_e3 = "e3-nf-c2a";
    let c2b_e3 = "e3-nf-c2b";
    let c2ab_e3 = "e3-nf-c2ab";

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

    let c2a_proof = ShareComputationCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &share_sk,
            c2a_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C2a proof");
    let c2b_proof = ShareComputationCircuit
        .prove_with_variant(
            &prover,
            &preset,
            &share_esm,
            c2b_e3,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("C2b proof");

    let c2a_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::SkShareComputation,
    )
    .expect("c2a vk");
    let c2b_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::ESmShareComputation,
    )
    .expect("c2b vk");

    let c2a_pub = proof_public_fields(&c2a_proof);
    let c2b_pub = proof_public_fields(&c2b_proof);
    let c2ab = C2abFoldWitness {
        c2a_vk: c2a_vk.verification_key,
        c2a_proof: fold_witness_field_strings(&c2a_proof.data).expect("c2a proof fields"),
        c2a_public: c2a_pub.clone(),
        c2b_vk: c2b_vk.verification_key,
        c2b_proof: fold_witness_field_strings(&c2b_proof.data).expect("c2b proof fields"),
        c2b_public: c2b_pub.clone(),
        c2a_key_hash: c2a_vk.key_hash.clone(),
        c2b_key_hash: c2b_vk.key_hash.clone(),
    };

    let c2ab_json = serde_json::to_value(&c2ab).expect("c2ab json");
    let c2ab_map = fold_witness_input_map(&c2ab_json).expect("c2ab input map");
    let c2ab_compiled = CompiledCircuit::from_file(
        &prover
            .circuits_dir(CircuitVariant::Default, &artifacts_dir)
            .join(CircuitName::C2abFold.dir_path())
            .join(format!("{}.json", CircuitName::C2abFold.as_str())),
    )
    .expect("c2ab compiled");
    let c2ab_witness = WitnessGenerator::new()
        .generate_witness(&c2ab_compiled, c2ab_map)
        .expect("c2ab witness");
    let c2ab_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C2abFold,
            &c2ab_witness,
            c2ab_e3,
            &artifacts_dir,
        )
        .expect("c2ab_fold proof");

    let (_dkg_th, dkg_dkg) = e3_fhe_params::build_pair_for_preset(preset).expect("pair");
    let mut rng = rand::rng();
    let dkg_sk = fhe::bfv::SecretKey::random(&dkg_dkg, &mut rng);
    let dkg_pk = fhe::bfv::PublicKey::new(&dkg_sk, &mut rng);

    let total_slots = c3_fold_total_slots_from_compiled_json();
    assert_eq!(
        total_slots,
        committee.n * preset.metadata().num_moduli,
        "C3 has one slot per party and threshold modulus"
    );
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
    assert_eq!(slot_indices, vec![2, 3, 4, 5]);

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

    let c3a_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &artifacts_dir),
        CircuitName::C3Fold,
    )
    .expect("c3a fold vk");
    let c3b_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &artifacts_dir),
        CircuitName::C3Fold,
    )
    .expect("c3b fold vk");

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
    let c3ab = C3abFoldWitness {
        c3a_vk: c3a_vk.verification_key,
        c3a_proof: fold_witness_field_strings(&c3a_folded.data).expect("c3a fold proof"),
        c3a_public: c3a_pub,
        c3b_vk: c3b_vk.verification_key,
        c3b_proof: fold_witness_field_strings(&c3b_folded.data).expect("c3b fold proof"),
        c3b_public: c3b_pub,
        c3a_key_hash: c3a_vk.key_hash.clone(),
        c3b_key_hash: c3b_vk.key_hash.clone(),
    };
    let c3ab_json = serde_json::to_value(&c3ab).expect("c3ab json");
    let c3ab_map = fold_witness_input_map(&c3ab_json).expect("c3ab map");
    let c3ab_compiled = CompiledCircuit::from_file(
        &prover
            .circuits_dir(CircuitVariant::Default, &artifacts_dir)
            .join(CircuitName::C3abFold.dir_path())
            .join(format!("{}.json", CircuitName::C3abFold.as_str())),
    )
    .expect("c3ab compiled");
    let c3ab_witness = WitnessGenerator::new()
        .generate_witness(&c3ab_compiled, c3ab_map)
        .expect("c3ab witness");
    let c3ab_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C3abFold,
            &c3ab_witness,
            "e3-nf-c3ab",
            &artifacts_dir,
        )
        .expect("c3ab_fold proof");

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

    let c4a_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::DkgShareDecryption,
    )
    .expect("c4a vk");
    let c4b_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::DkgShareDecryption,
    )
    .expect("c4b vk");

    let c4ab = C4abFoldWitness {
        c4a_vk: c4a_vk.verification_key,
        c4a_proof: fold_witness_field_strings(&c4a_proof.data).expect("c4a"),
        c4a_public: proof_public_fields(&c4a_proof),
        c4b_vk: c4b_vk.verification_key,
        c4b_proof: fold_witness_field_strings(&c4b_proof.data).expect("c4b"),
        c4b_public: proof_public_fields(&c4b_proof),
        c4a_key_hash: c4a_vk.key_hash.clone(),
        c4b_key_hash: c4b_vk.key_hash.clone(),
    };
    let c4ab_json = serde_json::to_value(&c4ab).expect("c4ab json");
    let c4ab_map = fold_witness_input_map(&c4ab_json).expect("c4ab map");
    let c4ab_compiled = CompiledCircuit::from_file(
        &prover
            .circuits_dir(CircuitVariant::Default, &artifacts_dir)
            .join(CircuitName::C4abFold.dir_path())
            .join(format!("{}.json", CircuitName::C4abFold.as_str())),
    )
    .expect("c4ab compiled");
    let c4ab_witness = WitnessGenerator::new()
        .generate_witness(&c4ab_compiled, c4ab_map)
        .expect("c4ab witness");
    let c4ab_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C4abFold,
            &c4ab_witness,
            "e3-nf-c4ab",
            &artifacts_dir,
        )
        .expect("c4ab_fold proof");

    let c0_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::PkBfv,
    )
    .expect("c0 vk");
    let c1_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::PkGeneration,
    )
    .expect("c1 vk");
    let c2ab_fold_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &artifacts_dir),
        CircuitName::C2abFold,
    )
    .expect("c2ab fold vk");
    let c3ab_fold_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &artifacts_dir),
        CircuitName::C3abFold,
    )
    .expect("c3ab fold vk");
    let c4ab_fold_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &artifacts_dir),
        CircuitName::C4abFold,
    )
    .expect("c4ab fold vk");

    let nf = json!({
        "c0_vk": c0_vk.verification_key,
        "c0_proof": fold_witness_field_strings(&c0_proof.data).expect("c0 proof"),
        "c0_public": proof_public_fields(&c0_proof),
        "c1_vk": c1_vk.verification_key,
        "c1_proof": fold_witness_field_strings(&c1_proof.data).expect("c1 proof"),
        "c1_public": proof_public_fields(&c1_proof),
        "c2ab_vk": c2ab_fold_vk.verification_key,
        "c2ab_proof": fold_witness_field_strings(&c2ab_proof.data).expect("c2ab"),
        "c2ab_public": proof_public_fields(&c2ab_proof),
        "c3ab_vk": c3ab_fold_vk.verification_key,
        "c3ab_proof": fold_witness_field_strings(&c3ab_proof.data).expect("c3ab"),
        "c3ab_public": proof_public_fields(&c3ab_proof),
        "c4ab_vk": c4ab_fold_vk.verification_key,
        "c4ab_proof": fold_witness_field_strings(&c4ab_proof.data).expect("c4ab"),
        "c4ab_public": proof_public_fields(&c4ab_proof),
        "party_id": field_str_zero(),
        "c0_key_hash": c0_vk.key_hash,
        "c1_key_hash": c1_vk.key_hash,
        "c2ab_key_hash": c2ab_fold_vk.key_hash,
        "c3ab_key_hash": c3ab_fold_vk.key_hash,
        "c4ab_key_hash": c4ab_fold_vk.key_hash,
    });

    let nf_map = fold_witness_input_map(&nf).expect("node_fold map");
    let nf_compiled = CompiledCircuit::from_file(&gate).expect("node_fold compiled");
    let nf_witness = WitnessGenerator::new()
        .generate_witness(&nf_compiled, nf_map)
        .expect("node_fold witness");
    let nf_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::NodeFold,
            &nf_witness,
            "e3-nf-node",
            &artifacts_dir,
        )
        .expect("node_fold proof");

    let ok = prover
        .verify_fold_proof(&nf_proof, "e3-nf-node", 0, &artifacts_dir)
        .expect("verify node_fold");
    assert!(ok, "node_fold should verify");

    let expected_node_hash = |input: &serde_json::Value| {
        vk_hash(&[
            input["c0_key_hash"].as_str().unwrap().to_owned(),
            input["c1_key_hash"].as_str().unwrap().to_owned(),
            input["c2ab_key_hash"].as_str().unwrap().to_owned(),
            input["c2ab_public"][2].as_str().unwrap().to_owned(),
            input["c3ab_key_hash"].as_str().unwrap().to_owned(),
            input["c3ab_public"][2].as_str().unwrap().to_owned(),
            input["c4ab_key_hash"].as_str().unwrap().to_owned(),
            input["c4ab_public"][2].as_str().unwrap().to_owned(),
        ])
    };
    assert_eq!(fields(&nf_proof)[6], expected_node_hash(&nf));

    let fake_c2a = substitute_proof(
        &prover,
        CircuitName::SkShareComputation,
        CircuitVariant::Recursive,
        &fields(&c2a_proof),
        None,
        "nested-c2-leaf",
    );
    let mut changed_c2 = c2ab_json.clone();
    changed_c2["c2a_vk"] = json!(fake_c2a.vk);
    changed_c2["c2a_proof"] = json!(fold_witness_field_strings(&fake_c2a.proof.data).unwrap());
    changed_c2["c2a_key_hash"] = json!(fake_c2a.key_hash);
    let changed_c2_witness = WitnessGenerator::new()
        .generate_witness(&c2ab_compiled, fold_witness_input_map(&changed_c2).unwrap())
        .expect("alternate nested leaf is valid under its own VK");
    let changed_c2_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C2abFold,
            &changed_c2_witness,
            "nested-vk-c2ab",
            &artifacts_dir,
        )
        .unwrap();
    let mut changed_node = nf.clone();
    changed_node["c2ab_public"] = json!(fields(&changed_c2_proof));
    changed_node["c2ab_proof"] = json!(fold_witness_field_strings(&changed_c2_proof.data).unwrap());
    let changed_node_witness = witness(&gate, &changed_node).unwrap();
    let changed_node_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::NodeFold,
            &changed_node_witness,
            "nested-vk-node",
            &artifacts_dir,
        )
        .unwrap();
    assert!(prover
        .verify_fold_proof(&changed_node_proof, "nested-vk-node", 0, &artifacts_dir)
        .unwrap());
    let changed_public = fields(&changed_node_proof);
    assert_eq!(changed_public[6], expected_node_hash(&changed_node));
    assert_ne!(
        changed_public[6],
        fields(&nf_proof)[6],
        "a nested leaf substitution must change the node-tree anchor"
    );
    assert_eq!(
        &changed_public[..6],
        &fields(&nf_proof)[..6],
        "the immediate node-fold VK parameters do not change"
    );
    assert_eq!(
        &changed_public[7..],
        &fields(&nf_proof)[7..],
        "the protocol statement is unchanged"
    );
    assert_final_dkg_tree_binding(&prover, &nf_proof, &changed_node_proof, &artifacts_dir);

    drop(temp);
}
