// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Accumulation integration tests: a node's C3 batch through the C3 Chonk stacks, tubes and
//! accumulate proofs ([`generate_c3_chonk_chain`]), and sequential [`generate_sequential_c6_fold`]
//! (prove + [`ZkProver::verify_fold_proof`]) with the slot count read from the compiled `c6_fold`
//! ABI and artifacts staged under [`CircuitVariant::Default`] (`noir-recursive-no-zk` VKs — see
//! `crates/zk/build`).
//!
//! The node-fold pipeline ([`CircuitName::C2abFold`] … [`CircuitName::NodeFold`]), which consumes
//! the C3 Chonk chains, is proven in `node_fold_correlated_e2e_tests.rs`.
//!
//! - [`c3_chonk_chain_proves_and_exposes_its_key_list`]: two inner `ShareEncryption` proofs →
//!   [`generate_c3_chonk_chain`].
//! - [`c3_chonk_rejects_a_corrupted_leaf_or_a_substituted_key`]: a leaf whose claimed row differs
//!   from its proof, or a stack stage handed another stage's key, never yields a chain.
//! - [`c6_fold_sequential_proves_and_verifies`]: two inner `ThresholdShareDecryption` proofs → [`generate_sequential_c6_fold`].

mod common;
#[path = "common/recursive_vk_substitution.rs"]
mod recursive_vk_substitution;

use std::path::PathBuf;

use common::{
    find_bb, setup_c3_chonk_circuits, setup_compiled_circuit,
    setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::Proof;
use e3_fhe_params::BfvPreset;
use e3_zk_config::DkgInputType;
use e3_zk_config::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_config::{CircuitName, CircuitVariant};
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, generate_c3_chonk_chain_with_substituted_key, load_vk_artifacts,
};
use e3_zk_prover::{
    generate_c3_chonk_chain, generate_sequential_c6_fold, Provable, ZkBackend, ZkProver,
};
use e3_zk_prover::{
    ShareEncryptionCircuit, ThresholdShareDecryptionCircuit as ShareDecryptionCircuit,
};
use e3_zk_witness::threshold::share_decryption::ShareDecryptionCircuitData;
use recursive_vk_substitution::{assert_fold_rejected, fields, substitute_proof, vk_hash, witness};
use serde_json::json;

fn c6_fold_json_path() -> PathBuf {
    e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json")
}

/// Reads slot count from the compiled `c6_fold` ABI
/// (`acc_public_inputs` length is `7 + 4 * slots`: five fold parameters and two domain limbs).
fn c6_fold_total_slots_from_compiled_json() -> usize {
    let path = c6_fold_json_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {} (run `pnpm build:circuits --group recursive_aggregation`)",
            path.display(),
            e
        )
    });
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
    let len = v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| {
                    p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into()))
                })
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c6_fold.json: abi.parameters.acc_public_inputs.length") as usize;
    assert!(
        len >= 7 && (len - 7).is_multiple_of(4),
        "unexpected acc_public_inputs length {} (expected 7 + 4 * slots)",
        len
    );
    (len - 7) / 4
}

/// Expected C6 fold slot count when circuits are compiled for the minimum committee (N=3, T=1).
const MINIMUM_C6_FOLD_SLOTS: usize = 2;

fn assert_recursive_vk_binding(
    prover: &ZkProver,
    fold: CircuitName,
    kernel: CircuitName,
    inners: &[Proof],
    folded: &Proof,
    total_slots: usize,
    artifacts_dir: &str,
) {
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let recursive_dir = prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir);
    let leaf_vk = load_vk_artifacts(&recursive_dir, inners[0].circuit).unwrap();
    let fold_vk = load_vk_artifacts(&default_dir, fold).unwrap();
    let kernel_vk = load_vk_artifacts(&default_dir, kernel).unwrap();
    let fold_path = default_dir
        .join(fold.dir_path())
        .join(format!("{}.json", fold.as_str()));
    let kernel_path = default_dir
        .join(kernel.dir_path())
        .join(format!("{}.json", kernel.as_str()));
    // The kernel proves the chain's first leaf at slot 0.
    let mut input = json!({
        "inner_vk": leaf_vk.verification_key,
        "inner_proof": fold_witness_field_strings(&inners[0].data).unwrap(),
        "acc_vk": kernel_vk.verification_key,
        "acc_proof": vec!["0"; folded.data.len() / 32],
        "acc_public_inputs": vec!["0"; fields(folded).len()],
        "inner_key_hash": leaf_vk.key_hash,
        "fold_key_hash": fold_vk.key_hash,
        "kernel_key_hash": kernel_vk.key_hash,
        "is_first_step": true,
        "slot_index": 0,
    });
    input["c6_public_inputs"] = json!(fields(&inners[0]));
    let kernel_witness = witness(&kernel_path, &input).expect("honest genesis witness");
    let genesis = prover
        .generate_recursive_aggregation_bin_proof(
            kernel,
            &kernel_witness,
            "vk-binding-genesis",
            artifacts_dir,
        )
        .expect("honest genesis proof");

    // The first fold step adds the second leaf at slot 1 on top of the kernel proof.
    input["acc_proof"] = json!(fold_witness_field_strings(&genesis.data).unwrap());
    input["acc_public_inputs"] = json!(fields(&genesis));
    input["inner_proof"] = json!(fold_witness_field_strings(&inners[1].data).unwrap());
    input["c6_public_inputs"] = json!(fields(&inners[1]));
    input["slot_index"] = json!(1);
    let first_witness = witness(&fold_path, &input).expect("honest first-step witness");
    let first = prover
        .generate_recursive_aggregation_bin_proof(
            fold,
            &first_witness,
            "vk-binding-first",
            artifacts_dir,
        )
        .expect("honest first-step proof");

    let mut reused_slot = input.clone();
    reused_slot["slot_index"] = json!(0);
    assert!(
        witness(&fold_path, &reused_slot).is_err(),
        "the first fold step must not refill the kernel's slot"
    );

    // A substituted predecessor carries the honest predecessor's public inputs, so the step's own
    // constraints, slot 1 still empty included, hold: the witness solves, and only the recursive
    // verification of the predecessor under its VK can reject it.
    let fake_kernel = substitute_proof(
        prover,
        kernel,
        CircuitVariant::Default,
        &fields(&genesis),
        None,
        "kernel-predecessor",
    );
    let mut fake_genesis = input.clone();
    fake_genesis["acc_vk"] = json!(fake_kernel.vk);
    fake_genesis["acc_proof"] = json!(fold_witness_field_strings(&fake_kernel.proof.data).unwrap());
    fake_genesis["acc_public_inputs"] = json!(fields(&fake_kernel.proof));
    witness(&fold_path, &fake_genesis).expect("a substituted kernel leaves the step satisfiable");
    assert_fold_rejected(
        prover,
        fold,
        &fold_path,
        &fake_genesis,
        artifacts_dir,
        "substituted-genesis",
    );

    let fake_acc = substitute_proof(
        prover,
        fold,
        CircuitVariant::Default,
        &fields(&first),
        None,
        "predecessor",
    );

    // With a third slot, a continuation verifies a fold predecessor under the fold key.
    let mut steps = vec![(input.clone(), 1)];
    if total_slots >= 3 {
        let mut continuation = input.clone();
        continuation["acc_vk"] = json!(fold_vk.verification_key);
        continuation["acc_proof"] = json!(fold_witness_field_strings(&first.data).unwrap());
        continuation["acc_public_inputs"] = json!(fields(&first));
        continuation["inner_proof"] = json!(fold_witness_field_strings(&inners[0].data).unwrap());
        continuation["c6_public_inputs"] = json!(fields(&inners[0]));
        continuation["is_first_step"] = json!(false);
        continuation["slot_index"] = json!(2);
        witness(&fold_path, &continuation).expect("honest continuation witness");

        let mut fake_prior = continuation.clone();
        fake_prior["acc_vk"] = json!(fake_acc.vk);
        fake_prior["acc_proof"] = json!(fold_witness_field_strings(&fake_acc.proof.data).unwrap());
        fake_prior["acc_public_inputs"] = json!(fields(&fake_acc.proof));
        witness(&fold_path, &fake_prior)
            .expect("a substituted fold predecessor leaves the step satisfiable");
        assert_fold_rejected(
            prover,
            fold,
            &fold_path,
            &fake_prior,
            artifacts_dir,
            "substituted-predecessor",
        );
        steps.push((continuation, 0));
    }

    for (step, leaf) in steps {
        let fake_leaf = substitute_proof(
            prover,
            inners[leaf].circuit,
            CircuitVariant::Recursive,
            &fields(&inners[leaf]),
            None,
            "leaf",
        );
        let mut changed_leaf = step.clone();
        changed_leaf["inner_vk"] = json!(fake_leaf.vk);
        changed_leaf["inner_proof"] =
            json!(fold_witness_field_strings(&fake_leaf.proof.data).unwrap());
        changed_leaf["inner_key_hash"] = json!(fake_leaf.key_hash);
        assert!(
            witness(&fold_path, &changed_leaf).is_err(),
            "a fold step must retain its predecessor's leaf VK hash"
        );
        for key in ["fold_key_hash", "kernel_key_hash"] {
            let mut changed_key = step.clone();
            changed_key[key] = json!(fake_acc.key_hash);
            assert!(
                witness(&fold_path, &changed_key).is_err(),
                "a fold step must retain its predecessor's {key}"
            );
        }
    }
}

fn assert_final_c6_tree_binding(
    prover: &ZkProver,
    inner: &Proof,
    folded: &Proof,
    artifacts_dir: &str,
) {
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let leaf_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        inner.circuit,
    )
    .unwrap();
    let fold_vk = load_vk_artifacts(&default_dir, CircuitName::C6Fold).unwrap();
    let kernel_vk = load_vk_artifacts(&default_dir, CircuitName::C6FoldKernel).unwrap();
    let fold_path = default_dir.join("recursive_aggregation/c6_fold/c6_fold.json");
    let kernel_path = default_dir.join("recursive_aggregation/c6_fold_kernel/c6_fold_kernel.json");
    let final_path =
        default_dir.join("recursive_aggregation/decryption_aggregator/decryption_aggregator.json");
    let canonical_tree = format!(
        "0x{}",
        hex::encode(
            std::fs::read(default_dir.join("recursive_aggregation/c6_fold/c6_fold.vk_tree_hash"))
                .unwrap()
        )
    );
    let leaf_public = fields(inner);
    let fake_leaf = substitute_proof(
        prover,
        inner.circuit,
        CircuitVariant::Recursive,
        &leaf_public,
        None,
        "c6-tree-leaf",
    );
    let mut genesis_public = vec!["0".to_owned(); fields(folded).len()];
    genesis_public[..3].clone_from_slice(&[
        leaf_vk.key_hash.clone(),
        fold_vk.key_hash.clone(),
        kernel_vk.key_hash.clone(),
    ]);
    // Every fold step checks the predecessor's domain and keeps its rows, the first one included, so
    // the substituted genesis carries the leaf in slot 0 as a real kernel proof would. Layout: seven
    // prefix fields, then the sk, e_sm, ct and d columns of `slots` entries each.
    genesis_public[5] = leaf_public[3].clone();
    genesis_public[6] = leaf_public[4].clone();
    let slots = (genesis_public.len() - 7) / 4;
    for (column, leaf_field) in [0, 1, 2, 5].into_iter().enumerate() {
        genesis_public[7 + column * slots] = leaf_public[leaf_field].clone();
    }
    let fake_genesis = substitute_proof(
        prover,
        CircuitName::C6FoldKernel,
        CircuitVariant::Default,
        &genesis_public,
        Some(2),
        "c6-tree-genesis",
    );

    // This alternate C7 relation isolates the C6 tree boundary. The EVM suite checks the separate C7 pin.
    let mut c7_public = vec![
        leaf_public[5].clone(),
        leaf_public[5].clone(),
        "1".into(),
        "2".into(),
    ];
    c7_public.extend(vec!["0".to_owned(); MAX_MSG_NON_ZERO_COEFFS]);
    let c7 = substitute_proof(
        prover,
        CircuitName::DecryptedSharesAggregation,
        CircuitVariant::Default,
        &c7_public,
        None,
        "c6-tree-c7",
    );
    let addresses: Vec<_> = (1..=3)
        .map(|i| alloy::primitives::Address::from_word(alloy::primitives::U256::from(i).into()))
        .collect();
    let (committee_hi, committee_lo) = e3_committee_hash::committee_hash_field_hex(&addresses);

    for replace_genesis in [true, false] {
        let mut step = json!({
            "inner_vk": if replace_genesis { &leaf_vk.verification_key } else { &fake_leaf.vk },
            "inner_proof": fold_witness_field_strings(if replace_genesis { &inner.data } else { &fake_leaf.proof.data }).unwrap(),
            "c6_public_inputs": leaf_public,
            "acc_vk": kernel_vk.verification_key,
            "acc_proof": vec!["0"; folded.data.len() / 32],
            "acc_public_inputs": vec!["0"; fields(folded).len()],
            "inner_key_hash": if replace_genesis { &leaf_vk.key_hash } else { &fake_leaf.key_hash },
            "fold_key_hash": fold_vk.key_hash,
            "kernel_key_hash": if replace_genesis { &fake_genesis.key_hash } else { &kernel_vk.key_hash },
            "is_first_step": true,
            "slot_index": 0,
        });
        let genesis = if replace_genesis {
            fake_genesis.proof.clone()
        } else {
            let kernel_witness = witness(&kernel_path, &step).unwrap();
            prover
                .generate_recursive_aggregation_bin_proof(
                    CircuitName::C6FoldKernel,
                    &kernel_witness,
                    "c6-tree-kernel",
                    artifacts_dir,
                )
                .unwrap()
        };
        step["acc_vk"] = if replace_genesis {
            json!(fake_genesis.vk)
        } else {
            json!(kernel_vk.verification_key)
        };
        // The first fold step fills the second slot on top of the genesis proof.
        step["acc_proof"] = json!(fold_witness_field_strings(&genesis.data).unwrap());
        step["acc_public_inputs"] = json!(fields(&genesis));
        step["slot_index"] = json!(1);
        let second_witness = witness(&fold_path, &step).unwrap();
        let changed_fold = prover
            .generate_recursive_aggregation_bin_proof(
                CircuitName::C6Fold,
                &second_witness,
                "c6-tree-second",
                artifacts_dir,
            )
            .unwrap();
        assert!(prover
            .verify_fold_proof(&changed_fold, "c6-tree-second", 0, artifacts_dir)
            .unwrap());
        let public = fields(&changed_fold);
        let tree = vk_hash(&[
            fold_vk.key_hash.clone(),
            public[2].clone(),
            public[0].clone(),
        ]);
        assert_ne!(tree, canonical_tree);
        let mut final_input = json!({
            "c6_fold_vk": fold_vk.verification_key,
            "c6_fold_vk_hash": fold_vk.key_hash,
            "c6_fold_proof": fold_witness_field_strings(&changed_fold.data).unwrap(),
            "c6_fold_public": public,
            "c7_vk": c7.vk,
            "c7_proof": fold_witness_field_strings(&c7.proof.data).unwrap(),
            "c7_public": fields(&c7.proof),
            "c6_fold_key_hash": tree,
            "c7_key_hash": c7.key_hash,
            "committee_members": ["1", "2", "3"],
            "committee_hash_hi": committee_hi,
            "committee_hash_lo": committee_lo,
            "domain_hi": leaf_public[3],
            "domain_lo": leaf_public[4],
            "ciphertext_commitment": leaf_public[2],
        });
        let control_witness =
            witness(&final_path, &final_input).expect("alternate tree is internally consistent");
        let control = prover
            .generate_recursive_aggregation_bin_proof(
                CircuitName::DecryptionAggregator,
                &control_witness,
                "c6-tree-final",
                artifacts_dir,
            )
            .unwrap();
        assert!(prover
            .verify_fold_proof(&control, "c6-tree-final", 0, artifacts_dir)
            .unwrap());
        final_input["c6_fold_key_hash"] = json!(canonical_tree);
        assert!(
            witness(&final_path, &final_input).is_err(),
            "a substituted leaf or genesis must not claim the deployment's canonical tree anchor"
        );
    }
}

/// Expected C3 slot count when circuits are compiled for the minimum committee (N=3, T=1): one
/// slot per party and insecure-64 threshold modulus (3 × 3).
const MINIMUM_C3_SLOTS: usize = 9;

/// Reads `C3_SLOTS` from the compiled `c3_chonk_tube` ABI (`stack_outputs` is `3 * C3_SLOTS + 4`).
fn c3_total_slots_from_compiled_json() -> usize {
    let path = e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/recursive_aggregation/c3_chonk_tube/target/c3_chonk_tube.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {} (run `pnpm build:circuits --group recursive_aggregation`)",
            path.display(),
            e
        )
    });
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
    let len = v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| p.get("name") == Some(&serde_json::Value::String("stack_outputs".into())))
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c3_chonk_tube.json: abi.parameters.stack_outputs.length") as usize;
    assert!(
        len >= 4 && (len - 4).is_multiple_of(3),
        "unexpected stack_outputs length {len} (expected 3 * slots + 4)"
    );
    (len - 4) / 3
}

/// A prover with the C3 Chonk circuits set up, and two inner C3 proofs.
struct C3Fixture {
    prover: ZkProver,
    inners: [Proof; 2],
    total_slots: usize,
    artifacts_dir: String,
    _backend: ZkBackend,
    _temp: tempfile::TempDir,
}

async fn c3_fixture() -> C3Fixture {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb()
        .await
        .expect("missing required test prerequisite: bb not found");
    let (backend, temp) = setup_test_prover(&bb).await;
    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;
    setup_c3_chonk_circuits(&backend).await;
    let prover = ZkProver::new(&backend);

    let total_slots = c3_total_slots_from_compiled_json();
    assert_eq!(
        total_slots, MINIMUM_C3_SLOTS,
        "circuits compiled for a non-minimum committee; rebuild with `pnpm build:circuits --committee minimum`"
    );
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let sd = preset.search_defaults().unwrap();
    let (threshold_params, dkg_params) = preset.build_pair().unwrap();
    let inners = [0, 1].map(|i| {
        let sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            preset,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let inner = ShareEncryptionCircuit
            .prove_with_variant(
                &prover,
                &e3_zk_config::dkg::share_encryption::Configs::for_preset(preset).unwrap(),
                &sample,
                &format!("e3-c3chonk-inner-{i}"),
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("inner ShareEncryption proof");
        assert_eq!(inner.circuit, CircuitName::ShareEncryption);
        inner
    });
    C3Fixture {
        prover,
        inners,
        total_slots,
        artifacts_dir,
        _backend: backend,
        _temp: temp,
    }
}

/// Two leaves go into two stacks, their tubes into one accumulate proof. It exposes the C3 Chonk
/// key list in the order the VK tree hashes it (`crates/zk/build/src/vk_tree.rs`), with the keys
/// each stage appended, and the leaves' rows in their slots.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_chonk_chain_proves_and_exposes_its_key_list() {
    let f = c3_fixture().await;
    let chain = generate_c3_chonk_chain(
        &f.prover,
        &f.inners,
        &[0u32, 1u32],
        f.total_slots,
        "e3-c3chonk-chain",
        &f.artifacts_dir,
    )
    .expect("C3 Chonk chain");
    assert_eq!(chain.circuit, CircuitName::C3ChonkAccumulate);

    let default_dir = f
        .prover
        .circuits_dir(CircuitVariant::Default, &f.artifacts_dir);
    let leaf = load_vk_artifacts(
        &f.prover
            .circuits_dir(CircuitVariant::Recursive, &f.artifacts_dir),
        CircuitName::ShareEncryption,
    )
    .unwrap();
    let key = |circuit| load_vk_artifacts(&default_dir, circuit).unwrap().key_hash;
    let public = fields(&chain);
    assert_eq!(public.len(), 7 + 3 * f.total_slots);
    assert_eq!(
        public[..7],
        [
            key(CircuitName::C3ChonkAccumulate),
            key(CircuitName::C3ChonkTube),
            key(CircuitName::C3ChonkHidingKernel),
            leaf.key_hash,
            key(CircuitName::C3ChonkApp),
            key(CircuitName::C3ChonkInitKernel),
            key(CircuitName::C3ChonkTailKernel),
        ]
    );

    let zero = format!("0x{}", "0".repeat(64));
    for column in 0..3 {
        for slot in 0..f.total_slots {
            let expected = f
                .inners
                .get(slot)
                .map_or(zero.clone(), |inner| fields(inner)[column].clone());
            assert_eq!(
                public[7 + column * f.total_slots + slot],
                expected,
                "column {column}, slot {slot}"
            );
        }
    }
    for i in 0..2 {
        f.prover.cleanup(&format!("e3-c3chonk-inner-{i}")).unwrap();
    }
}

/// A stack cannot carry a leaf whose claimed row differs from what it proved, nor a stage passed
/// off under another stage's key: the chain fails to prove.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_chonk_rejects_a_corrupted_leaf_or_a_substituted_key() {
    let f = c3_fixture().await;
    let slots = [0u32, 1u32];

    // The leaf's last public signal is its `ct_commitment`, the row the stack writes for it.
    let mut signals = f.inners[1].public_signals.extract_bytes();
    *signals.last_mut().unwrap() ^= 1;
    let corrupted = Proof::new(
        f.inners[1].circuit,
        f.inners[1].data.clone(),
        e3_utils::ArcBytes::from_bytes(&signals),
    );
    let result = generate_c3_chonk_chain(
        &f.prover,
        &[f.inners[0].clone(), corrupted],
        &slots,
        f.total_slots,
        "c3-corrupted-leaf",
        &f.artifacts_dir,
    );
    assert!(
        result.is_err(),
        "a leaf whose claimed row differs from its proof must not reach a chain"
    );

    for (stage, from) in [(0, 1), (1, 2), (2, 1)] {
        let result = generate_c3_chonk_chain_with_substituted_key(
            &f.prover,
            &f.inners,
            &slots,
            f.total_slots,
            (stage, from),
            &format!("c3-key-{stage}-as-{from}"),
            &f.artifacts_dir,
        );
        assert!(
            result.is_err(),
            "stack stage {stage} claimed under stage {from}'s key must not reach a chain"
        );
    }
    for i in 0..2 {
        f.prover.cleanup(&format!("e3-c3chonk-inner-{i}")).unwrap();
    }
}

async fn setup_c6_fold_with_inner_threshold_share_decryption() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareDecryptionCircuit,
    ShareDecryptionCircuitData,
    ShareDecryptionCircuitData,
    BfvPreset,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb().await?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C6Fold).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C6FoldKernel).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::DecryptionAggregator).await;

    let (params, _) = preset.build_pair().ok()?;
    let sample_a =
        e3_zk_samples::threshold::share_decryption::generate(&params, preset, committee.clone())
            .ok()?;
    let sample_b =
        e3_zk_samples::threshold::share_decryption::generate(&params, preset, committee).ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ShareDecryptionCircuit,
        sample_a,
        sample_b,
        preset,
    ))
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_fold_sequential_proves_and_verifies() {
    let Some((_backend, _temp, prover, circuit, sample_a, sample_b, preset)) =
        setup_c6_fold_with_inner_threshold_share_decryption().await
    else {
        panic!("missing required test prerequisite: bb not found or prerequisites missing");
    };

    let total_slots = c6_fold_total_slots_from_compiled_json();
    if total_slots != MINIMUM_C6_FOLD_SLOTS {
        panic!(
            "c6_fold_sequential_proves_and_verifies: circuits compiled for \
             non-minimum committee (total_slots={total_slots}, expected {MINIMUM_C6_FOLD_SLOTS}). \
             Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
    }
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let inner_e3_a = "e3-c6fold-inner-0";
    let inner_e3_b = "e3-c6fold-inner-1";
    let fold_e3 = "e3-c6fold-step";

    let inner_a = circuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap(),
            &sample_a,
            inner_e3_a,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("inner ThresholdShareDecryption proof 0");
    assert_eq!(inner_a.circuit, CircuitName::ThresholdShareDecryption);

    let inner_b = circuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap(),
            &sample_b,
            inner_e3_b,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("inner ThresholdShareDecryption proof 1");
    assert_eq!(inner_b.circuit, CircuitName::ThresholdShareDecryption);

    let inners = [inner_a, inner_b];
    let folded = generate_sequential_c6_fold(
        &prover,
        &inners,
        &[0u32, 1u32],
        total_slots,
        fold_e3,
        &artifacts_dir,
    )
    .expect("c6_fold sequential fold");
    assert_eq!(folded.circuit, CircuitName::C6Fold);
    assert!(
        !folded.data.is_empty(),
        "fold proof data should not be empty"
    );
    assert!(
        !folded.public_signals.is_empty(),
        "fold public signals should not be empty"
    );

    let party_id = 1u64;
    let ok = prover
        .verify_fold_proof(&folded, fold_e3, party_id, &artifacts_dir)
        .expect("verify_fold_proof invocation");
    assert!(ok, "c6_fold proof should verify under Default VK layout");
    assert_recursive_vk_binding(
        &prover,
        CircuitName::C6Fold,
        CircuitName::C6FoldKernel,
        &inners,
        &folded,
        total_slots,
        &artifacts_dir,
    );
    assert_final_c6_tree_binding(&prover, &inners[0], &folded, &artifacts_dir);

    prover.cleanup(inner_e3_a).unwrap();
    prover.cleanup(inner_e3_b).unwrap();
    prover.cleanup(fold_e3).unwrap();
}
