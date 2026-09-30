// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fold **accumulators** integration tests: sequential [`generate_sequential_c3_fold`] /
//! [`generate_sequential_c6_fold`] (prove + [`ZkProver::verify_fold_proof`]), ABI/slot inference from
//! compiled `c3_fold` / `c6_fold` JSON, and artifact staging under [`CircuitVariant::Default`]
//! (`noir-recursive-no-zk` VKs — see `scripts/build-circuits.ts`).
//!
//! Loads compiled JSON for the node-fold **pipeline** ([`CircuitName::C2abFold`] … [`CircuitName::NodeFold`])
//! and stages those artifacts; it does **not** run a full correlated `node_fold` proof — use
//! `node_fold_correlated_e2e_tests.rs` for that.
//!
//! - [`recursive_aggregation_default_artifacts_staged`]: staged `c3_fold` paths (no `bb prove`).
//! - [`recursive_aggregation_c6_fold_kernel_artifacts_staged`]: staged `c6_fold_kernel` paths.
//! - [`c3_fold_sequential_proves_and_verifies`]: two inner `ShareEncryption` proofs → [`generate_sequential_c3_fold`].
//! - [`c6_fold_sequential_proves_and_verifies`]: two inner `ThresholdShareDecryption` proofs → [`generate_sequential_c6_fold`].
//! - [`node_fold_pipeline_compiled_json_load`] / [`node_fold_pipeline_recursive_aggregation_artifacts_staged`]:
//!   pipeline circuits load + staged artifacts for C2ab/C3ab/C4ab/NodeFold.

mod common;
#[path = "common/recursive_vk_substitution.rs"]
mod recursive_vk_substitution;

use std::path::PathBuf;

use common::{
    find_bb, setup_compiled_circuit, setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit, ShareDecryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::{fold_witness_field_strings, load_vk_artifacts};
use e3_zk_prover::{
    generate_sequential_c3_fold, generate_sequential_c6_fold, CircuitVariant, CompiledCircuit,
    Provable, ZkBackend, ZkProver,
};
use recursive_vk_substitution::{assert_fold_rejected, fields, substitute_proof, vk_hash, witness};
use serde_json::json;

fn c3_fold_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json")
}

fn c6_fold_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json")
}

fn recursive_aggregation_compiled_json_path(circuit: CircuitName) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin")
        .join(circuit.dir_path())
        .join("target")
        .join(format!("{}.json", circuit.as_str()))
}

/// `c2ab_fold` → `c3ab_fold` → `c4ab_fold` → inputs to `node_fold` (see `node_fold/src/main.nr`).
const NODE_FOLD_PIPELINE: &[CircuitName] = &[
    CircuitName::C2abFold,
    CircuitName::C3abFold,
    CircuitName::C4abFold,
    CircuitName::NodeFold,
];

/// Reads `C3_SLOTS` from the compiled `c3_fold` ABI (`acc_public_inputs` length is `5 + 3 * C3_SLOTS`).
fn c3_fold_total_slots_from_compiled_json() -> usize {
    let path = c3_fold_json_path();
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
        .expect("c3_fold.json: abi.parameters.acc_public_inputs.length") as usize;
    assert!(
        len >= 5 && (len - 5).is_multiple_of(3),
        "unexpected acc_public_inputs length {} (expected 5 + 3 * slots)",
        len
    );
    (len - 5) / 3
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

#[test]
#[ignore = "requires compiled circuits; run pnpm rust:test:proofs"]
fn c3_fold_compiled_abi_has_consistent_slot_count() {
    if !c3_fold_json_path().exists() {
        panic!(
            "missing required test prerequisite: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            c3_fold_json_path().display()
        );
    }
    let slots = c3_fold_total_slots_from_compiled_json();
    assert!(slots > 0, "C3_SLOTS inferred from ABI should be positive");
    let _ =
        CompiledCircuit::from_file(&c3_fold_json_path()).expect("load compiled c3_fold circuit");
}

#[test]
#[ignore = "requires compiled circuits; run pnpm rust:test:proofs"]
fn c6_fold_compiled_abi_has_consistent_slot_count() {
    if !c6_fold_json_path().exists() {
        panic!(
            "missing required test prerequisite: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            c6_fold_json_path().display()
        );
    }
    let slots = c6_fold_total_slots_from_compiled_json();
    assert!(slots > 0, "C6 slots inferred from ABI should be positive");
    let _ =
        CompiledCircuit::from_file(&c6_fold_json_path()).expect("load compiled c6_fold circuit");
}

#[test]
#[ignore = "requires compiled circuits; run pnpm rust:test:proofs"]
fn node_fold_pipeline_compiled_json_load() {
    let mut missing = Vec::new();
    for &c in NODE_FOLD_PIPELINE {
        let p = recursive_aggregation_compiled_json_path(c);
        if !p.exists() {
            missing.push(p);
        }
    }
    if !missing.is_empty() {
        panic!(
            "missing required test prerequisite: missing compiled JSON(s) (run `pnpm build:circuits --group recursive_aggregation`): {:?}",
            missing
        );
    }
    for &c in NODE_FOLD_PIPELINE {
        let path = recursive_aggregation_compiled_json_path(c);
        let _ = CompiledCircuit::from_file(&path)
            .unwrap_or_else(|e| panic!("load compiled {}: {}", c.as_str(), e));
    }
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn recursive_aggregation_default_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        panic!("missing required test prerequisite: bb not found");
    };
    if !c3_fold_json_path().exists() {
        panic!(
            "missing required test prerequisite: {} not found",
            c3_fold_json_path().display()
        );
    }

    let (backend, temp) = setup_test_prover(&bb).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C3Fold).await;

    let base = backend
        .circuits_dir
        .join("insecure-512")
        .join("minimum")
        .join("default")
        .join(CircuitName::C3Fold.dir_path());
    let pkg = CircuitName::C3Fold.as_str();
    assert!(
        base.join(format!("{pkg}.json")).exists(),
        "expected staged {}.json under default/ variant",
        pkg
    );
    assert!(
        base.join(format!("{pkg}.vk")).exists(),
        "expected staged {}.vk (noir-recursive-no-zk) under default/ variant",
        pkg
    );

    drop(temp);
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn recursive_aggregation_c6_fold_kernel_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        panic!("missing required test prerequisite: bb not found");
    };
    let kernel_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json");
    if !kernel_json.exists() {
        panic!(
            "missing required test prerequisite: {} not found",
            kernel_json.display()
        );
    }

    let (backend, temp) = setup_test_prover(&bb).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C6FoldKernel).await;

    let base = backend
        .circuits_dir
        .join("insecure-512")
        .join("minimum")
        .join("default")
        .join(CircuitName::C6FoldKernel.dir_path());
    let pkg = CircuitName::C6FoldKernel.as_str();
    assert!(
        base.join(format!("{pkg}.json")).exists(),
        "expected staged {}.json under default/ variant",
        pkg
    );
    assert!(
        base.join(format!("{pkg}.vk")).exists(),
        "expected staged {}.vk (noir-recursive-no-zk) under default/ variant",
        pkg
    );

    drop(temp);
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn node_fold_pipeline_recursive_aggregation_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        panic!("missing required test prerequisite: bb not found");
    };
    let gate = recursive_aggregation_compiled_json_path(CircuitName::NodeFold);
    if !gate.exists() {
        panic!(
            "missing required test prerequisite: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            gate.display()
        );
    }

    let (backend, temp) = setup_test_prover(&bb).await;
    for &c in NODE_FOLD_PIPELINE {
        setup_recursive_aggregation_fold_circuit(&backend, c).await;
    }

    let preset_base = backend
        .circuits_dir
        .join("insecure-512")
        .join("minimum")
        .join("default");
    for &c in NODE_FOLD_PIPELINE {
        let base = preset_base.join(c.dir_path());
        let pkg = c.as_str();
        assert!(
            base.join(format!("{pkg}.json")).exists(),
            "expected staged {}.json under default/ variant",
            pkg
        );
        assert!(
            base.join(format!("{pkg}.vk")).exists(),
            "expected staged {}.vk (noir-recursive-no-zk) under default/ variant",
            pkg
        );
    }

    drop(temp);
}

async fn setup_c3_fold_with_inner_share_encryption() -> Option<(
    ZkBackend,
    tempfile::TempDir,
    ZkProver,
    ShareEncryptionCircuit,
    ShareEncryptionCircuitData,
    ShareEncryptionCircuitData,
    BfvPreset,
)> {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    let (backend, temp) = setup_test_prover(&bb).await;

    let sd = BfvPreset::InsecureThreshold512.search_defaults()?;

    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C3Fold).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C3FoldKernel).await;

    let sample_a = ShareEncryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
        sd.z,
    )
    .ok()?;
    let sample_b = ShareEncryptionCircuitData::generate_sample(
        preset,
        committee,
        DkgInputType::SecretKey,
        sd.z,
    )
    .ok()?;
    let prover = ZkProver::new(&backend);

    Some((
        backend,
        temp,
        prover,
        ShareEncryptionCircuit,
        sample_a,
        sample_b,
        preset,
    ))
}

/// Expected C3 fold slot count when circuits are compiled for the minimum committee (N=3, T=1).
const MINIMUM_C3_FOLD_SLOTS: usize = 6;
/// Expected C6 fold slot count when circuits are compiled for the minimum committee (N=3, T=1).
const MINIMUM_C6_FOLD_SLOTS: usize = 2;

fn assert_recursive_vk_binding(
    prover: &ZkProver,
    fold: CircuitName,
    kernel: CircuitName,
    inners: &[Proof],
    folded: &Proof,
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
    let public_name = if fold == CircuitName::C3Fold {
        "c3_public_inputs"
    } else {
        "c6_public_inputs"
    };
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
    input[public_name] = json!(fields(&inners[0]));
    let kernel_witness = witness(&kernel_path, &input).expect("honest genesis witness");
    let genesis = prover
        .generate_recursive_aggregation_bin_proof(
            kernel,
            &kernel_witness,
            "vk-binding-genesis",
            artifacts_dir,
        )
        .expect("honest genesis proof");
    input["acc_proof"] = json!(fold_witness_field_strings(&genesis.data).unwrap());
    input["acc_public_inputs"] = json!(fields(&genesis));
    let first_witness = witness(&fold_path, &input).expect("honest first-step witness");
    let first = prover
        .generate_recursive_aggregation_bin_proof(
            fold,
            &first_witness,
            "vk-binding-first",
            artifacts_dir,
        )
        .expect("honest first-step proof");

    let fake_acc = substitute_proof(
        prover,
        fold,
        CircuitVariant::Default,
        &fields(&first),
        None,
        "predecessor",
    );
    let mut fake_genesis = input.clone();
    fake_genesis["acc_vk"] = json!(fake_acc.vk);
    fake_genesis["acc_proof"] = json!(fold_witness_field_strings(&fake_acc.proof.data).unwrap());
    fake_genesis["acc_public_inputs"] = json!(fields(&fake_acc.proof));
    assert_fold_rejected(
        prover,
        fold,
        &fold_path,
        &fake_genesis,
        artifacts_dir,
        "substituted-genesis",
    );

    input["acc_vk"] = json!(fold_vk.verification_key);
    input["acc_proof"] = json!(fold_witness_field_strings(&first.data).unwrap());
    input["acc_public_inputs"] = json!(fields(&first));
    input["inner_proof"] = json!(fold_witness_field_strings(&inners[1].data).unwrap());
    input[public_name] = json!(fields(&inners[1]));
    input["is_first_step"] = json!(false);
    input["slot_index"] = json!(1);
    witness(&fold_path, &input).expect("honest continuation witness");

    let mut fake_prior = input.clone();
    fake_prior["acc_vk"] = json!(fake_acc.vk);
    fake_prior["acc_proof"] = json!(fold_witness_field_strings(&fake_acc.proof.data).unwrap());
    fake_prior["acc_public_inputs"] = json!(fields(&fake_acc.proof));
    assert_fold_rejected(
        prover,
        fold,
        &fold_path,
        &fake_prior,
        artifacts_dir,
        "substituted-predecessor",
    );

    let fake_leaf = substitute_proof(
        prover,
        inners[1].circuit,
        CircuitVariant::Recursive,
        &fields(&inners[1]),
        None,
        "leaf",
    );
    let mut changed_leaf = input.clone();
    changed_leaf["inner_vk"] = json!(fake_leaf.vk);
    changed_leaf["inner_proof"] = json!(fold_witness_field_strings(&fake_leaf.proof.data).unwrap());
    changed_leaf["inner_key_hash"] = json!(fake_leaf.key_hash);
    assert!(
        witness(&fold_path, &changed_leaf).is_err(),
        "a continuation must retain its predecessor's leaf VK hash"
    );
    for key in ["fold_key_hash", "kernel_key_hash"] {
        let mut changed_key = input.clone();
        changed_key[key] = json!(fake_acc.key_hash);
        assert!(
            witness(&fold_path, &changed_key).is_err(),
            "a continuation must retain its predecessor's {key}"
        );
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
    c7_public.extend(vec!["0".to_owned(); 100]);
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
        step["acc_proof"] = json!(fold_witness_field_strings(&genesis.data).unwrap());
        step["acc_public_inputs"] = json!(fields(&genesis));
        let first_witness = witness(&fold_path, &step).unwrap();
        let first = prover
            .generate_recursive_aggregation_bin_proof(
                CircuitName::C6Fold,
                &first_witness,
                "c6-tree-first",
                artifacts_dir,
            )
            .unwrap();
        step["acc_vk"] = json!(fold_vk.verification_key);
        step["acc_proof"] = json!(fold_witness_field_strings(&first.data).unwrap());
        step["acc_public_inputs"] = json!(fields(&first));
        step["is_first_step"] = json!(false);
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

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_fold_sequential_proves_and_verifies() {
    let Some((_backend, _temp, prover, circuit, sample_a, sample_b, preset)) =
        setup_c3_fold_with_inner_share_encryption().await
    else {
        panic!("missing required test prerequisite: bb not found or prerequisites missing");
    };

    let total_slots = c3_fold_total_slots_from_compiled_json();
    if total_slots != MINIMUM_C3_FOLD_SLOTS {
        panic!(
            "c3_fold_sequential_proves_and_verifies: circuits compiled for \
             non-minimum committee (total_slots={total_slots}, expected {MINIMUM_C3_FOLD_SLOTS}). \
             Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
    }

    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let inner_e3_a = "e3-c3fold-inner-0";
    let inner_e3_b = "e3-c3fold-inner-1";
    let fold_e3 = "e3-c3fold-step";

    let inner_a = circuit
        .prove_with_variant(
            &prover,
            &preset,
            &sample_a,
            inner_e3_a,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("inner ShareEncryption proof 0");
    assert_eq!(inner_a.circuit, CircuitName::ShareEncryption);

    let inner_b = circuit
        .prove_with_variant(
            &prover,
            &preset,
            &sample_b,
            inner_e3_b,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("inner ShareEncryption proof 1");
    assert_eq!(inner_b.circuit, CircuitName::ShareEncryption);

    let inners = [inner_a, inner_b];
    let folded = generate_sequential_c3_fold(
        &prover,
        &inners,
        &[0u32, 1u32],
        total_slots,
        fold_e3,
        &artifacts_dir,
    )
    .expect("c3_fold sequential fold");
    assert_eq!(folded.circuit, CircuitName::C3Fold);
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
    assert!(ok, "c3_fold proof should verify under Default VK layout");
    assert_recursive_vk_binding(
        &prover,
        CircuitName::C3Fold,
        CircuitName::C3FoldKernel,
        &inners,
        &folded,
        &artifacts_dir,
    );

    prover.cleanup(inner_e3_a).unwrap();
    prover.cleanup(inner_e3_b).unwrap();
    prover.cleanup(fold_e3).unwrap();
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
    let preset = BfvPreset::InsecureThreshold512;
    let bb = find_bb().await?;
    let (backend, temp) = setup_test_prover(&bb).await;

    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C6Fold).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::C6FoldKernel).await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::DecryptionAggregator).await;

    let sample_a = ShareDecryptionCircuitData::generate_sample(preset, committee.clone()).ok()?;
    let sample_b = ShareDecryptionCircuitData::generate_sample(preset, committee).ok()?;
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
            &preset,
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
            &preset,
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
        &artifacts_dir,
    );
    assert_final_c6_tree_binding(&prover, &inners[0], &folded, &artifacts_dir);

    prover.cleanup(inner_e3_a).unwrap();
    prover.cleanup(inner_e3_b).unwrap();
    prover.cleanup(fold_e3).unwrap();
}
