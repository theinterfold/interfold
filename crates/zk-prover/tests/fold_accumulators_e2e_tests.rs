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

use std::path::PathBuf;

use common::{
    find_bb, setup_compiled_circuit, setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit, ShareDecryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    generate_sequential_c3_fold, generate_sequential_c6_fold, CircuitVariant, CompiledCircuit,
    Provable, ZkBackend, ZkProver,
};

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

/// Reads `C3_SLOTS` from the compiled `c3_fold` ABI (`acc_public_inputs` length is `4 + 3 * C3_SLOTS`).
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
        len >= 4 && (len - 4).is_multiple_of(3),
        "unexpected acc_public_inputs length {} (expected 4 + 3 * slots)",
        len
    );
    (len - 4) / 3
}

/// Reads slot count from the compiled `c6_fold` ABI (`acc_public_inputs` length is `4 + 4 * slots`).
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
        len >= 4 && (len - 4).is_multiple_of(4),
        "unexpected acc_public_inputs length {} (expected 4 + 4 * slots)",
        len
    );
    (len - 4) / 4
}

#[test]
fn c3_fold_compiled_abi_has_consistent_slot_count() {
    if !c3_fold_json_path().exists() {
        println!(
            "skipping: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            c3_fold_json_path().display()
        );
        return;
    }
    let slots = c3_fold_total_slots_from_compiled_json();
    assert!(slots > 0, "C3_SLOTS inferred from ABI should be positive");
    let _ =
        CompiledCircuit::from_file(&c3_fold_json_path()).expect("load compiled c3_fold circuit");
}

#[test]
fn c6_fold_compiled_abi_has_consistent_slot_count() {
    if !c6_fold_json_path().exists() {
        println!(
            "skipping: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            c6_fold_json_path().display()
        );
        return;
    }
    let slots = c6_fold_total_slots_from_compiled_json();
    assert!(slots > 0, "C6 slots inferred from ABI should be positive");
    let _ =
        CompiledCircuit::from_file(&c6_fold_json_path()).expect("load compiled c6_fold circuit");
}

#[test]
fn node_fold_pipeline_compiled_json_load() {
    let mut missing = Vec::new();
    for &c in NODE_FOLD_PIPELINE {
        let p = recursive_aggregation_compiled_json_path(c);
        if !p.exists() {
            missing.push(p);
        }
    }
    if !missing.is_empty() {
        println!(
            "skipping: missing compiled JSON(s) (run `pnpm build:circuits --group recursive_aggregation`): {:?}",
            missing
        );
        return;
    }
    for &c in NODE_FOLD_PIPELINE {
        let path = recursive_aggregation_compiled_json_path(c);
        let _ = CompiledCircuit::from_file(&path)
            .unwrap_or_else(|e| panic!("load compiled {}: {}", c.as_str(), e));
    }
}

#[tokio::test]
async fn recursive_aggregation_default_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    if !c3_fold_json_path().exists() {
        println!("skipping: {} not found", c3_fold_json_path().display());
        return;
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
async fn recursive_aggregation_c6_fold_kernel_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let kernel_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c6_fold_kernel/target/c6_fold_kernel.json");
    if !kernel_json.exists() {
        println!("skipping: {} not found", kernel_json.display());
        return;
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
async fn node_fold_pipeline_recursive_aggregation_artifacts_staged() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let gate = recursive_aggregation_compiled_json_path(CircuitName::NodeFold);
    if !gate.exists() {
        println!(
            "skipping: {} not found (run `pnpm build:circuits --group recursive_aggregation`)",
            gate.display()
        );
        return;
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
const MINIMUM_C3_FOLD_SLOTS: usize = 2;
/// Expected C6 fold slot count when circuits are compiled for the minimum committee (N=3, T=1).
const MINIMUM_C6_FOLD_SLOTS: usize = 2;

#[tokio::test]
async fn c3_fold_sequential_proves_and_verifies() {
    let Some((_backend, _temp, prover, circuit, sample_a, sample_b, preset)) =
        setup_c3_fold_with_inner_share_encryption().await
    else {
        println!("skipping: bb not found or prerequisites missing");
        return;
    };

    let total_slots = c3_fold_total_slots_from_compiled_json();
    if total_slots != MINIMUM_C3_FOLD_SLOTS {
        println!(
            "skipping c3_fold_sequential_proves_and_verifies: circuits compiled for \
             non-minimum committee (total_slots={total_slots}, expected {MINIMUM_C3_FOLD_SLOTS}). \
             Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
        return;
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
async fn c6_fold_sequential_proves_and_verifies() {
    let Some((_backend, _temp, prover, circuit, sample_a, sample_b, preset)) =
        setup_c6_fold_with_inner_threshold_share_decryption().await
    else {
        println!("skipping: bb not found or prerequisites missing");
        return;
    };

    let total_slots = c6_fold_total_slots_from_compiled_json();
    if total_slots != MINIMUM_C6_FOLD_SLOTS {
        println!(
            "skipping c6_fold_sequential_proves_and_verifies: circuits compiled for \
             non-minimum committee (total_slots={total_slots}, expected {MINIMUM_C6_FOLD_SLOTS}). \
             Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
        return;
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

    prover.cleanup(inner_e3_a).unwrap();
    prover.cleanup(inner_e3_b).unwrap();
    prover.cleanup(fold_e3).unwrap();
}
