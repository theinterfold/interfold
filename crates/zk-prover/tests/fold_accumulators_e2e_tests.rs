// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Fold **accumulators** integration tests: sequential [`generate_sequential_c3_fold`] /
//! [`generate_sequential_c6_fold`] (prove + [`ZkProver::verify_fold_proof`]) with the slot count read
//! from the compiled `c3_fold` / `c6_fold` ABI and artifacts staged under [`CircuitVariant::Default`]
//! (`noir-recursive-no-zk` VKs — see `scripts/build-circuits.ts`).
//!
//! The node-fold pipeline ([`CircuitName::C2abFold`] … [`CircuitName::NodeFold`]) is proven in
//! `node_fold_correlated_e2e_tests.rs`.
//!
//! - [`c3_fold_sequential_proves_and_verifies`]: two inner `ShareEncryption` proofs → [`generate_sequential_c3_fold`].
//! - [`c6_fold_sequential_proves_and_verifies`]: two inner `ThresholdShareDecryption` proofs → [`generate_sequential_c6_fold`].

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
    generate_sequential_c3_fold, generate_sequential_c6_fold, CircuitVariant, Provable, ZkBackend,
    ZkProver,
};

fn c3_fold_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json")
}

fn c6_fold_json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c6_fold/target/c6_fold.json")
}

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

/// Reads slot count from the compiled `c6_fold` ABI
/// (`acc_public_inputs` length is `6 + 4 * slots`: four fold params plus two domain limbs).
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
        len >= 6 && (len - 6).is_multiple_of(4),
        "unexpected acc_public_inputs length {} (expected 6 + 4 * slots)",
        len
    );
    (len - 6) / 4
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

    prover.cleanup(inner_e3_a).unwrap();
    prover.cleanup(inner_e3_b).unwrap();
    prover.cleanup(fold_e3).unwrap();
}
