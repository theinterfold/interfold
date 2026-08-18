// SPDX-License-Identifier: LGPL-3.0-only
//
// I5 r44 REAL wall clock: serial c3 fold vs batched c3 fold, 3 shared inner
// ShareEncryption ZK proofs, insecure-512, minimum committee (C3_SLOTS=6), bb v5.1.0.
//
// Serial arm: kernel genesis + 3 c3_fold step proves (first step proves the kernel).
// Batch arm : the SAME kernel genesis + 1 c3_fold_batch_n3 prove (2 leaves over the
//             kernel-anchor accumulator, slots 1 and 2; anchor occupies slot 0).
// Both arms must verify AND land on the identical accumulator state (byte equality of
// the 18-field slot tail). Shared inners are timed once and reported as shared setup.

mod common;
use std::path::PathBuf;
use std::time::Instant;
use common::{
    find_bb, setup_compiled_circuit, setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{
    ShareEncryptionCircuit, ShareEncryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::{
    c3_fold_kernel_genesis, extract_single_field, field_keys, fold_witness_field_strings,
    fold_witness_input_map, load_vk_artifacts,
};
use e3_zk_prover::{
    generate_batched_c3_fold, generate_sequential_c3_fold, CompiledCircuit, Provable, ZkProver,
    WitnessGenerator,
};
use serde_json::{json, Value};

/// C3_SLOTS from the compiled c3_fold ABI (acc_public_inputs = 4 + 3 * slots).
fn c3_slots() -> usize {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let len = v["abi"]["parameters"].as_array().unwrap().iter().find(|p| {
        p.get("name") == Some(&Value::String("acc_public_inputs".into()))
    }).and_then(|p| p.get("type")?.get("length")?.as_u64()).unwrap() as usize;
    (len - 4) / 3
}

fn secs(t: &Instant) -> f64 {
    t.elapsed().as_secs_f64()
}
// Round 8 - PRODUCTION DROP-IN: crate API generate_batched_c3_fold must be a true
// replacement for generate_sequential_c3_fold (same inners/slots -> same state).

#[tokio::test]
async fn batched_c3_fold_dropin_equivalence() {
    let total_slots = c3_slots();
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let (backend, _temp) = setup_test_prover(&bb).await;
    let preset = BfvPreset::InsecureThreshold512;
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let sd = preset.search_defaults().unwrap();
    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee("minimum");
    for c in [
        CircuitName::C3Fold,
        CircuitName::C3FoldKernel,
        CircuitName::C3FoldBatchN3,
    ] {
        setup_recursive_aggregation_fold_circuit(&backend, c).await;
    }
    let circuit = ShareEncryptionCircuit;
    let inners: Vec<Proof> = (0..3u32)
        .map(|i| {
            let sample = ShareEncryptionCircuitData::generate_sample(
                preset.clone(),
                committee.clone(),
                DkgInputType::SecretKey,
                sd.z,
            )
            .unwrap_or_else(|_| panic!("no sample for inner {i}"));
            circuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &sample,
                    &format!("e3-r8-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();

    println!("=== I5 r8 DROP-IN EQUIVALENCE (crate APIs, 3 inners) ===");
    let t0 = Instant::now();
    let seq = generate_sequential_c3_fold(
        &prover,
        &inners,
        &[0u32, 1, 2],
        total_slots,
        "e3-r8-seq",
        &ad,
    )
    .unwrap_or_else(|e| panic!("sequential c3 fold: {e}"));
    let seq_wall = secs(&t0);
    let seq_ok = prover
        .verify_fold_proof(&seq, "e3-r8-seq", 1, &ad)
        .unwrap_or_else(|e| panic!("seq verify: {e}"));
    assert!(seq_ok, "sequential fold must verify");
    println!("  generate_sequential_c3_fold  wall = {seq_wall:.1}s  verify = PASS");

    let t1 = Instant::now();
    let bat = generate_batched_c3_fold(
        &prover,
        &inners,
        total_slots,
        "e3-r8-bat",
        &ad,
    )
    .unwrap_or_else(|e| panic!("batched c3 fold: {e}"));
    let bat_wall = secs(&t1);
    let bat_ok = prover
        .verify_fold_proof(&bat, "e3-r8-bat", 1, &ad)
        .unwrap_or_else(|e| panic!("bat verify: {e}"));
    assert!(bat_ok, "batched fold must verify");
    println!("  generate_batched_c3_fold     wall = {bat_wall:.1}s  verify = PASS");

    let s = fold_witness_field_strings(&seq.public_signals).unwrap();
    let b = fold_witness_field_strings(&bat.public_signals).unwrap();
    assert_eq!(s.len(), 4 + 3 * total_slots, "seq pub signals len ({})", s.len());
    assert_eq!(b.len(), 5 + 3 * total_slots, "bat pub signals len ({})", b.len());
    let eq = s[4..] == b[5..];
    println!("  IDENTICAL ACCUMULATOR STATE ({} slot fields): {}", total_slots * 3, eq);
    assert!(eq, "sequential and batched folds must be byte-identical");
    println!("=================================================");
    prover.cleanup("e3-r8-seq").ok();
    prover.cleanup("e3-r8-bat").ok();
prover.cleanup("e3-r8-bat-kernel").ok();
    for i in 0..3u32 {
        prover.cleanup(&format!("e3-r8-in{i}")).ok();
    }
}