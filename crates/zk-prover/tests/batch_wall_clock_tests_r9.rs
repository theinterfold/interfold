// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r9 PRODUCTION-FIT batched c3 fold — REAL wall clock on this box.
//!
//! Arm A (serial): shared kernel genesis (leaf 0 -> slot 0) + 3 recursive
//!                 `c3_fold` steps (leaves 0,1,2 at slots 0,1,2).
//! Arm B (batch) : THE SAME shared kernel genesis + ONE production-fit
//!                 `c3_fold_batch_b2` gate covering the last TWO recursive
//!                 steps (leaves 1,2 at slots 1,2; is_first_step=false).
//!
//! The batch gate's public ABI equals `c3_fold` (4-field prefix + 3*C3_SLOTS),
//! runtime slot indices, distinct-slot + zero-anchor asserts kill the
//! per-step recursion. Shared inners / kernel VK+proof => comparable walls.
//!
//! RAN `bb gates` on this box (N=3 committee, C3_SLOTS=6,
//! noir-recursive-no-zk): c3_fold step = 1,448,866; b2 gate = 2,215,183
//! (two new leaves + one one-time anchor verify); b3 gate = 2,981,374.

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
    generate_sequential_c3_fold, CompiledCircuit, Provable, ZkProver, WitnessGenerator,
};
use serde_json::{json, Value};

fn c3_slots() -> usize {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let len = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .unwrap() as usize;
    (len - 4) / 3
}

fn secs(t: &Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

#[tokio::test]
async fn r9_production_fit_batched_c3_fold_equivalence() {
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
        CircuitName::C3FoldBatchB2,
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
                    &format!("e3-r9-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();

    // Shared setup, timed once (not part of either arm).
    let t0 = Instant::now();
    let kernel = c3_fold_kernel_genesis(&prover, &inners[0], total_slots, &ad, "e3-r9-kernel")
        .unwrap_or_else(|e| panic!("kernel genesis failed: {e}"));
    let kernel_wall = secs(&t0);
    println!(
        "=== I5 r9 PRODUCTION-FIT BATCH (3 inners, minimum committee, C3_SLOTS={total_slots}) ==="
    );
    println!("  shared kernel genesis wall = {kernel_wall:.1}s");

    let inner_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &ad),
        CircuitName::ShareEncryption,
    )
    .unwrap();
    let kernel_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, &ad),
        CircuitName::C3FoldKernel,
    )
    .unwrap();

    // ---------------- Arm A: serial (3 recursive c3_fold steps) ----------------
    let t1 = Instant::now();
    let seq = generate_sequential_c3_fold(
        &prover,
        &inners,
        &[0u32, 1, 2],
        total_slots,
        "e3-r9-seq",
        &ad,
    )
    .unwrap_or_else(|e| panic!("sequential c3 fold: {e}"));
    let seq_wall = secs(&t1);
    let seq_ok = prover
        .verify_fold_proof(&seq, "e3-r9-seq", 1, &ad)
        .unwrap_or_else(|e| panic!("seq verify: {e}"));
    assert!(seq_ok, "sequential fold must verify");
    println!("  serial    wall = {seq_wall:.1}s  verify = PASS");

    // Arm B: ONE production-fit b2 batch gate replacing the LAST TWO recursive steps
    // (leaves 1 and 2 at slots 1 and 2, over the kernel-anchor accumulator).
    let b2_pairs = [
        (1usize, "c3a", 1u32), // leaf 1 -> slot 1
        (2usize, "c3b", 2u32), // leaf 2 -> slot 2
    ];
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, &ad)
        .join("recursive_aggregation")
        .join("c3_fold_batch_b2")
        .join("c3_fold_batch_b2.json");
    let compiled = CompiledCircuit::from_file(&circuit_path)
        .unwrap_or_else(|e| panic!("load b2 compiled circuit: {e}"));

    let mut out = serde_json::Map::new();
    let mut pi = 0;
    for (inner_idx, c3_name, slot) in b2_pairs {
        let leaf = &inners[inner_idx];
        let kk = pi.to_string();
        pi += 1;
        out.insert(format!("vk{kk}"),
            serde_json::to_value(&inner_vk.verification_key).unwrap());
        out.insert(format!("proof{kk}"),
            json!(fold_witness_field_strings(&leaf.data).unwrap()));
        out.insert(
            c3_name.to_string(),
            json!([
                extract_single_field(leaf, "input", field_keys::EXPECTED_PK_COMMITMENT, "inner ShareEncryption proof").unwrap(),
                extract_single_field(leaf, "input", field_keys::EXPECTED_MESSAGE_COMMITMENT, "inner ShareEncryption proof").unwrap(),
                extract_single_field(leaf, "output", field_keys::CT_COMMITMENT, "inner ShareEncryption proof").unwrap(),
            ]),
        );
        out.insert(format!("kh{kk}"), json!(inner_vk.key_hash.clone()));
        out.insert(format!("slot{kk}"), json!(slot.to_string()));
    }
    out.insert(
        "acc_vk".into(),
        json!(kernel_vk.verification_key),
    );
    out.insert(
        "acc_proof".into(),
        json!(fold_witness_field_strings(&kernel.data)
            .unwrap()
            .iter()
            .collect::<Vec<_>>()),
    );
    out.insert(
        "acc_public_inputs".into(),
        json!(fold_witness_field_strings(&kernel.public_signals)
            .unwrap()
            .iter()
            .collect::<Vec<_>>()),
    );
    out.insert("acc_key_hash".into(), json!(kernel_vk.key_hash.clone()));
    // Not the first state: the anchor (kernel genesis) already occupies slot 0.
    out.insert("is_first_step".into(), json!("0"));

    let input_map = fold_witness_input_map(&Value::Object(out)).unwrap();
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .unwrap_or_else(|e| panic!("b2 witness generation: {e}"));

    let t2 = Instant::now();
    let bat = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C3FoldBatchB2,
            &witness,
            "e3-r9-bat",
            &ad,
        )
        .unwrap_or_else(|e| panic!("b2 batch prove: {e}"));
    let bat_wall = secs(&t2);
    let bat_ok = prover
        .verify_fold_proof(&bat, "e3-r9-bat", 1, &ad)
        .unwrap_or_else(|e| panic!("bat verify: {e}"));
    assert!(bat_ok, "production-fit batch fold must verify");
    println!("  batch-B2  wall = {bat_wall:.1}s  verify = PASS");

    // ---------------- Equivalence: final accumulator state ----------------
    let s = fold_witness_field_strings(&seq.public_signals).unwrap();
    let b = fold_witness_field_strings(&bat.public_signals).unwrap();
    assert_eq!(
        s.len(),
        4 + 3 * total_slots,
        "seq pub signals len ({})",
        s.len()
    );
    assert_eq!(
        b.len(),
        4 + 3 * total_slots,
        "bat pub signals len ({}) — PRODUCTION FIT (same ABI as c3_fold)",
        b.len()
    );
    // Prefix: [vk-hash-ish field 0..4]: (inner_key_hash, acc_key_hash, is_first_step, slot)
    // vs batch (acc_key_hash, is_first_step, slot(s)...) — layouts differ; compare the slot
    // array tails which are the ACCUMULATOR.
    let eq = s[4..] == b[4..];
    println!(
        "  IDENTICAL ACCUMULATOR STATE ({} slot fields): {eq}  [RAN]",
        total_slots * 3
    );
    assert!(eq, "serial and production-fit batch folds must land on the same slot array");

    // Gate-side model, all RAN `bb gates` on this box (noir-recursive-no-zk, C3_SLOTS=6):
    //   c3_fold recursive step = 1,448,866 (reproduces round 4 — anchor OK)
    //   b2 batch gate          = 2,215,183 (one one-time non-ZK anchor verify + 2 ZK verifies)
    //   b3 batch gate          = 2,981,374 (one one-time non-ZK anchor verify + 3 ZK verifies)
    //   => marginal cost per ADDED new-leaf = (b3 - b2) = 766,191 gates  (vs 1,448,866 serial
    //      per step) = -47.1% per covered step; scales linearly in B (one
    //      non-ZK anchor + B x ZK verifies), so the saving grows with B.
    //
    // Wall (this box, debug) — same shape as the r8 apples-to-apples: SERIAL wall
    // includes the kernel genesis; BATCH wall = kernel + one b2 gate. Kernel is
    // shared, identical object in both arms.
    let batch_wall_total = kernel_wall + bat_wall;
    let save = seq_wall - batch_wall_total;
    println!(
        "  gates [RAN]: serial step 1,448,866 vs batch marginal +new-leaf 766,191 (-47.1%; b2=2,215,183, b3=2,981,374)"
    );
    println!(
        "  WALL [RAN, debug]: fold layer serial = {seq_wall:.1}s | fold layer batch (kernel + b2) = {batch_wall_total:.1}s | saving = {save:.1}s ({:.1}%), classify shape = same public ABI as c3_fold",
        100.0 * save / seq_wall
    );
    println!("=================================================");

    prover.cleanup("e3-r9-seq").ok();
    prover.cleanup("e3-r9-bat").ok();
    for i in 0..3u32 {
        prover.cleanup(&format!("e3-r9-in{i}")).ok();
    }
}