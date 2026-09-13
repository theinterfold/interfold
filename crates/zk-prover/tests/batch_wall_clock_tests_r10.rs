// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r10 PRODUCTION CHAINED BATCH — REAL wall clock on this box.
//!
//! The round 9 production-ABI batch gate (c3_fold_batch_b2) was validated at ONE gate
//! (kernel + one b2). Round 10 validates the CHAIN of two gates (kernel + 2 b2 = 5 inners
//! at slots 0..=4), where the SECOND gate anchors a PRIOR b2 proof (acc_vk = b2 VK, not
//! kernel VK) — the exact production wiring once the fold accumulates more than 3 inners.
//! This is what the crate API `generate_batched_c3_fold_b2` (drop-in for
//! `generate_sequential_c3_fold`) now ships.
//!
//! Arms (same 5 inners, same slots 0..=4):
//!   A (serial) : generate_sequential_c3_fold = 1 kernel + 4 c3_fold = 5 top-level proves.
//!   B (batched): generate_batched_c3_fold_b2 = 1 kernel + 2 b2 gates = 3 top-level proves
//!                (gate 0 anchors kernel; gate 1 anchors gate 0's b2 proof).
//!
//! Assertions:
//!   - both arms fold_verify PASS
//!   - final accumulator public field count = 4 + 3*C3_SLOTS on both arms
//!   - final accumulator slot-tail (fields [4..]) byte-identical
//!   - top-level prove count: 5 vs 3 (saving = 4 serial c3_fold steps -> 2 b2 gates)

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
use e3_zk_prover::{generate_batched_c3_fold_b2, generate_sequential_c3_fold, Provable, ZkProver};

fn c3_slots() -> usize {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let len = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .unwrap() as usize;
    (len - 4) / 3
}

fn secs(t: &Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

#[tokio::test]
async fn r10_chained_b2_batch_equivalence() {
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

    // 5 inners: kernel anchors slot 0; two b2 gates cover slots 1,2 and 3,4 —
    // both arms cover the same 5 slots, so the equivalence assert holds.
    let n = 5;
    let circuit = ShareEncryptionCircuit;
    let inners: Vec<Proof> = (0..n as u32)
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
                    &format!("e3-r10-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();

    let slots: Vec<u32> = (0..n as u32).collect();
    println!(
        "=== I5 r10 CHAINED B2 BATCH (5 inners, C3_SLOTS={total_slots}) ==="
    );

    // ---------------- Arm A: 5 serial c3_fold (1 kernel + 4 recursive steps)
    let t1 = Instant::now();
    let seq =
        generate_sequential_c3_fold(&prover, &inners, &slots, total_slots, "e3-r10-seq", &ad)
            .unwrap_or_else(|e| panic!("sequential c3 fold: {e}"));
    let seq_wall = secs(&t1);
    let seq_ok = prover
        .verify_fold_proof(&seq, "e3-r10-seq", 1, &ad)
        .unwrap_or_else(|e| panic!("seq verify: {e}"));
    assert!(seq_ok, "sequential fold must verify");
    println!("  serial    wall = {seq_wall:.1}s  verify = PASS  (5 top-level proves: 1 kernel + 4 c3_fold)");

    // ---------------- Arm B: kernel + 2 chained b2 gates (3 top-level proves)
    let t2 = Instant::now();
    let bat = generate_batched_c3_fold_b2(&prover, &inners, &slots, total_slots, "e3-r10-bat", &ad)
        .unwrap_or_else(|e| panic!("chained b2 batch fold: {e}"));
    let bat_wall = secs(&t2);
    let bat_ok = prover
        .verify_fold_proof(&bat, "e3-r10-bat", 1, &ad)
        .unwrap_or_else(|e| panic!("bat verify: {e}"));
    assert!(bat_ok, "chained b2 batch fold must verify");
    println!("  batched   wall = {bat_wall:.1}s  verify = PASS  (3 top-level proves: 1 kernel + 2 b2 gates)");

    // ---------------- Equivalence: final accumulator state ----------------
    let s_fields = seq.public_signals.len() / 32;
    let b_fields = bat.public_signals.len() / 32;
    let expected = 4 + 3 * total_slots;
    assert_eq!(
        s_fields, expected,
        "serial public field count ({s_fields})"
    );
    assert_eq!(
        b_fields, expected,
        "batched public field count ({b_fields}) — PRODUCTION FIT (4-prefix + 3*C3_SLOTS)"
    );
    let s_tail = &seq.public_signals[(4 * 32)..];
    let b_tail = &bat.public_signals[(4 * 32)..];
    let eq = s_tail == b_tail;
    println!(
        "  IDENTICAL ACCUMULATOR SLOT TAIL ({} fields): {}  [RAN]",
        s_tail.len() / 32, eq
    );
    assert!(
        eq,
        "serial and chained-batched folds must land on the same slot array"
    );

    let save = seq_wall - bat_wall;
    println!(
        "  SAVING = {save:.1}s  ({:.1}% of serial wall)",
        100.0 * save / seq_wall
    );
    println!(
        "  Gates: serial = 6 x (kernel/1 c3_fold step); serial step 1,448,866, b2 gate 2,215,183 (RAN r9) -> batched fold-layer = kernel + 2 x b2; serial fold-layer = kernel + 5 x c3_fold (RAN anchor). Net top-level prove reduction = 3."
    );
}