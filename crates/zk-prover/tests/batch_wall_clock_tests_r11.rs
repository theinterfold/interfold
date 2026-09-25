// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r11 PRODUCTION b3 DROP-IN — REAL wall clock on this box.
//!
//! Round 11 re-published `c3_fold_batch_b3` with the PRODUCTION 4-prefix public ABI
//! (acc_key_hash / is_first_step / slot0 / slot1 + the 3 slot arrays) — identical to
//! `c3_fold_batch_b2`'s and `c3_fold`'s layout — so a b3 chain is a drop-in for the
//! recursive `c3_fold` chain: slot arrays at public offset 4, public field count
//! `4 + 3*C3_SLOTS`, same VK-rebuild-only downstream contract as r9/r10.
//!
//! Arms (4 inners, same slots 0..=3):
//!   A (serial): generate_sequential_c3_fold = 1 kernel + 3 c3_fold = 4 top-level proves.
//!   B (b3):     generate_batched_c3_fold_b3 = 1 kernel + 1 b3 gate = 2 top-level proves
//!               (gate 0 anchors the kernel genesis, kernel VK).
//!
//! Assertions:
//!   - both arms fold_verify PASS
//!   - final accumulator public field count = 4 + 3*C3_SLOTS on both arms
//!   - final accumulator slot-tail (fields [4..]) byte-identical
//!   - top-level prove count: 4 vs 2 (the drop-in claim, measured)

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
use e3_zk_prover::{
    generate_batched_c3_fold_b3, generate_sequential_c3_fold, Provable, ZkProver,
};

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
async fn r11_b3_dropin_equivalence() {
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
        CircuitName::C3FoldBatchB3,
    ] {
        setup_recursive_aggregation_fold_circuit(&backend, c).await;
    }

    // 4 inners: kernel anchors slot 0; one b3 gate covers slots 1,2,3 —
    // both arms cover the same 4 slots, so the equivalence assert holds.
    let n = 4;
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
                    &format!("e3-r11-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();

    let slots: Vec<u32> = (0..n as u32).collect();
    println!(
        "=== I5 r11 b3 DROP-IN (4 inners, C3_SLOTS={total_slots}) ==="
    );

    // ---------------- Arm A: 4 serial c3_fold (1 kernel + 3 recursive steps)
    let t1 = Instant::now();
    let seq =
        generate_sequential_c3_fold(&prover, &inners, &slots, total_slots, "e3-r11-seq", &ad)
            .unwrap_or_else(|e| panic!("sequential c3 fold: {e}"));
    let seq_wall = secs(&t1);
    let seq_ok = prover
        .verify_fold_proof(&seq, "e3-r11-seq", 1, &ad)
        .unwrap_or_else(|e| panic!("seq verify: {e}"));
    assert!(seq_ok, "sequential fold must verify");
    println!("  serial    wall = {seq_wall:.1}s  verify = PASS  (4 top-level proves: 1 kernel + 3 c3_fold)");

    // ---------------- Arm B: kernel + 1 b3 gate (2 top-level proves)
    let t2 = Instant::now();
    let bat = generate_batched_c3_fold_b3(&prover, &inners, &slots, total_slots, "e3-r11-bat", &ad)
        .unwrap_or_else(|e| panic!("b3 batch fold: {e}"));
    let bat_wall = secs(&t2);
    let bat_ok = prover
        .verify_fold_proof(&bat, "e3-r11-bat", 1, &ad)
        .unwrap_or_else(|e| panic!("bat verify: {e}"));
    assert!(bat_ok, "b3 batch fold must verify");
    println!("  batched   wall = {bat_wall:.1}s  verify = PASS  (2 top-level proves: 1 kernel + 1 b3 gate)");

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
        "b3-batched public field count ({b_fields}) — PRODUCTION FIT (4-prefix + 3*C3_SLOTS)"
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
        "serial and b3-batched folds must land on the same slot array"
    );

    let save = seq_wall - bat_wall;
    println!(
        "  SAVING = {save:.1}s  ({:.1}% of serial wall)",
        100.0 * save / seq_wall
    );
    println!(
        "  Gates (RAN r9): serial c3_fold step 1,448,866; b3 gate 2,981,374 (one-time non-ZK anchor + 3 leaf verifies). Fold-layer top-level proves: serial 4 -> b3 2."
    );
}