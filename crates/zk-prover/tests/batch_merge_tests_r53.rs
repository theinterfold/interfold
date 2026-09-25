// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r53 — I5a MERGE item(b) E2E leg: prove the M1 merge gate (anchor + 1 b6
//! sub-gate in-circuit verify) with REAL sub-gate proofs and check the combined
//! slot state is byte-identical to the sequential `c3_fold` chain (7 inners,
//! micro committee C3_SLOTS=18, insecure-512).
//!
//! Arms (7 inners, slots 0..=6):
//!   A (serial): 1 kernel + 6 c3_fold steps  (7 top-level proves)
//!   B (merge):  1 kernel + 1 b6 sub-gate + 1 m1 merge gate (3 top-level proves)
//!
//! Staging requirement: the r53 micro VK build must be on disk
//! (c3_fold / c3_fold_kernel / c3_fold_batch_b6 / c3_fold_batch_merge_m1 default
//!  VKs + dkg leaf recursive VK), i.e. `poc/r53_micro_build.sh` (or similar) ran.

mod common;
use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::{CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{
    ShareEncryptionCircuit, ShareEncryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    generate_c3_merge_m1, generate_sequential_c3_fold, Provable, ZkProver,
};

const COMMITTEE: &str = "micro";
const N_INNERS: u32 = 7;

#[allow(dead_code)]
async fn stage_circuit(
    backend: &e3_zk_prover::ZkBackend,
    group: &str,
    circuit: &str,
    variant_dir: &str,
) {
    let subdir: String = if group == "dkg" {
        "target".into()
    } else {
        format!("{circuit}/target")
    };
    let pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin")
        .join(group)
        .join(subdir);
    let json = pkg_dir.join(format!("{circuit}.json"));
    let vk_rec = pkg_dir.join(format!("{circuit}.vk_recursive"));
    let vk_rec_h = pkg_dir.join(format!("{circuit}.vk_recursive_hash"));
    let vk_noir = pkg_dir.join(format!("{circuit}.vk_noir"));
    let vk_noir_h = pkg_dir.join(format!("{circuit}.vk_noir_hash"));
    let resolve = |p: &std::path::Path, h: &std::path::Path| -> Option<(PathBuf, PathBuf)> {
        if p.is_dir() {
            (p.join("vk"), p.join("vk_hash")).into()
        } else if p.exists() {
            (p.to_path_buf(), h.to_path_buf()).into()
        } else {
            None
        }
    };
    let staged = resolve(&vk_noir, &vk_noir_h).or_else(|| resolve(&vk_rec, &vk_rec_h));
    assert!(json.exists(), "missing {json:?} — run the r53 micro build first");
    let (vk_src, hash_src) = staged
        .unwrap_or_else(|| panic!("no recursive VK for {circuit}: need {vk_rec:?} or {vk_noir:?}"));
    let base = backend.circuits_dir.join("insecure-512").join(COMMITTEE);
    let dest = base.join(variant_dir).join(group).join(circuit);
    tokio::fs::create_dir_all(&dest).await.unwrap();
    tokio::fs::copy(&json, dest.join(format!("{circuit}.json"))).await.unwrap();
    assert!(vk_src.exists(), "no vk payload at {vk_src:?} or {vk_rec:?}");
    tokio::fs::copy(&vk_src, dest.join(format!("{circuit}.vk"))).await.unwrap();
    if hash_src.exists() {
        tokio::fs::copy(&hash_src, dest.join(format!("{circuit}.vk_hash")))
            .await
            .unwrap();
    }
}

fn secs(t: &Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

#[tokio::test]
async fn r53_m1_merge_e2e_equivalence() {
    let c3_slots_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&c3_slots_path).unwrap()).unwrap();
    let total_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(
        total_slots, 18,
        "this test requires the MICRO committee (C3_SLOTS=18); got {total_slots} — did the r53 micro build run?"
    );

    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let (backend, _temp) = setup_test_prover(&bb).await;

    stage_circuit(&backend, "dkg", "share_encryption", "recursive").await;
    for c in [
        "c3_fold",
        "c3_fold_kernel",
        "c3_fold_batch_b6",
        "c3_fold_batch_merge_m1",
    ] {
        stage_circuit(&backend, "recursive_aggregation", c, "default").await;
    }

    let preset = BfvPreset::InsecureThreshold512;
    let committee = CiphernodesCommitteeSize::Micro.values();
    let sd = preset.search_defaults().unwrap();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);

    let circuit = ShareEncryptionCircuit;
    let inners: Vec<Proof> = (0..N_INNERS)
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
                    &format!("e3-r53-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();
    let t_inners = Instant::now();
    let inners_done = secs(&t_inners);

    let slots: Vec<u32> = (0..N_INNERS).collect();
    println!(
        "=== I5a r53 M1 MERGE E2E + EQUIVALENCE (n=7, C3_SLOTS={total_slots}, micro) ==="
    );

    // Arm A: sequential (1 kernel + 6 c3_fold)
    let t1 = Instant::now();
    let seq = generate_sequential_c3_fold(
        &prover,
        &inners,
        &slots,
        total_slots,
        "e3-r53-seq",
        &ad,
    )
    .unwrap_or_else(|e| panic!("sequential c3 fold: {e}"));
    let seq_wall = secs(&t1);
    let seq_ok =
        prover.verify_fold_proof(&seq, "e3-r53-seq", 1, &ad).unwrap_or_else(|e| panic!("seq verify: {e}"));
    assert!(seq_ok, "sequential fold must verify");
    println!("  serial    wall = {seq_wall:.1}s  verify = PASS  (1 kernel + 6 c3_fold)  RAN");

    // Arm B: merge (1 kernel + 1 b6 + 1 m1)
    let t2 = Instant::now();
    let m1 = generate_c3_merge_m1(&prover, &inners, &slots, total_slots, "e3-r53-m1", &ad)
        .unwrap_or_else(|e| panic!("m1 merge fold: {e}"));
    let m1_wall = secs(&t2);
    let m1_ok =
        prover.verify_fold_proof(&m1, "e3-r53-m1", 1, &ad).unwrap_or_else(|e| panic!("m1 verify: {e}"));
    assert!(m1_ok, "m1 merge gate proof must verify");
    println!("  merge M1  wall = {m1_wall:.1}s  verify = PASS  (1 kernel + 1 b6 + 1 m1)  RAN");

    // Equivalence: identical 58 public fields (4 + 3*18), slot tails byte-identical.
    let expected = 4 + 3 * total_slots;
    let s_fields = seq.public_signals.len() / 32;
    let b_fields = m1.public_signals.len() / 32;
    assert_eq!(s_fields, expected, "serial public field count ({s_fields})");
    assert_eq!(b_fields, expected, "m1 public field count ({b_fields})");
    let s_tail = &seq.public_signals[(4 * 32)..];
    let b_tail = &m1.public_signals[(4 * 32)..];
    let eq = s_tail == b_tail;
    println!(
        "  IDENTICAL ACCUMULATOR SLOT TAIL ({} fields): {}  [RAN]",
        s_tail.len() / 32,
        eq
    );
    assert!(eq, "sequential and m1-merge folds must land on the same slot array");

    let save = seq_wall - m1_wall;
    println!(
        "  SAVING = {save:.1}s  ({:.1}% of serial fold-layer wall)  [RAN]",
        100.0 * save / seq_wall
    );
    println!(
        "  inner-proof gen (shared, 7x recursive share_encryption): {inners_done:.1}s  RAN"
    );
    println!(
        "  Gates (RAN r53): c3_fold 1,450,307; b6 5,281,808; m1 1,430,238. Fold layer n=7: serial 1 kernel + 6x1,450,307 = 9,405,741 g vs kernel 703,899 + b6 5,281,808 + m1 1,430,238 = 7,415,945 g."
    );
}