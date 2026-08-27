// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5 r59 — I5a N=19 tree-split, item (c): the b6 leg on the r52 harness —
//! ONE `bb prove` on the 5,281,808-gate b6 circuit (kernel + 1×b6 = 2 top-level
//! proves) vs the 7 top-level serial fold, byte-identical slot tail (n=7).
//!
//! Same contract as the r52 harness: micro (N=9/T=4/H=5) circuit set (leaves AND
//! folds), C3_SLOTS=18, insecure-512. Staging set: dkg/share_encryption (micro ZK
//! VK) + c3_fold/c3_fold_kernel/c3_fold_batch_b3/c3_fold_batch_b6 (micro VKs). The
//! r59 staging rebuilt c3_fold_kernel + the dkg leaf under micro (r55's secure/small
//! stage had overwritten them).
//!
//! Arms (7 inners, slots 0..=6):
//!   A (serial): generate_sequential_c3_fold = 1 kernel + 6 c3_fold steps.
//!   B (b6):     generate_batched_c3_fold_b6 = 1 kernel + 1 b6 gate.
//! Assertions: both verify (fold_verify PASS), both land on 4+3*18=58 public fields,
//! the slot tails (fields [4..58)) are byte-identical, saving% is printed.

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
    generate_batched_c3_fold_b6, generate_sequential_c3_fold, Provable, ZkProver,
};

const COMMITTEE: &str = "micro"; // staged committee — must match circuits/bin build config
const N_INNERS: u32 = 7; // b6 = 6 fresh slots, anchored after the kernel slot

async fn stage_circuit(
    backend: &e3_zk_prover::ZkBackend,
    group: &str,
    circuit: &str,
    variant_dir: &str,
) {
    // dkg-group circuits share the group-level target dir (circuits/bin/dkg/target/<name>.json);
    // recursive_aggregation circuits have a per-package target dir.
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
    // Recursive-variant staging source: prefer the ZK VK (.vk_noir — leaf circuits are proven
    // as noir-recursive ZK), fall back to .vk_recursive (fold circuits emit no-zk only).
    // bb write_vk writes either a file or a dir {vk, vk_hash}; both layouts handled.
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
    assert!(json.exists(), "missing {json:?} — run the r52 micro build first");
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
async fn r59_b6_prove_and_equivalence() {
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
        "this test requires the MICRO committee (C3_SLOTS=18); got {total_slots} — did the r52 micro build run?"
    );

    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let (backend, _temp) = setup_test_prover(&bb).await;

    // Stage: recursive leaf VK (minimum-std artifact, witness-fed by the fold circuits)
    // + default-variant fold circuits (micro-committee 18-slot artifacts).
    stage_circuit(
        &backend,
        "dkg",
        "share_encryption",
        "recursive",
    )
    .await;
    for c in [
        "c3_fold",
        "c3_fold_kernel",
        "c3_fold_batch_b3",
        "c3_fold_batch_b6",
    ] {
        stage_circuit(&backend, "recursive_aggregation", c, "default").await;
    }

    let preset = BfvPreset::InsecureThreshold512;
    let committee = CiphernodesCommitteeSize::Micro.values();
    let sd = preset.search_defaults().unwrap();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);

    // 7 shared real FHE inner proofs (insecure-512, minimum std — committee-consistent).
    let circuit = ShareEncryptionCircuit;
    let t_inners = Instant::now();
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
                    &format!("e3-r59-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();
    let inners_done = secs(&t_inners);

    let slots: Vec<u32> = (0..N_INNERS).collect();
    let skip_serial = std::env::var("E3_R59_SKIP_SERIAL").map(|v| v == "1").unwrap_or(false);
    println!("=== I5 r59 b6 PROVE + EQUIVALENCE (n=7, C3_SLOTS={total_slots}, micro) ===");

    // ---------------- Arm A: 7 serial c3_fold (1 kernel + 6 recursive steps)
    let t1 = Instant::now();
    let seq = if skip_serial {
        println!("  serial arm SKIPPED (E3_R59_SKIP_SERIAL=1) for an isolated b6 measure");
        None
    } else {
        Some(
            generate_sequential_c3_fold(
                &prover,
                &inners,
                &slots,
                total_slots,
                "e3-r59-seq",
                &ad,
            )
            .unwrap_or_else(|e| panic!("sequential c3 fold: {e}")),
        )
    };
    let seq_wall = secs(&t1);
    if !skip_serial {
        println!(
            "  serial    fold wall = {seq_wall:.1}s  (7 top-level proves: 1 kernel + 6 c3_fold; verify in equivalence)  RAN"
        );
    }

    // ---------------- Arm B: kernel + 1 b6 gate (2 top-level proves — the 5.28M-gate one)
    let t2 = Instant::now();
    let bat = generate_batched_c3_fold_b6(
        &prover,
        &inners,
        &slots,
        total_slots,
        "e3-r59-b6",
        &ad,
    )
    .unwrap_or_else(|e| panic!("b6 batch fold: {e}"));
    let bat_wall = secs(&t2);
    let bat_ok = prover
        .verify_fold_proof(&bat, "e3-r59-b6", 1, &ad)
        .unwrap_or_else(|e| panic!("bat verify: {e}"));
    assert!(bat_ok, "b6 batch fold must verify");
    println!(
        "  b6 batch wall = {bat_wall:.1}s  verify = PASS  (2 top-level proves: 1 kernel + 1 b6 gate)  RAN"
    );

    // ---------------- Equivalence: final accumulator state (serial-vs-b6 tail) or solo count
    let expected = 4 + 3 * total_slots;
    let b_fields = bat.public_signals.len() / 32;
    assert_eq!(
        b_fields, expected,
        "b6 public field count ({b_fields}) — PRODUCTION FIT (4-prefix + 3*18)"
    );
    if skip_serial {
        println!(
            "  solo b6: 2 top-level proves, verify PASS, {} public fields  [RAN]",
            b_fields
        );
    } else {
        let seq = seq.unwrap();
        let seq_ok =
            prover.verify_fold_proof(&seq, "e3-r59-seq", 1, &ad).unwrap_or_else(|e| panic!("seq verify: {e}"));
        assert!(seq_ok, "sequential fold must verify");
        println!(
            "  serial    wall = {seq_wall:.1}s  verify = PASS  (7 top-level proves: 1 kernel + 6 c3_fold)  RAN"
        );
        let s_fields = seq.public_signals.len() / 32;
        assert_eq!(s_fields, expected, "serial public field count ({s_fields})");
        let s_tail = &seq.public_signals[(4 * 32)..];
        let b_tail = &bat.public_signals[(4 * 32)..];
        let eq = s_tail == b_tail;
        println!(
            "  IDENTICAL ACCUMULATOR SLOT TAIL ({} fields): {}  [RAN]",
            s_tail.len() / 32,
            eq
        );
        assert!(eq, "serial and b6-batched folds must land on the same slot array");

        let save = seq_wall - bat_wall;
        println!(
            "  SAVING = {save:.1}s  ({:.1}% of serial fold-layer wall)  [RAN]",
            100.0 * save / seq_wall
        );
    }
    println!(
        "  inner-proof gen (shared, 7x recursive share_encryption): {inners_done:.1}s  RAN"
    );
    println!(
        "  Gates (RAN r51/r52, micro n=7 anchors): c3_fold 1,450,307; b6 5,281,808. Fold layer n=7: serial 1 kernel + 6x1,450,307 vs kernel + 1x5,281,808."
    );
}