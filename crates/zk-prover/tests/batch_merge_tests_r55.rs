// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a r55 — MERGE item (b2): PRODUCTION-shape M7 merge PROVE on real 54 inners
//! (N=19, secure-8192/small, C3_SLOTS = 19*3 = 57; M7 circuit requires C3_SLOTS >= 55).
//!
//! The production C3b tree split, ONE merge, proven end-to-end:
//!   56 recursive share_encryption inner proofs (secure-8192/small):
//!     inner 0       -> anchors slot 0 via the kernel genesis
//!     inners 1..=54 -> C3b chain rows 1..=54 (5 x B10 blocks + 2 x B2 blocks)
//!   MERGE arm (9 top-level proves inside generate_c3_merge_m7):
//!     1 kernel + 5 x b10 sub-gate (rows 1-10, 11-20, ..., 41-50)
//!     + 2 x b2 sub-gate (rows 51-52, 53-54)
//!     + 1 x c3_fold_batch_merge_m7 (in-circuit-verifies all 7 sub-gate proofs + the
//!       genesis; folds rows 1..=54 from the sub-gate publics; rows 0, 55, 56 pass
//!       through from the genesis).
//!
//! Equivalence check (SELF-CONTAINED — no 54-step serial arm, which is hours of secure
//! c3_fold proves; r53 already proved serial-vs-merge slot-tail byte-identicality at the
//! 7-inner/micro design level): rebuild each sub-gate proof INDEPENDENTLY via the public
//! `generate_batched_c3_fold_b10` / `generate_batched_c3_fold_b2` APIs (each makes its own
//! kernel genesis over the SAME anchor inner => same genesis, deterministic) and assert the
//! M7 fold tail is byte-identical to:
//!     tail[s] == sub_j.tail[s]   for s in block j's covered rows (sub j = the b10/b2 gate
//!                                whose covered RANGE contains s)
//!     tail[0]    == sub_0.tail[0]  (kernel genesis pass-through, rows 55/56 == zero by
//!                                   the genesis-only-owns-row-0 + merge zero-assert)
//! Any wrong-slot fold, dropped row, duplicate, or overwrite fails the assert.
//!
//! STAGING (run first — `poc/r55_stage.sh`, secure-8192/small):
//!   the secure-8192/small stage build stages share_encryption (recursive) +
//!   c3_fold_kernel / c3_fold_batch_b10 / c3_fold_batch_b2 / c3_fold_batch_merge_m7
//!   (default group) under backend circuits_dir/secure-8192/small/. The M7 json+VK are
//!   the in-repo r53 artifact (circuits/bin/recursive_aggregation/c3_fold_batch_merge_m7/
//!   target). `cargo test --no-run` compiles this file regardless; the RUN needs staging
//!   + the 56 secure inners (asserts below point at the missing stage otherwise).
//!
//! Run:
//!   cargo test --release -p e3-zk-prover --test batch_merge_tests_r55 -- --nocapture
//!   (quiet box, RELEASE profile — 56 secure inner proves are the dominant cost class)

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
    generate_batched_c3_fold_b10, generate_batched_c3_fold_b2, generate_c3_merge_m7, Provable,
    ZkProver,
};

const COMMITTEE: &str = "small";
const N_INNERS: u32 = 56; // anchor + 54 covered
const COVER_START: usize = 1;
const N_COVERED: usize = 54;
const BYTES_PER_FIELD: usize = 32;

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
    assert!(
        json.exists(),
        "missing {json:?} — run poc/r55_stage.sh first (secure-8192/small stage build)"
    );
    let (vk_src, hash_src) = staged.unwrap_or_else(|| {
        panic!("no recursive VK for {circuit}: need {vk_rec:?} or {vk_noir:?} (r55_stage.sh)")
    });
    let base = backend.circuits_dir.join("secure-8192").join(COMMITTEE);
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

/// Tail field `s` (3 x 32-byte: pk, msg, ct at row `s`) of a c3_fold-layout
/// proof's public signals.
///
/// RAN r58b layout probe (batch_merge_diag / r58b): the flat public tail is the
/// THREE CONTIGUOUS arrays `[pk[0..S]][msg[0..S]][ct[0..S]]` (nonzero field set
/// `{4,5,6, 61,62,63, 118,119,120}` at S=57), NOT row-interleaved. The old
/// stride-3 96-byte window read `pk[s..s+3]` across block boundaries — the r57
/// leg's byte-identity "failure" rows were this oracle, not a fold defect.
fn tail_field(proof: &Proof, s: usize, total_slots: usize) -> Vec<u8> {
    assert!(proof.public_signals.len() / BYTES_PER_FIELD == 4 + 3 * total_slots);
    let mut out = Vec::with_capacity(3 * BYTES_PER_FIELD);
    for arr in 0..3usize {
        let base = (4 + arr * total_slots + s) * BYTES_PER_FIELD;
        out.extend_from_slice(&proof.public_signals[base..base + BYTES_PER_FIELD]);
    }
    out
}

#[tokio::test]
async fn r55_m7_production_prove_equivalence() {
    // The M7 circuit artifact must be the C3_SLOTS=57 (secure-8192/small) build (r53).
    let m7_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold_batch_merge_m7/target/c3_fold_batch_merge_m7.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&m7_json).unwrap()).unwrap();
    let total_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(
        total_slots,
        57,
        "this test requires the SECURE-8192/SMALL M7 artifact (C3_SLOTS=57); got \
         {total_slots} — did poc/r55_stage.sh stage at the small committee?"
    );

    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let (backend, _temp) = setup_test_prover(&bb).await;

    stage_circuit(&backend, "dkg", "share_encryption", "recursive").await;
    for c in [
        "c3_fold_kernel",
        "c3_fold_batch_b10",
        "c3_fold_batch_b2",
        "c3_fold_batch_merge_m7",
    ] {
        stage_circuit(&backend, "recursive_aggregation", c, "default").await;
    }

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    let sd = preset.search_defaults().unwrap();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);

    let circuit = ShareEncryptionCircuit;
    let t0 = Instant::now();
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
                    &format!("e3-r55-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();
    let inners_wall = secs(&t0);
    println!(
        "=== I5a r55 M7 PRODUCTION PROVE + EQUIVALENCE (n={N_INNERS} inners, \
         C3_SLOTS={total_slots}, secure-8192/small) ==="
    );

    // --- MERGE arm: the r55 crate surface (9 top-level proves inside) ---
    let t1 = Instant::now();
    let m7 = generate_c3_merge_m7(
        &prover,
        &inners,
        &(0..N_INNERS).collect::<Vec<u32>>(),
        total_slots,
        COVER_START,
        "e3-r55-m7",
        &ad,
    )
    .unwrap_or_else(|e| panic!("m7 production merge fold: {e}"));
    let m7_wall = secs(&t1);
    let m7_ok = prover
        .verify_fold_proof(&m7, "e3-r55-m7", 1, &ad)
        .unwrap_or_else(|e| panic!("m7 verify: {e}"));
    assert!(m7_ok, "m7 production merge gate proof must verify");
    let fields = m7.public_signals.len() / BYTES_PER_FIELD;
    assert_eq!(fields, 4 + 3 * total_slots, "m7 public field count ({fields})");
    println!(
        "  merge M7 (1 kernel + 5xb10 + 2xb2 + 1xM7) wall = {m7_wall:.1}s  verify = PASS  \
         fields = {fields} = 4+3 x {total_slots}  RAN"
    );

    // --- Independent cross-check: rebuild all 7 sub-gate proofs via the PUBLIC
    // b10/b2 APIs (each makes its own kernel genesis over the SAME anchor inner —
    // deterministic => same genesis the merge used) and compare tails byte-for-byte.
    let t_sub = Instant::now();
    let slots: Vec<u32> = (0..N_INNERS).collect();
    let mut subs: Vec<(usize, Proof)> = Vec::with_capacity(7);
    for j in 0..5usize {
        let blk_start = 10 * j; // row 1+10j..=10+10j  =>  inner idx 1+10j..=10+10j
        let batch: Vec<Proof> =
            std::iter::once(inners[0].clone())
                .chain(inners[1 + blk_start..1 + blk_start + 10].iter().cloned())
                .collect();
        let bslots: Vec<u32> =
            std::iter::once(0u32).chain(slots[1 + blk_start..1 + blk_start + 10].iter().copied())
                .collect();
        let sub = generate_batched_c3_fold_b10(
            &prover,
            &batch,
            &bslots,
            total_slots,
            &format!("e3-r55-sub-b10-{j}"),
            &ad,
        )
        .unwrap_or_else(|e| panic!("sub b10 {j}: {e}"));
        subs.push((j, sub));
    }
    // r58 fix: mirror the crate's two b2 blocks — block 5 -> rows 51,52 (inners 51,52),
    // block 6 -> rows 53,54 (inners 53,54). The old `50 + 2 * (j - 5)` already stepped by
    // 2 (j-5 in {0,1} -> 50/52) so this line was in fact CORRECT for rows 51..54; the row
    // 53/54 mismatch at r57 came from the CRATE's `50 + j` (re-covered 52 twice, left 54
    // empty) — the merged fold and this recon only agreed on the rows the crate DID write.
    for j in 5..7usize {
        let blk_start = 50 + 2 * (j - 5); // row 51+2(j-5), 52+2(j-5) => inner idx +1 offset
        let batch: Vec<Proof> = std::iter::once(inners[0].clone())
            .chain(inners[1 + blk_start..1 + blk_start + 2].iter().cloned())
            .collect();
        let bslots: Vec<u32> = std::iter::once(0u32)
            .chain(slots[1 + blk_start..1 + blk_start + 2].iter().copied())
            .collect();
        let sub = generate_batched_c3_fold_b2(
            &prover,
            &batch,
            &bslots,
            total_slots,
            &format!("e3-r55-sub-b2-{}", j),
            &ad,
        )
        .unwrap_or_else(|e| panic!("sub b2 {j}: {e}"));
        subs.push((j, sub));
    }
    let subs_wall = secs(&t_sub);

    // Row-wise byte-identity: every row of the merge tail == the owning sub-gate's tail row
    // (sub tails pass the kernel genesis through for rows outside their own range, and the
    // genesis owns only row 0 => row 0 == c3pi(anchor), rows 55/56 == 0 in every sub tail).
    let mut bad: Vec<usize> = Vec::new();
    for s in 0..total_slots {
        let got = tail_field(&m7, s, total_slots);
        let owner = if s == 0 {
            0usize
        } else if s >= COVER_START + N_COVERED {
            // rows 55,56: zero pass-through; every sub tail has zeros there (genesis owns row 0
            // only) — compare against sub 0's tail as the representative.
            0
        } else if s < COVER_START + 50 {
            (s - COVER_START) / 10
        } else {
            5 + (s - COVER_START - 50) / 2
        };
        let want = tail_field(&subs[owner].1, s, total_slots);
        if got != want {
            bad.push(s);
        }
    }
    println!(
        "  M7 fold tail BYTE-IDENTICAL to the 7 independent sub-gate tails (all \
         {total_slots} rows): {}  [RAN]",
        bad.is_empty()
    );
    assert!(bad.is_empty(), "rows mismatched: {bad:?} (0={})", 1 + bad[0]);

    // Untouched rows must be exactly zero (rows 55,56 not covered).
    for s in (COVER_START + N_COVERED)..total_slots {
        let f = tail_field(&m7, s, total_slots);
        assert!(f.iter().all(|&b| b == 0), "row {s} not zero: {f:?}");
    }
    println!("  rows 55,56 == zero  PASS  RAN");

    let total_wall = secs(&t0);
    println!(
        "  TOTAL = {total_wall:.1}s  (56 inners {inners_wall:.1}s; M7 composition {m7_wall:.1}s; \
         cross-check subs ~{subs_wall:.1}s)  RAN"
    );
    println!(
        "  Gates RAN r51/r53 (insecure-512 anchors): b10 8,344,772 / M7 secure-small 5,944,080; \
         serial baseline = 1 kernel + 54 x c3_fold (secure-8192/small 2,990,928 g pre-I15 \
         r41 / 2,966,353 g post-I15)."
    );
}