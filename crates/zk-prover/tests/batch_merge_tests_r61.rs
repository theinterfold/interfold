// SPDX-License-Identifier: LGPL-3.0-only
//
//! I5a-fix-test (p2) / r61 — SCHEDULE-AWARE e2e for the M7x production-schedule merge.
//!
//! Deterministically constructs node P=1's actual C3b geometry
//! (N=19, secure-8192/small, L=3, C3_SLOTS=57):
//!   W_1 = {0..57}\{3,4,5}       (54 slots, the node's own 3-slot hole at 3..5)
//!   anchor = W_1[0] = 0 (the kernel), covered = W_1[1..] (53 scattered slots).
//!
//! Arms (same 54 inners + same slot schedule, byte-for-byte):
//!   SERIAL: `generate_sequential_c3_fold` — the PRODUCTION C3b fold
//!           (kernel at W_P[0] + 53 c3_fold steps over W_P[1..]).
//!   MERGE:  `generate_c3_merge_m7x` — 1 kernel (anchored at slot_indices[0])
//!           + 5 x b10 + 1 x b3 sub-gates + 1 M7x merge gate (in-circuit)
//!           = 8 top-level proves.
//! ASSERT: M7x verify PASS + 175 public fields + SERIAL tail == MERGE tail
//!         byte-identical (all 57 rows, the concatenation layout pk[57]|msg[57]|ct[57])
//!         + both tails equal the reference ORACLE derived from the inners
//!         (slot -> (pk,msg,ct) commitments; own block rows 3,4,5 = zero in both).
//!
//! This is the all-pass that licenses the production drop-in claim r60 proved
//! FALSE for the legacy M7 (count/anchor/window faults). The same test with
//! P=0 (anchor 3) exercises the non-zero-anchor leg of the fix (B1) and is the
//! planned next arm; P=1 already carries the B2 leg (scattered cover with
//! slots 55,56 outside any contiguous window).
//!
//! STAGING: `poc/r61_stage.sh` (secure-8192/small) — adds c3_fold_batch_merge_m7x
//! to the r55 circuit set. Run:
//!   cargo test --release -p e3-zk-prover --test batch_merge_tests_r61 -- --nocapture
//!   (quiet box, release profile; 54 secure inner proves dominate ~ 5 min)

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
    generate_c3_merge_m7x, generate_sequential_c3_fold, Provable, ZkProver,
};

const COMMITTEE: &str = "small";
/// Production C3b chain for node P=1: W_1 = {0..57}\{3,4,5} ascending (54 slots).
const NODE_P: u32 = 1;
const N_SLOTS_TOTAL: u32 = 57;
const BYTES_PER_FIELD: usize = 32;

/// W_P ascending: all slots 0..57 except the node's own 3-slot block {3P, 3P+1, 3P+2}
/// (slot = recipient_party_id * L + mod_idx; a node never computes C3 for itself).
fn w_p(p: u32) -> Vec<u32> {
    (0..N_SLOTS_TOTAL)
        .filter(|&s| !((p * 3)..(p * 3 + 3)).contains(&s))
        .collect()
}

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
        "missing {json:?} — run poc/r61_stage.sh first (secure-8192/small stage build)"
    );
    let (vk_src, hash_src) = staged.unwrap_or_else(|| {
        panic!("no recursive VK for {circuit}: need {vk_rec:?} or {vk_noir:?} (r61_stage.sh)")
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

/// Tail row `s` (3 x 32-byte: pk, msg, ct) of a c3_fold-layout proof — the
/// RAN r58b layout = three CONCATENATED arrays pk[0..S] msg[0..S] ct[0..S].
fn tail_row(proof: &Proof, s: usize, total_slots: usize) -> Vec<u8> {
    assert!(proof.public_signals.len() / BYTES_PER_FIELD == 4 + 3 * total_slots);
    let mut out = Vec::with_capacity(3 * BYTES_PER_FIELD);
    for arr in 0..3usize {
        let base = (4 + arr * total_slots + s) * BYTES_PER_FIELD;
        out.extend_from_slice(&proof.public_signals[base..base + BYTES_PER_FIELD]);
    }
    out
}

#[tokio::test]
async fn r61_m7x_schedule_aware_equivalence() {
    // The M7x artifact must be the C3_SLOTS=57 (secure-8192/small) build.
    let m7x_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold_batch_merge_m7x/target/c3_fold_batch_merge_m7x.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&m7x_json).unwrap()).unwrap();
    let total_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(
        total_slots, 57,
        "this test requires the SECURE-8192/SMALL M7x artifact (C3_SLOTS=57); got {total_slots}"
    );

    // r63 guard: the SERIAL arm's staged c3_fold base must be the SAME C3_SLOTS=57 build.
    // r62 hit exactly this class (stale micro C3_SLOTS=18 target read mid-run, after all
    // inners + the merge arm had proved) — fail fast instead of ~15 min into the run.
    let c3_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&c3_json).unwrap_or_else(|e| {
            panic!("cannot read staged c3_fold.json: {e} — run poc/r61_stage.sh (and r63_c3fold_stage.sh) first")
        })).unwrap();
    let c3_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(
        c3_slots, 57,
        "staged c3_fold base is C3_SLOTS={c3_slots}, not 57 — the SERIAL arm would TypeMismatch mid-run; re-stage (poc/r63_c3fold_stage.sh)"
    );

    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let (backend, _temp) = setup_test_prover(&bb).await;

    stage_circuit(&backend, "dkg", "share_encryption", "recursive").await;
    for c in [
        "c3_fold_kernel",
        "c3_fold",
        "c3_fold_batch_b10",
        "c3_fold_batch_b3",
        "c3_fold_batch_merge_m7x",
    ] {
        stage_circuit(&backend, "recursive_aggregation", c, "default").await;
    }

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    let sd = preset.search_defaults().unwrap();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);

    let w = w_p(NODE_P);
    assert_eq!(w.len(), 54, "W_1 must be 54 slots (N=19, L=3)");
    assert_eq!(w[0], 0, "P=1 anchor must be slot 0 (W_1[0])");
    assert!(
        !w.contains(&3) && !w.contains(&4) && !w.contains(&5),
        "own block 3..5 must be the hole"
    );
    assert!(w.contains(&55) && w.contains(&56), "slots 55,56 must be covered (P<=17)");
    let anchor = w[0];
    println!(
        "=== I5a-fix r61 M7x SCHEDULE-AWARE E2E (node P={NODE_P}, anchor={anchor}, \
         C3_SLOTS={total_slots}, secure-8192/small) ==="
    );

    // 54 inners = production C3b fan-out for node P (independently sampled per slot).
    let circuit = ShareEncryptionCircuit;
    let t0 = Instant::now();
    let inners: Vec<Proof> = (0..54)
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
                    &format!("e3-r61-i{i}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"))
        })
        .collect();
    let inners_wall = secs(&t0);

    // --- MERGE arm: M7x over the production schedule (8 top-level proves inside). ---
    let t1 = Instant::now();
    let m7x = generate_c3_merge_m7x(
        &prover,
        &inners,
        &w,
        total_slots,
        "e3-r61-m7x",
        &ad,
    )
    .unwrap_or_else(|e| panic!("m7x production-schedule merge: {e}"));
    let m7x_wall = secs(&t1);
    let m7x_ok = prover
        .verify_fold_proof(&m7x, "e3-r61-m7x", 1, &ad)
        .unwrap_or_else(|e| panic!("m7x verify: {e}"));
    assert!(m7x_ok, "m7x production-schedule merge gate proof must verify");
    let fields = m7x.public_signals.len() / BYTES_PER_FIELD;
    assert_eq!(fields, 4 + 3 * total_slots, "m7x public field count ({fields})");
    println!(
        "  M7x (1 kernel + 5xb10 + 1xb3 + 1xM7x) wall = {m7x_wall:.1}s  verify = PASS  \
         fields = {fields} = 4+3 x {total_slots}  RAN"
    );

    // --- SERIAL arm: the production C3b fold (kernel at W_P[0] + 53 c3_fold steps). ---
    let t2 = Instant::now();
    let serial = generate_sequential_c3_fold(
        &prover,
        &inners,
        &w,
        total_slots,
        "e3-r61-serial",
        &ad,
    )
    .unwrap_or_else(|e| panic!("serial production-schedule fold: {e}"));
    let serial_wall = secs(&t2);
    let serial_ok = prover
        .verify_fold_proof(&serial, "e3-r61-serial", 1, &ad)
        .unwrap_or_else(|e| panic!("serial verify: {e}"));
    assert!(serial_ok, "serial production-schedule fold proof must verify");
    println!("  SERIAL (1 kernel + 53x c3_fold) wall = {serial_wall:.1}s  verify = PASS  RAN");

    // --- Byte-identity: all 57 rows, merge tail == serial tail. ---
    let mut bad: Vec<usize> = Vec::new();
    let mut own_nonzero: Vec<usize> = Vec::new();
    for s in 0..total_slots {
        let a = tail_row(&serial, s, total_slots);
        let b = tail_row(&m7x, s, total_slots);
        if a != b {
            bad.push(s);
        }
        if w.contains(&(s as u32)) {
            continue; // scheduled slot: must match (checked above)
        }
        if !a.iter().all(|&x| x == 0) {
            own_nonzero.push(s);
        }
    }
    println!(
        "  MERGE tail BYTE-IDENTICAL to SERIAL production schedule (all {total_slots} rows): {}  RAN",
        bad.is_empty()
    );
    assert!(bad.is_empty(), "rows mismatched: {bad:?}");
    // The node's own 3-slot block (3,4,5 for P=1): unscheduled => zero in both arms.
    let own_zero = own_nonzero.is_empty();
    println!("  own-block rows (3,4,5) == zero in both arms: {own_zero}  RAN");
    assert!(own_zero, "own-block rows not zero: {own_nonzero:?}");

    // --- Reference oracle from the inner commitments (3rd independent leg). ---
    // c3 inner public signals: inputs = (expected_pk_commitment,
    // expected_message_commitment), output = ct_commitment (the fold copies exactly
    // these three fields into the slot row — crate `share_encryption_inner_public_inputs`).
    let field_of = |p: &Proof, kind: &str, name: &str| -> Vec<u8> {
        let xb = if kind == "input" {
            p.extract_input(name)
                .unwrap_or_else(|| panic!("inner missing input {name}"))
        } else {
            p.extract_output(name)
                .unwrap_or_else(|| panic!("inner missing output {name}"))
        };
        let bytes: &[u8] = &*xb;
        assert_eq!(
            bytes.len(),
            32,
            "inner {kind}:{name} must be one 32-byte field, got {} bytes",
            bytes.len()
        );
        bytes.to_vec()
    };
    let mut oracle_bad: Vec<usize> = Vec::new();
    for (i, s) in w.iter().enumerate() {
        let pk = field_of(&inners[i], "input", "expected_pk_commitment");
        let msg = field_of(&inners[i], "input", "expected_message_commitment");
        let ct = field_of(&inners[i], "output", "ct_commitment");
        let a = tail_row(&serial, *s as usize, total_slots);
        let b = tail_row(&m7x, *s as usize, total_slots);
        let mut got = Vec::with_capacity(96);
        got.extend_from_slice(&pk);
        got.extend_from_slice(&msg);
        got.extend_from_slice(&ct);
        if a != got || b != got {
            oracle_bad.push(*s as usize);
        }
    }
    println!(
        "  both arms match the per-slot COMMITMENT ORACLE on all 54 scheduled slots: {}  RAN",
        oracle_bad.is_empty()
    );
    assert!(oracle_bad.is_empty(), "oracle mismatch slots: {oracle_bad:?}");

    let total_wall = secs(&t0);
    println!(
        "  TOTAL = {total_wall:.1}s  (54 inners {inners_wall:.1}s; M7x {m7x_wall:.1}s; \
         serial {serial_wall:.1}s)  RAN"
    );
}