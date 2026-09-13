// SPDX-License-Identifier: LGPL-3.0-only
//
//! r70 — I70 PoC: route the C3a lane through the M7x merge (production N=19), secure-8192/small.
//!
//! I70 (filed r69): node_dkg_fold folds the c3a lane ALWAYS sequential (only the c3b arm was
//! routed to M7x in r65). r69 RAN: c3a serial = 634.4 s = 11.9% of the per-node c3-bulk wall
//! (5321.6 s @4c) vs c3b-M7x 479.5 s. I70 = prove the SAME 54 c3a inners + W_P through
//! `generate_c3_merge_m7x` (identical 54-inner/54-slot geometry as c3b) and verify:
//!   (1) the arm: M7x verify PASS + c3_fold-EXACT 175 fields + circuit identity;
//!   (2) BYTE-IDENTITY vs the 54-step sequential fold on the same inners + slots (the r63/r65
//!       equivalence class, now for the C3a shape: anchor W_P[0], scattered schedule);
//!   (3) the SEAM: c3ab witness with BOTH arms pinned to the M7x VK (c3a and c3b each produced
//!       by an M7x merge) — c3ab artifact UNRECOMPILED (the VK-polymorphic r35/r65 pattern;
//!       c3ab_fold's in-circuit verify is over witness-input VKs), verify PASS + corruption
//!       checks (pinned key-hash publics == M7x VK hash; columns == both arms' tails all 57 rows).
//! Premises (source-verified r70 before building, all RAN-reads):
//!   (a) `generate_c3_merge_m7x` is lane-agnostic: anchor = slot_indices[0] (any slot; the r67
//!       P=0 arm RAN-proved anchor=3), sub-blocks over the public slot array, adds/writes pk|msg|ct
//!       fields only; guards = exactly 54 inners + 54 in-range pairwise-distinct slots + staged
//!       C3_SLOTS == total_slots — the c3a production lane (54 inners over W_P) satisfies all.
//!   (b) `c3ab_fold/src/main.nr` (full read): `c3a_vk`/`c3b_vk`/`c3a_public`/`c3b_public`/key-hashes
//!       are WITNESS inputs; `verify_honk_proof_non_zk` is VK-polymorphic; publics are arrays only
//!       ⇒ pinning c3a to the M7x VK needs NO c3ab recompile (r35/r65 r66/r67/r69 precedent for c3b).
//!   (c) `node_dkg_fold.rs:219-266`: the c3a arm call site = `generate_sequential_c3_fold(c3a_inner_
//!       proofs, c3_slot_indices_a, c3_total_slots, ...)` with the same 54/54/w_a guard shape as c3b's
//!       M7x branch, and the c3ab witness builder pins each arm to the producing circuit's VK
//!       (c3b branch at :300-316) — the c3a mirror is a mechanical clone (the production wiring
//!       follow-up, filed).
//! Production wall impact (RAN-anchored DRAFT when the leg lands): the node's c3-bulk wall drops
//! c3a-serial (634.4 RAN r69) for c3a-M7x (≈480 s-class, r63/r65/r67/r69 box-width-only anchors)
//! ⇒ ≈155 s/node @4c on the 5321.6 s baseline.
//!
//! (Harness base: the r69 production-geometry leg — 108 secure-8192/small inners (54 sk-lane
//! C3a + 54 esm-lane C3b) over the scattered W_1, node P=1 (the r63/r65 RAN class). Run:
//!   cargo test --release -p e3-zk-prover --test m7x_c3a_arm_tests_r70 -- --nocapture
//!   quiet box, release profile, UNCONTESTED; 108 inners (~70 min @4c) + 3 M7x arms (~1440 s) +
//!   1 serial c3a (~634 s) + c3ab (~12 s) ⇒ ~100 min wall @4c, ~7.5 GiB-class peak (r69 RAN
//!   7.47 GiB for the 108-inner + 2-arm class; the extra M7x arm is serial in the same
//!   ~4-8 GiB per-top-level-prove envelope — watch Swaps, the 8 GiB /swapfile carries r63-class).)

mod common;
use std::path::PathBuf;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{
    ShareEncryptionCircuit, ShareEncryptionCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::circuits::utils::inputs_json_to_input_map;
use e3_zk_prover::circuits::vk::load_vk_artifacts;
use e3_zk_prover::{
    generate_c3_merge_m7x, generate_sequential_c3_fold, CompiledCircuit, Provable, WitnessGenerator,
    ZkProver,
};

const COMMITTEE: &str = "small";
/// Node P=1: W_1 = {0..57}\{3,4,5}, anchor W_1[0] = 0 (the r63/r65/r69 RAN class; the merged
/// wall is box-width-only by r67's schedule-invariance RAN, so the P=1 number is the per-node
/// number for every node).
const NODE_P: u32 = 1;
const C3A_COUNT: usize = 54;
const N_SLOTS_TOTAL: u32 = 57;
const BYTES_PER_FIELD: usize = 32;

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
        "missing {json:?} — run the r65 secure/small stage build first"
    );
    let (vk_src, hash_src) = staged.unwrap_or_else(|| {
        panic!("no recursive VK for {circuit}: need {vk_rec:?} or {vk_noir:?} (r61_stage.sh / r65_c3ab_vk.sh)")
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

/// c3_fold-layout tail row `s` = (pk[s], msg[s], ct[s]) — the three CONCATENATED-array
/// layout (RAN r58b), offset by `4 + arr*S`.
fn tail_row(proof: &Proof, s: usize, total_slots: usize) -> Vec<u8> {
    assert_eq!(
        proof.public_signals.len() / BYTES_PER_FIELD,
        4 + 3 * total_slots,
        "tail_row: wrong public field count"
    );
    let mut out = Vec::with_capacity(3 * BYTES_PER_FIELD);
    for arr in 0..3usize {
        let base = (4 + arr * total_slots + s) * BYTES_PER_FIELD;
        out.extend_from_slice(&proof.public_signals[base..base + BYTES_PER_FIELD]);
    }
    out
}

/// c3ab public-tail column `c in 0..6` (pk_a0 msg_a1 ct_a2 pk_b3 msg_b4 ct_b5), row `s`.
/// Layout: [c3a_key_hash, c3b_key_hash, combined_key_hash] then 6 x C3_SLOTS columns.
fn c3ab_col_row(proof: &Proof, c: usize, s: usize, total_slots: usize) -> Vec<u8> {
    assert_eq!(
        proof.public_signals.len() / BYTES_PER_FIELD,
        3 + 6 * total_slots,
        "c3ab_col_row: wrong c3ab public field count"
    );
    let base = (3 + c * total_slots + s) * BYTES_PER_FIELD;
    proof.public_signals[base..base + BYTES_PER_FIELD].to_vec()
}

fn pub_scalar_field(proof: &Proof, i: usize) -> Vec<u8> {
    proof.public_signals[i * BYTES_PER_FIELD..(i + 1) * BYTES_PER_FIELD].to_vec()
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + 2 * bytes.len());
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Stage the c3ab FK-guard: the on-disk c3ab json must be the small build (175/arm).
fn assert_small_c3ab_json() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3ab_fold/target/c3ab_fold.json");
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("cannot read staged c3ab_fold.json: {e} — run poc/r65_c3ab_vk.sh first")),
    )
    .unwrap();
    let ps = v["abi"]["parameters"].as_array().unwrap();
    for name in ["c3a_public", "c3b_public"] {
        let len = ps
            .iter()
            .find(|p| p.get("name") == Some(&serde_json::Value::String(name.into())))
            .and_then(|p| p.get("type")?.get("length")?.as_u64())
            .unwrap_or(0);
        assert_eq!(
            len, 175,
            "staged c3ab_fold is not the small build ({name} len={len} != 175); re-stage"
        );
    }
}

fn slots_of(proof: &Proof) -> usize {
    proof.public_signals.len() / BYTES_PER_FIELD
}

#[tokio::test]
async fn r70_c3a_arm_m7x_vs_serial_byte_identity_plus_both_m7x_seam() {
    // Fail-fast guards (r63 class): M7x + c3_fold bases must be the C3_SLOTS=57 build.
    let m7x_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold_batch_merge_m7x/target/c3_fold_batch_merge_m7x.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&m7x_json).unwrap()).unwrap();
    let total_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(total_slots, 57, "M7x artifact is not C3_SLOTS=57 (secure/small)");
    let c3_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&c3_json).unwrap()).unwrap();
    let c3_slots = v["abi"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into())))
        .and_then(|p| p.get("type")?.get("length")?.as_u64())
        .map(|len| (len - 4) / 3)
        .unwrap() as usize;
    assert_eq!(c3_slots, 57, "staged c3_fold base is not C3_SLOTS=57 (re-stage r63)");
    assert_small_c3ab_json();

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
        "c3ab_fold",
    ] {
        stage_circuit(&backend, "recursive_aggregation", c, "default").await;
    }

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    let sd = preset.search_defaults().unwrap();
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);

    // --- 108 secure inners, serial (54 esm-lane C3b + 54 sk-lane C3a over scattered W_1 —
    //     the PRODUCTION C3, r69 geometry). Serial deliberate: the 4c/7.8 GiB ceiling (r63
    //     UNCONTESTED 10.27 GiB class on 16 GiB; r69 7.47 GiB on this box, Swaps 0).
    let c3b_count = 54;
    let c3a_count = C3A_COUNT;
    let presenter = ShareEncryptionCircuit;
    let t0 = Instant::now();
    let mut inners: Vec<Proof> = Vec::with_capacity(c3b_count + c3a_count);
    for (tag, dkg_type, n) in [
        ("c3b", DkgInputType::SecretKey, c3b_count),
        ("c3a", DkgInputType::SmudgingNoise, c3a_count),
    ] {
        for j in 0..n {
            let sample = ShareEncryptionCircuitData::generate_sample(
                preset.clone(),
                committee.clone(),
                dkg_type.clone(),
                sd.z,
            )
            .unwrap_or_else(|e| panic!("{tag} inner {j} no sample: {e}"));
            let p = presenter
                .prove_with_variant(
                    &prover,
                    &preset,
                    &sample,
                    &format!("e3-r70-{tag}-i{j}"),
                    CircuitVariant::Recursive,
                    &ad,
                )
                .unwrap_or_else(|e| panic!("{tag} inner {j} ZK prove failed: {e}"));
            inners.push(p);
        }
    }
    let (c3b_inners, c3a_inners) = inners.split_at(c3b_count);
    let inners_wall = secs(&t0);
    println!(
        "  {c3b_count} c3b-lane + {c3a_count} c3a-lane secure inners (serial) wall = {inners_wall:.1}s  RAN"
    );

    let w_a: Vec<u32> = w_p(NODE_P);
    let w_b = w_p(NODE_P);
    assert_eq!(w_b.len(), 54, "W_P must be 54 slots (N=19, L=3)");
    assert_eq!(w_a.len(), C3A_COUNT, "c3a production schedule must be C3A_COUNT (54) slots");
    assert_eq!(w_a, w_b, "production: c3a and c3b both cover the node's full W_P");

    // --- THE I70 ARM: c3a lane through the M7x merge (1 kernel + 5×b10 + 1×b3 + 1 M7x =
    //     8 top-level proves) — the same builder call a production c3a wiring would make. ---
    let t1 = Instant::now();
    let c3a_m7x = generate_c3_merge_m7x(
        &prover,
        &c3a_inners,
        &w_a,
        total_slots,
        "e3-r70-c3a-m7x",
        &ad,
    )
    .unwrap_or_else(|e| panic!("c3a M7x merge arm: {e}"));
    let c3a_m7x_wall = secs(&t1);
    assert_eq!(
        c3a_m7x.circuit,
        CircuitName::C3FoldBatchMergeM7x,
        "c3a M7x final proof must carry the M7x circuit identity"
    );
    assert_eq!(
        slots_of(&c3a_m7x) as usize,
        4 + 3 * total_slots,
        "c3a M7x public field count"
    );
    println!(
        "  c3a arm M7x (8 top-level proves) wall = {c3a_m7x_wall:.1}s  fields = 175  circuit = M7x  RAN"
    );

    // --- c3a arm: the CURRENT production wiring (sequential 1 kernel + 53 c3_fold steps) —
    //     the byte-identity oracle for the M7x arm. ---
    let t2 = Instant::now();
    let c3a_serial = generate_sequential_c3_fold(
        &prover,
        &c3a_inners,
        &w_a,
        total_slots,
        "e3-r70-c3a-serial",
        &ad,
    )
    .unwrap_or_else(|e| panic!("c3a sequential arm: {e}"));
    let c3a_serial_wall = secs(&t2);
    assert_eq!(
        c3a_serial.circuit,
        CircuitName::C3Fold,
        "c3a serial final proof must carry the c3_fold circuit identity"
    );
    assert_eq!(slots_of(&c3a_serial) as usize, 4 + 3 * total_slots, "c3a public field count");
    println!(
        "  c3a arm sequential (1 kernel + 53 c3_fold steps) wall = {c3a_serial_wall:.1}s  fields = 175  circuit = c3_fold  RAN"
    );

    // --- THE EQUIVALENCE (I70's load-bearing claim): M7x fold tail == sequential fold tail,
    //     all 57 rows, on the SAME 54 c3a inners + W_1 schedule (r63/r65/r69 equivalence class).
    let mut bad_serial: Vec<usize> = Vec::new();
    for s in 0..total_slots {
        if tail_row(&c3a_m7x, s, total_slots) != tail_row(&c3a_serial, s, total_slots) {
            bad_serial.push(s);
        }
    }
    println!(
        "  c3a M7x tail == c3a serial tail all 57 rows: {} (mismatches: {:?})  RAN",
        bad_serial.is_empty(),
        bad_serial.iter().take(8).cloned().collect::<Vec<_>>()
    );
    assert!(bad_serial.is_empty(), "c3a M7x vs serial tail mismatch: {bad_serial:?}");

    // --- c3b arm: the M7x merge (unchanged production wiring; second M7x arm this leg). ---
    let t3 = Instant::now();
    let c3b_m7x = generate_c3_merge_m7x(
        &prover,
        &c3b_inners,
        &w_b,
        total_slots,
        "e3-r70-c3b-m7x",
        &ad,
    )
    .unwrap_or_else(|e| panic!("c3b M7x merge arm: {e}"));
    let c3b_m7x_wall = secs(&t3);
    assert_eq!(c3b_m7x.circuit, CircuitName::C3FoldBatchMergeM7x, "c3b M7x identity");
    assert_eq!(slots_of(&c3b_m7x) as usize, 4 + 3 * total_slots, "c3b M7x field count");
    println!(
        "  c3b arm M7x (8 top-level proves) wall = {c3b_m7x_wall:.1}s  fields = 175  circuit = M7x  RAN"
    );

    // --- THE BOTH-ARMS-M7x SEAM (I70's production-shape question): c3ab witness with c3a
    //     pinned to the M7x VK (NOT the c3_fold VK) and c3b pinned to the M7x VK — c3ab
    //     artifact UNRECOMPILED (c3ab_fold verifies against witness-input VKs; r35/r65
    //     pattern, previously RAN-verified only for c3b=M7x/c3a=c3_fold — this leg adds the
    //     c3a=M7x pin, the state a post-I70-wiring production node_fold would present node_fold).
    let default_dir = prover.circuits_dir(CircuitVariant::Default, &ad);
    let m7x_vk = load_vk_artifacts(&default_dir, CircuitName::C3FoldBatchMergeM7x)
        .unwrap_or_else(|e| panic!("m7x VK: {e}"));
    let hex = |p: &Proof| {
        p.data
            .chunks(BYTES_PER_FIELD)
            .map(|c| format!("0x{}", hex::encode(c)))
            .collect::<Vec<_>>()
    };
    let pubhex = |p: &Proof| {
        p.public_signals
            .chunks(BYTES_PER_FIELD)
            .map(|c| format!("0x{}", hex::encode(c)))
            .collect::<Vec<_>>()
    };
    let mut json = serde_json::Map::new();
    json.insert(
        "c3a_vk".into(),
        serde_json::to_value(&m7x_vk.verification_key).unwrap(),
    );
    json.insert("c3a_proof".into(), serde_json::to_value(&hex(&c3a_m7x)).unwrap());
    json.insert("c3a_public".into(), serde_json::to_value(&pubhex(&c3a_m7x)).unwrap());
    json.insert(
        "c3b_vk".into(),
        serde_json::to_value(&m7x_vk.verification_key).unwrap(),
    );
    json.insert("c3b_proof".into(), serde_json::to_value(&hex(&c3b_m7x)).unwrap());
    json.insert("c3b_public".into(), serde_json::to_value(&pubhex(&c3b_m7x)).unwrap());
    json.insert(
        "c3a_key_hash".into(),
        serde_json::to_value(&m7x_vk.key_hash).unwrap(),
    );
    json.insert(
        "c3b_key_hash".into(),
        serde_json::to_value(&m7x_vk.key_hash).unwrap(),
    );
    let c3ab_path = default_dir
        .join(CircuitName::C3abFold.dir_path())
        .join(format!("{}.json", CircuitName::C3abFold.as_str()));
    let compiled = CompiledCircuit::from_file(&c3ab_path)
        .unwrap_or_else(|e| panic!("c3ab compiled circuit: {e}"));
    let t4 = Instant::now();
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(json))
        .unwrap_or_else(|e| panic!("c3ab witness json: {e}"));
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .unwrap_or_else(|e| panic!("c3ab witness gen (c3a=M7x proof, c3b=M7x proof, both VK=M7x): {e}"));
    let c3ab = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C3abFold,
            &witness,
            "e3-r70-c3ab",
            &ad,
        )
        .unwrap_or_else(|e| panic!("c3ab prove: {e}"));
    let c3ab_wall = secs(&t4);
    let c3ab_ok = prover
        .verify_fold_proof(&c3ab, "e3-r70-c3ab", 1, &ad)
        .unwrap_or_else(|e| panic!("c3ab verify: {e}"));
    assert!(
        c3ab_ok,
        "c3ab (c3a=M7x, c3b=M7x, both pinned to the M7x VK) must verify with the UNTOUCHED c3ab artifact"
    );
    println!(
        "  c3ab wall = {c3ab_wall:.1}s  verify = PASS (c3a AND c3b pinned to the M7x VK; c3ab json un-recompiled)  RAN"
    );

    // --- (4) Corruption check ---
    // (a) pinned key-hash publics mirror the M7x VK pin on BOTH arms.
    let got_akh = hex_of(&pub_scalar_field(&c3ab, 0));
    let got_bkh = hex_of(&pub_scalar_field(&c3ab, 1));
    assert_eq!(got_akh, m7x_vk.key_hash, "c3ab c3a_key_hash pub != M7x VK hash");
    assert_eq!(got_bkh, m7x_vk.key_hash, "c3ab c3b_key_hash pub != M7x VK hash");
    println!(
        "  c3ab pinned publics = M7x VK hash (c3a={got_akh}, c3b={got_bkh})  RAN"
    );
    // (b) c3a columns (0..3) == c3a-M7x arm tail; c3b columns (3..6) == c3b-M7x arm tail,
    //     all 57 rows.
    let mut bad_a: Vec<usize> = Vec::new();
    let mut bad_b: Vec<usize> = Vec::new();
    for s in 0..total_slots {
        for (c, src) in [(0, &c3a_m7x), (1, &c3a_m7x), (2, &c3a_m7x), (3, &c3b_m7x), (4, &c3b_m7x), (5, &c3b_m7x)] {
            let got = c3ab_col_row(&c3ab, c, s, total_slots);
            let want = tail_row(src, s, total_slots)[c % 3 * BYTES_PER_FIELD..(c % 3 + 1) * BYTES_PER_FIELD].to_vec();
            if got != want {
                if c < 3 {
                    bad_a.push(s);
                } else {
                    bad_b.push(s);
                }
            }
        }
    }
    println!(
        "  c3ab columns == arm tails all 57 rows (c3a cols: {:?} mismatches; c3b cols: {:?} mismatches): {}  RAN",
        bad_a.iter().take(4).cloned().collect::<Vec<_>>(),
        bad_b.iter().take(4).cloned().collect::<Vec<_>>(),
        bad_a.is_empty() && bad_b.is_empty()
    );
    assert!(bad_a.is_empty() && bad_b.is_empty(), "column mismatch a={bad_a:?} b={bad_b:?}");

    // --- Wall ledger (the I70 payoff arithmetic, RAN inputs): ---
    // r69 baseline @4c: inners ~4196.3 + c3b-M7x 479.5 + c3a-serial 634.4 + c3ab 11.4 = 5321.6 s.
    // Post-I70-wiring node c3-bulk = inners + c3b-M7x + c3a-M7x + c3ab (this leg measures the
    // three new pieces directly).
    println!(
        "  r70 I70 wall ledger @4c: inners {inners_wall:.1}s + c3a-M7x {c3a_m7x_wall:.1}s + c3a-serial {c3a_serial_wall:.1}s (oracle) + c3b-M7x {c3b_m7x_wall:.1}s + c3ab {c3ab_wall:.1}s  RAN"
    );
    println!(
        "  I70 payoff DRAFT-RAN-anchored: node c3-bulk 5321.6 s (r69 RAN baseline) - c3a-serial 634.4 s (r69 RAN) + c3a-M7x {c3a_m7x_wall:.1}s (THIS LEG RAN) = {:.1} s  ({:.1} min; DRAFT correction on the RAN baseline, lint: inners/c3b re-measured this leg at {inners_wall:.1}/{c3b_m7x_wall:.1}s)",
        5321.6 - 634.4 + c3a_m7x_wall,
        (5321.6 - 634.4 + c3a_m7x_wall) / 60.0
    );
}