// SPDX-License-Identifier: LGPL-3.0-only
//
//! r69 — N=19 production-geometry DKG WALL LEG (per-node c3-bulk), secure-8192/small.
//!
//! Corrects round-68's wall table to PRODUCTION C3 geometry. r66/r67 ran 84 inners
//! (54 SecretKey + 30 SmudgingNoise) with the SmudgingNoise lane over a contiguous
//! {3..33} block — r67 itself flagged "the c3a arm's shape is not under test". Source
//! (this commit) proves production = 54 inners PER lane (sk→C3a, esm→C3b; gen_esi_sss
//! returns 1 SSS; generate_shares discourages own party×L=3 rows), C3 = 108 inners/node,
//! and node_dkg_fold folds C3b via M7x + C3a via the SEQUENTIAL 54-step fold. This leg
//! RANs that production per-node wall: 108 inners + c3b M7x + c3a 54-step serial + c3ab.
//!
//! (Base: the r67 P=0 anchor=3 seam, edited to the r69 production data: c3b/c3a inners
//! both raised to 54 over the SAME scattered W_P, c3a fold count to 54 — and the node
//! run is P=1 (NODE_P), NOT P=0: the merged c3b wall cross-checks the r63/r65 P=1 M7x
//! anchor, and the r67 P=0 RAN arm + box-width-only schedule-invariance (r67 landing)
//! cover the P=2..18 arm arithmetically — one code path, the merge wall is
//! box-width-only, so the P=1 number IS the per-node number for every node.)
//!
//!   c3b arm = `generate_c3_merge_m7x` over W_1 (kernel at 0 + 53 covered) -> M7x circuit
//!   c3a arm = `generate_sequential_c3_fold` over W_1 (production 54-slot scatter; the
//!             r65/r67 30-slot contiguous {3..33} block was "shape not under test")
//!   c3ab seam = witness built exactly as `C3abFoldWitness` does, c3b pinned to the M7x
//!               VK, c3a to the c3_fold VK — artifact UNRECOMPILED; verify + corruption
//!               checks (column tails all 57 rows, pinned key-hash publics).
//!
//! identical shape to r65 (same staged artifacts; slot arrays are witness inputs, so NO
//! circuit rebuild is needed for the production geometry). Run:
//!   cargo test --release -p e3-zk-prover --test m7x_seam_prod_geo_tests_r69 -- --nocapture
//!   (quiet box, release profile, UNCONTESTED; ~108 secure inners dominate ~90 min on 4c —
//!    r65 RAN 1:11:55 total for the 84-inner class, maxrss 7.47 GiB, Swaps 0 on this
//!    4c/7.8 GiB + 8 GiB swap box.)

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
/// Node P=1 production C3 chain: W_1 = {0..57}\{3,4,5} ascending (54 slots), anchor
/// W_1[0] = 0 — the r63/r65 RAN P=1 arm, so this leg's c3b M7x wall cross-checks the
/// r63 @8c and r65 @4c anchors directly. (Production C3 covers every node's W_P; the
/// merged wall is box-width-only by r67's schedule-invariance RAN, so the P=1 number
/// is the per-node number for all 19.)
const NODE_P: u32 = 1;
/// PRODUCTION c3 (one node) = C3a(SkLane) + C3b(SmudgeLane), each 54 inners (skipped
/// own party × L=3). Node P=1: W_1 = {0..57}\\{3,4,5}, anchor W_1[0] = 0 (the r65/r63
/// RAN arm, so this leg cross-checks against the r63 M7x wall). C3a folds 1 kernel +
/// 53 c3_fold steps (the r65/r67 30-slot contiguous block was "shape not under test").
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
async fn r69_prod_geo_54plus54_inners_c3b_m7x_c3a_serial() {
    // Fail-fast guards (r63 class): M7x + c3_fold bases must be the C3_SLOTS=57 build.
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
    assert_eq!(total_slots, 57, "M7x artifact is not C3_SLOTS=57 (secure/small)");
    let c3_json = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&c3_json).unwrap()).unwrap();
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

    // --- 108 secure inners, serial (54 sk-lane + 54 smudge-lane = the PRODUCTION C3),
    //     both over the node's scattered W_P. Serial deliberate: the r63 RAN maxrss for
    //     the 54-inner + 2-arm class was 10.27 GiB UNCONTESTED on the 16 GiB box; the
    //     4c/7.8 GiB box carries the serial lane at ~7.4-7.5 GiB peak (r66/r67 RAN,
    //     Swaps 0) — two concurrent multi-threaded teams would risk the ceiling.
    let c3b_count = 54;
    // c3a (SkLane): C3A_COUNT = 54 inners over the SAME scattered W_P as the c3b arm —
    // production geometry (r65/r67's contiguous {3..33} block was "shape not under test").
    let c3a_count = C3A_COUNT;
    let presenter = ShareEncryptionCircuit;
    let t0 = Instant::now();
    let mut inners: Vec<Proof> = Vec::with_capacity(c3b_count + c3a_count);
    for (i, tag, dkg_type, n) in [
        (0u32, "c3b", DkgInputType::SecretKey, c3b_count),
        (0u32, "c3a", DkgInputType::SmudgingNoise, c3a_count),
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
                    &format!("e3-r69-{tag}-i{i}{j}"),
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

    // c3a slot schedule: the SAME scattered W_P as the c3b arm (production C3a = all of
    // the node's non-own slots, same as C3b). The sequential arm only requires
    // pairwise-disjoint in-range slots; W_P is exactly that (no duplicates, all <57).
    let w_a: Vec<u32> = w_p(NODE_P);
    let w_b = w_p(NODE_P);
    assert_eq!(w_b.len(), 54, "W_P must be 54 slots (N=19, L=3)");
    assert_eq!(w_a.len(), C3A_COUNT, "c3a production schedule must be C3A_COUNT (54) slots");
    assert_eq!(w_a, w_b, "production: c3a and c3b both cover the node's full W_P");

    // --- c3b arm: the M7x merge (the wiring under test). ---
    let t1 = Instant::now();
    let m7x = generate_c3_merge_m7x(
        &prover,
        &c3b_inners,
        &w_b,
        total_slots,
        "e3-r69-c3b",
        &ad,
    )
    .unwrap_or_else(|e| panic!("c3b M7x merge arm: {e}"));
    let m7x_wall = secs(&t1);
    assert_eq!(
        m7x.circuit,
        CircuitName::C3FoldBatchMergeM7x,
        "c3b final proof must carry the M7x circuit identity (the production guard keys on this)"
    );
    assert_eq!(
        slots_of(&m7x) as usize,
        4 + 3 * total_slots,
        "m7x public field count"
    );
    println!(
        "  c3b arm M7x (8 top-level proves) wall = {m7x_wall:.1}s  fields = 175  circuit = M7x  RAN"
    );

    // --- c3a arm: the UNCHANGED sequential fold (the c3a leg of the wiring). ---
    let t2 = Instant::now();
    let c3a = generate_sequential_c3_fold(
        &prover,
        &c3a_inners,
        &w_a,
        total_slots,
        "e3-r69-c3a",
        &ad,
    )
    .unwrap_or_else(|e| panic!("c3a sequential arm: {e}"));
    let c3a_wall = secs(&t2);
    assert_eq!(
        c3a.circuit,
        CircuitName::C3Fold,
        "c3a final proof must carry the c3_fold circuit identity"
    );
    assert_eq!(slots_of(&c3a) as usize, 4 + 3 * total_slots, "c3a public field count");
    println!(
        "  c3a arm sequential (1 kernel + 53 c3_fold steps) wall = {c3a_wall:.1}s  fields = 175  circuit = c3_fold  RAN"
    );

    // --- THE R35 SEAM: production-shape c3ab witness with c3b pinned to the M7x VK ---
    // (mirrors node_dkg_fold.rs: c3a_vk/key_hash from C3Fold, c3b_vk/key_hash from the
    //  producing circuit's VK — M7x for the production C3b arm). c3ab json is read-only
    //  (no recompile) — the VK enters c3ab purely as witness data.
    let default_dir = prover.circuits_dir(CircuitVariant::Default, &ad);
    let c3fold_vk = load_vk_artifacts(&default_dir, CircuitName::C3Fold)
        .unwrap_or_else(|e| panic!("c3_fold VK: {e}"));
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
        serde_json::to_value(&c3fold_vk.verification_key).unwrap(),
    );
    json.insert("c3a_proof".into(), serde_json::to_value(&hex(&c3a)).unwrap());
    json.insert("c3a_public".into(), serde_json::to_value(&pubhex(&c3a)).unwrap());
    json.insert(
        "c3b_vk".into(),
        serde_json::to_value(&m7x_vk.verification_key).unwrap(),
    );
    json.insert("c3b_proof".into(), serde_json::to_value(&hex(&m7x)).unwrap());
    json.insert("c3b_public".into(), serde_json::to_value(&pubhex(&m7x)).unwrap());
    json.insert(
        "c3a_key_hash".into(),
        serde_json::to_value(&c3fold_vk.key_hash).unwrap(),
    );
    json.insert("c3b_key_hash".into(), serde_json::to_value(&m7x_vk.key_hash).unwrap());
    let c3ab_path = default_dir
        .join(CircuitName::C3abFold.dir_path())
        .join(format!("{}.json", CircuitName::C3abFold.as_str()));
    let compiled = CompiledCircuit::from_file(&c3ab_path)
        .unwrap_or_else(|e| panic!("c3ab compiled circuit: {e}"));
    let t3 = Instant::now();
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(json))
        .unwrap_or_else(|e| panic!("c3ab witness json: {e}"));
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .unwrap_or_else(|e| panic!("c3ab witness gen (c3b=M7x proof, c3b_vk=M7x VK): {e}"));
    let c3ab = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C3abFold,
            &witness,
            "e3-r69-c3ab",
            &ad,
        )
        .unwrap_or_else(|e| panic!("c3ab prove: {e}"));
    let c3ab_wall = secs(&t3);
    let c3ab_ok = prover
        .verify_fold_proof(&c3ab, "e3-r69-c3ab", 1, &ad)
        .unwrap_or_else(|e| panic!("c3ab verify: {e}"));
    assert!(c3ab_ok, "c3ab (c3a=c3_fold, c3b=M7x) must verify with the UNTouched c3ab artifact");
    println!(
        "  c3ab wall = {c3ab_wall:.1}s  verify = PASS (c3b pinned to M7x VK, c3a to c3_fold VK; c3ab json un-recompiled)  RAN"
    );

    // --- (4) Corruption check ---
    // (a) pinned key-hash publics mirror the VK pin (what node_fold's c3ab_key_hash chains).
    let got_akh = hex_of(&pub_scalar_field(&c3ab, 0));
    let got_bkh = hex_of(&pub_scalar_field(&c3ab, 1));
    assert_eq!(got_akh, c3fold_vk.key_hash, "c3ab c3a_key_hash pub != c3_fold VK hash");
    assert_eq!(got_bkh, m7x_vk.key_hash, "c3ab c3b_key_hash pub != M7x VK hash");
    println!(
        "  c3ab pinned publics = VK hashes (c3a=c3_fold {got_akh}, c3b=M7x {got_bkh})  RAN"
    );
    // (b) c3a columns (0..3) == c3a arm tail; c3b columns (3..6) == M7x arm tail, all 57 rows.
    let mut bad_a: Vec<usize> = Vec::new();
    let mut bad_b: Vec<usize> = Vec::new();
    for s in 0..total_slots {
        for (c, src) in [(0, &c3a), (1, &c3a), (2, &c3a), (3, &m7x), (4, &m7x), (5, &m7x)] {
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

    println!(
        "  r69 production-geometry per-node TOTAL (inners {inners_wall:.1}s + c3b {m7x_wall:.1}s + c3a {c3a_wall:.1}s + c3ab {c3ab_wall:.1}s) = {:.1}s  RAN",
        inners_wall + m7x_wall + c3a_wall + c3ab_wall
    );
}