// SPDX-License-Identifier: LGPL-3.0-only
//
//! r66 — I5a P=0 (anchor=3) SEAM ARM: the r65 seam replicated at node P=0.
//!
//! r65 RAN-verified the P=1 arm; this round closes the source-derived DRAFT-structural
//! byte-identity leg by exercising the SAME production wiring (M7x c3b arm + c3ab VK pin)
//! at the P=0 geometry (W_0 = {0..57}\{0,1,2}, anchor = W_0[0] = 3 — the crux premise of
//! the seam arm: `generate_c3_merge_m7x` mints the kernel genesis at `slot_indices[0]`,
//! and M7x's circuit passes the anchor row + the node's own block through from genesis).
//!
//!   c3b arm = `generate_c3_merge_m7x` over W_0 (kernel at 3 + 53 covered) -> M7x circuit
//!   c3a arm = `generate_sequential_c3_fold` over the SAME 30-slot block {3..33} as r65
//!             (the c3a arm is schedule-independent; only that c3ab consumes BOTH arms)
//!   c3ab seam = witness built exactly as `C3abFoldWitness` does, c3b pinned to the M7x
//!               VK, c3a to the c3_fold VK — artifact UNRECOMPILED; verify + corruption
//!               checks (column tails all 57 rows, pinned key-hash publics).
//!
//! Identical shape to r65 (same staged artifacts; slot arrays are witness inputs, so NO
//! circuit rebuild is needed for the P=0 rotation). Run:
//!   cargo test --release -p e3-zk-prover --test m7x_seam_p0_tests_r67 -- --nocapture
//!   (quiet box, release profile, UNCONTESTED; ~84 secure inners dominate ~70 min on 4c —
//!    r65 RAN 1:11:55 total, maxrss 7.47 GiB, Swaps 0 on this 4c/7.8 GiB + 8 GiB swap box.)

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
/// Node P=0 production C3b chain: W_0 = {0..57}\{0,1,2} ascending (54 slots),
/// anchor W_0[0] = 3 — the P=0 rotation of r65's P=1 arm (W_1, anchor 0).
const NODE_P: u32 = 0;
/// C3a fan-out for the seam: a 30-slot contiguous block {3..33} (N=19, L=3 — the same
/// block as r65; the c3a arm stays the SEQUENTIAL fold and its shape is not under test —
/// only that c3ab consumes BOTH arms at the full c3_fold ABI).
const C3A_COUNT: usize = 30;
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
async fn r66_c3ab_wiring_seam_p0_m7x_c3b_c3fold_c3a() {
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

    // --- 84 secure inners, serial (54 c3b-lane + 30 c3a-lane). Serial deliberate: the
    //     r63 RAN maxrss for the 54-inner + 2-arm class was 10.27 GiB UNCONTESTED on this
    //     16 GiB box; two concurrent multi-threaded bb prove lanes would risk the 16 GiB
    //     ceiling (heuristic overcommit, r45 class) for ~20 min saved — not worth it.
    //     RAM guard: the leaf is SecureThreshold8192; per-prove peak is the leaf class
    //     (~4-5 GiB RAN-class per r52/r61 staging).
    let c3b_count = 54;
    // c3a-lane: C3A_COUNT inners over the contiguous {3..33} block (see w_a below). The
    // c3a arm's SHAPE is not the wiring under test (sequential arm) — only that c3ab
    // consumes both arm proofs at the full c3_fold ABI.
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
                    &format!("e3-r67-{tag}-i{i}{j}"),
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

    // c3a slot schedule: contiguous block {3..33} (30 slots, C3A_COUNT). The sequential
    // arm only requires pairwise-distinct in-range slots; the c3a arm's shape is NOT the
    // wiring under test (only that c3ab consumes BOTH arm proofs at full c3_fold ABI).
    let w_a: Vec<u32> = (3u32..3u32 + C3A_COUNT as u32).collect();
    let w_b = w_p(NODE_P);
    assert_eq!(w_b.len(), 54, "W_0 must be 54 slots (anchor 3)");
    assert_eq!(w_a.len(), C3A_COUNT, "c3a block must be C3A_COUNT slots");

    // --- c3b arm: the M7x merge (the wiring under test). ---
    let t1 = Instant::now();
    let m7x = generate_c3_merge_m7x(
        &prover,
        &c3b_inners,
        &w_b,
        total_slots,
        "e3-r67-c3b",
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
        "e3-r67-c3a",
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
        "  c3a arm sequential (1 kernel + 29 c3_fold steps) wall = {c3a_wall:.1}s  fields = 175  circuit = c3_fold  RAN"
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
            "e3-r67-c3ab",
            &ad,
        )
        .unwrap_or_else(|e| panic!("c3ab prove: {e}"));
    let c3ab_wall = secs(&t3);
    let c3ab_ok = prover
        .verify_fold_proof(&c3ab, "e3-r67-c3ab", 1, &ad)
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
        "  r66 seam P=0 TOTAL (inners {inners_wall:.1}s + c3b {m7x_wall:.1}s + c3a {c3a_wall:.1}s + c3ab {c3ab_wall:.1}s) = {:.1}s  RAN",
        inners_wall + m7x_wall + c3a_wall + c3ab_wall
    );
}