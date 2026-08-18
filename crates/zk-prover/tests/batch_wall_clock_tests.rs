// SPDX-License-Identifier: LGPL-3.0-only
//
// I5 r44 REAL wall clock: serial c3 fold vs batched c3 fold, 3 shared inner
// ShareEncryption ZK proofs, insecure-512, minimum committee (C3_SLOTS=6), bb v5.1.0.
//
// Serial arm: kernel genesis + 3 c3_fold step proves (first step proves the kernel).
// Batch arm : the SAME kernel genesis + 1 c3_fold_batch_n3 prove (2 leaves over the
//             kernel-anchor accumulator, slots 1 and 2; anchor occupies slot 0).
// Both arms must verify AND land on the identical accumulator state (byte equality of
// the 18-field slot tail). Shared inners are timed once and reported as shared setup.

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

/// C3_SLOTS from the compiled c3_fold ABI (acc_public_inputs = 4 + 3 * slots).
fn c3_slots() -> usize {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation/c3_fold/target/c3_fold.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let len = v["abi"]["parameters"].as_array().unwrap().iter().find(|p| {
        p.get("name") == Some(&Value::String("acc_public_inputs".into()))
    }).and_then(|p| p.get("type")?.get("length")?.as_u64()).unwrap() as usize;
    (len - 4) / 3
}

fn secs(t: &Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

/// Inner C3 transcript of a ShareEncryption proof: (pk_commit, msg_commit, ct_commit).
fn c3pi_of(proof: &Proof) -> [String; 3] {
    let ctx = "inner ShareEncryption proof";
    [
        extract_single_field(proof, "input", field_keys::EXPECTED_PK_COMMITMENT, ctx).unwrap(),
        extract_single_field(proof, "input", field_keys::EXPECTED_MESSAGE_COMMITMENT, ctx).unwrap(),
        extract_single_field(proof, "output", field_keys::CT_COMMITMENT, ctx).unwrap(),
    ]
}/// Assemble the Noir input object for `c3_fold_batch_n3` (kernel anchor + 2 leaves).
/// Mirrors the sequential-step ABI: VK 115 fields, ZK proof 458, non-ZK acc proof 410,
/// acc public 22 (= 4 + 3*6). gen_hash pins are pub passthroughs (pass 0).
fn batch_n3_inputs(prover: &ZkProver, anchor: &Proof, leaves: &[Proof], ad: &str)
    -> Result<Value, String> {
    let ivk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, ad),
        CircuitName::ShareEncryption,
    ).map_err(|e| e.to_string())?;
    let akh = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, ad),
        CircuitName::C3FoldKernel,
    ).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let push = |n: &str, v: Value, names: &mut Vec<String>, out: &mut Vec<(String, Value)>| {
        names.push(n.to_string());
        out.push((n.to_string(), v));
    };
    let mut names2 = Vec::new();
    for k in 0..leaves.len() {
        let kk = k.to_string();
        push(&format!("ivk{kk}"), json!(ivk.verification_key.clone()), &mut names2, &mut out);
        push(&format!("iprf{kk}"), json!(
            fold_witness_field_strings(&leaves[k].data).map_err(|e| e.to_string())?
        ), &mut names2, &mut out);
        push(&format!("c3pi{kk}"), json!(c3pi_of(&leaves[k])), &mut names2, &mut out);
        push(&format!("ikh{kk}"), json!(ivk.key_hash.clone()), &mut names2, &mut out);
    }
    push("avk", json!(akh.verification_key), &mut names2, &mut out);
    push("aproof", json!(
        fold_witness_field_strings(&anchor.data).map_err(|e| e.to_string())?
    ), &mut names2, &mut out);
    push("api", json!(
        fold_witness_field_strings(anchor.public_signals.as_ref()).map_err(|e| e.to_string())?
    ), &mut names2, &mut out);
    push("akh", json!(akh.key_hash), &mut names2, &mut out);
    push("gen_hash0", json!("0"), &mut names2, &mut out);
    push("gen_hash1", json!("0"), &mut names2, &mut out);
    let mut obj = serde_json::Map::new();
    for (n, v) in out {
        obj.insert(n, v);
    }
    let _ = names2;
    Ok(Value::Object(obj))
}#[tokio::test]
async fn serial_vs_batch_wall_clock() {
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
    for c in [CircuitName::C3Fold, CircuitName::C3FoldKernel, CircuitName::C3FoldBatchN3] {
        setup_recursive_aggregation_fold_circuit(&backend, c).await;
    }
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee("minimum");
    println!("=== I5 r44 WALL CLOCK (real bb proves, box-local) ===");
    println!("preset=insecure-512 committee=minimum C3_SLOTS={total_slots}");

    // ---- 3 shared inner ShareEncryption ZK proofs (shared setup, timed once) ----
    let circuit = ShareEncryptionCircuit;
    let mut inners: Vec<Proof> = Vec::new();
    for i in 0..3u32 {
        let sample = ShareEncryptionCircuitData::generate_sample(
            preset.clone(),
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        ).unwrap_or_else(|_| panic!("no sample for inner {i}"));
        let t0 = Instant::now();
        let p = circuit
            .prove_with_variant(&prover, &preset, &sample, &format!("e3-r44-in{i}"), CircuitVariant::Recursive, &ad)
            .unwrap_or_else(|e| panic!("inner {i} ZK prove failed: {e}"));
        println!("  [shared inner {i}: ShareEncryption ZK ultra_honk] wall = {:6.1}s", secs(&t0));
        inners.push(p);
    }
    let inners = inners.clone();// ---- SERIAL ARM: production code path = kernel genesis + one c3_fold step per leaf ----
    println!("--- SERIAL ARM (1 kernel + 3 c3_fold steps, production sequential) ---");
    let t_ser = Instant::now();
    let folded = generate_sequential_c3_fold(
        &prover,
        &inners,
        &[0u32, 1, 2],
        total_slots,
        "e3-r44-serial",
        &ad,
    )
    .unwrap_or_else(|e| panic!("serial c3 fold: {e}"));
    let ser_wall = secs(&t_ser);
    println!("  SERIAL arm (kernel + 3 c3_fold steps) wall = {ser_wall:.1}s");
    let ser_ok = prover
        .verify_fold_proof(&folded, "e3-r44-serial", 1, &ad)
        .unwrap_or_else(|e| panic!("serial verify: {e}"));
    assert!(ser_ok, "serial fold must verify");
    println!("  SERIAL verify_fold_proof = PASS");

    // ---- BATCH ARM: same kernel genesis + ONE c3_fold_batch_n3 (leaves 1,2; anchor slot 0) ----
    println!("--- BATCH ARM (shared kernel + 1 c3_fold_batch_n3 circuit) ---");
    let t_bat = Instant::now();
    let anchor = c3_fold_kernel_genesis(
        &prover,
        &inners[0],
        total_slots,
        &ad,
        "e3-r44-batch-kernel",
    )
    .unwrap_or_else(|e| panic!("batch kernel genesis: {e}"));
    let k_wall = secs(&t_bat);
    println!("  batch kernel genesis wall = {k_wall:.1}s  (== serial's first-step kernel)");

    let bpath = backend
        .circuits_dir
        .join(&ad)
        .join("default/recursive_aggregation/c3_fold_batch_n3/c3_fold_batch_n3.json");
    let compiled = CompiledCircuit::from_file(&bpath)
        .unwrap_or_else(|e| panic!("load batch n3 json: {e}"));
    let vals = batch_n3_inputs(&prover, &anchor, &inners[1..3], &ad)
        .unwrap_or_else(|e| panic!("build batch noir inputs: {e}"));
    let imap = fold_witness_input_map(&vals)
        .unwrap_or_else(|e| panic!("batch input map: {e}"));
    let t1 = Instant::now();
    let witness = WitnessGenerator::new()
        .generate_witness(&compiled, imap)
        .unwrap_or_else(|e| panic!("batch witness gen: {e}"));
    let w_wall = secs(&t1);
    let batch_proof = prover
        .generate_recursive_aggregation_bin_proof(
            CircuitName::C3FoldBatchN3,
            &witness,
            "e3-r44-batch",
            &ad,
        )
        .unwrap_or_else(|e| panic!("batch bb prove: {e}"));
    let p_wall = secs(&t1) - w_wall;
    let bat_wall = secs(&t_bat);
    println!("  witness gen wall = {w_wall:.1}s   bb prove wall = {p_wall:.1}s");
    println!("  BATCH  arm (kernel + 1 batch circuit) wall = {bat_wall:.1}s");
    let b_ok = prover
        .verify_fold_proof(&batch_proof, "e3-r44-batch", 1, &ad)
        .unwrap_or_else(|e| panic!("batch verify: {e}"));
    assert!(b_ok, "batch fold must verify");
    println!("  BATCH  verify_fold_proof = PASS");// ---- CORRECTNESS: both arms must land on the IDENTICAL accumulator state ----
    let ser_prs = fold_witness_field_strings(&folded.public_signals)
        .unwrap_or_else(|e| panic!("serial pub signals: {e}"));
    let bat_prs = fold_witness_field_strings(&batch_proof.public_signals)
        .unwrap_or_else(|e| panic!("batch pub signals: {e}"));
    let expected_len = 4 + 3 * total_slots; // serial: 4 pub scalars + 18 slots
    assert_eq!(ser_prs.len(), expected_len, "serial pub signals len");
    // batch n3: 5 pub scalars (ikh0/ikh1/akh/gen0/gen1) + same 18-slot return
    assert_eq!(bat_prs.len(), 5 + 3 * total_slots, "batch pub signals len");
    let slots_eq = ser_prs[4..] == bat_prs[5..];
    println!(
        "  ACCUMULATOR SLOT STATES IDENTICAL ({} slot fields): {}",
        total_slots * 3, slots_eq
    );
    assert!(slots_eq, "serial and batch must land on the same accumulator state");

    // ---- REPORT ----
    println!("============================================================");
    println!("  SERIAL (kernel + 3 c3_fold)      wall = {ser_wall:.1}s  proves=4");
    println!("  BATCH  (kernel + 1 c3_fold_batch) wall = {bat_wall:.1}s  proves=2");
    println!(
        "  FOLD-LAYER SAVING = {sav:.1}s   (kernel shared: {k_wall:.1}s of both arms)",
        sav = ser_wall - bat_wall
    );
    println!("============================================================");
    prover.cleanup("e3-r44-in0").ok();
    for i in 0..3u32 {
        prover.cleanup(&format!("e3-r44-in{i}")).ok();
    }
    prover.cleanup("e3-r44-serial").ok();
    prover.cleanup("e3-r44-batch").ok();
    prover.cleanup("e3-r44-batch-kernel").ok();
}