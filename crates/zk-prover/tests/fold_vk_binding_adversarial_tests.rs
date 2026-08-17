// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Adversarial tests for the recursive VK binding in `c3_fold` / `nodes_fold` (plan section 1:
//! "Bind Every Fold Step").
//!
//! Every fold step must assert that the previous accumulator's child VK hash (public input 0)
//! equals the current step's `inner_key_hash`, so one canonical child VK applies to the complete
//! chain. A "compatible dummy circuit" — a real circuit with the exact public ABI of the canonical
//! inner circuit (`share_encryption` / `node_fold`) but a different VK — must be rejected at every
//! step.
//!
//! Because `recursive_aggregation` is a no-op during witness generation (see
//! `acvm-repo/acvm/src/pwg/blackbox/mod.rs`), the tests construct fold-step inputs directly and run
//! the fold circuit's [`WitnessGenerator`]. The positive controls establish that a fully canonical
//! step succeeds; each adversarial case flips exactly one binding and must fail.
//!
//! Artifact reads are cheap and deterministic; the `*_with_real_dummy_proof` tests additionally
//! mint a real `bb prove` proof of the dummy circuit to show a valid, ABI-compatible, noncanonical
//! proof is still rejected.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use common::{find_bb, setup_test_prover};
use e3_zk_prover::{inputs_json_to_input_map, CompiledCircuit, WitnessGenerator, ZkBackend};
use serde::Serialize;

// ---------------------------------------------------------------------------------------------
// Artifact paths (compiled output tree under `circuits/bin/`)
// ---------------------------------------------------------------------------------------------

fn ra_pkg_dir(pkg: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/recursive_aggregation")
        .join(pkg)
}

fn ra_artifact(pkg: &str, ext: &str) -> PathBuf {
    ra_pkg_dir(pkg).join("target").join(format!("{pkg}.{ext}"))
}

fn dkg_artifact(pkg: &str, ext: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/dkg/target")
        .join(format!("{pkg}.{ext}"))
}

// ---------------------------------------------------------------------------------------------
// Field / hash helpers
// ---------------------------------------------------------------------------------------------

fn zero_fields(n: usize) -> Vec<String> {
    vec!["0x00".to_string(); n]
}

fn read_vk_hash(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    (bytes.len() == 32).then(|| format!("0x{}", hex::encode(bytes)))
}

fn read_vk_fields(path: &Path) -> Option<Vec<String>> {
    let bytes = std::fs::read(path).ok()?;
    if !bytes.len().is_multiple_of(32) {
        return None;
    }
    Some(
        bytes
            .chunks(32)
            .map(|c| format!("0x{}", hex::encode(c)))
            .collect(),
    )
}

/// Reads a fixed-width array length from the compiled circuit ABI (e.g. `acc_public_inputs`).
fn abi_array_len(json_path: &Path, param: &str) -> Option<usize> {
    let raw = std::fs::read_to_string(json_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v["abi"]["parameters"]
        .as_array()?
        .iter()
        .find(|p| p.get("name") == Some(&serde_json::Value::String(param.into())))?
        .get("type")?
        .get("length")?
        .as_u64()
        .map(|x| x as usize)
}

// ---------------------------------------------------------------------------------------------
// Fold-step input builders
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct C3FoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    c3_public_inputs: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
    expected_kernel_key_hash: String,
    expected_fold_key_hash: String,
}

/// A fully canonical `c3_fold` step for `slot_index = 0` (party 0, modulus limb 0), so the
/// `c3_public_inputs[2] == slot/L` / `[3] == slot%L` assertions hold for any `L`.
///
/// `acc_child_vk` / `acc_vk_hash` model the accumulator's child VK (position 0) and the VK that
/// actually produced the accumulator. `acc_is_first` is the accumulator's own `is_first_step` flag
/// (position 2). The per-slot tail is zeroed, which satisfies the empty-slot assertions.
#[allow(clippy::too_many_arguments)]
fn c3_fold_step_input(
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    inner_key_hash: &str,
    acc_vk: Vec<String>,
    acc_child_vk: &str,
    acc_vk_hash: &str,
    acc_is_first: u32,
    is_first_step: bool,
    expected_kernel_key_hash: &str,
    expected_fold_key_hash: &str,
    total_slots: usize,
) -> C3FoldStepInput {
    let mut acc_public_inputs = zero_fields(6 + 3 * total_slots);
    acc_public_inputs[0] = acc_child_vk.to_string();
    acc_public_inputs[1] = acc_vk_hash.to_string();
    acc_public_inputs[2] = acc_is_first.to_string();
    acc_public_inputs[4] = expected_kernel_key_hash.to_string();
    acc_public_inputs[5] = expected_fold_key_hash.to_string();

    C3FoldStepInput {
        inner_vk,
        inner_proof,
        c3_public_inputs: vec!["0x00".to_string(); 5],
        acc_vk,
        acc_proof: zero_fields(410),
        acc_public_inputs,
        inner_key_hash: inner_key_hash.to_string(),
        acc_key_hash: acc_vk_hash.to_string(),
        is_first_step,
        slot_index: 0,
        expected_kernel_key_hash: expected_kernel_key_hash.to_string(),
        expected_fold_key_hash: expected_fold_key_hash.to_string(),
    }
}

#[derive(Serialize)]
struct NodesFoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    node_fold_public_inputs: Vec<String>,
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
    expected_kernel_key_hash: String,
    expected_fold_key_hash: String,
}

#[allow(clippy::too_many_arguments)]
fn nodes_fold_step_input(
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    inner_key_hash: &str,
    acc_vk: Vec<String>,
    acc_child_vk: &str,
    acc_vk_hash: &str,
    acc_is_first: u32,
    is_first_step: bool,
    expected_kernel_key_hash: &str,
    expected_fold_key_hash: &str,
    node_fold_len: usize,
    total_slots: usize,
) -> NodesFoldStepInput {
    let mut acc_public_inputs = zero_fields(6 + total_slots * node_fold_len);
    acc_public_inputs[0] = acc_child_vk.to_string();
    acc_public_inputs[1] = acc_vk_hash.to_string();
    acc_public_inputs[2] = acc_is_first.to_string();
    acc_public_inputs[4] = expected_kernel_key_hash.to_string();
    acc_public_inputs[5] = expected_fold_key_hash.to_string();

    NodesFoldStepInput {
        inner_vk,
        inner_proof,
        node_fold_public_inputs: zero_fields(node_fold_len),
        acc_vk,
        acc_proof: zero_fields(410),
        acc_public_inputs,
        inner_key_hash: inner_key_hash.to_string(),
        acc_key_hash: acc_vk_hash.to_string(),
        is_first_step,
        slot_index: 0,
        expected_kernel_key_hash: expected_kernel_key_hash.to_string(),
        expected_fold_key_hash: expected_fold_key_hash.to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Witness generation harness
// ---------------------------------------------------------------------------------------------

fn run_witness_gen(json_path: &Path, input: &impl Serialize) -> Result<(), String> {
    let compiled =
        CompiledCircuit::from_file(json_path).map_err(|e| format!("load circuit: {e}"))?;
    let json = serde_json::to_value(input).map_err(|e| format!("serialize input: {e}"))?;
    let input_map = inputs_json_to_input_map(&json).map_err(|e| format!("input map: {e}"))?;
    WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .map(|_| ())
        .map_err(|e| format!("witness gen: {e}"))
}

fn expect_success(result: Result<(), String>, label: &str) {
    assert!(
        result.is_ok(),
        "{label}: expected witness generation to succeed, got Err({})",
        result.err().unwrap_or_default()
    );
}

fn expect_failure(result: Result<(), String>, label: &str) {
    assert!(
        result.is_err(),
        "{label}: expected witness generation to FAIL (VK binding violated)"
    );
}

// ---------------------------------------------------------------------------------------------
// Shared artifact set
// ---------------------------------------------------------------------------------------------

struct C3Artifacts {
    json: PathBuf,
    canonical_inner_vk: Vec<String>,
    canonical_inner_hash: String,
    dummy_inner_vk: Vec<String>,
    dummy_inner_hash: String,
    fold_vk: Vec<String>,
    fold_hash: String,
    kernel_vk: Vec<String>,
    kernel_hash: String,
    total_slots: usize,
}

fn load_c3_artifacts() -> Option<C3Artifacts> {
    let json = ra_artifact("c3_fold", "json");
    let canonical_inner_vk = read_vk_fields(&dkg_artifact("share_encryption", "vk_noir"))?;
    let canonical_inner_hash = read_vk_hash(&dkg_artifact("share_encryption", "vk_noir_hash"))?;
    let dummy_inner_vk = read_vk_fields(&dkg_artifact("dummy_c3_inner", "vk_noir"))?;
    let dummy_inner_hash = read_vk_hash(&dkg_artifact("dummy_c3_inner", "vk_noir_hash"))?;
    let fold_vk = read_vk_fields(&ra_artifact("c3_fold", "vk_recursive"))?;
    let fold_hash = read_vk_hash(&ra_artifact("c3_fold", "vk_recursive_hash"))?;
    let kernel_vk = read_vk_fields(&ra_artifact("c3_fold_kernel", "vk_recursive"))?;
    let kernel_hash = read_vk_hash(&ra_artifact("c3_fold_kernel", "vk_recursive_hash"))?;
    let total_slots = abi_array_len(&json, "acc_public_inputs").map(|n| (n - 6) / 3)?;

    assert_ne!(
        canonical_inner_hash, dummy_inner_hash,
        "dummy circuit must have a distinct VK"
    );

    Some(C3Artifacts {
        json,
        canonical_inner_vk,
        canonical_inner_hash,
        dummy_inner_vk,
        dummy_inner_hash,
        fold_vk,
        fold_hash,
        kernel_vk,
        kernel_hash,
        total_slots,
    })
}

struct NodesArtifacts {
    json: PathBuf,
    canonical_inner_vk: Vec<String>,
    canonical_inner_hash: String,
    dummy_inner_vk: Vec<String>,
    dummy_inner_hash: String,
    fold_vk: Vec<String>,
    fold_hash: String,
    kernel_vk: Vec<String>,
    kernel_hash: String,
    node_fold_len: usize,
    total_slots: usize,
}

fn load_nodes_artifacts() -> Option<NodesArtifacts> {
    let json = ra_artifact("nodes_fold", "json");
    let canonical_inner_vk = read_vk_fields(&ra_artifact("node_fold", "vk_recursive"))?;
    let canonical_inner_hash = read_vk_hash(&ra_artifact("node_fold", "vk_recursive_hash"))?;
    let dummy_inner_vk = read_vk_fields(&ra_artifact("dummy_nodes_inner", "vk_recursive"))?;
    let dummy_inner_hash = read_vk_hash(&ra_artifact("dummy_nodes_inner", "vk_recursive_hash"))?;
    let fold_vk = read_vk_fields(&ra_artifact("nodes_fold", "vk_recursive"))?;
    let fold_hash = read_vk_hash(&ra_artifact("nodes_fold", "vk_recursive_hash"))?;
    let kernel_vk = read_vk_fields(&ra_artifact("nodes_fold_kernel", "vk_recursive"))?;
    let kernel_hash = read_vk_hash(&ra_artifact("nodes_fold_kernel", "vk_recursive_hash"))?;
    let node_fold_len = abi_array_len(&json, "node_fold_public_inputs")?;
    let total_slots = abi_array_len(&json, "acc_public_inputs").map(|n| (n - 6) / node_fold_len)?;

    assert_ne!(
        canonical_inner_hash, dummy_inner_hash,
        "dummy circuit must have a distinct VK"
    );

    Some(NodesArtifacts {
        json,
        canonical_inner_vk,
        canonical_inner_hash,
        dummy_inner_vk,
        dummy_inner_hash,
        fold_vk,
        fold_hash,
        kernel_vk,
        kernel_hash,
        node_fold_len,
        total_slots,
    })
}

// ---------------------------------------------------------------------------------------------
// c3_fold adversarial scenarios
// ---------------------------------------------------------------------------------------------

#[test]
fn c3_fold_rejects_vk_substitution() {
    let Some(a) = load_c3_artifacts() else {
        println!(
            "skipping: c3_fold / share_encryption / dummy_c3_inner artifacts not found \
             (run `pnpm build:circuits --group recursive_aggregation --group dkg`)"
        );
        return;
    };
    let zero_proof = zero_fields(458);

    // --- Positive controls: a fully canonical step (first and non-first) must generate a witness.
    let first_canonical = c3_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_success(
        run_witness_gen(&a.json, &first_canonical),
        "c3_fold canonical first step",
    );

    let mid_canonical = c3_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_success(
        run_witness_gen(&a.json, &mid_canonical),
        "c3_fold canonical middle step",
    );

    // --- Scenario 1: reject a noncanonical FIRST proof (dummy child on the genesis step).
    let bad_first = c3_fold_step_input(
        a.dummy_inner_vk.clone(),
        zero_proof.clone(),
        &a.dummy_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_first),
        "c3_fold noncanonical first proof",
    );

    // --- Scenario 2: reject a noncanonical MIDDLE proof.
    let bad_middle = c3_fold_step_input(
        a.dummy_inner_vk.clone(),
        zero_proof.clone(),
        &a.dummy_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_middle),
        "c3_fold noncanonical middle proof",
    );

    // --- Scenario 3: reject a canonical FINAL proof over an accumulator already poisoned by a
    // noncanonical child VK (the accumulator's child VK hash is the dummy hash).
    let bad_then_canonical = c3_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.dummy_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_then_canonical),
        "c3_fold noncanonical accumulator then canonical final proof",
    );

    // --- Scenario 4: reject a chain whose KERNEL VK changes (`expected_kernel_key_hash` mismatch).
    let bad_kernel = c3_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.fold_hash, // noncanonical: expected kernel hash swapped for the fold hash
        &a.fold_hash,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_kernel),
        "c3_fold kernel VK change",
    );

    // --- Scenario 5: reject a chain whose FOLD VK changes (`expected_fold_key_hash` mismatch).
    let bad_fold = c3_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.kernel_hash, // noncanonical: expected fold hash swapped for the kernel hash
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_fold),
        "c3_fold fold VK change",
    );
}

// ---------------------------------------------------------------------------------------------
// nodes_fold adversarial scenarios
// ---------------------------------------------------------------------------------------------

#[test]
fn nodes_fold_rejects_vk_substitution() {
    let Some(a) = load_nodes_artifacts() else {
        println!(
            "skipping: nodes_fold / node_fold / dummy_nodes_inner artifacts not found \
             (run `pnpm build:circuits --group recursive_aggregation`)"
        );
        return;
    };
    let zero_proof = zero_fields(410);

    let first_canonical = nodes_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_success(
        run_witness_gen(&a.json, &first_canonical),
        "nodes_fold canonical first step",
    );

    let mid_canonical = nodes_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_success(
        run_witness_gen(&a.json, &mid_canonical),
        "nodes_fold canonical middle step",
    );

    let bad_first = nodes_fold_step_input(
        a.dummy_inner_vk.clone(),
        zero_proof.clone(),
        &a.dummy_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_first),
        "nodes_fold noncanonical first proof",
    );

    let bad_middle = nodes_fold_step_input(
        a.dummy_inner_vk.clone(),
        zero_proof.clone(),
        &a.dummy_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_middle),
        "nodes_fold noncanonical middle proof",
    );

    let bad_then_canonical = nodes_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.dummy_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_then_canonical),
        "nodes_fold noncanonical accumulator then canonical final proof",
    );

    let bad_kernel = nodes_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.kernel_vk.clone(),
        &a.canonical_inner_hash,
        &a.kernel_hash,
        1,
        true,
        &a.fold_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_kernel),
        "nodes_fold kernel VK change",
    );

    let bad_fold = nodes_fold_step_input(
        a.canonical_inner_vk.clone(),
        zero_proof.clone(),
        &a.canonical_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.kernel_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &bad_fold),
        "nodes_fold fold VK change",
    );
}

// ---------------------------------------------------------------------------------------------
// Real dummy-proof rejection (bb-gated)
// ---------------------------------------------------------------------------------------------

/// Proves an arbitrary staged circuit with `bb` and returns `(proof, public_inputs)`.
fn prove_named_bin(
    backend: &ZkBackend,
    json: &Path,
    vk: &Path,
    witness: &[u8],
    verifier_target: &str,
    job_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let job_dir = backend.work_dir.join(job_id);
    std::fs::create_dir_all(&job_dir).map_err(|e| e.to_string())?;
    let witness_path = job_dir.join("witness.gz");
    std::fs::write(&witness_path, witness).map_err(|e| e.to_string())?;
    let out_dir = job_dir.join("out");
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

    let status = StdCommand::new(&backend.bb_binary)
        .arg("prove")
        .arg("-b")
        .arg(json)
        .arg("-w")
        .arg(&witness_path)
        .arg("-k")
        .arg(vk)
        .arg("-o")
        .arg(&out_dir)
        .arg("-v")
        .arg("-t")
        .arg(verifier_target)
        .status()
        .map_err(|e| format!("bb spawn: {e}"))?;
    if !status.success() {
        return Err(format!("bb prove failed with status {status}"));
    }
    let proof = std::fs::read(out_dir.join("proof")).map_err(|e| e.to_string())?;
    let public_inputs = std::fs::read(out_dir.join("public_inputs")).map_err(|e| e.to_string())?;
    Ok((proof, public_inputs))
}

fn dummy_c3_witness() -> Result<Vec<u8>, String> {
    let compiled = CompiledCircuit::from_file(&dkg_artifact("dummy_c3_inner", "json"))
        .map_err(|e| e.to_string())?;
    let input = serde_json::json!({
        "expected_pk_commitment": "0x00",
        "expected_message_commitment": "0x01",
        "party_idx": 0,
        "mod_idx": 0,
    });
    let input_map = inputs_json_to_input_map(&input).map_err(|e| e.to_string())?;
    WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .map_err(|e| e.to_string())
}

fn dummy_nodes_witness(node_fold_len: usize) -> Result<Vec<u8>, String> {
    let compiled = CompiledCircuit::from_file(&ra_artifact("dummy_nodes_inner", "json"))
        .map_err(|e| e.to_string())?;
    let input = serde_json::json!({ "node_fold_public_inputs": zero_fields(node_fold_len) });
    let input_map = inputs_json_to_input_map(&input).map_err(|e| e.to_string())?;
    WitnessGenerator::new()
        .generate_witness(&compiled, input_map)
        .map_err(|e| e.to_string())
}

/// A real, valid UltraHonk proof of a compatible dummy circuit, fed into a canonical `c3_fold`
/// middle step, must be rejected at witness generation.
#[tokio::test]
async fn c3_fold_rejects_real_dummy_proof() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let Some(a) = load_c3_artifacts() else {
        println!("skipping: c3_fold artifacts not found");
        return;
    };

    let (backend, _temp) = setup_test_prover(&bb).await;
    let witness = dummy_c3_witness().expect("dummy_c3_inner witness");
    let (proof, _pi) = prove_named_bin(
        &backend,
        &dkg_artifact("dummy_c3_inner", "json"),
        &dkg_artifact("dummy_c3_inner", "vk_noir"),
        &witness,
        "noir-recursive",
        "dummy-c3-inner",
    )
    .expect("real dummy_c3_inner proof");

    let mut proof_fields = zero_fields(458);
    for (i, f) in proof
        .chunks(32)
        .map(|c| format!("0x{}", hex::encode(c)))
        .enumerate()
        .take(proof_fields.len())
    {
        proof_fields[i] = f;
    }

    let step = c3_fold_step_input(
        a.dummy_inner_vk.clone(),
        proof_fields,
        &a.dummy_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &step),
        "c3_fold real dummy proof must be rejected",
    );
}

/// A real, valid UltraHonk proof of a compatible dummy circuit, fed into a canonical `nodes_fold`
/// middle step, must be rejected at witness generation.
#[tokio::test]
async fn nodes_fold_rejects_real_dummy_proof() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let Some(a) = load_nodes_artifacts() else {
        println!("skipping: nodes_fold artifacts not found");
        return;
    };

    let (backend, _temp) = setup_test_prover(&bb).await;
    let witness = dummy_nodes_witness(a.node_fold_len).expect("dummy_nodes_inner witness");
    let (proof, _pi) = prove_named_bin(
        &backend,
        &ra_artifact("dummy_nodes_inner", "json"),
        &ra_artifact("dummy_nodes_inner", "vk_recursive"),
        &witness,
        "noir-recursive-no-zk",
        "dummy-nodes-inner",
    )
    .expect("real dummy_nodes_inner proof");

    let mut proof_fields = zero_fields(410);
    for (i, f) in proof
        .chunks(32)
        .map(|c| format!("0x{}", hex::encode(c)))
        .enumerate()
        .take(proof_fields.len())
    {
        proof_fields[i] = f;
    }

    let step = nodes_fold_step_input(
        a.dummy_inner_vk.clone(),
        proof_fields,
        &a.dummy_inner_hash,
        a.fold_vk.clone(),
        &a.canonical_inner_hash,
        &a.fold_hash,
        0,
        false,
        &a.kernel_hash,
        &a.fold_hash,
        a.node_fold_len,
        a.total_slots,
    );
    expect_failure(
        run_witness_gen(&a.json, &step),
        "nodes_fold real dummy proof must be rejected",
    );
}
