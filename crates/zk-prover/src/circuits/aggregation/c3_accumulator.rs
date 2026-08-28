// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sequential C3 fold: each step verifies one inner `ShareEncryption` proof and the accumulator
//! (`c3_fold` non-ZK proof). The first step proves [`CircuitName::C3FoldKernel`] at runtime to obtain
//! a valid genesis `UltraHonkProof` (see `circuits/bin/recursive_aggregation/c3_fold_kernel`).
//!
//! Ciphernodes integrate via [`generate_sequential_c3_fold`] only: they supply the full list of C3
//! inner proofs and slot indices; per-step folding is not exposed outside this crate.

use crate::circuits::aggregation::helpers::{
    extract_single_field, field_keys, parse_acc_public_field_strings, sequential_fold,
    zero_field_hex_strings, ACC_NONZK_PROOF_FIELDS,
};
use crate::circuits::utils::{bytes_to_field_strings, inputs_json_to_input_map};
use crate::circuits::vk;
use crate::error::ZkError;
use crate::prover::ZkProver;
use crate::witness::{CompiledCircuit, WitnessGenerator};
use e3_events::{CircuitName, CircuitVariant, Proof};
use serde::Serialize;

/// `total_slots` = N_PARTIES * L_THRESHOLD (one slot per party-modulus pair).
fn c3_fold_public_input_field_count(total_slots: usize) -> usize {
    4 + 3 * total_slots
}

/// Public-signal layout of `c3_fold`: 4-field prefix, then 3-field-wide per-slot tail.
const C3_FOLD_PREFIX_LEN: usize = 4;
const C3_FOLD_SLOT_WIDTH: usize = 3;

struct C3FoldVks {
    inner_vk: vk::VkArtifacts,
    fold_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C3FoldVks {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareEncryption,
            )?,
            fold_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3Fold,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3FoldKernel,
            )?,
        })
    }
}

/// Proves [`CircuitName::C3FoldKernel`] for the same `inner` / `total_slots` as the fold step.
///
/// Uses work dir `job_id` (caller should use a suffix of the fold `e3_id` so jobs stay distinct).
/// Removes that work dir after the proof is returned.
#[allow(unused)]
pub(crate) fn generate_c3_fold_kernel_genesis_proof(
    prover: &ZkProver,
    inner: &Proof,
    total_slots: usize,
    artifacts_dir: &str,
    job_id: &str,
) -> Result<Proof, ZkError> {
    generate_c3_fold_kernel_genesis_at(prover, inner, total_slots, artifacts_dir, job_id, 0)
}

/// [`generate_c3_fold_kernel_genesis_proof`] with an explicit anchor slot: the kernel circuit
/// stamps the genesis accumulator at `slot_index` (its `slot_index` witness param), so the
/// production C3b schedule (which anchors `W_P[0]`, not slot 0) can mint its genesis — the
/// circuit supported this all along; the crate just hardcoded 0 (surfaced by the r60 premise
/// kill of the M7 drop-in).
pub(crate) fn generate_c3_fold_kernel_genesis_at(
    prover: &ZkProver,
    inner: &Proof,
    total_slots: usize,
    artifacts_dir: &str,
    job_id: &str,
    slot_index: u32,
) -> Result<Proof, ZkError> {
    let inner_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
        CircuitName::ShareEncryption,
    )?;
    let kernel_vk = vk::load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
        CircuitName::C3FoldKernel,
    )?;
    let c3_public_inputs = share_encryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c3_fold_public_input_field_count(total_slots);
    let acc_pi = zero_field_hex_strings(expected_acc_pub)?;
    let acc_pf = zero_field_hex_strings(ACC_NONZK_PROOF_FIELDS)?;

    let full_input = C3FoldStepInput {
        inner_vk: inner_vk.verification_key,
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c3_public_inputs,
        acc_vk: kernel_vk.verification_key,
        acc_proof: acc_pf,
        acc_public_inputs: acc_pi,
        inner_key_hash: inner_vk.key_hash,
        acc_key_hash: kernel_vk.key_hash,
        is_first_step: true,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C3FoldKernel.dir_path())
        .join(format!("{}.json", CircuitName::C3FoldKernel.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;
    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    let proof = prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C3FoldKernel,
        &witness,
        job_id,
        artifacts_dir,
    )?;
    Ok(proof)
}

/// Inner C3 public transcript: two inputs + `ct_commitment` output.
fn share_encryption_inner_public_inputs(proof: &Proof) -> Result<[String; 3], ZkError> {
    if proof.circuit != CircuitName::ShareEncryption {
        return Err(ZkError::InvalidInput(format!(
            "expected ShareEncryption inner proof, got {}",
            proof.circuit
        )));
    }
    let ctx = "C3 inner ShareEncryption proof";
    Ok([
        extract_single_field(proof, "input", field_keys::EXPECTED_PK_COMMITMENT, ctx)?,
        extract_single_field(proof, "input", field_keys::EXPECTED_MESSAGE_COMMITMENT, ctx)?,
        extract_single_field(proof, "output", field_keys::CT_COMMITMENT, ctx)?,
    ])
}

#[derive(Serialize)]
struct C3FoldStepInput {
    inner_vk: Vec<String>,
    inner_proof: Vec<String>,
    c3_public_inputs: [String; 3],
    acc_vk: Vec<String>,
    acc_proof: Vec<String>,
    acc_public_inputs: Vec<String>,
    inner_key_hash: String,
    acc_key_hash: String,
    is_first_step: bool,
    slot_index: u32,
}

fn parse_c3_fold_public_field_strings(proof: &Proof) -> Result<Vec<String>, ZkError> {
    parse_acc_public_field_strings(
        proof,
        CircuitName::C3Fold,
        C3_FOLD_PREFIX_LEN,
        C3_FOLD_SLOT_WIDTH,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_c3_fold_step_with_vks(
    prover: &ZkProver,
    inner: &Proof,
    prior_fold: Option<&Proof>,
    slot_index: u32,
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
    vks: &C3FoldVks,
) -> Result<Proof, ZkError> {
    let is_first_step = prior_fold.is_none();

    let c3_public_inputs = share_encryption_inner_public_inputs(inner)?;
    let expected_acc_pub = c3_fold_public_input_field_count(total_slots);

    let (acc_vk_fields, acc_vk_hash, acc_proof, acc_public_inputs) = if is_first_step {
        let kernel_job_id = format!("{e3_id}-c3fold-kernel");
        let kernel_proof = generate_c3_fold_kernel_genesis_proof(
            prover,
            inner,
            total_slots,
            artifacts_dir,
            &kernel_job_id,
        )?;
        let acc_pi = bytes_to_field_strings(kernel_proof.public_signals.as_ref())?;
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "c3_fold kernel proof public_inputs field count {} != expected {} (total_slots={})",
                acc_pi.len(),
                expected_acc_pub,
                total_slots
            )));
        }
        (
            vks.kernel_vk.verification_key.clone(),
            vks.kernel_vk.key_hash.clone(),
            bytes_to_field_strings(&kernel_proof.data)?,
            acc_pi,
        )
    } else {
        let p = prior_fold.expect("prior_fold required when is_first_step is false");
        let acc_pi = parse_c3_fold_public_field_strings(p)?;
        let prior_slots = (acc_pi.len() - 4) / 3;
        if prior_slots == 0 {
            return Err(ZkError::InvalidInput(
                "c3_fold proof implies zero slots".into(),
            ));
        }
        if prior_slots != total_slots {
            return Err(ZkError::InvalidInput(format!(
                "prior c3_fold slot count {} != expected {}",
                prior_slots, total_slots
            )));
        }
        if acc_pi.len() != expected_acc_pub {
            return Err(ZkError::InvalidInput(format!(
                "prior c3_fold public field count {} != expected {} for total_slots={}",
                acc_pi.len(),
                expected_acc_pub,
                total_slots
            )));
        }
        (
            vks.fold_vk.verification_key.clone(),
            vks.fold_vk.key_hash.clone(),
            bytes_to_field_strings(&p.data)?,
            acc_pi,
        )
    };

    let full_input = C3FoldStepInput {
        inner_vk: vks.inner_vk.verification_key.clone(),
        inner_proof: bytes_to_field_strings(&inner.data)?,
        c3_public_inputs,
        acc_vk: acc_vk_fields,
        acc_proof,
        acc_public_inputs,
        inner_key_hash: vks.inner_vk.key_hash.clone(),
        acc_key_hash: acc_vk_hash,
        is_first_step,
        slot_index,
    };

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C3Fold.dir_path())
        .join(format!("{}.json", CircuitName::C3Fold.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::to_value(&full_input)
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
    let input_map = inputs_json_to_input_map(&json)?;

    let witness_gen = WitnessGenerator::new();
    let witness = witness_gen.generate_witness(&compiled, input_map)?;

    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C3Fold,
        &witness,
        e3_id,
        artifacts_dir,
    )
}

/// Folds `inner_proofs` in order, one inner C3 proof per step — the integration surface for
/// ciphernodes (batch in, single `C3Fold` proof out).
///
/// `slot_indices[i]` is the `(party * L_THRESHOLD + modulus)` slot for `inner_proofs[i]`.
/// `total_slots` must equal `N_PARTIES * L_THRESHOLD` and determines the accumulator size.
pub fn generate_sequential_c3_fold(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // Defense in depth: every slot index must be in range and used at most once. C3 chains are
    // allowed to be partial (one C3 per (recipient, modulus) actually computed by this party),
    // unlike C6 which must cover all `T + 1` slots, so length equality is intentionally not
    // enforced here.
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_sequential_c3_fold: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len()
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c3_fold: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_sequential_c3_fold: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let vks = C3FoldVks::load(prover, artifacts_dir)?;
    sequential_fold(
        "generate_sequential_c3_fold",
        inner_proofs,
        slot_indices,
        |inner, prior, slot| {
            generate_c3_fold_step_with_vks(
                prover,
                inner,
                prior,
                slot,
                total_slots,
                e3_id,
                artifacts_dir,
                &vks,
            )
        },
    )
}

/// VK artifacts for a production-ABI (`c3_fold_batch_b{2,3}`) gate. The batch gates are sized
/// by C3_SLOTS like `c3_fold` (loaded from the standard per-committee artifacts dir).
pub(crate) struct C3FoldBatchVks {
    inner_vk: vk::VkArtifacts,
    batch_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C3FoldBatchVks {
    fn load(prover: &ZkProver, artifacts_dir: &str, batch: CircuitName) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareEncryption,
            )?,
            batch_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                batch,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3FoldKernel,
            )?,
        })
    }
}

/// One production-ABI `c3_fold_batch` gate (`b2`: B=2 leaves, `b3`: B=3) over a prior
/// accumulator (kernel genesis or a prior batch gate of the same circuit).
///
/// `anchor_vk` selects which VK the in-circuit `verify_honk_proof_non_zk` runs against: the FIRST
/// gate anchors the `C3FoldKernel` genesis proof (kernel VK), every LATER gate anchors a PRIOR
/// gate's proof (b2/b3 VK) — so the anchor VK follows the anchor proof's circuit.
///
/// `is_first_step` is `false` here: the gate always runs over a prior accumulator that already owns
/// the kernel slot; its covered slots must be zero in that anchor (in-circuit assert). The emitted
/// public tuple is `c3_fold`'s `([C3_SLOTS]; [C3_SLOTS]; [C3_SLOTS])` — the same public ABI
/// `c3ab_fold` binds against — so chained batch gates replace a tail of the recursive `c3_fold`
/// chain with no downstream circuit edits (VK rebuild only).
fn generate_c3_fold_batch_gate(
    prover: &ZkProver,
    gate: CircuitName,
    acc: &Proof,
    anchor_vk: &vk::VkArtifacts,
    inners: &[&Proof],
    slots: [u32; 3],
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let b = match gate {
        CircuitName::C3FoldBatchB2 => 2,
        CircuitName::C3FoldBatchB3 => 3,
        CircuitName::C3FoldBatchB6 => 6,
        CircuitName::C3FoldBatchB10 => 10,
        other => {
            return Err(ZkError::InvalidInput(format!(
                "generate_c3_fold_batch_gate: circuit {other:?} is not a batch gate (b2/b3/b6/b10)"
            )))
        }
    };
    // One field = 32 bytes (`bytes_to_field_strings` chunk size).
    const BYTES_PER_FIELD: usize = 32;
    let expected_fields = 4 + 3 * total_slots;
    if acc.public_signals.len() / BYTES_PER_FIELD != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "{gate:?} gate: prior accumulator public field count {} != expected {}",
            acc.public_signals.len() / BYTES_PER_FIELD,
            expected_fields,
        )));
    }
    let vks = C3FoldBatchVks::load(prover, artifacts_dir, gate)?;
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    // Field-name keys: the Noir batch gates declare params vk0/proof0/c3a/kh0/vk1/proof1/c3b/kh1
    // (b3 adds vk2/proof2/c3c/kh2).
    let c3_names = ["c3a", "c3b", "c3c"];
    for idx in 0..b {
        let leaf = inners[idx as usize];
        let c3_public_inputs = share_encryption_inner_public_inputs(leaf)?;
        out.insert(
            format!("vk{idx}"),
            serde_json::to_value(&vks.inner_vk.verification_key)
                .map_err(|e| ZkError::SerializationError(e.to_string()))?,
        );
        out.insert(
            format!("proof{idx}"),
            serde_json::to_value(&bytes_to_field_strings(&leaf.data)?)
                .map_err(|e| ZkError::SerializationError(e.to_string()))?,
        );
        out.insert(
            c3_names[idx as usize].to_string(),
            serde_json::to_value(&c3_public_inputs)
                .map_err(|e| ZkError::SerializationError(e.to_string()))?,
        );
        out.insert(
            format!("kh{idx}"),
            serde_json::to_value(&vks.inner_vk.key_hash)
                .map_err(|e| ZkError::SerializationError(e.to_string()))?,
        );
    }
    out.insert(
        "acc_vk".into(),
        serde_json::to_value(&anchor_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".into(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".into(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert("acc_key_hash".into(), serde_json::to_value(&anchor_vk.key_hash).unwrap());
    out.insert("is_first_step".into(), serde_json::json!(false));
    // Inject exactly the `b` public slot params this gate declares: b2 -> slot0/slot1,
    // b3 -> slot0/slot1/slot2. The ABI declares exactly `b` of them (b2 has 2, b3 has 3),
    // so over-injecting (the old hardcoded 0..3) yields `UnexpectedParams` on the b2 gate.
    for idx in 0..b {
        out.insert(format!("slot{idx}").into(), serde_json::json!(slots[idx as usize]));
    }

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(gate.dir_path())
        .join(format!("{}.json", gate.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(gate, &witness, job_id, artifacts_dir)
}

/// Production-ABI batched C3 fold over `c3_fold_batch_b2` gates — a drop-in alternative to
/// [`generate_sequential_c3_fold`] for ODD inner counts 3..=5.
///
/// `inner_proofs[0]` anchors slot 0 via a fresh `C3FoldKernel` genesis; the remaining inners are
/// paired into `c3_fold_batch_b2` gates, each covering two distinct fresh slots and re-verifying
/// the prior (non-ZK) accumulator once — the one-time ~700K-gate non-ZK anchor that
/// `generate_sequential_c3_fold` re-pays EVERY step (see I5). With 6 inners this replaces 5
/// recursive `c3_fold` steps (5 top-level proves) with kernel + 2 gates (3 proves).
///
/// Public ABI: the returned fold proof is a `C3FoldBatchB2` proof whose public slot array is
/// byte-identical to `generate_sequential_c3_fold`'s (both use `c3_fold`'s `([SLOTS];[SLOTS];[SLOTS])`
/// return), so `c3ab_fold` / `node_fold` / the onchain verifier are unchanged (VK rebuild only).
///
/// Constraint: odd inner count in 3..=5 — `inner_proofs[0]` anchors slot 0 (kernel), the rest are
/// paired into `(n-1)/2` chained `c3_fold_batch_b2` gates (each b2 gate covers two fresh slots).
pub fn generate_batched_c3_fold_b2(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b2: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len(),
        )));
    }
    // Production variant expects an odd count (n >= 3): inner 0 anchors slot 0 (kernel genesis),
    // the remaining (n - 1) are PAIRED into (n - 1) / 2 chained b2 gates, each covering two
    // distinct fresh slots and re-verifying the prior (non-ZK) accumulator once. With n inners
    // this replaces (n - 1) recursive `c3_fold` steps (n - 1 top-level proves) with (n - 1) / 2
    // b2 gates + kernel (= (n + 1) / 2 top-level proves).
    if !(3..=5).contains(&inner_proofs.len()) {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b2: expected an odd count of inners in 3..=5 (b2-gate variant), got {}",
            inner_proofs.len(),
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b2: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b2: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB2)?;
    // Genesis: anchor inner 0 in slot 0 (kernel).
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    // Pair inners[1..] into (n-1)/2 chained b2 gates, each over the running accumulator.
    // Gate 0 anchors the kernel genesis (kernel VK); gate b>=1 anchors gate b-1's b2 proof
    // (b2 VK) — the anchor VK always follows the anchor proof's circuit.
    let n_gates = inner_proofs.len() / 2;
    let mut cur = acc;
    for b in 0..n_gates {
        let a = 1 + 2 * b;
        let z = a + 1;
        let anchor_vk = if b == 0 { &vks.kernel_vk } else { &vks.batch_vk };
        let job_id = format!("{e3_id}-b2g{b}");
        cur = generate_c3_fold_batch_gate(
            prover,
            CircuitName::C3FoldBatchB2,
            &cur,
            anchor_vk,
            &[&inner_proofs[a], &inner_proofs[z]],
            [slot_indices[a], slot_indices[z], 0],
            total_slots,
            &job_id,
            artifacts_dir,
        )?;
    }
    Ok(cur)
}

/// Production-ABI batched C3 fold over `c3_fold_batch_b3` gates — a drop-in alternative to
/// [`generate_sequential_c3_fold`] for inner counts `n ≡ 1 (mod 3)` (4..=7).
///
/// Same contract as [`generate_batched_c3_fold_b2`] (kernel genesis anchors `inner_proofs[0]`;
/// the remaining inners are tripled into chained `c3_fold_batch_b3` gates; the emitted proof is
/// vk-rebuild-only for `c3ab_fold` / `node_fold` / onchain) — per gate the bulkier B=3 shape
/// covers three leaves per one-time ~700K-gate non-ZK anchor, so the gate-level saving over the
/// recursive chain is larger per covered step (RAN r9: b3 gate 2,981,374 = one-time anchor + 3
/// leaf verifies; marginal 4th leaf costs only +766,191 gates vs 1,448,866 per serial step).
pub fn generate_batched_c3_fold_b3(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b3: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len(),
        )));
    }
    // Production variant expects an inner count n ≡ 1 (mod 3), 4..=7: inner 0 anchors slot 0
    // (kernel genesis), the remaining (n - 1) — divisible by 3 — are TRIPLD into (n - 1) / 3
    // chained b3 gates, each covering three distinct fresh slots and re-verifying the prior
    // (non-ZK) accumulator once. With n inners this replaces (n - 1) recursive `c3_fold` steps
    // (n - 1 top-level proves) with (n - 1) / 3 b3 gates + kernel (= (n + 2) / 3 top-level proves:
    // n=4 -> 2 proves vs 3, n=7 -> 3 proves vs 6).
    if !(4..=7).contains(&inner_proofs.len()) || (inner_proofs.len() - 1) % 3 != 0 {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b3: expected an inner count n ≡ 1 (mod 3) in 4..=7 (b3-gate variant), got {}",
            inner_proofs.len(),
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b3: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b3: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB3)?;
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    // Triple inners[1..] into (n-1)/3 chained b3 gates over the running accumulator.
// Gate b covers inners 1+3b, 2+3b, 3+3b. Gate 0 anchors the kernel genesis (kernel VK);
// gate b>=1 anchors gate b-1's b3 proof (b3 VK).
let n_gates = (inner_proofs.len() - 1) / 3;
let mut cur = acc;
for b in 0..n_gates {
    let a = 1 + 3 * b;
    let c = a + 1;
    let d = a + 2;
    let anchor_vk = if b == 0 {
        &vks.kernel_vk
    } else {
        &vks.batch_vk
    };
    let job_id = format!("{e3_id}-b3g{b}");
    cur = generate_c3_fold_batch_gate(
        prover,
        CircuitName::C3FoldBatchB3,
        &cur,
        anchor_vk,
        &[
            &inner_proofs[a],
            &inner_proofs[c],
            &inner_proofs[d],
        ],
        [
            slot_indices[a],
            slot_indices[c],
            slot_indices[d],
        ],
        total_slots,
        &job_id,
        artifacts_dir,
    )?;
}
Ok(cur)
}

/// N=19 tree-split (I5a, r51/r52) — production-ABI batched C3 fold over the B=10 sub-gate:
/// ONE `c3_fold_batch_b10` gate (8,344,772 gates, RAN r51) over a fresh kernel genesis instead
/// of 10 sequential `c3_fold` steps.
///
/// Same contract as [`generate_batched_c3_fold_b3`]: `inner_proofs[0]` anchors slot 0 (kernel
/// genesis); the 10 remaining inners fill `slot_indices[1..=10]` inside the single gate. The
/// emitted proof is a `C3FoldBatchB10` proof with `c3_fold`'s public ABI
/// (`4 + 3*C3_SLOTS` fields: acc_key_hash / is_first_step / slot0 / slot1 + 3 slot arrays),
/// so downstream circuits are VK-rebuild-only.
///
/// Constraint: EXACTLY 11 inners (1 kernel anchor + 10 leaves) and `total_slots` (C3_SLOTS) >=
/// 11 — the gate covers all 10 fresh slots at once, so committees with C3_SLOTS < 11 (minimum:
/// 6) cannot witness it; micro (N=9/L=2, C3_SLOTS=18) is the smallest fitting committee.
pub fn generate_batched_c3_fold_b10(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b10: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len(),
        )));
    }
    if inner_proofs.len() != 11 {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b10: expected exactly 11 inners (1 kernel anchor + 10 b10 leaves), got {}",
            inner_proofs.len()
        )));
    }
    if total_slots < 11 {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b10: total_slots must be >= 11 (B=10 gate covers 10 fresh slots + the kernel slot), got {total_slots}"
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b10: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b10: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    // Single b10 gate over the kernel genesis: inners 1..=10 inside one 8.34M-gate circuit.
    let mut inners_refs: Vec<&Proof> = Vec::with_capacity(10);
    for p in &inner_proofs[1..] {
        inners_refs.push(p);
    }
    b10_gate_over_genesis(
        prover,
        &acc,
        &inners_refs,
        slot_indices,
        total_slots,
        e3_id,
        artifacts_dir,
    )
}

/// N=19 tree-split (I5a) — B=6 batch drop-in over 7 inners: 1 kernel genesis
/// (anchors `inner_proofs[0]` at `slot_indices[0]`) + ONE b6 gate covering
/// `slot_indices[1..=6]` — byte-equal in public tail to the kernel + 6 serial
/// `c3_fold` steps (r59 leg asserts it).
pub fn generate_batched_c3_fold_b6(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != slot_indices.len() {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b6: inner_proofs and slot_indices length mismatch ({} vs {})",
            inner_proofs.len(),
            slot_indices.len(),
        )));
    }
    if inner_proofs.len() != 7 {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b6: expected exactly 7 inners (1 kernel anchor + 6 b6 leaves), got {}",
            inner_proofs.len()
        )));
    }
    if total_slots < 7 {
        return Err(ZkError::InvalidInput(format!(
            "generate_batched_c3_fold_b6: total_slots must be >= 7 (B=6 gate covers 6 fresh slots + the kernel slot), got {total_slots}"
        )));
    }
    let mut seen = vec![false; total_slots];
    for &s in slot_indices {
        let idx = s as usize;
        if idx >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b6: slot index {s} out of range (total_slots={total_slots})"
            )));
        }
        if seen[idx] {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold_b6: duplicate slot index {s}"
            )));
        }
        seen[idx] = true;
    }
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    let mut inners_refs: Vec<&Proof> = Vec::with_capacity(6);
    for p in &inner_proofs[1..] {
        inners_refs.push(p);
    }
    b6_gate_over_genesis(
        prover,
        &acc,
        &inners_refs,
        slot_indices,
        total_slots,
        e3_id,
        artifacts_dir,
    )
}

/// Witness + prove for the B=6 / B=10 production-ABI gates over a prior accumulator.
///
/// The shared [`generate_c3_fold_batch_gate`] caps at 3 slots (b2/b3 ABI); the b6/b10 bins
/// take `slot0..slot{B-1}` (all `B` of them, `slot0`/`slot1` public + the rest private), so
/// this builder mirrors its input-map construction with `B` leaves and `B` slot entries.
fn b10_gate_over_genesis(
    prover: &ZkProver,
    acc: &Proof,
    inners: &[&Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    const BYTES_PER_FIELD: usize = 32;
    let expected_fields = 4 + 3 * total_slots;
    if inners.len() != 10 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b10 gate: expected 10 inners, got {}",
            inners.len()
        )));
    }
    if slot_indices.len() != 11 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b10 gate: expected 11 slot indices (kernel anchor + 10 covered), got {}",
            slot_indices.len()
        )));
    }
    if acc.public_signals.len() / BYTES_PER_FIELD != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b10 gate: prior accumulator public field count {} != expected {expected_fields}",
            acc.public_signals.len() / BYTES_PER_FIELD
        )));
    }
    let vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB10)?;
    // c3 leaf-name suffixes in the b10 ABI: c3a..c3j (leaf order 0..=9 = inners 1..=10).
    const C3_NAMES: [&str; 10] = ["c3a", "c3b", "c3c", "c3d", "c3e", "c3f", "c3g", "c3h", "c3i", "c3j"];
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    for (idx, leaf) in inners.iter().enumerate() {
        let c3_public_inputs = share_encryption_inner_public_inputs(leaf)?;
        out.insert(
            format!("vk{idx}"),
            serde_json::to_value(&vks.inner_vk.verification_key).unwrap(),
        );
        out.insert(
            format!("proof{idx}"),
            serde_json::to_value(&bytes_to_field_strings(&leaf.data)?).unwrap(),
        );
        out.insert(
            C3_NAMES[idx].to_string(),
            serde_json::to_value(&c3_public_inputs).unwrap(),
        );
        out.insert(format!("kh{idx}"), serde_json::to_value(&vks.inner_vk.key_hash).unwrap());
    }
    // The gate anchors the KERNEL GENESIS proof (kernel VK) — gate 0 of the chain.
    out.insert(
        "acc_vk".to_string(),
        serde_json::to_value(&vks.kernel_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".to_string(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert(
        "acc_key_hash".to_string(),
        serde_json::to_value(&vks.kernel_vk.key_hash).unwrap(),
    );
    out.insert("is_first_step".to_string(), serde_json::json!(false));
    // The b10 ABI's slot_i = the slot of the (i+1)-th inner (inner 0 is the kernel-anchored
    // slot 0, not a gate param): slot_i = slot_indices[i+1] for i in 0..9.
    for idx in 0..10 {
        out.insert(
            format!("slot{idx}"),
            serde_json::json!(slot_indices[idx as usize + 1]),
        );
    }

    let circuit_name = CircuitName::C3FoldBatchB10;
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        &format!("{e3_id}-b10g0"),
        artifacts_dir,
    )
}

/// Witness + prove for the B=6 production-ABI gate over a prior accumulator.
/// Mirror of [`b10_gate_over_genesis`] for the 6-cover ABI (`slot0..slot5`,
/// leaf order = inners 1..=6, b6 c3-name suffixes c3a..c3f).
fn b6_gate_over_genesis(
    prover: &ZkProver,
    acc: &Proof,
    inners: &[&Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    const BYTES_PER_FIELD: usize = 32;
    let expected_fields = 4 + 3 * total_slots;
    if inners.len() != 6 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b6 gate: expected 6 inners, got {}",
            inners.len()
        )));
    }
    if slot_indices.len() != 7 {
        return Err(ZkError::InvalidInput(
            "c3_fold_batch_b6 gate: expected 7 slot indices (kernel anchor + 6 covered), got {}"
                .to_string(),
        ));
    }
    if acc.public_signals.len() / BYTES_PER_FIELD != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b6 gate: prior accumulator public field count {} != expected {expected_fields}",
            acc.public_signals.len() / BYTES_PER_FIELD
        )));
    }
    let vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB6)?;
    const C3_NAMES: [&str; 6] = ["c3a", "c3b", "c3c", "c3d", "c3e", "c3f"];
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    for (idx, leaf) in inners.iter().enumerate() {
        let c3_public_inputs = share_encryption_inner_public_inputs(leaf)?;
        out.insert(
            format!("vk{idx}"),
            serde_json::to_value(&vks.inner_vk.verification_key).unwrap(),
        );
        out.insert(
            format!("proof{idx}"),
            serde_json::to_value(&bytes_to_field_strings(&leaf.data)?).unwrap(),
        );
        out.insert(C3_NAMES[idx].to_string(), serde_json::to_value(&c3_public_inputs).unwrap());
        out.insert(format!("kh{idx}"), serde_json::to_value(&vks.inner_vk.key_hash).unwrap());
    }
    out.insert(
        "acc_vk".to_string(),
        serde_json::to_value(&vks.kernel_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".to_string(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert("acc_key_hash".to_string(), serde_json::to_value(&vks.kernel_vk.key_hash).unwrap());
    out.insert("is_first_step".to_string(), serde_json::json!(false));
    // b6 ABI's slot_i = the slot of the (i+1)-th inner (inner 0 = kernel-anchored slot 0).
    for idx in 0..6 {
        out.insert(format!("slot{idx}"), serde_json::json!(slot_indices[idx + 1]));
    }
    let circuit_name = CircuitName::C3FoldBatchB6;
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        &format!("{e3_id}-b6g0"),
        artifacts_dir,
    )
}

/// N=19 tree-split (I5a r53) — MERGE tier M1: ONE `c3_fold_batch_merge_m1` gate that
/// in-circuit-verifies a b6 sub-gate proof (and the prior accumulator) and folds the b6
/// covered range into the combined 3 x C3_SLOTS state — the production merge's building
/// block (r53 M-tier: M1 = M0 + 1 in-circuit sub-gate verify).
///
/// `inner_proofs[0]` anchors slot `slot_indices[0]` via a fresh kernel genesis; the next 6
/// inners form the b6 sub-gate (slots `slot_indices[1..=6]`); the M1 gate then anchors that
/// kernel genesis and replaces the 6-step c3_fold tail the sub-gate covers.
///
/// Constraint: EXACTLY 7 inners (1 kernel anchor + 6 b6 leaves) and `total_slots` >= 7.
pub fn generate_c3_merge_m1(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != 7 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m1: expected exactly 7 inners (1 kernel anchor + 6 b6 leaves), got {}",
            inner_proofs.len()
        )));
    }
    if slot_indices.len() != 7 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m1: expected 7 slot indices, got {}",
            slot_indices.len()
        )));
    }
    if total_slots < 7 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m1: total_slots must be >= 7 (b6 covers 6 fresh slots + the kernel slot), got {total_slots}"
        )));
    }
    // Kernel genesis anchors inner 0 at slot_indices[0].
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    // b6 sub-gate over the kernel genesis: inners 1..=6 cover slot_indices[1..=6].
    let mut inners_refs: Vec<&Proof> = Vec::with_capacity(6);
    for p in &inner_proofs[1..] {
        inners_refs.push(p);
    }
    let sub = b6_gate_over_genesis(
        prover,
        &acc,
        &inners_refs,
        slot_indices,
        total_slots,
        e3_id,
        artifacts_dir,
    )?;
    // M1 merge gate: in-circuit-verify the b6 sub-gate PROOF + the anchor, fold the
    // covered range [slot1, slot1+6) from the sub's public tail, pass through the rest.
    let expected_fields = 4 + 3 * total_slots;
    if sub.public_signals.len() / 32 != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "c3 merge m1: sub-gate public field count {} != expected {expected_fields}",
            sub.public_signals.len() / 32
        )));
    }
    let sub_vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB6)?;
    let merge_vks =
        C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchMergeM1)?;
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    out.insert(
        "sub_vk".to_string(),
        serde_json::to_value(&sub_vks.batch_vk.verification_key).unwrap(),
    );
    out.insert(
        "sub_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&sub.data)?).unwrap(),
    );
    out.insert(
        "sub_public".to_string(),
        serde_json::to_value(&bytes_to_field_strings(sub.public_signals.as_ref())?).unwrap(),
    );
    out.insert("sub_key_hash".to_string(), serde_json::to_value(&sub_vks.batch_vk.key_hash).unwrap());
    out.insert(
        "slot1".to_string(),
        serde_json::json!(slot_indices[1]),
    );
    out.insert(
        "acc_vk".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".to_string(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert(
        "acc_key_hash".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.key_hash).unwrap(),
    );
    out.insert("is_first_step".to_string(), serde_json::json!(true));
    out.insert("slot0".to_string(), serde_json::json!(slot_indices[0]));

    let circuit_name = CircuitName::C3FoldBatchMergeM1;
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        &format!("{e3_id}-m1g0"),
        artifacts_dir,
    )
}

/// Witness + prove for the PRODUCTION-SHAPE MERGE tier M7 (`c3_fold_batch_merge_m7`) over a
/// KERNEL GENESIS accumulator — 5 x B10 sub-gates (slots cover_start..=cover_start+49) + 2 x B2
/// sub-gates (slots cover_start+50..=cover_start+53) = 54 covered slots, then ONE in-circuit
/// M7 verify-and-fold. All 7 sub-gates anchor the SAME kernel genesis (disjoint ranges; the
/// M7 circuit asserts pairwise disjointness + zero-overwrite in-circuit), mirroring the
/// production C3b tree split (5 x B10 + 2 x B2 = (N-1)*L at N=19, secure-8192/small,
/// C3_SLOTS = 19*3 = 57, cover_start = 1 after the anchor at slot 0).
///
/// `cover_start` must satisfy `cover_start + 54 <= total_slots`; `slot_indices[0]` = the
/// kernel-anchored slot, `slot_indices[cover_start..cover_start+54]` = the covered slots in
/// row order (b10 block i covers rows 10i+1..=10i+10; b2 block 5 covers row 51, block 6 row 52
/// RELATIVE to cover_start). Each covered slot must be zero in the kernel genesis (true in the
/// production layout: the genesis owns only `slot_indices[0]`, outside the covered range).
///
/// The returned proof is `CircuitName::C3FoldBatchMergeM7` with c3_fold's exact 4+3*C3_SLOTS
/// public layout => `c3ab_fold` / `node_fold` / onchain are VK-rebuild-only.
fn m7_gate_over_genesis(
    prover: &ZkProver,
    acc: &Proof,
    inners: &[&Proof],
    slot_indices: &[u32],
    total_slots: usize,
    cover_start: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inners.len() != 54 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7 gate: expected 54 chain inners, got {}",
            inners.len()
        )));
    }
    if slot_indices.len() < cover_start + 54 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7 gate: slot_indices too short ({} < cover_start {} + 54)",
            slot_indices.len(),
            cover_start
        )));
    }
    if cover_start + 54 > total_slots {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7 gate: cover_start {} + 54 > total_slots {}",
            cover_start, total_slots
        )));
    }
    let is_small = {
        // The M7 artifact's C3_SLOTS = N_PARTIES * L_THRESHOLD of the STAGED circuit build;
        // read it from the compiled json (single source of truth).
        let circuit_name = CircuitName::C3FoldBatchMergeM7;
        let jpath = prover
            .circuits_dir(CircuitVariant::Default, artifacts_dir)
            .join(circuit_name.dir_path())
            .join(format!("{}.json", circuit_name.as_str()));
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&jpath)
                .map_err(|e| ZkError::SerializationError(format!("read M7 json: {e}")))?,
        )
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        let len = v["abi"]["parameters"]
            .as_array()
            .and_then(|ps| {
                ps.iter()
                    .find(|p| p.get("name") == Some(&serde_json::Value::String(
                        "acc_public_inputs".into(),
                    )))
            })
            .and_then(|p| p.get("type")?.get("length")?.as_u64())
            .ok_or_else(|| {
                ZkError::InvalidInput("M7 json abi: acc_public_inputs length not found".into())
            })?;
        (len - 4) as usize / 3
    };
    // The staged sub-gate artifacts must emit the same slot-array width as the M7 circuit.
    let b10_json = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C3FoldBatchB10.dir_path())
        .join("c3_fold_batch_b10.json");
    let sols: usize = {
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&b10_json)
                .map_err(|e| ZkError::SerializationError(format!("read b10 json: {e}")))?,
        )
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        let len = v["abi"]["parameters"]
            .as_array()
            .and_then(|ps| {
                ps.iter()
                    .find(|p| p.get("name") == Some(&serde_json::Value::String(
                        "acc_public_inputs".into(),
                    )))
            })
            .and_then(|p| p.get("type")?.get("length")?.as_u64())
            .unwrap_or((4 + 3 * is_small) as u64);
        (len - 4) as usize / 3
    };
    if sols != is_small {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7 gate: staged b10 C3_SLOTS ({sols}) != staged M7 C3_SLOTS \
             ({is_small}) — rebuild the sub-gate artifacts at the same committee"
        )));
    }

    let sub_vks_b10 = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB10)?;
    let sub_vks_b2 = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB2)?;
    let merge_vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchMergeM7)?;
    debug_assert_eq!(sub_vks_b10.kernel_vk.key_hash, sub_vks_b2.kernel_vk.key_hash);

    // 1) The `acc` argument IS the kernel genesis (anchoring inners[0] at slot_indices[0]).
    if acc.public_signals.len() / 32 != 4 + 3 * is_small {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7 gate: kernel genesis public field count {} != {}",
            acc.public_signals.len() / 32,
            4 + 3 * is_small
        )));
    }
    // 2) Five B10 sub-gates over the genesis (block j covers rows 10j+1..=10j+10).
    let mut subs: Vec<(CircuitName, Proof)> =
        Vec::with_capacity(7);
    for j in 0..5usize {
        let block_start = j * 10;
        let blk: Vec<&Proof> = inners[block_start..block_start + 10].to_vec();
        let mut slots11 = Vec::with_capacity(11);
        slots11.push(slot_indices[0]);
        for k in 0..10 {
            slots11.push(slot_indices[cover_start + block_start + k]);
        }
        let sub = b10_gate_over_genesis(
            prover,
            &acc,
            &blk,
            &slots11,
            is_small,
            e3_id,
            artifacts_dir,
        )?;
        subs.push((CircuitName::C3FoldBatchB10, sub));
    }
    // 3) Two B2 sub-gates over the genesis (block 5 -> rows 51,52; block 6 -> rows 53,54).
    //    NOTE (r58, RAN-verified): the stride is 2, not 1 — the legacy `50 + j` made block 6
    //    re-cover row 52 (double-leaf) and never fold row 54 (the last C3b row); the
    //    in-circuit zero-overwrite assert cannot catch that (the genesis is zero there).
    //    Surfaced by the r57 M7 byte-identity leg.
    for j in 0..2usize {
        let blk_start = 50 + 2 * j;
        let blk: Vec<&Proof> = inners[blk_start..blk_start + 2].to_vec();
        let sub = generate_c3_fold_batch_gate(
            prover,
            CircuitName::C3FoldBatchB2,
            &acc,
            &sub_vks_b2.kernel_vk,
            &blk,
            [
                slot_indices[cover_start + blk_start],
                slot_indices[cover_start + blk_start + 1],
                0,
            ],
            is_small,
            &format!("{e3_id}-b2g{j}"),
            artifacts_dir,
        )?;
        subs.push((CircuitName::C3FoldBatchB2, sub));
    }

    // 4) The M7 merge gate: in-circuit-verify all 7 sub-gate proofs + the genesis, fold
    //    the 54 covered rows from each sub's public tail, pass the rows outside through.
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    for (idx, (c_name, sub)) in subs.iter().enumerate() {
        let sub_vks = match c_name {
            CircuitName::C3FoldBatchB10 => &sub_vks_b10,
            CircuitName::C3FoldBatchB2 => &sub_vks_b2,
            _ => unreachable!("m7 subs are b10/b2"),
        };
        out.insert(
            format!("vk{idx}"),
            serde_json::to_value(&sub_vks.batch_vk.verification_key).unwrap(),
        );
        out.insert(
            format!("proof{idx}"),
            serde_json::to_value(&bytes_to_field_strings(&sub.data)?).unwrap(),
        );
        out.insert(
            format!("public{idx}"),
            serde_json::to_value(&bytes_to_field_strings(sub.public_signals.as_ref())?).unwrap(),
        );
        out.insert(
            format!("kh{idx}"),
            serde_json::to_value(&sub_vks.batch_vk.key_hash).unwrap(),
        );
    }
    out.insert(
        "acc_vk".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".to_string(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert(
        "acc_key_hash".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.key_hash).unwrap(),
    );
    out.insert("is_first_step".to_string(), serde_json::json!(true));
    out.insert("slot0".to_string(), serde_json::json!(slot_indices[0]));
    out.insert("slot1".to_string(), serde_json::json!(cover_start as u32));

    let circuit_name = CircuitName::C3FoldBatchMergeM7;
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        &format!("{e3_id}-m7g0"),
        artifacts_dir,
    )
}

/// N=19 C3b tree split as ONE production-shape M7 merge (I5a r55, item b3) — the crate
/// surface for the `c3_fold_batch_merge_m7` circuit built in r53.
///
/// `inner_proofs` (>= 56): index 0 = the kernel anchor; indices `cover_start..cover_start+54`
/// = the C3b chain's 54 leaves in slot-row order (block boundaries every 10 rows: 5 x B10,
/// then the trailing 2+2 as 2 x B2). `slot_indices` is positionally aligned (index 0 = anchor
/// slot, index `cover_start` = the first covered slot). At the production layout (N=19,
/// secure-8192/small, L=3, C3_SLOTS=57) that is anchor 0 + chain slots 1..=54 and
/// `cover_start = 1` — exactly the circuit's covered geometry.
///
/// Returns a `CircuitName::C3FoldBatchMergeM7` proof: 1 kernel + 7 sub-gates + 1 M7 (9
/// top-level proves) replacing the 54-step `c3_fold` tail, byte-identical combined slot
/// state (the M7 circuit's zero-overwrite + pass-through assertions make the slot tail
/// deterministic in the sub-gate publics).
pub fn generate_c3_merge_m7(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    cover_start: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() < cover_start + 54 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m7: expected >= {} inner proofs (anchor + {} covered), got {}",
            cover_start + 54,
            54,
            inner_proofs.len()
        )));
    }
    if slot_indices.len() < cover_start + 54 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m7: expected >= {} slot indices, got {}",
            cover_start + 54,
            slot_indices.len()
        )));
    }
    if cover_start > total_slots - 54 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m7: cover_start+54 ({}) exceeds total_slots {total_slots}",
            cover_start + 54
        )));
    }
    // Kernel genesis anchoring inner 0 at slot_indices[0].
    let acc = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;
    let mut refs: Vec<&Proof> = Vec::with_capacity(54);
    for p in inner_proofs[1..cover_start + 54].iter() {
        refs.push(p);
    }
    m7_gate_over_genesis(
        prover,
        &acc,
        &refs,
        slot_indices,
        total_slots,
        cover_start,
        e3_id,
        artifacts_dir,
    )
}

/// Witness + prove for the PRODUCTION-SCHEDULE MERGE tier M7x (`c3_fold_batch_merge_m7x`) over a
/// KERNEL GENESIS accumulator that anchors `inner[0]` at `slot_indices[0]` (any slot — the
/// production C3b chain anchors `W_P[0]`, not slot 0). 5 x B10 sub-gates cover
/// `slot_indices[1..51]` in row order (block j covers rows 1+10j..=10+10j) + 1 x B3 sub-gate
/// covers `slot_indices[51..54]`; all 6 sub-gates anchor the SAME kernel genesis (disjoint
/// covers, asserted in-circuit by the sub-gates; the M7x circuit re-asserts pairwise
/// disjointness across sub-gate covered-sets + zero-overwrite on the genesis). ONE in-circuit
/// M7x verify-and-fold then unions the covered rows (read from each sub's public tail) with
/// the genesis pass-through (anchor row + the node's own un-computed 3-slot block).
///
/// Returns a `CircuitName::C3FoldBatchMergeM7x` proof with c3_fold's exact 4+3*C3_SLOTS public
/// layout => byte-identical slot state to `generate_sequential_c3_fold` over the same inners +
/// slot schedule (the I5a-fix-test e2e arm verifies exactly that), so `c3ab_fold` / `node_fold`
/// / onchain are VK-rebuild-only.
fn m7x_gate_over_genesis(
    prover: &ZkProver,
    acc: &Proof,
    inners: &[&Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inners.len() != 53 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7x gate: expected 53 chain inners (the C3b leaves after the \
             kernel anchor), got {}",
            inners.len()
        )));
    }
    if slot_indices.len() != 54 {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7x gate: expected 54 slot indices (anchor + 53 covered), got \
             {}",
            slot_indices.len()
        )));
    }
    for (i, &s) in slot_indices.iter().enumerate() {
        if s as usize >= total_slots {
            return Err(ZkError::InvalidInput(format!(
                "c3_fold_batch_merge_m7x gate: slot {s} (index {i}) out of range \
                 (total_slots={total_slots})"
            )));
        }
    }
    for i in 0..slot_indices.len() {
        for j in i + 1..slot_indices.len() {
            if slot_indices[i] == slot_indices[j] {
                return Err(ZkError::InvalidInput(format!(
                    "c3_fold_batch_merge_m7x gate: duplicate slot {} (indices {i}, {})",
                    slot_indices[i],
                    j
                )));
            }
        }
    }
    // The artifact's C3_SLOTS = N_PARTIES * L_THRESHOLD of the STAGED circuit build; the
    // compiled json is the single source of truth (mirrors the M7 builder, r55).
    let slots: usize = {
        let circuit_name = CircuitName::C3FoldBatchMergeM7x;
        let jpath = prover
            .circuits_dir(CircuitVariant::Default, artifacts_dir)
            .join(circuit_name.dir_path())
            .join(format!("{}.json", circuit_name.as_str()));
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&jpath)
                .map_err(|e| ZkError::SerializationError(format!("read M7x json: {e}")))?,
        )
        .map_err(|e| ZkError::SerializationError(e.to_string()))?;
        let len = v["abi"]["parameters"]
            .as_array()
            .and_then(|ps| {
                ps.iter().find(|p| {
                    p.get("name") == Some(&serde_json::Value::String("acc_public_inputs".into()))
                })
            })
            .and_then(|p| p.get("type")?.get("length")?.as_u64())
            .ok_or_else(|| {
                ZkError::InvalidInput("M7x json abi: acc_public_inputs length not found".into())
            })?;
        (len - 4) as usize / 3
    };
    if slots != total_slots {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7x gate: staged circuit C3_SLOTS ({slots}) != total_slots \
             ({total_slots}) — rebuild the artifact at the same committee"
        )));
    }
    let sub_vks_b10 = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB10)?;
    let sub_vks_b3 = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchB3)?;
    let merge_vks = C3FoldBatchVks::load(prover, artifacts_dir, CircuitName::C3FoldBatchMergeM7x)?;
    debug_assert_eq!(sub_vks_b10.kernel_vk.key_hash, sub_vks_b3.kernel_vk.key_hash);
    if acc.public_signals.len() / 32 != 4 + 3 * slots {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_merge_m7x gate: kernel genesis public field count {} != {}",
            acc.public_signals.len() / 32,
            4 + 3 * slots
        )));
    }
    // 1) Five B10 sub-gates over the genesis (block j covers rows 1+10j..=10+10j):
    //    sub witness slot vector = (anchor, row 1+10j, ..., row 10+10j) — 11 entries,
    //    the b10 ABI convention (slot_i = slot_indices[i+1]).
    let mut subs: Vec<(CircuitName, Proof)> = Vec::with_capacity(6);
    for j in 0..5usize {
        let blk: Vec<&Proof> = inners[j * 10..j * 10 + 10].to_vec();
        let mut slots11 = Vec::with_capacity(11);
        slots11.push(slot_indices[0]);
        for k in 0..10 {
            slots11.push(slot_indices[1 + j * 10 + k]);
        }
        let sub =
            b10_gate_over_genesis(prover, &acc, &blk, &slots11, slots, e3_id, artifacts_dir)?;
        subs.push((CircuitName::C3FoldBatchB10, sub));
    }
    // 2) One B3 sub-gate over the genesis (rows 51,52,53): 4-entry witness vector
    //    (kernel anchor + 3 covered), the b3 ABI convention.
    {
        let blk: Vec<&Proof> = inners[50..53].to_vec();
        let sub = generate_c3_fold_batch_gate(
            prover,
            CircuitName::C3FoldBatchB3,
            &acc,
            &sub_vks_b3.kernel_vk,
            &blk,
            [
                slot_indices[51],
                slot_indices[52],
                slot_indices[53],
            ],
            slots,
            &format!("{e3_id}-b3g5"),
            artifacts_dir,
        )?;
        subs.push((CircuitName::C3FoldBatchB3, sub));
    }
    // 3) The M7x merge gate: in-circuit-verify all 6 sub-gate proofs + the genesis, fold the
    //    53 covered rows from each sub's public tail (exact-slot membership), pass the other
    //    rows (anchor + the node's own block) through from the genesis.
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    for (idx, (c_name, sub)) in subs.iter().enumerate() {
        let sub_vks = match c_name {
            CircuitName::C3FoldBatchB10 => &sub_vks_b10,
            CircuitName::C3FoldBatchB3 => &sub_vks_b3,
            _ => unreachable!("m7x subs are b10/b3"),
        };
        out.insert(
            format!("vk{idx}"),
            serde_json::to_value(&sub_vks.batch_vk.verification_key).unwrap(),
        );
        out.insert(
            format!("proof{idx}"),
            serde_json::to_value(&bytes_to_field_strings(&sub.data)?).unwrap(),
        );
        out.insert(
            format!("public{idx}"),
            serde_json::to_value(&bytes_to_field_strings(sub.public_signals.as_ref())?).unwrap(),
        );
        out.insert(
            format!("kh{idx}"),
            serde_json::to_value(&sub_vks.batch_vk.key_hash).unwrap(),
        );
    }
    out.insert(
        "acc_vk".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.verification_key).unwrap(),
    );
    out.insert(
        "acc_proof".to_string(),
        serde_json::to_value(&bytes_to_field_strings(&acc.data)?).unwrap(),
    );
    out.insert(
        "acc_public_inputs".to_string(),
        serde_json::to_value(&bytes_to_field_strings(acc.public_signals.as_ref())?).unwrap(),
    );
    out.insert(
        "acc_key_hash".to_string(),
        serde_json::to_value(&merge_vks.kernel_vk.key_hash).unwrap(),
    );
    for s in 0..54u32 {
        out.insert(format!("slot{s}"), serde_json::json!(slot_indices[s as usize]));
    }
    let circuit_name = CircuitName::C3FoldBatchMergeM7x;
    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        &format!("{e3_id}-m7xg0"),
        artifacts_dir,
    )
}

/// N=19 C3b production-schedule tree split as ONE M7x merge (I5a-fix, r61) — the crate
/// surface for the `c3_fold_batch_merge_m7x` circuit.
///
/// `inner_proofs` (exactly 54, POSITIONALLY the production C3b fan-out order): index 0 anchors
/// `slot_indices[0]` (the kernel genesis — for node P this is `W_P[0]`, ANY slot, unlike the
/// legacy `generate_c3_merge_m7` which required slot 0); indices 1..=53 cover
/// `slot_indices[1..=53]` (the public slot array the M7x circuit reads, e.g.
/// `W_P[1..] = W_P \ {W_P[0]}` ascending — the scattered schedule with the node's own 3-slot
/// hole and, for P <= 17, the out-of-window slots 55/56). The sub-block partition is FIXED in
/// the circuit (5 x B10 + 1 x B3 over the 53 covered rows) and is schedule-INDEPENDENT: the
/// covered slots' absolute addresses ride the public `slot_i` params.
///
/// Returns a `CircuitName::C3FoldBatchMergeM7x` proof: 1 kernel + 6 sub-gates + 1 M7x (8
/// top-level proves) replacing the 54-step `c3_fold` chain, byte-identical combined slot state
/// (membership routing + in-circuit disjointness/zero-overwrite asserts).
pub fn generate_c3_merge_m7x(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    slot_indices: &[u32],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if inner_proofs.len() != 54 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m7x: expected exactly 54 inner proofs (anchor + 53 covered), \
             got {}",
            inner_proofs.len()
        )));
    }
    if slot_indices.len() != 54 {
        return Err(ZkError::InvalidInput(format!(
            "generate_c3_merge_m7x: expected exactly 54 slot indices (anchor + 53 covered), \
             got {}",
            slot_indices.len()
        )));
    }
    // Kernel genesis anchoring inner 0 at slot_indices[0] (the circuit stamps the genesis at
    // the given slot; the legacy slot-0 path is the wrapper default).
    let acc = generate_c3_fold_kernel_genesis_at(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
        slot_indices[0],
    )?;
    let refs: Vec<&Proof> = inner_proofs[1..].iter().collect();
    m7x_gate_over_genesis(prover, &acc, &refs, slot_indices, total_slots, e3_id, artifacts_dir)
}

/// Batched c3 fold (I5 productionization, drop-in alternative to ``generate_sequential_c3_fold``):
/// proves the ``c3_fold_batch_n{K+1}`` circuit once for ``K = inner_proofs.len() - 1`` leaves over
/// a fresh kernel genesis, instead of ``K`` sequential ``c3_fold`` steps.
///
/// Semantics mirror the sequential API with ``slot_indices = [0, 1, ..., K]``:
/// ``inner_proofs[0]`` anchors slot 0 (kernel genesis) and the remaining proofs fill slots
/// 1..=K. The returned fold proof verifies the inner proofs against the same accumulator layout
/// as ``generate_sequential_c3_fold``, landing on the identical slot state.
///
/// Constraint: 2..=4 inners (circuits n2/n3/n4 exist; larger trees need the batched-root
/// composition, not a single deeper circuit).
pub fn generate_batched_c3_fold(
    prover: &ZkProver,
    inner_proofs: &[Proof],
    total_slots: usize,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    match inner_proofs.len() {
        2 => CircuitName::C3FoldBatchN2,
        3 => CircuitName::C3FoldBatchN3,
        4 => CircuitName::C3FoldBatchN4,
        _ => {
            return Err(ZkError::InvalidInput(format!(
                "generate_batched_c3_fold: {} inners not supported (need 2..=4; batch the rest at the tree level)",
                inner_proofs.len()
            )))
        }
    };
    let circuit_name = match inner_proofs.len() {
        2 => CircuitName::C3FoldBatchN2,
        _ => match inner_proofs.len() {
            3 => CircuitName::C3FoldBatchN3,
            _ => CircuitName::C3FoldBatchN4,
        },
    };

    let vks = C3FoldVks::load(prover, artifacts_dir)?;

    // Fresh kernel genesis: anchor = first inner proof fills slot 0 (same convention as the
    // sequential chain's first step).
    let anchor = generate_c3_fold_kernel_genesis_proof(
        prover,
        &inner_proofs[0],
        total_slots,
        artifacts_dir,
        &format!("{e3_id}-kernel"),
    )?;

    // Batch noir inputs: avk/aproof/api = kernel genesis; ivk/iprf/c3pi/ikh per leaf.
    let mut out = serde_json::Map::new();
    let mut push = |name: &str, v: serde_json::Value| out.insert(name.to_string(), v);
    for (k, leaf) in inner_proofs[1..].iter().enumerate() {
        let kk = k.to_string();
        push(&format!("ivk{kk}"), serde_json::to_value(&vks.inner_vk.verification_key).unwrap());
        push(
            &format!("iprf{kk}"),
            serde_json::to_value(&bytes_to_field_strings(&leaf.data)?).unwrap(),
        );
        push(
            &format!("c3pi{kk}"),
            serde_json::to_value(&[
                extract_single_field(leaf, "input", field_keys::EXPECTED_PK_COMMITMENT, "inner ShareEncryption proof")?,
                extract_single_field(leaf, "input", field_keys::EXPECTED_MESSAGE_COMMITMENT, "inner ShareEncryption proof")?,
                extract_single_field(leaf, "output", field_keys::CT_COMMITMENT, "inner ShareEncryption proof")?,
            ])
            .unwrap(),
        );
        push(&format!("ikh{kk}"), serde_json::to_value(&vks.inner_vk.key_hash).unwrap());
    }
    push("avk", serde_json::to_value(&vks.kernel_vk.verification_key).unwrap());
    push("aproof", serde_json::to_value(&bytes_to_field_strings(&anchor.data)?).unwrap());
    push(
        "api",
        serde_json::to_value(&bytes_to_field_strings(anchor.public_signals.as_ref())?).unwrap(),
    );
    push("akh", serde_json::to_value(&vks.kernel_vk.key_hash).unwrap());
    push("gen_hash0", serde_json::json!("0"));
    push("gen_hash1", serde_json::json!("0"));
    drop(push); // (closure borrows `out`; JSON object is built above before this fns below)

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(circuit_name.dir_path())
        .join(format!("{}.json", circuit_name.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;

    let json = serde_json::Value::Object(out);
    let input_map = inputs_json_to_input_map(&json)?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;

    prover.generate_recursive_aggregation_bin_proof(
        circuit_name,
        &witness,
        e3_id,
        artifacts_dir,
    )
}
