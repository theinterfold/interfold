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
        slot_index: 0,
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

/// VK artifacts for the production-ABI (`c3_fold_batch_b2`) gate. The b2 gate is sized by
/// C3_SLOTS like `c3_fold` (loaded from the standard per-committee artifacts dir).
pub(crate) struct C3FoldBatchB2Vks {
    inner_vk: vk::VkArtifacts,
    b2_vk: vk::VkArtifacts,
    kernel_vk: vk::VkArtifacts,
}

impl C3FoldBatchB2Vks {
    fn load(prover: &ZkProver, artifacts_dir: &str) -> Result<Self, ZkError> {
        Ok(Self {
            inner_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Recursive, artifacts_dir),
                CircuitName::ShareEncryption,
            )?,
            b2_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3FoldBatchB2,
            )?,
            kernel_vk: vk::load_vk_artifacts(
                &prover.circuits_dir(CircuitVariant::Default, artifacts_dir),
                CircuitName::C3FoldKernel,
            )?,
        })
    }
}

/// One `c3_fold_batch_b2` gate over a prior accumulator (kernel genesis or a prior b2 gate).
///
/// `anchor_vk` selects which VK the in-circuit `verify_honk_proof_non_zk` runs against: the FIRST
/// gate anchors the `C3FoldKernel` genesis proof (kernel VK), every LATER gate anchors a PRIOR
/// `C3FoldBatchB2` proof (b2 VK) — so the anchor VK follows the anchor proof's circuit.
///
/// `is_first_step` is `false` here: the gate always runs over a prior accumulator that already owns
/// slot 0; its covered slots must be zero in that anchor (in-circuit assert). The emitted public
/// tuple is `c3_fold`'s `([C3_SLOTS]; [C3_SLOTS]; [C3_SLOTS])` — the same public ABI `c3ab_fold`
/// binds against — so chaining b2 gates replaces a tail of the recursive `c3_fold` chain with no
/// downstream circuit edits (VK rebuild only).
fn generate_c3_fold_batch_b2_gate(
    prover: &ZkProver,
    acc: &Proof,
    anchor_vk: &vk::VkArtifacts,
    inner_a: &Proof,
    inner_b: &Proof,
    slot_a: u32,
    slot_b: u32,
    total_slots: usize,
    job_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    // One field = 32 bytes (`bytes_to_field_strings` chunk size).
    const BYTES_PER_FIELD: usize = 32;
    let expected_fields = 4 + 3 * total_slots;
    if acc.public_signals.len() / BYTES_PER_FIELD != expected_fields {
        return Err(ZkError::InvalidInput(format!(
            "c3_fold_batch_b2 gate: prior accumulator public field count {} != expected {}",
            acc.public_signals.len() / BYTES_PER_FIELD,
            expected_fields,
        )));
    }
    let vks = C3FoldBatchB2Vks::load(prover, artifacts_dir)?;
    let mut out = serde_json::Map::<String, serde_json::Value>::new();
    // Field-name keys: the Noir b2 gate declares params vk0/proof0/c3a/kh0/vk1/proof1/c3b/kh1.
    let leaf =
        |out: &mut serde_json::Map<String, serde_json::Value>, idx: &str, c3: &str, leaf: &Proof| {
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
                c3.to_string(),
                serde_json::to_value(&c3_public_inputs)
                    .map_err(|e| ZkError::SerializationError(e.to_string()))?,
            );
            out.insert(
                format!("kh{idx}"),
                serde_json::to_value(&vks.inner_vk.key_hash)
                    .map_err(|e| ZkError::SerializationError(e.to_string()))?,
            );
            Ok::<(), ZkError>(())
        };
    leaf(&mut out, "0", "c3a", inner_a)?;
    leaf(&mut out, "1", "c3b", inner_b)?;
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
    out.insert("slot0".into(), serde_json::json!(slot_a));
    out.insert("slot1".into(), serde_json::json!(slot_b));

    let circuit_path = prover
        .circuits_dir(CircuitVariant::Default, artifacts_dir)
        .join(CircuitName::C3FoldBatchB2.dir_path())
        .join(format!("{}.json", CircuitName::C3FoldBatchB2.as_str()));
    let compiled = CompiledCircuit::from_file(&circuit_path)?;
    let input_map = inputs_json_to_input_map(&serde_json::Value::Object(out))?;
    let witness = WitnessGenerator::new().generate_witness(&compiled, input_map)?;
    prover.generate_recursive_aggregation_bin_proof(
        CircuitName::C3FoldBatchB2,
        &witness,
        job_id,
        artifacts_dir,
    )
}

/// Production-ABI batched C3 fold — a drop-in alternative to [`generate_sequential_c3_fold`].
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
    let vks = C3FoldBatchB2Vks::load(prover, artifacts_dir)?;
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
        let anchor_vk = if b == 0 { &vks.kernel_vk } else { &vks.b2_vk };
        let job_id = format!("{e3_id}-b2g{b}");
        cur = generate_c3_fold_batch_b2_gate(
            prover,
            &cur,
            anchor_vk,
            &inner_proofs[a],
            &inner_proofs[z],
            slot_indices[a],
            slot_indices[z],
            total_slots,
            &job_id,
            artifacts_dir,
        )?;
    }
    Ok(cur)
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
