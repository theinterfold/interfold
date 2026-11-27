// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Accumulation integration tests: a node's C3 batch through the C3 Chonk stacks, tubes and
//! accumulate proofs ([`generate_c3_chonk_chain`]), and a decryption's C6 column through the C6
//! Chonk stack, tube and root ([`generate_c6_chonk_root`]), proven and verified natively under
//! [`CircuitVariant::Default`] (`noir-recursive-no-zk` VKs — see `crates/zk/build`), with slot
//! counts read from the compiled circuits.
//!
//! The node-fold pipeline ([`CircuitName::C2abFold`] … [`CircuitName::NodeFold`]), which consumes
//! the C3 Chonk chains, is proven in `node_fold_correlated_e2e_tests.rs`.
//!
//! - [`c3_chonk_chain_proves_and_exposes_its_key_list`]: two inner `ShareEncryption` proofs →
//!   [`generate_c3_chonk_chain`].
//! - [`c3_chonk_rejects_a_corrupted_leaf_or_a_substituted_key`]: a leaf whose claimed row differs
//!   from its proof, or a stack stage handed another stage's key, never yields a chain.
//! - [`c3_chonk_accumulate_and_c3ab_reject_children_of_the_wrong_kind`]: an accumulator merges a
//!   third tube as the left child; the accumulate step and `c3ab_fold` reject children of the
//!   wrong kind, and a tube under the accumulator's key.
//! - [`c6_chonk_root_proves_and_binds_the_decryption_aggregator`]: `T + 1` inner
//!   `ThresholdShareDecryption` proofs → [`generate_c6_chonk_root`], whose key list hashes to the
//!   anchored C6 tree the decryption aggregator pins; a root under another key cannot claim it.
//! - [`c6_chonk_rejects_a_corrupted_leaf_or_a_substituted_key`]: a leaf whose claimed row differs
//!   from its proof, or a stack stage handed another stage's key, never yields a root.
//! - [`c6_chonk_app_rejects_a_shared_slot_an_out_of_range_slot_and_a_foreign_domain`]: the app
//!   constrains slots and the domain, each next to an honest twin that solves.

mod common;
#[allow(dead_code)]
#[path = "common/recursive_vk_substitution.rs"]
mod recursive_vk_substitution;

use common::{
    find_bb, setup_c3_chonk_circuits, setup_c6_chonk_circuits, setup_compiled_circuit,
    setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::Proof;
use e3_fhe_params::BfvPreset;
use e3_zk_config::DkgInputType;
use e3_zk_config::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_config::{CircuitName, CircuitVariant};
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, generate_c3_chonk_accumulate,
    generate_c3_chonk_chain_with_substituted_key, generate_c3_chonk_tubes,
    generate_c6_chonk_root_with_substituted_key, load_vk_artifacts,
};
use e3_zk_prover::{
    generate_c3_chonk_chain, generate_c6_chonk_root, Provable, ZkBackend, ZkError, ZkProver,
};
use e3_zk_prover::{
    ShareEncryptionCircuit, ThresholdShareDecryptionCircuit as ShareDecryptionCircuit,
};
use recursive_vk_substitution::{fields, substitute_proof, vk_hash, witness};
use serde_json::json;

/// Expected C3 slot count when circuits are compiled for the minimum committee (N=3, T=1): one
/// slot per party and insecure-64 threshold modulus (3 × 3).
const MINIMUM_C3_SLOTS: usize = 9;

/// Reads `C3_SLOTS` from the compiled `c3_chonk_tube` ABI (`stack_outputs` is `3 * C3_SLOTS + 4`).
fn c3_total_slots_from_compiled_json() -> usize {
    let path = e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/recursive_aggregation/c3_chonk_tube/target/c3_chonk_tube.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {} (run `pnpm build:circuits --group recursive_aggregation,chonk`)",
            path.display(),
            e
        )
    });
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
    let len = v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| p.get("name") == Some(&serde_json::Value::String("stack_outputs".into())))
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c3_chonk_tube.json: abi.parameters.stack_outputs.length") as usize;
    assert!(
        len >= 4 && (len - 4).is_multiple_of(3),
        "unexpected stack_outputs length {len} (expected 3 * slots + 4)"
    );
    (len - 4) / 3
}

/// A prover with the C3 Chonk circuits set up, and two inner C3 proofs.
struct C3Fixture {
    prover: ZkProver,
    inners: [Proof; 2],
    total_slots: usize,
    artifacts_dir: String,
    _backend: ZkBackend,
    _temp: tempfile::TempDir,
}

async fn c3_fixture() -> C3Fixture {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb()
        .await
        .expect("missing required test prerequisite: bb not found");
    let (backend, temp) = setup_test_prover(&bb).await;
    setup_compiled_circuit(&backend, "dkg", "share_encryption").await;
    setup_c3_chonk_circuits(&backend).await;
    let prover = ZkProver::new(&backend);

    let total_slots = c3_total_slots_from_compiled_json();
    assert_eq!(
        total_slots, MINIMUM_C3_SLOTS,
        "circuits compiled for a non-minimum committee; rebuild with `pnpm build:circuits --committee minimum`"
    );
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let sd = preset.search_defaults().unwrap();
    let (threshold_params, dkg_params) = preset.build_pair().unwrap();
    let inners = [0, 1].map(|i| {
        let sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            preset,
            committee.clone(),
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let inner = ShareEncryptionCircuit
            .prove_with_variant(
                &prover,
                &e3_zk_config::dkg::share_encryption::Configs::for_preset(preset).unwrap(),
                &sample,
                &format!("e3-c3chonk-inner-{i}"),
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("inner ShareEncryption proof");
        assert_eq!(inner.circuit, CircuitName::ShareEncryption);
        inner
    });
    C3Fixture {
        prover,
        inners,
        total_slots,
        artifacts_dir,
        _backend: backend,
        _temp: temp,
    }
}

/// Two leaves go into two stacks, their tubes into one accumulate proof. It exposes the C3 Chonk
/// key list in the order the VK tree hashes it (`crates/zk/build/src/vk_tree.rs`), with the keys
/// each stage appended, and the leaves' rows in their slots.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_chonk_chain_proves_and_exposes_its_key_list() {
    let f = c3_fixture().await;
    let chain = generate_c3_chonk_chain(
        &f.prover,
        CircuitName::ShareEncryption,
        &f.inners,
        &[0u32, 1u32],
        f.total_slots,
        "e3-c3chonk-chain",
        &f.artifacts_dir,
    )
    .expect("C3 Chonk chain");
    assert_eq!(chain.circuit, CircuitName::C3ChonkAccumulate);
    assert!(
        f.prover
            .verify_rollup_proof(&chain, "e3-c3chonk-chain", &f.artifacts_dir)
            .expect("verify_rollup_proof invocation"),
        "the chain proof should verify under its rollup VK"
    );

    let default_dir = f
        .prover
        .circuits_dir(CircuitVariant::Default, &f.artifacts_dir);
    let leaf = load_vk_artifacts(
        &f.prover
            .circuits_dir(CircuitVariant::Recursive, &f.artifacts_dir),
        CircuitName::ShareEncryption,
    )
    .unwrap();
    let key = |circuit| load_vk_artifacts(&default_dir, circuit).unwrap().key_hash;
    let public = fields(&chain);
    assert_eq!(public.len(), 7 + 3 * f.total_slots);
    assert_eq!(
        public[..7],
        [
            key(CircuitName::C3ChonkAccumulate),
            key(CircuitName::C3ChonkTube),
            key(CircuitName::C3ChonkHidingKernel),
            leaf.key_hash,
            key(CircuitName::C3ChonkApp),
            key(CircuitName::C3ChonkInitKernel),
            key(CircuitName::C3ChonkTailKernel),
        ]
    );

    let zero = format!("0x{}", "0".repeat(64));
    for column in 0..3 {
        for slot in 0..f.total_slots {
            let expected = f
                .inners
                .get(slot)
                .map_or(zero.clone(), |inner| fields(inner)[column].clone());
            assert_eq!(
                public[7 + column * f.total_slots + slot],
                expected,
                "column {column}, slot {slot}"
            );
        }
    }
    for i in 0..2 {
        f.prover.cleanup(&format!("e3-c3chonk-inner-{i}")).unwrap();
    }
}

/// A stack cannot carry a leaf whose claimed row differs from what it proved, nor a stage passed
/// off under another stage's key: bb rejects the stack, or cannot even accumulate it.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_chonk_rejects_a_corrupted_leaf_or_a_substituted_key() {
    let f = c3_fixture().await;
    let slots = [0u32, 1u32];

    // The leaf's last public signal is its `ct_commitment`, the row the stack writes for it.
    let mut signals = f.inners[1].public_signals.extract_bytes();
    *signals.last_mut().unwrap() ^= 1;
    let corrupted = Proof::new(
        f.inners[1].circuit,
        f.inners[1].data.clone(),
        e3_utils::ArcBytes::from_bytes(&signals),
    );
    let error = generate_c3_chonk_chain(
        &f.prover,
        CircuitName::ShareEncryption,
        &[f.inners[0].clone(), corrupted],
        &slots,
        f.total_slots,
        "c3-corrupted-leaf",
        &f.artifacts_dir,
    )
    .expect_err("a leaf whose claimed row differs from its proof must not reach a chain");
    assert!(
        matches!(&error, ZkError::ProofRejected(message)
            if message.contains("Failed to verify the generated proof")),
        "{error:?}"
    );

    // The init kernel's key has a different number of public inputs than the app's, so bb cannot
    // accumulate the stack. The kernels share a shape: the stack proves, and bb rejects it.
    let error = generate_c3_chonk_chain_with_substituted_key(
        &f.prover,
        &f.inners,
        &slots,
        f.total_slots,
        (0, 1),
        "c3-key-0-as-1",
        &f.artifacts_dir,
    )
    .expect_err("the app claimed under the init kernel's key must not reach a chain");
    assert!(
        matches!(&error, ZkError::ProveFailed(message) if message.contains("IO size mismatch")),
        "{error:?}"
    );
    for (stage, from) in [(1, 2), (2, 1)] {
        let error = generate_c3_chonk_chain_with_substituted_key(
            &f.prover,
            &f.inners,
            &slots,
            f.total_slots,
            (stage, from),
            &format!("c3-key-{stage}-as-{from}"),
            &f.artifacts_dir,
        )
        .expect_err("a kernel claimed under the other kernel's key must not reach a chain");
        assert!(
            matches!(&error, ZkError::ProofRejected(message)
                if message.contains("Failed to verify the generated proof")),
            "stage {stage} as {from}: {error:?}"
        );
    }
    for i in 0..2 {
        f.prover.cleanup(&format!("e3-c3chonk-inner-{i}")).unwrap();
    }
}

/// The witness fails on a constraint of the circuit. The solver reports only that a constraint
/// failed, so each case also solves its honest twin, which differs in the one edit under test.
/// nargo reports an unsatisfied constraint as a failed assertion when the opcode carries an
/// assertion payload, and as an unsolvable program when the compiler merged the `assert` into an
/// opcode without one (for example an equality with a hash output).
fn assert_witness_rejected(result: Result<Vec<u8>, ZkError>, case: &str) {
    match result {
        Err(ZkError::WitnessGenerationFailed(message)) => assert!(
            message == "Failed assertion"
                || message == "Failed to solve program: 'Cannot satisfy constraint'",
            "{case}: expected an unsatisfied constraint, got {message}"
        ),
        other => panic!("{case}: expected an unsatisfied constraint, got {other:?}"),
    }
}

/// `c3_chonk_accumulate` takes a tube on the right, and a tube or an accumulator on the left;
/// `c3ab_fold` takes accumulators. An honest accumulator merges a third, disjoint tube as the chain
/// does from its third stack on. The checks are constraints of the circuits, so each witness
/// fails where its honest twin solves. A tube handed to the accumulate step under the
/// accumulator's key is a statement the circuit's constraints allow, so only bb's recursive
/// verification rejects it.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c3_chonk_accumulate_and_c3ab_reject_children_of_the_wrong_kind() {
    let f = c3_fixture().await;
    let tubes = generate_c3_chonk_tubes(
        &f.prover,
        &f.inners,
        &[0u32, 1u32],
        f.total_slots,
        "e3-c3chonk-tubes",
        &f.artifacts_dir,
    )
    .expect("C3 Chonk tubes");
    assert_eq!(tubes.len(), 2);
    assert!(tubes.iter().all(|t| t.circuit == CircuitName::C3ChonkTube));
    let accumulator = generate_c3_chonk_accumulate(
        &f.prover,
        &tubes[0],
        &tubes[1],
        f.total_slots,
        "e3-c3chonk-accumulate",
        &f.artifacts_dir,
    )
    .expect("honest accumulate step");
    assert!(f
        .prover
        .verify_rollup_proof(&accumulator, "e3-c3chonk-accumulate", &f.artifacts_dir)
        .unwrap());

    // From the third tube on, the chain takes an accumulator as the left child: a small
    // committee's 54 leaves fill three stacks. A tube over a third, disjoint slot merges into it.
    let third = generate_c3_chonk_tubes(
        &f.prover,
        &f.inners[..1],
        &[2u32],
        f.total_slots,
        "e3-c3chonk-third-tube",
        &f.artifacts_dir,
    )
    .expect("one disjoint tube");
    assert_eq!(third.len(), 1);
    let deeper = generate_c3_chonk_accumulate(
        &f.prover,
        &accumulator,
        &third[0],
        f.total_slots,
        "e3-c3chonk-accumulate-deeper",
        &f.artifacts_dir,
    )
    .expect("an accumulator as the left child");
    assert!(f
        .prover
        .verify_rollup_proof(&deeper, "e3-c3chonk-accumulate-deeper", &f.artifacts_dir)
        .unwrap());
    let public = fields(&deeper);
    assert_eq!(public[..7], fields(&accumulator)[..7]);
    let zero = format!("0x{}", "0".repeat(64));
    let leaves = [&f.inners[0], &f.inners[1], &f.inners[0]];
    for column in 0..3 {
        for slot in 0..f.total_slots {
            let expected = leaves
                .get(slot)
                .map_or(zero.clone(), |inner| fields(inner)[column].clone());
            assert_eq!(
                public[7 + column * f.total_slots + slot],
                expected,
                "column {column}, slot {slot}"
            );
        }
    }

    let default_dir = f
        .prover
        .circuits_dir(CircuitVariant::Default, &f.artifacts_dir);
    let tube_vk = load_vk_artifacts(&default_dir, CircuitName::C3ChonkTube).unwrap();
    let accumulate_vk = load_vk_artifacts(&default_dir, CircuitName::C3ChonkAccumulate).unwrap();
    let compiled = |group: &str, name: &str| {
        e3_zk_prover::test_utils::workspace_root()
            .join(format!("circuits/bin/{group}/{name}/target/{name}.json"))
    };
    let accumulate_path = compiled("recursive_aggregation", "c3_chonk_accumulate");
    let accumulate_input = |left: (&Proof, &[String]), right: &Proof| {
        json!({
            "left_vk": left.1,
            "left_proof": fold_witness_field_strings(&left.0.data).unwrap(),
            "left_public": fields(left.0),
            "right_vk": tube_vk.verification_key,
            "right_proof": fold_witness_field_strings(&right.data).unwrap(),
            "right_public": fields(right),
            "own_key_hash": accumulate_vk.key_hash,
        })
    };
    witness(
        &accumulate_path,
        &accumulate_input((&tubes[0], &tube_vk.verification_key), &tubes[1]),
    )
    .expect("honest accumulate witness");

    // The right child must be a tube: an accumulator names a different key as its own.
    assert_witness_rejected(
        witness(
            &accumulate_path,
            &accumulate_input((&tubes[0], &tube_vk.verification_key), &accumulator),
        ),
        "the right child must be a tube",
    );
    // The left child must be a tube or an accumulator: name the hiding kernel's key as its own.
    let mut neither = accumulate_input((&tubes[0], &tube_vk.verification_key), &tubes[1]);
    let hiding_key = fields(&tubes[0])[2].clone();
    neither["left_public"][0] = json!(hiding_key);
    assert_witness_rejected(
        witness(&accumulate_path, &neither),
        "the left child must be a tube or this accumulator",
    );

    // The key list is not enough: a tube verified under the accumulator's key is still rejected.
    let relabelled = Proof::new(
        CircuitName::C3ChonkAccumulate,
        tubes[0].data.clone(),
        tubes[0].public_signals.clone(),
    );
    let error = generate_c3_chonk_accumulate(
        &f.prover,
        &relabelled,
        &tubes[1],
        f.total_slots,
        "e3-c3chonk-wrong-left-key",
        &f.artifacts_dir,
    )
    .expect_err("a tube verified under the accumulator's key must be rejected");
    assert!(matches!(&error, ZkError::ProofRejected(_)), "{error:?}");

    // `c3ab_fold` closes accumulators: a chain that ends on a bare tube is rejected.
    let c3ab_path = compiled("recursive_aggregation", "c3ab_fold");
    let c3ab_input = |a: (&Proof, &[String]), b: (&Proof, &[String])| {
        json!({
            "c3a_vk": a.1,
            "c3a_proof": fold_witness_field_strings(&a.0.data).unwrap(),
            "c3a_public": fields(a.0),
            "c3b_vk": b.1,
            "c3b_proof": fold_witness_field_strings(&b.0.data).unwrap(),
            "c3b_public": fields(b.0),
            "c3a_key_hash": fields(a.0)[0],
            "c3b_key_hash": fields(b.0)[0],
        })
    };
    let acc = (&accumulator, accumulate_vk.verification_key.as_slice());
    let tube = (&tubes[0], tube_vk.verification_key.as_slice());
    witness(&c3ab_path, &c3ab_input(acc, acc)).expect("honest c3ab witness");
    let deep = (&deeper, accumulate_vk.verification_key.as_slice());
    witness(&c3ab_path, &c3ab_input(deep, deep)).expect("honest c3ab witness over a deeper chain");
    assert_witness_rejected(
        witness(&c3ab_path, &c3ab_input(tube, acc)),
        "the chain must end on an accumulator",
    );
    assert_witness_rejected(
        witness(&c3ab_path, &c3ab_input(acc, tube)),
        "the chain must end on an accumulator",
    );
    for i in 0..2 {
        f.prover.cleanup(&format!("e3-c3chonk-inner-{i}")).unwrap();
    }
}

/// Expected C6 slot count when circuits are compiled for the minimum committee (N=3, T=1): one slot
/// per party that reconstructs, `T + 1`.
const MINIMUM_C6_SLOTS: usize = 2;

/// Reads `T + 1` from the compiled `c6_chonk_app` ABI (the length of `slot_indices`).
fn c6_total_slots_from_compiled_json() -> usize {
    let path = e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/chonk/target/c6_chonk_app.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {} (run `pnpm build:circuits --group chonk`)",
            path.display(),
            e
        )
    });
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
    v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| p.get("name") == Some(&serde_json::Value::String("slot_indices".into())))
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c6_chonk_app.json: abi.parameters.slot_indices.length") as usize
}

/// A prover with the C6 Chonk circuits set up, and one inner C6 proof.
struct C6Fixture {
    prover: ZkProver,
    inner: Proof,
    total_slots: usize,
    artifacts_dir: String,
    _backend: ZkBackend,
    _temp: tempfile::TempDir,
}

async fn c6_fixture() -> C6Fixture {
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let preset = BfvPreset::InsecureThreshold64;
    let bb = find_bb()
        .await
        .expect("missing required test prerequisite: bb not found");
    let (backend, temp) = setup_test_prover(&bb).await;
    setup_compiled_circuit(&backend, "threshold", "share_decryption").await;
    setup_recursive_aggregation_fold_circuit(&backend, CircuitName::DecryptionAggregator).await;
    setup_c6_chonk_circuits(&backend).await;
    let prover = ZkProver::new(&backend);

    let total_slots = c6_total_slots_from_compiled_json();
    assert_eq!(
        total_slots, MINIMUM_C6_SLOTS,
        "circuits compiled for a non-minimum committee; rebuild with `pnpm build:circuits --committee minimum`"
    );
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let (params, _) = preset.build_pair().unwrap();
    let sample =
        e3_zk_samples::threshold::share_decryption::generate(&params, preset, committee).unwrap();
    let inner = ShareDecryptionCircuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::share_decryption::Configs::for_preset(preset).unwrap(),
            &sample,
            "e3-c6chonk-inner",
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("inner ThresholdShareDecryption proof");
    assert_eq!(inner.circuit, CircuitName::ThresholdShareDecryption);
    C6Fixture {
        prover,
        inner,
        total_slots,
        artifacts_dir,
        _backend: backend,
        _temp: temp,
    }
}

/// One inner proof in every slot, so every slot commits to the same ciphertext.
fn c6_leaves(f: &C6Fixture) -> (Vec<Proof>, Vec<u32>) {
    (
        vec![f.inner.clone(); f.total_slots],
        (0..f.total_slots as u32).collect(),
    )
}

/// The root of a decryption's `T + 1` leaves carries their columns and a key list hashing to the
/// anchored C6 tree, which `decryption_aggregator` pins. A root under another key verifies in the
/// aggregator's own constraints but cannot claim that tree.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_chonk_root_proves_and_binds_the_decryption_aggregator() {
    let f = c6_fixture().await;
    let default_dir = f
        .prover
        .circuits_dir(CircuitVariant::Default, &f.artifacts_dir);
    let final_path =
        default_dir.join("recursive_aggregation/decryption_aggregator/decryption_aggregator.json");
    let canonical_tree = format!(
        "0x{}",
        hex::encode(
            std::fs::read(default_dir.join("recursive_aggregation/c6_fold/c6_fold.vk_tree_hash"))
                .unwrap()
        )
    );
    let (inners, slots) = c6_leaves(&f);
    let root = generate_c6_chonk_root(
        &f.prover,
        &inners,
        &slots,
        f.total_slots,
        "e3-c6chonk-root",
        &f.artifacts_dir,
    )
    .expect("C6 Chonk root");
    assert_eq!(root.circuit, CircuitName::C6ChonkRoot);
    assert!(
        f.prover
            .verify_fold_proof(&root, "e3-c6chonk-root", 0, &f.artifacts_dir)
            .expect("verify_fold_proof invocation"),
        "the root proof should verify under its VK"
    );

    // The root exposes the key list hash, the domain limbs, then the sk, esm, ct and d columns.
    let leaf = fields(&f.inner);
    let public = fields(&root);
    assert_eq!(public.len(), 3 + 4 * f.total_slots);
    assert_eq!(public[1..3], leaf[3..5]);
    for (column, field) in [0, 1, 2, 5].into_iter().enumerate() {
        for slot in 0..f.total_slots {
            assert_eq!(
                public[3 + column * f.total_slots + slot],
                leaf[field],
                "column {column}, slot {slot}"
            );
        }
    }
    let root_vk = load_vk_artifacts(&default_dir, CircuitName::C6ChonkRoot).unwrap();
    assert_eq!(
        vk_hash(&[root_vk.key_hash.clone(), public[0].clone()]),
        canonical_tree,
        "the real C6 Chonk circuits must hash to the anchored C6 tree"
    );

    // This alternate C7 relation isolates the C6 tree boundary. The EVM suite checks the separate
    // C7 pin.
    let mut c7_public = vec![leaf[5].clone(); f.total_slots];
    c7_public.extend((1..=f.total_slots).map(|id| id.to_string()));
    c7_public.extend(vec!["0".to_owned(); MAX_MSG_NON_ZERO_COEFFS]);
    let c7 = substitute_proof(
        &f.prover,
        CircuitName::DecryptedSharesAggregation,
        CircuitVariant::Default,
        &c7_public,
        None,
        "c6-tree-c7",
    );
    let addresses: Vec<_> = (1..=3)
        .map(|i| alloy::primitives::Address::from_word(alloy::primitives::U256::from(i).into()))
        .collect();
    let (committee_hi, committee_lo) = e3_committee_hash::committee_hash_field_hex(&addresses);
    let final_input = |vk: &[String], vk_hash: &str, proof: &Proof, tree: &str| {
        json!({
            "c6_root_vk": vk,
            "c6_root_vk_hash": vk_hash,
            "c6_root_proof": fold_witness_field_strings(&proof.data).unwrap(),
            "c6_root_public": fields(proof),
            "c7_vk": c7.vk,
            "c7_proof": fold_witness_field_strings(&c7.proof.data).unwrap(),
            "c7_public": fields(&c7.proof),
            "c6_fold_key_hash": tree,
            "c7_key_hash": c7.key_hash,
            "committee_members": ["1", "2", "3"],
            "committee_hash_hi": committee_hi,
            "committee_hash_lo": committee_lo,
            "domain_hi": leaf[3],
            "domain_lo": leaf[4],
            "ciphertext_commitment": leaf[2],
        })
    };
    witness(
        &final_path,
        &final_input(
            &root_vk.verification_key,
            &root_vk.key_hash,
            &root,
            &canonical_tree,
        ),
    )
    .expect("the real C6 Chonk root claims the canonical tree");

    let fake_root = substitute_proof(
        &f.prover,
        CircuitName::C6ChonkRoot,
        CircuitVariant::Default,
        &public,
        None,
        "c6-tree-root",
    );
    let fake_tree = vk_hash(&[fake_root.key_hash.clone(), public[0].clone()]);
    witness(
        &final_path,
        &final_input(
            &fake_root.vk,
            &fake_root.key_hash,
            &fake_root.proof,
            &fake_tree,
        ),
    )
    .expect("a substituted root is internally consistent under its own tree");
    assert_witness_rejected(
        witness(
            &final_path,
            &final_input(
                &fake_root.vk,
                &fake_root.key_hash,
                &fake_root.proof,
                &canonical_tree,
            ),
        ),
        "a substituted C6 root must not claim the deployment's canonical tree anchor",
    );
    f.prover.cleanup("e3-c6chonk-inner").unwrap();
}

/// A stack cannot carry a leaf whose claimed row differs from what it proved, nor a stage passed
/// off under another stage's key: bb rejects the stack, or cannot even accumulate it.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_chonk_rejects_a_corrupted_leaf_or_a_substituted_key() {
    let f = c6_fixture().await;
    let (inners, slots) = c6_leaves(&f);

    // The leaf's last public signal is its `d_commitment`, a column the stack writes for it.
    let mut signals = f.inner.public_signals.extract_bytes();
    *signals.last_mut().unwrap() ^= 1;
    let corrupted = Proof::new(
        f.inner.circuit,
        f.inner.data.clone(),
        e3_utils::ArcBytes::from_bytes(&signals),
    );
    let mut with_corrupted = inners.clone();
    with_corrupted[f.total_slots - 1] = corrupted;
    let error = generate_c6_chonk_root(
        &f.prover,
        &with_corrupted,
        &slots,
        f.total_slots,
        "c6-corrupted-leaf",
        &f.artifacts_dir,
    )
    .expect_err("a leaf whose claimed row differs from its proof must not reach a root");
    assert!(
        matches!(&error, ZkError::ProofRejected(message)
            if message.contains("Failed to verify the generated proof")),
        "{error:?}"
    );

    // The init kernel's key has a different number of public inputs than the app's, so bb cannot
    // accumulate the stack. The kernels share a shape: the stack proves, and bb rejects it.
    let error = generate_c6_chonk_root_with_substituted_key(
        &f.prover,
        &inners,
        &slots,
        f.total_slots,
        (0, 1),
        "c6-key-0-as-1",
        &f.artifacts_dir,
    )
    .expect_err("the app claimed under the init kernel's key must not reach a root");
    assert!(
        matches!(&error, ZkError::ProveFailed(message) if message.contains("IO size mismatch")),
        "{error:?}"
    );
    for (stage, from) in [(1, 2), (2, 1)] {
        let error = generate_c6_chonk_root_with_substituted_key(
            &f.prover,
            &inners,
            &slots,
            f.total_slots,
            (stage, from),
            &format!("c6-key-{stage}-as-{from}"),
            &f.artifacts_dir,
        )
        .expect_err("a kernel claimed under the other kernel's key must not reach a root");
        assert!(
            matches!(&error, ZkError::ProofRejected(message)
                if message.contains("Failed to verify the generated proof")),
            "stage {stage} as {from}: {error:?}"
        );
    }

    // The honest leaves, unchanged but for those edits, make a root that verifies.
    let root = generate_c6_chonk_root(
        &f.prover,
        &inners,
        &slots,
        f.total_slots,
        "c6-honest-twin",
        &f.artifacts_dir,
    )
    .expect("honest twin");
    assert!(f
        .prover
        .verify_fold_proof(&root, "c6-honest-twin", 0, &f.artifacts_dir)
        .unwrap());
    f.prover.cleanup("e3-c6chonk-inner").unwrap();
}

/// The app places each leaf in its own slot of `0..T + 1` and takes one domain for all of them.
/// The checks are constraints of the circuit, so each witness fails where its honest twin, which
/// differs in the one edit under test, solves.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_chonk_app_rejects_a_shared_slot_an_out_of_range_slot_and_a_foreign_domain() {
    let f = c6_fixture().await;
    let leaf_vk = load_vk_artifacts(
        &f.prover
            .circuits_dir(CircuitVariant::Recursive, &f.artifacts_dir),
        CircuitName::ThresholdShareDecryption,
    )
    .unwrap();
    let app_path = e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/chonk/target/c6_chonk_app.json");
    let leaf = fields(&f.inner);
    let app_input = |publics: Vec<Vec<String>>, slots: Vec<u32>| {
        json!({
            "leaf_vk": leaf_vk.verification_key,
            "leaf_key_hash": leaf_vk.key_hash,
            "proofs": vec![fold_witness_field_strings(&f.inner.data).unwrap(); f.total_slots],
            "c6_public_inputs": publics,
            "slot_indices": slots,
        })
    };
    let honest_publics = vec![leaf.clone(); f.total_slots];
    let honest_slots: Vec<u32> = (0..f.total_slots as u32).collect();
    witness(
        &app_path,
        &app_input(honest_publics.clone(), honest_slots.clone()),
    )
    .expect("honest app witness");

    let mut shared = honest_slots.clone();
    shared[1] = shared[0];
    assert_witness_rejected(
        witness(&app_path, &app_input(honest_publics.clone(), shared)),
        "two leaves cannot share a slot",
    );
    let mut out_of_range = honest_slots.clone();
    out_of_range[1] = f.total_slots as u32;
    assert_witness_rejected(
        witness(&app_path, &app_input(honest_publics.clone(), out_of_range)),
        "a slot past the last is rejected",
    );
    let mut foreign = honest_publics.clone();
    foreign[1][4] = "1".to_owned();
    assert_witness_rejected(
        witness(&app_path, &app_input(foreign, honest_slots)),
        "every leaf must carry the first leaf's domain",
    );
    f.prover.cleanup("e3-c6chonk-inner").unwrap();
}
