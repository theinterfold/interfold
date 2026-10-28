// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C6 accumulation integration test: a decryption's `T + 1` C6 proofs through the C6 Chonk stack,
//! tube and root ([`generate_c6_chonk_root`]), verified under [`CircuitVariant::Default`]
//! (`noir-recursive-no-zk` VKs — see `crates/zk/build`), and the decryption aggregator's binding
//! of that root to the anchored C6 tree.
//!
//! The node-fold pipeline, including the C3 Chonk chains, is proven in
//! `node_fold_correlated_e2e_tests.rs`.

mod common;
#[allow(dead_code)]
#[path = "common/recursive_vk_substitution.rs"]
mod recursive_vk_substitution;

use common::{
    find_bb, setup_c6_chonk_circuits, setup_compiled_circuit,
    setup_recursive_aggregation_fold_circuit, setup_test_prover,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{CircuitName, Proof};
use e3_fhe_params::BfvPreset;
use e3_zk_config::MAX_MSG_NON_ZERO_COEFFS;
use e3_zk_prover::test_utils::{
    fold_witness_field_strings, generate_c6_chonk_root_with_substituted_key, load_vk_artifacts,
};
use e3_zk_prover::ThresholdShareDecryptionCircuit as ShareDecryptionCircuit;
use e3_zk_prover::{generate_c6_chonk_root, CircuitVariant, Provable, ZkError, ZkProver};
use recursive_vk_substitution::{fields, substitute_proof, vk_hash, witness};
use serde_json::json;

/// Slots of a C6 column (`T + 1`): the compiled `c6_chonk_app`'s `slot_indices` length.
fn c6_total_slots_from_compiled_json() -> usize {
    let path = e3_zk_prover::test_utils::workspace_root()
        .join("circuits/bin/chonk/target/c6_chonk_app.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| p.get("name") == Some(&serde_json::Value::String("slot_indices".into())))
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .expect("c6_chonk_app slot_indices length") as usize
}

/// Proves a C6 Chonk root over `T + 1` copies of `inner` (one per slot, so every slot commits to
/// the same ciphertext) and checks the decryption aggregator's anchor: the real root claims the
/// canonical C6 tree; a root under a substituted key verifies but cannot.
fn assert_c6_chonk_tree_binding(
    prover: &ZkProver,
    inner: &Proof,
    total_slots: usize,
    artifacts_dir: &str,
) {
    let default_dir = prover.circuits_dir(CircuitVariant::Default, artifacts_dir);
    let final_path =
        default_dir.join("recursive_aggregation/decryption_aggregator/decryption_aggregator.json");
    let canonical_tree = format!(
        "0x{}",
        hex::encode(
            std::fs::read(default_dir.join("recursive_aggregation/c6_fold/c6_fold.vk_tree_hash"))
                .unwrap()
        )
    );
    let inners = vec![inner.clone(); total_slots];
    let slots: Vec<u32> = (0..total_slots as u32).collect();
    let root = generate_c6_chonk_root(
        prover,
        &inners,
        &slots,
        total_slots,
        "c6-chonk-root",
        artifacts_dir,
    )
    .expect("C6 Chonk root");
    assert_eq!(root.circuit, CircuitName::C6ChonkRoot);
    assert!(prover
        .verify_fold_proof(&root, "c6-chonk-root", 0, artifacts_dir)
        .unwrap());
    let root_vk = load_vk_artifacts(&default_dir, CircuitName::C6ChonkRoot).unwrap();
    let root_public = fields(&root);
    assert_eq!(
        vk_hash(&[root_vk.key_hash.clone(), root_public[0].clone()]),
        canonical_tree,
        "the real C6 Chonk circuits must hash to the anchored C6 tree"
    );

    let leaf_public = fields(inner);
    // This alternate C7 relation isolates the C6 tree boundary. The EVM suite checks the separate C7 pin.
    let mut c7_public = vec![leaf_public[5].clone(); total_slots];
    c7_public.extend((1..=total_slots).map(|id| id.to_string()));
    c7_public.extend(vec!["0".to_owned(); MAX_MSG_NON_ZERO_COEFFS]);
    let c7 = substitute_proof(
        prover,
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
            "domain_hi": leaf_public[3],
            "domain_lo": leaf_public[4],
            "ciphertext_commitment": leaf_public[2],
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
        prover,
        CircuitName::C6ChonkRoot,
        CircuitVariant::Default,
        &root_public,
        None,
        "c6-tree-root",
    );
    let fake_tree = vk_hash(&[fake_root.key_hash.clone(), root_public[0].clone()]);
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
    assert!(
        witness(
            &final_path,
            &final_input(
                &fake_root.vk,
                &fake_root.key_hash,
                &fake_root.proof,
                &canonical_tree
            ),
        )
        .is_err(),
        "a substituted C6 root must not claim the deployment's canonical tree anchor"
    );
}

/// A decryption's prover with the C6 Chonk circuits set up, and one inner C6 proof.
struct C6Fixture {
    prover: ZkProver,
    inner: Proof,
    total_slots: usize,
    artifacts_dir: String,
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
        total_slots,
        committee.threshold + 1,
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
            "e3-c6-inner",
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
        _temp: temp,
    }
}

#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_chonk_root_proves_and_binds_the_decryption_aggregator() {
    let f = c6_fixture().await;
    assert_c6_chonk_tree_binding(&f.prover, &f.inner, f.total_slots, &f.artifacts_dir);
    f.prover.cleanup("e3-c6-inner").unwrap();
}

/// A stack cannot carry a leaf whose claimed outputs differ from what it proved, nor a stage
/// passed off under another stage's key: each root either fails to prove or does not verify.
#[tokio::test]
#[ignore = "requires prepared integration artifacts; run pnpm rust:test:proofs"]
async fn c6_chonk_rejects_a_corrupted_leaf_or_a_substituted_key() {
    let f = c6_fixture().await;
    let slots: Vec<u32> = (0..f.total_slots as u32).collect();
    let rejected = |root: Result<Proof, ZkError>, job: &str| match root {
        Err(e) => {
            eprintln!("{job} rejected: {e}");
            true
        }
        Ok(root) => !f
            .prover
            .verify_fold_proof(&root, job, 0, &f.artifacts_dir)
            .unwrap_or(false),
    };

    // The leaf's last public signal is its `d` commitment, the row the stack writes for it.
    let mut signals = f.inner.public_signals.extract_bytes();
    *signals.last_mut().unwrap() ^= 1;
    let corrupted = Proof::new(
        f.inner.circuit,
        f.inner.data.clone(),
        e3_utils::ArcBytes::from_bytes(&signals),
    );
    let mut inners = vec![f.inner.clone(); f.total_slots];
    inners[f.total_slots - 1] = corrupted;
    assert!(
        rejected(
            generate_c6_chonk_root(
                &f.prover,
                &inners,
                &slots,
                f.total_slots,
                "c6-corrupted-leaf",
                &f.artifacts_dir,
            ),
            "c6-corrupted-leaf",
        ),
        "a leaf whose claimed row differs from its proof must not reach a verifying root"
    );

    let inners = vec![f.inner.clone(); f.total_slots];
    for (stage, from) in [(0, 1), (1, 2), (2, 1)] {
        let job = format!("c6-key-{stage}-as-{from}");
        assert!(
            rejected(
                generate_c6_chonk_root_with_substituted_key(
                    &f.prover,
                    &inners,
                    &slots,
                    f.total_slots,
                    (stage, from),
                    &job,
                    &f.artifacts_dir,
                ),
                &job,
            ),
            "stack stage {stage} claimed under stage {from}'s key must not reach a verifying root"
        );
    }
    f.prover.cleanup("e3-c6-inner").unwrap();
}
