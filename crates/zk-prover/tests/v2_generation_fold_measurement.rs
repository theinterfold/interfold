// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use std::{env, fs, path::PathBuf};

use common::find_bb;
use e3_config::BBPath;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::threshold::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_zk_helpers::threshold::lbfv_pk_aggregation::{
    LbfvPkAggregationCircuit, LbfvPkAggregationCircuitData,
};
use e3_zk_helpers::threshold::pk_generation::{LbfvPkGenerationAdapter, LbfvPkGenerationCircuit};
use e3_zk_helpers::threshold::rlk_aggregation::{RlkAggregationCircuit, RlkAggregationCircuitData};
use e3_zk_helpers::threshold::rlk_generation::RlkGenerationAdapter;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::test_utils::load_vk_artifacts;
use e3_zk_prover::{
    prove_lbfv_generation_fold_step, prove_rlk_generation_row, Provable, ZkBackend, ZkProver,
};
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare};

const ARTIFACT_ROOT_ENV: &str = "INTERFOLD_SECURE_16384_ARTIFACTS";
const ARTIFACTS_DIR: &str = "secure-16384/minimum";
const PROOF_CACHE_ENV: &str = "INTERFOLD_V2_PROOF_CACHE";

fn load_cached_proof(circuit: CircuitName, label: &str) -> Option<Proof> {
    let directory = env::var_os(PROOF_CACHE_ENV).map(PathBuf::from)?;
    let data = fs::read(directory.join(format!("{label}.proof"))).ok()?;
    let public_signals = fs::read(directory.join(format!("{label}.public"))).ok()?;
    Some(Proof::new(
        circuit,
        ArcBytes::from_bytes(&data),
        ArcBytes::from_bytes(&public_signals),
    ))
}

fn store_cached_proof(proof: &Proof, label: &str) {
    let Some(directory) = env::var_os(PROOF_CACHE_ENV).map(PathBuf::from) else {
        return;
    };
    fs::create_dir_all(&directory).expect("proof cache directory");
    let proof_data: &[u8] = proof.data.as_ref();
    let public_signals: &[u8] = proof.public_signals.as_ref();
    fs::write(directory.join(format!("{label}.proof")), proof_data).expect("cached proof");
    fs::write(directory.join(format!("{label}.public")), public_signals)
        .expect("cached public signals");
}

fn print_measurement(label: &str, proof: &Proof) {
    println!(
        "{label}: proof_bytes={}, public_signal_bytes={}, public_fields={}",
        proof.data.len(),
        proof.public_signals.len(),
        proof.public_signals.len() / 32
    );
}

#[tokio::test]
async fn secure_generation_fold_kernel_proves_and_verifies() {
    let Some(artifact_root) = env::var_os(ARTIFACT_ROOT_ENV).map(PathBuf::from) else {
        println!("skipping: {ARTIFACT_ROOT_ENV} is not set");
        return;
    };
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let required = artifact_root
        .join(ARTIFACTS_DIR)
        .join("recursive/threshold/lbfv_pk_generation/lbfv_pk_generation.json");
    if !required.is_file() {
        panic!("secure artifact is missing: {}", required.display());
    }

    let work = tempfile::tempdir().expect("temporary prover work directory");
    let backend = ZkBackend::new(BBPath::Default(bb), artifact_root, work.path().join("work"));
    let prover = ZkProver::new(&backend);
    let preset = BfvPreset::SecureThreshold16384;
    let committee = CiphernodesCommitteeSize::Minimum.values();

    let (params, _) = build_pair_for_preset(preset).expect("secure BFV parameters");
    let crp_a = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_crs_seed(preset).expect("secure l-BFV CRS seed"),
    )
    .expect("l-BFV CRS");
    let crp_d1 = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_urs_seed(preset).expect("secure l-BFV URS seed"),
    )
    .expect("l-BFV URS");
    let mut rng = rand::rng();
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key =
        PublicKeyShare::contribute_with_crp(&secret_key, &crp_a, &mut rng).expect("l-BFV PK");
    let (rlk_share, rlk_witness) =
        RelinKeyShare::contribution_with_crp_extended(&secret_key, &crp_d1, &crp_a, 0, 0, &mut rng)
            .expect("l-BFV RLK");

    let domain = sample_lbfv_proof_domain();
    let pk_data = LbfvPkGenerationAdapter::new(preset)
        .expect("PK adapter")
        .row_data(committee.clone(), domain, 0, 0, &secret_key, &public_key)
        .expect("matching PK row");
    let rlk_data = RlkGenerationAdapter::new(preset)
        .expect("RLK adapter")
        .row_data(
            committee,
            domain,
            0,
            0,
            &secret_key,
            &rlk_share,
            &rlk_witness,
        )
        .expect("matching RLK row");

    let pk_proof = if let Some(cached) =
        load_cached_proof(CircuitName::LbfvPkGeneration, "lbfv_pk_generation")
    {
        cached
    } else {
        let proof = LbfvPkGenerationCircuit
            .prove_with_variant(
                &prover,
                &preset,
                &pk_data,
                "secure-v2-generation-fold",
                CircuitVariant::Recursive,
                ARTIFACTS_DIR,
            )
            .expect("PK generation proof");
        store_cached_proof(&proof, "lbfv_pk_generation");
        proof
    };
    print_measurement("lbfv_pk_generation", &pk_proof);
    assert!(LbfvPkGenerationCircuit
        .verify_with_variant(
            &prover,
            &pk_proof,
            "secure-v2-generation-fold",
            0,
            CircuitVariant::Recursive,
            ARTIFACTS_DIR,
        )
        .expect("PK generation verification"));

    let limb_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, ARTIFACTS_DIR),
        CircuitName::RlkGenerationLimb,
    )
    .expect("RLK limb VK");
    let limb_vk_hash: [u8; 32] = hex::decode(limb_vk.key_hash.trim_start_matches("0x"))
        .expect("RLK limb VK hash")
        .try_into()
        .expect("RLK limb VK hash length");
    let rlk_terminal_proof =
        if let Some(cached) = load_cached_proof(CircuitName::RlkGeneration, "rlk_generation") {
            cached
        } else {
            let proofs = prove_rlk_generation_row(
                &prover,
                preset,
                &rlk_data,
                &limb_vk_hash,
                "secure-v2-generation-fold",
                ARTIFACTS_DIR,
            )
            .expect("RLK generation row proof");
            store_cached_proof(&proofs.terminal_proof, "rlk_generation");
            proofs.terminal_proof
        };
    print_measurement("rlk_generation", &rlk_terminal_proof);
    assert!(prover
        .verify_proof_with_variant(
            &rlk_terminal_proof,
            "secure-v2-generation-fold",
            0,
            CircuitVariant::Recursive,
            ARTIFACTS_DIR,
        )
        .expect("RLK generation verification"));

    let generation_fold = prove_lbfv_generation_fold_step(
        &prover,
        &pk_proof,
        &rlk_terminal_proof,
        None,
        0,
        &ArcBytes::from_bytes(&limb_vk_hash),
        "secure-v2-generation-fold",
        ARTIFACTS_DIR,
    )
    .expect("generation fold kernel proof");
    print_measurement("lbfv_generation_fold_kernel", &generation_fold);
    assert_eq!(
        generation_fold.circuit,
        CircuitName::LbfvGenerationFoldKernel
    );
    assert!(prover
        .verify_fold_proof(
            &generation_fold,
            "secure-v2-generation-fold",
            0,
            ARTIFACTS_DIR,
        )
        .expect("generation fold kernel verification"));

    let aggregation_committee = CiphernodesCommitteeSize::Minimum.values();
    let pk_aggregation_data = LbfvPkAggregationCircuitData::generate_sample_for_row(
        preset,
        aggregation_committee.clone(),
        0,
    )
    .expect("PK aggregation row");
    let rlk_aggregation_data =
        RlkAggregationCircuitData::generate_sample_for_row(preset, aggregation_committee, 0)
            .expect("RLK aggregation row");

    let pk_aggregation_proof = if let Some(cached) =
        load_cached_proof(CircuitName::LbfvPkAggregation, "lbfv_pk_aggregation")
    {
        cached
    } else {
        let proof = LbfvPkAggregationCircuit
            .prove_with_variant(
                &prover,
                &preset,
                &pk_aggregation_data,
                "secure-v2-aggregation-fold",
                CircuitVariant::Recursive,
                ARTIFACTS_DIR,
            )
            .expect("PK aggregation proof");
        store_cached_proof(&proof, "lbfv_pk_aggregation");
        proof
    };
    print_measurement("lbfv_pk_aggregation", &pk_aggregation_proof);
    assert!(LbfvPkAggregationCircuit
        .verify_with_variant(
            &prover,
            &pk_aggregation_proof,
            "secure-v2-aggregation-fold",
            0,
            CircuitVariant::Recursive,
            ARTIFACTS_DIR,
        )
        .expect("PK aggregation verification"));

    let rlk_aggregation_proof =
        if let Some(cached) = load_cached_proof(CircuitName::RlkAggregation, "rlk_aggregation") {
            cached
        } else {
            let proof = RlkAggregationCircuit
                .prove_with_variant(
                    &prover,
                    &preset,
                    &rlk_aggregation_data,
                    "secure-v2-aggregation-fold",
                    CircuitVariant::Recursive,
                    ARTIFACTS_DIR,
                )
                .expect("RLK aggregation proof");
            store_cached_proof(&proof, "rlk_aggregation");
            proof
        };
    print_measurement("rlk_aggregation", &rlk_aggregation_proof);
    assert!(RlkAggregationCircuit
        .verify_with_variant(
            &prover,
            &rlk_aggregation_proof,
            "secure-v2-aggregation-fold",
            0,
            CircuitVariant::Recursive,
            ARTIFACTS_DIR,
        )
        .expect("RLK aggregation verification"));

    let aggregation_fold = e3_zk_prover::prove_lbfv_aggregation_fold_step(
        &prover,
        &pk_aggregation_proof,
        &rlk_aggregation_proof,
        None,
        0,
        CiphernodesCommitteeSize::Minimum.values().h,
        "secure-v2-aggregation-fold",
        ARTIFACTS_DIR,
    )
    .expect("aggregation fold kernel proof");
    print_measurement("lbfv_aggregation_fold_kernel", &aggregation_fold);
    assert_eq!(
        aggregation_fold.circuit,
        CircuitName::LbfvAggregationFoldKernel
    );
    assert!(prover
        .verify_fold_proof(
            &aggregation_fold,
            "secure-v2-aggregation-fold",
            0,
            ARTIFACTS_DIR,
        )
        .expect("aggregation fold kernel verification"));
}
