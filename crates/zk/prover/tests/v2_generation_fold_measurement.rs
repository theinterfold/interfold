// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use std::{env, fs, path::PathBuf};

use common::{find_bb, secure_lbfv_cache_dir, secure_lbfv_committee};
use e3_config::BBPath;
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_utils::utility_types::ArcBytes;
use e3_zk_prover::test_utils::load_vk_artifacts;
use e3_zk_prover::LbfvPkAggregationCircuit;
use e3_zk_prover::{
    prove_lbfv_generation_fold_step, prove_lbfv_pk_generation_row, prove_rlk_generation_row,
    Provable, ZkBackend, ZkProver,
};
use e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain;
use e3_zk_witness::threshold::lbfv_pk_aggregation::LbfvPkAggregationCircuitData;
use e3_zk_witness::threshold::pk_generation::LbfvPkGenerationAdapter;

use e3_zk_prover::RlkAggregationCircuit;
use e3_zk_witness::threshold::rlk_aggregation::{
    RlkAggregationCircuitData, RlkAggregationComponent,
};
use e3_zk_witness::threshold::rlk_generation::RlkGenerationAdapter;

use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare};

const ARTIFACT_ROOT_ENV: &str = "INTERFOLD_SECURE_16384_ARTIFACTS";
const PROOF_CACHE_ENV: &str = "INTERFOLD_V2_PROOF_CACHE";

fn load_cached_proof(circuit: CircuitName, label: &str) -> Option<Proof> {
    let directory = secure_lbfv_cache_dir(PROOF_CACHE_ENV)?;
    let data = fs::read(directory.join(format!("{label}.proof"))).ok()?;
    let public_signals = fs::read(directory.join(format!("{label}.public"))).ok()?;
    Some(Proof::new(
        circuit,
        ArcBytes::from_bytes(&data),
        ArcBytes::from_bytes(&public_signals),
    ))
}

fn store_cached_proof(proof: &Proof, label: &str) {
    let Some(directory) = secure_lbfv_cache_dir(PROOF_CACHE_ENV) else {
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
    let preset = BfvPreset::SecureThreshold16384;
    let committee_size = secure_lbfv_committee();
    let committee = committee_size.values();
    let artifacts_dir = preset.artifacts_dir_for_committee(committee_size.as_str());
    let required = artifact_root
        .join(&artifacts_dir)
        .join("recursive/threshold/lbfv_pk_generation/lbfv_pk_generation.json");
    if !required.is_file() {
        panic!("secure artifact is missing: {}", required.display());
    }

    let work = tempfile::tempdir().expect("temporary prover work directory");
    let backend = ZkBackend::new(BBPath::Default(bb), artifact_root, work.path().join("work"));
    let prover = ZkProver::new(&backend);

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
    let pk_data = LbfvPkGenerationAdapter::from_config(
        &e3_zk_config::threshold::pk_generation::Configs::for_preset(preset, committee_size)
            .unwrap(),
    )
    .expect("PK adapter")
    .row_data(committee.clone(), domain, 0, 0, &secret_key, &public_key)
    .expect("matching PK row");
    let rlk_data = RlkGenerationAdapter::from_config(
        &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
            preset,
            committee_size,
        )
        .unwrap(),
    )
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

    let pk_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::LbfvPkGeneration,
    )
    .expect("public-key row VK");
    let pk_cache_label = format!(
        "lbfv_pk_generation_row_{}",
        pk_vk.key_hash.trim_start_matches("0x")
    );
    let pk_proof =
        if let Some(cached) = load_cached_proof(CircuitName::LbfvPkGeneration, &pk_cache_label) {
            cached
        } else {
            let proof = prove_lbfv_pk_generation_row(
                &prover,
                &e3_zk_config::threshold::pk_generation::Configs::for_preset(
                    preset,
                    e3_committee::CiphernodesCommitteeSize::from_threshold(
                        (&pk_data).committee.threshold,
                        (&pk_data).committee.n,
                    )
                    .unwrap(),
                )
                .unwrap(),
                &pk_data,
                "secure-v2-generation-fold",
                &artifacts_dir,
            )
            .expect("PK generation proof");
            store_cached_proof(&proof, &pk_cache_label);
            proof
        };
    print_measurement("lbfv_pk_generation", &pk_proof);
    assert!(prover
        .verify_proof_with_variant(
            &pk_proof,
            "secure-v2-generation-fold",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("PK generation verification"));

    let rlk_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::RlkGeneration,
    )
    .expect("RLK row VK");
    let rlk_cache_label = format!(
        "rlk_generation_row_{}",
        rlk_vk.key_hash.trim_start_matches("0x")
    );
    let rlk_proof =
        if let Some(cached) = load_cached_proof(CircuitName::RlkGeneration, &rlk_cache_label) {
            cached
        } else {
            let proof = prove_rlk_generation_row(
                &prover,
                &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
                    preset,
                    e3_committee::CiphernodesCommitteeSize::from_threshold(
                        (&rlk_data).committee.threshold,
                        (&rlk_data).committee.n,
                    )
                    .unwrap(),
                )
                .unwrap(),
                &rlk_data,
                "secure-v2-generation-fold",
                &artifacts_dir,
            )
            .expect("RLK generation row proof");
            store_cached_proof(&proof, &rlk_cache_label);
            proof
        };
    print_measurement("rlk_generation", &rlk_proof);
    assert!(prover
        .verify_proof_with_variant(
            &rlk_proof,
            "secure-v2-generation-fold",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("RLK generation verification"));

    let generation_fold = prove_lbfv_generation_fold_step(
        &prover,
        &pk_proof,
        &rlk_proof,
        None,
        0,
        "secure-v2-generation-fold",
        &artifacts_dir,
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
            &artifacts_dir,
        )
        .expect("generation fold kernel verification"));

    let aggregation_committee = committee_size.values();
    let pk_aggregation_data =
        e3_zk_samples::threshold::lbfv_pk_aggregation::generate_sample_for_row(
            preset,
            aggregation_committee.clone(),
            0,
        )
        .expect("PK aggregation row");
    let mut rlk_aggregation_data =
        e3_zk_samples::threshold::rlk_aggregation::generate_sample_for_row(
            preset,
            aggregation_committee,
            0,
            RlkAggregationComponent::D0,
        )
        .expect("RLK aggregation row");

    let pk_aggregation_proof = if let Some(cached) =
        load_cached_proof(CircuitName::LbfvPkAggregation, "lbfv_pk_aggregation")
    {
        cached
    } else {
        let proof = LbfvPkAggregationCircuit
            .prove_with_variant(&prover, &e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::for_preset(preset, e3_committee::CiphernodesCommitteeSize::from_threshold((&pk_aggregation_data).committee.threshold, (&pk_aggregation_data).committee.n).unwrap()).unwrap(), &pk_aggregation_data, "secure-v2-aggregation-fold", CircuitVariant::Recursive, &artifacts_dir)
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
            &artifacts_dir,
        )
        .expect("PK aggregation verification"));

    // One proof per RLK component, over the same shares.
    let mut rlk_aggregation_proofs = Vec::new();
    for component in RlkAggregationComponent::ALL {
        rlk_aggregation_data.component = component;
        let name = format!("rlk_aggregation_{component:?}").to_lowercase();
        let proof = if let Some(cached) = load_cached_proof(CircuitName::RlkAggregation, &name) {
            cached
        } else {
            let proof = RlkAggregationCircuit
                .prove_with_variant(
                    &prover,
                    &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                        preset,
                        e3_committee::CiphernodesCommitteeSize::from_threshold(
                            (&rlk_aggregation_data).committee.threshold,
                            (&rlk_aggregation_data).committee.n,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    &rlk_aggregation_data,
                    "secure-v2-aggregation-fold",
                    CircuitVariant::Recursive,
                    &artifacts_dir,
                )
                .expect("RLK aggregation proof");
            store_cached_proof(&proof, &name);
            proof
        };
        print_measurement(&name, &proof);
        assert!(RlkAggregationCircuit
            .verify_with_variant(
                &prover,
                &proof,
                "secure-v2-aggregation-fold",
                0,
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("RLK aggregation verification"));
        rlk_aggregation_proofs.push(proof);
    }

    let aggregation_fold = e3_zk_prover::prove_lbfv_aggregation_fold_step(
        &prover,
        &pk_aggregation_proof,
        &rlk_aggregation_proofs[0],
        &rlk_aggregation_proofs[1],
        None,
        0,
        committee_size.values().h,
        "secure-v2-aggregation-fold",
        &artifacts_dir,
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
            &artifacts_dir,
        )
        .expect("aggregation fold kernel verification"));
}
