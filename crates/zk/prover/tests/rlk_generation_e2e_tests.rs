// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod common;

use common::{
    active_bin_preset, compiled_circuit_artifacts_available, extract_field, find_bb,
    require_minimum_circuits_for_preset, setup_compiled_circuit_for_preset, setup_test_prover,
};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{CircuitName, CircuitVariant};
use e3_fhe_params::BfvPreset;
use e3_zk_witness::commitments::{
    compute_rlk_d0_commitment, compute_rlk_d2_commitment, compute_rlk_r_commitment,
    compute_sc_sk_secret_root_commitment,
};

use e3_zk_witness::threshold::lbfv_proof_domain::lbfv_proof_session;

use e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs;
use e3_zk_witness::threshold::rlk_generation::RlkGenerationCircuitData;

use e3_zk_prover::{c2_chunk_size, prove_rlk_generation_row, ZkProver};
use num_bigint::BigInt;
use std::time::Instant;

#[tokio::test]
async fn secure_rlk_generation_proves_one_row() {
    let preset = BfvPreset::SecureThreshold16384;
    if active_bin_preset().as_deref() != Some("secure-16384") {
        println!("skipping: secure-16384 circuit artifacts are not active");
        return;
    }
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    if require_minimum_circuits_for_preset(preset).is_none() {
        return;
    }
    if !compiled_circuit_artifacts_available("threshold", "rlk_generation") {
        println!("skipping: secure-16384 RLK circuit artifacts are not staged");
        return;
    }

    let (backend, _temp) = setup_test_prover(&bb).await;
    setup_compiled_circuit_for_preset(&backend, "threshold", "rlk_generation", preset, "minimum")
        .await;

    let committee = CiphernodesCommitteeSize::Minimum.values();
    let started = Instant::now();
    let row = e3_zk_samples::threshold::rlk_generation::generate_sample(preset, committee.clone())
        .expect("valid RLK row 0");
    assert_eq!(row.row_index, 0);
    println!("RLK row generation time: {:?}", started.elapsed());
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let prover = ZkProver::new(&backend);

    let started = Instant::now();
    let proof = prove_rlk_generation_row(
        &prover,
        &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
            preset,
            e3_committee::CiphernodesCommitteeSize::from_threshold(
                (&row).committee.threshold,
                (&row).committee.n,
            )
            .unwrap(),
        )
        .unwrap(),
        &row,
        "secure-rlk-row",
        &artifacts_dir,
    )
    .expect("RLK row proof");
    println!("RLK row proving time: {:?}", started.elapsed());

    assert_eq!(proof.circuit, CircuitName::RlkGeneration);
    let started = Instant::now();
    assert!(prover
        .verify_proof_with_variant(
            &proof,
            "secure-rlk-row",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("RLK row verification"));
    println!("RLK row verification time: {:?}", started.elapsed());

    let configs = e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs::for_preset(
        preset,
        e3_committee::CiphernodesCommitteeSize::Minimum,
    )
    .expect("RLK constants");
    assert_eq!(proof.public_signals.len(), 8 * 32);
    let actual = (0..8)
        .map(|field_index| extract_field(&proof.public_signals, field_index))
        .collect::<Vec<_>>();
    let session = lbfv_proof_session(row.proof_domain).expect("valid proof domain");
    let expected = vec![
        BigInt::from(session.session_id_hi),
        BigInt::from(session.session_id_lo),
        BigInt::from(row.party_id),
        BigInt::from(row.row_index),
        compute_sc_sk_secret_root_commitment(
            &row.sk,
            configs.bits.sk_bit,
            c2_chunk_size(preset.metadata().degree, committee.n),
        ),
        compute_rlk_r_commitment(&row.r, configs.bits.r_bit),
        compute_rlk_d0_commitment(row.row_index, &row.d0, configs.bits.d_bit),
        compute_rlk_d2_commitment(row.row_index, &row.d2, configs.bits.d_bit),
    ];
    assert_eq!(actual, expected);
}
