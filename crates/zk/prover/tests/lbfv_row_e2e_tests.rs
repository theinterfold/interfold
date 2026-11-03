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
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_witness::commitments::{
    compute_lbfv_pk_row_commitment, compute_pk_aggregation_commitment,
    compute_rlk_aggregation_commitment, compute_sc_sk_secret_root_commitment,
};

use e3_zk_prover::LbfvPkAggregationCircuit;
use e3_zk_witness::threshold::lbfv_pk_aggregation::LbfvPkAggregationCircuitData;
use e3_zk_witness::threshold::lbfv_proof_domain::lbfv_proof_session;

use e3_zk_witness::threshold::pk_generation::{
    LbfvPkGenerationAdapter, LbfvPkGenerationCircuitData,
};

use e3_zk_prover::RlkAggregationCircuit;
use e3_zk_witness::threshold::rlk_aggregation::{
    RlkAggregationCircuitData, RlkAggregationComponent,
};

use e3_zk_prover::{c2_chunk_size, prove_lbfv_pk_generation_row, Provable, ZkProver};
use num_bigint::BigInt;

const ROW_INDEX: u32 = 4;
const CIRCUITS: &[&str] = &[
    "lbfv_pk_generation",
    "lbfv_pk_aggregation",
    "rlk_aggregation",
];

fn assert_exact_public_signals(proof: &Proof, expected: &[BigInt]) {
    assert_eq!(
        proof.public_signals.len(),
        expected.len() * 32,
        "{} public signal count",
        proof.circuit
    );
    let actual = (0..expected.len())
        .map(|index| extract_field(&proof.public_signals, index))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "{} public signals", proof.circuit);
}

#[tokio::test]
async fn secure_lbfv_row_circuits_prove_verify_and_expose_exact_commitments() {
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
    if CIRCUITS
        .iter()
        .any(|circuit| !compiled_circuit_artifacts_available("threshold", circuit))
    {
        println!("skipping: secure-16384 l-BFV row circuit artifacts are not staged");
        return;
    }

    let (backend, _temp) = setup_test_prover(&bb).await;
    for circuit in CIRCUITS {
        setup_compiled_circuit_for_preset(&backend, "threshold", circuit, preset, "minimum").await;
    }

    let committee = CiphernodesCommitteeSize::Minimum.values();
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let prover = ZkProver::new(&backend);

    let generation_sample = e3_zk_samples::threshold::lbfv_pk_generation::generate_sample_for_row(
        preset,
        committee.clone(),
        ROW_INDEX,
    )
    .expect("valid l-BFV public-key generation row");
    let generation_config = e3_zk_config::threshold::pk_generation::Configs::for_preset(
        preset,
        e3_committee::CiphernodesCommitteeSize::Minimum,
    )
    .unwrap();
    let generation_bits = generation_config.bits.clone();
    let generation_proof = prove_lbfv_pk_generation_row(
        &prover,
        &e3_zk_config::threshold::pk_generation::Configs::for_preset(
            preset,
            e3_committee::CiphernodesCommitteeSize::from_threshold(
                (&generation_sample).committee.threshold,
                (&generation_sample).committee.n,
            )
            .unwrap(),
        )
        .unwrap(),
        &generation_sample,
        "secure-lbfv-pk-generation-row",
        &artifacts_dir,
    )
    .expect("l-BFV public-key generation row proof");
    assert_eq!(generation_proof.circuit, CircuitName::LbfvPkGeneration);
    assert!(prover
        .verify_proof_with_variant(
            &generation_proof,
            "secure-lbfv-pk-generation-row",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("l-BFV public-key generation verification"));
    let generation_session =
        lbfv_proof_session(generation_sample.proof_domain).expect("l-BFV proof session");
    assert_exact_public_signals(
        &generation_proof,
        &[
            BigInt::from(generation_session.session_id_hi),
            BigInt::from(generation_session.session_id_lo),
            BigInt::from(generation_sample.party_id),
            BigInt::from(generation_sample.row_index),
            compute_sc_sk_secret_root_commitment(
                &generation_sample.sk,
                generation_bits.sk_bit,
                c2_chunk_size(preset.metadata().degree, committee.n),
            ),
            compute_lbfv_pk_row_commitment(
                generation_sample.row_index,
                &generation_sample.pk0_share,
                generation_bits.pk_bit,
            ),
        ],
    );

    let mut wrong_row_signals = generation_proof.public_signals.extract_bytes();
    wrong_row_signals[3 * 32 + 31] ^= 1;
    let wrong_row_proof = Proof::new(
        generation_proof.circuit,
        generation_proof.data.clone(),
        ArcBytes::from_bytes(&wrong_row_signals),
    );
    assert!(!prover
        .verify_proof_with_variant(
            &wrong_row_proof,
            "secure-lbfv-pk-generation-wrong-row",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("wrong-row verification must execute"));

    let pk_aggregation_sample =
        e3_zk_samples::threshold::lbfv_pk_aggregation::generate_sample_for_row(
            preset,
            committee.clone(),
            ROW_INDEX,
        )
        .expect("valid l-BFV public-key aggregation row");
    let pk_aggregation_output = LbfvPkAggregationInputs::compute(
        &e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::for_preset(
            preset,
            e3_committee::CiphernodesCommitteeSize::from_threshold(
                (&pk_aggregation_sample).committee.threshold,
                (&pk_aggregation_sample).committee.n,
            )
            .unwrap(),
        )
        .unwrap(),
        &pk_aggregation_sample,
    )
    .expect("public-key aggregation inputs");
    let pk_aggregation_proof = LbfvPkAggregationCircuit
        .prove_with_variant(
            &prover,
            &e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::from_threshold(
                    (&pk_aggregation_sample).committee.threshold,
                    (&pk_aggregation_sample).committee.n,
                )
                .unwrap(),
            )
            .unwrap(),
            &pk_aggregation_sample,
            "secure-lbfv-pk-aggregation-row",
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("l-BFV public-key aggregation proof");
    assert_eq!(pk_aggregation_proof.circuit, CircuitName::LbfvPkAggregation);
    assert!(LbfvPkAggregationCircuit
        .verify_with_variant(
            &prover,
            &pk_aggregation_proof,
            "secure-lbfv-pk-aggregation-row",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("l-BFV public-key aggregation verification"));
    let mut expected_pk_aggregation = vec![
        BigInt::from(pk_aggregation_output.session_id_hi),
        BigInt::from(pk_aggregation_output.session_id_lo),
        BigInt::from(pk_aggregation_output.aggregator_party_id),
        BigInt::from(pk_aggregation_output.accepted_party_set_hash_hi),
        BigInt::from(pk_aggregation_output.accepted_party_set_hash_lo),
        BigInt::from(pk_aggregation_output.row_index),
    ];
    expected_pk_aggregation.extend(
        pk_aggregation_output
            .expected_pk_generation_commitments
            .iter()
            .cloned(),
    );
    expected_pk_aggregation.push(compute_pk_aggregation_commitment(
        &pk_aggregation_output.pk0_agg,
        &LbfvPkGenerationAdapter::from_config(
            &e3_zk_config::threshold::pk_generation::Configs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::Minimum,
            )
            .unwrap(),
        )
        .expect("l-BFV public-key adapter")
        .crs_row(ROW_INDEX)
        .expect("fixed l-BFV CRS row"),
        e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs::for_preset(
            preset,
            e3_committee::CiphernodesCommitteeSize::from_threshold(
                (&pk_aggregation_sample).committee.threshold,
                (&pk_aggregation_sample).committee.n,
            )
            .unwrap(),
        )
        .unwrap()
        .bits
        .pk_bit,
    ));
    assert_exact_public_signals(&pk_aggregation_proof, &expected_pk_aggregation);

    for component in RlkAggregationComponent::ALL {
        let rlk_aggregation_sample =
            e3_zk_samples::threshold::rlk_aggregation::generate_sample_for_row(
                preset,
                committee.clone(),
                ROW_INDEX,
                component,
            )
            .expect("valid RLK aggregation row");
        let rlk_aggregation_output = RlkAggregationInputs::compute(
            &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::from_threshold(
                    (&rlk_aggregation_sample).committee.threshold,
                    (&rlk_aggregation_sample).committee.n,
                )
                .unwrap(),
            )
            .unwrap(),
            &rlk_aggregation_sample,
        )
        .expect("RLK aggregation inputs");
        let rlk_aggregation_proof = RlkAggregationCircuit
            .prove_with_variant(
                &prover,
                &e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                    preset,
                    e3_committee::CiphernodesCommitteeSize::from_threshold(
                        (&rlk_aggregation_sample).committee.threshold,
                        (&rlk_aggregation_sample).committee.n,
                    )
                    .unwrap(),
                )
                .unwrap(),
                &rlk_aggregation_sample,
                "secure-rlk-aggregation-row",
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("RLK aggregation proof");
        assert_eq!(rlk_aggregation_proof.circuit, CircuitName::RlkAggregation);
        assert!(RlkAggregationCircuit
            .verify_with_variant(
                &prover,
                &rlk_aggregation_proof,
                "secure-rlk-aggregation-row",
                0,
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("RLK aggregation verification"));
        let mut expected_rlk_aggregation = vec![
            BigInt::from(rlk_aggregation_output.session_id_hi),
            BigInt::from(rlk_aggregation_output.session_id_lo),
            BigInt::from(rlk_aggregation_output.aggregator_party_id),
            BigInt::from(rlk_aggregation_output.accepted_party_set_hash_hi),
            BigInt::from(rlk_aggregation_output.accepted_party_set_hash_lo),
            BigInt::from(rlk_aggregation_output.row_index),
            BigInt::from(component.index()),
        ];
        expected_rlk_aggregation
            .extend(rlk_aggregation_output.expected_commitments.iter().cloned());
        expected_rlk_aggregation.push(compute_rlk_aggregation_commitment(
            &rlk_aggregation_output.agg,
            e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs::for_preset(
                preset,
                e3_committee::CiphernodesCommitteeSize::from_threshold(
                    (&rlk_aggregation_sample).committee.threshold,
                    (&rlk_aggregation_sample).committee.n,
                )
                .unwrap(),
            )
            .unwrap()
            .bits
            .d_bit,
        ));
        assert_exact_public_signals(&rlk_aggregation_proof, &expected_rlk_aggregation);
    }

    for e3_id in [
        "secure-lbfv-pk-generation-row",
        "secure-lbfv-pk-generation-wrong-row",
        "secure-lbfv-pk-aggregation-row",
        "secure-rlk-aggregation-row",
    ] {
        prover.cleanup(e3_id).expect("clean prover work directory");
    }
}

use e3_zk_witness::threshold::lbfv_pk_aggregation::LbfvPkAggregationInputs;

use e3_zk_witness::threshold::rlk_aggregation::RlkAggregationInputs;
