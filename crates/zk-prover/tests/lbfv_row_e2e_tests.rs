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
use e3_events::{CircuitName, CircuitVariant, Proof};
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use e3_zk_helpers::circuits::commitments::{
    compute_pk_aggregation_commitment, compute_rlk_aggregation_commitment,
    compute_sc_sk_secret_root_commitment, compute_threshold_pk_commitment,
};
use e3_zk_helpers::threshold::lbfv_pk_aggregation::{
    LbfvPkAggregationCircuit, LbfvPkAggregationCircuitData,
};
use e3_zk_helpers::threshold::lbfv_proof_domain::lbfv_proof_session;
use e3_zk_helpers::threshold::pk_generation::{
    Bits, Bounds, LbfvPkGenerationAdapter, LbfvPkGenerationCircuitData,
};
use e3_zk_helpers::threshold::rlk_aggregation::{RlkAggregationCircuit, RlkAggregationCircuitData};
use e3_zk_helpers::{CiphernodesCommitteeSize, CircuitComputation, Computation};
use e3_zk_prover::{
    load_staged_lbfv_pk_generation_limb_vk_hash, prove_lbfv_pk_generation_row, Provable, ZkProver,
};
use num_bigint::BigInt;

const ROW_INDEX: u32 = 4;
const CIRCUITS: &[&str] = &[
    "lbfv_pk_generation",
    "lbfv_pk_generation_limb",
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

    let generation_sample =
        LbfvPkGenerationCircuitData::generate_sample_for_row(preset, committee.clone(), ROW_INDEX)
            .expect("valid l-BFV public-key generation row");
    let generation_bounds = Bounds::compute(preset, &committee).expect("generation bounds");
    let generation_bits = Bits::compute(preset, &generation_bounds).expect("generation bits");
    let limb_vk_hash = load_staged_lbfv_pk_generation_limb_vk_hash(&prover, &artifacts_dir)
        .expect("staged public-key limb VK hash");
    let generation_proofs = prove_lbfv_pk_generation_row(
        &prover,
        preset,
        &generation_sample,
        &limb_vk_hash,
        "secure-lbfv-pk-generation-row",
        &artifacts_dir,
    )
    .expect("l-BFV public-key generation row proof");
    for (limb_index, limb_proof) in generation_proofs.limb_proofs.iter().enumerate() {
        assert!(prover
            .verify_proof_with_variant(
                limb_proof,
                &format!("secure-lbfv-pk-generation-limb-{limb_index}"),
                0,
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("l-BFV public-key limb verification"));
    }
    let generation_proof = generation_proofs.terminal_proof;
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
                512,
            ),
            compute_threshold_pk_commitment(&generation_sample.pk0_share, generation_bits.pk_bit),
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &limb_vk_hash),
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
        LbfvPkAggregationCircuitData::generate_sample_for_row(preset, committee.clone(), ROW_INDEX)
            .expect("valid l-BFV public-key aggregation row");
    let pk_aggregation_output = LbfvPkAggregationCircuit::compute(preset, &pk_aggregation_sample)
        .expect("public-key aggregation inputs");
    let pk_aggregation_proof = LbfvPkAggregationCircuit
        .prove_with_variant(
            &prover,
            &preset,
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
        BigInt::from(pk_aggregation_output.inputs.session_id_hi),
        BigInt::from(pk_aggregation_output.inputs.session_id_lo),
        BigInt::from(pk_aggregation_output.inputs.aggregator_party_id),
        BigInt::from(pk_aggregation_output.inputs.accepted_party_set_hash_hi),
        BigInt::from(pk_aggregation_output.inputs.accepted_party_set_hash_lo),
        BigInt::from(pk_aggregation_output.inputs.row_index),
    ];
    expected_pk_aggregation.extend(
        pk_aggregation_output
            .inputs
            .expected_pk_generation_commitments
            .iter()
            .cloned(),
    );
    expected_pk_aggregation.push(compute_pk_aggregation_commitment(
        &pk_aggregation_output.inputs.pk0_agg,
        &LbfvPkGenerationAdapter::new(preset)
            .expect("l-BFV public-key adapter")
            .crs_row(ROW_INDEX)
            .expect("fixed l-BFV CRS row"),
        pk_aggregation_output.configs.bits.pk_bit,
    ));
    assert_exact_public_signals(&pk_aggregation_proof, &expected_pk_aggregation);

    let rlk_aggregation_sample =
        RlkAggregationCircuitData::generate_sample_for_row(preset, committee, ROW_INDEX)
            .expect("valid RLK aggregation row");
    let rlk_aggregation_output = RlkAggregationCircuit::compute(preset, &rlk_aggregation_sample)
        .expect("RLK aggregation inputs");
    let rlk_aggregation_proof = RlkAggregationCircuit
        .prove_with_variant(
            &prover,
            &preset,
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
        BigInt::from(rlk_aggregation_output.inputs.session_id_hi),
        BigInt::from(rlk_aggregation_output.inputs.session_id_lo),
        BigInt::from(rlk_aggregation_output.inputs.aggregator_party_id),
        BigInt::from(rlk_aggregation_output.inputs.accepted_party_set_hash_hi),
        BigInt::from(rlk_aggregation_output.inputs.accepted_party_set_hash_lo),
        BigInt::from(rlk_aggregation_output.inputs.row_index),
    ];
    expected_rlk_aggregation.extend(
        rlk_aggregation_output
            .inputs
            .expected_d0_commitments
            .iter()
            .cloned(),
    );
    expected_rlk_aggregation.extend(
        rlk_aggregation_output
            .inputs
            .expected_d2_commitments
            .iter()
            .cloned(),
    );
    expected_rlk_aggregation.push(compute_rlk_aggregation_commitment(
        &rlk_aggregation_output.inputs.d0_agg,
        rlk_aggregation_output.configs.bits.d_bit,
    ));
    expected_rlk_aggregation.push(compute_rlk_aggregation_commitment(
        &rlk_aggregation_output.inputs.d2_agg,
        rlk_aggregation_output.configs.bits.d_bit,
    ));
    assert_exact_public_signals(&rlk_aggregation_proof, &expected_rlk_aggregation);

    for e3_id in [
        "secure-lbfv-pk-generation-row",
        "secure-lbfv-pk-generation-wrong-row",
        "secure-lbfv-pk-aggregation-row",
        "secure-rlk-aggregation-row",
    ] {
        prover.cleanup(e3_id).expect("clean prover work directory");
    }
}
