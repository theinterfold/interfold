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
use e3_events::{CircuitName, CircuitVariant};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::commitments::{
    compute_rlk_d0_commitment, compute_rlk_d2_commitment, compute_rlk_r_commitment,
    compute_sc_sk_secret_root_commitment,
};
use e3_zk_helpers::threshold::rlk_generation::{RlkGenerationCircuitData, RlkGenerationConfigs};
use e3_zk_helpers::{CiphernodesCommitteeSize, Computation};
use e3_zk_prover::test_utils::load_vk_artifacts;
use e3_zk_prover::{finalize_rlk_generation_row, prove_rlk_generation_row, ZkProver};
use num_bigint::{BigInt, Sign};
use std::time::Instant;

#[tokio::test]
async fn secure_rlk_limbs_finalize_one_row() {
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
    if ["rlk_generation_limb", "rlk_generation"]
        .iter()
        .any(|circuit| !compiled_circuit_artifacts_available("threshold", circuit))
    {
        println!("skipping: secure-16384 RLK circuit artifacts are not staged");
        return;
    }

    let (backend, _temp) = setup_test_prover(&bb).await;
    for circuit in ["rlk_generation_limb", "rlk_generation"] {
        setup_compiled_circuit_for_preset(&backend, "threshold", circuit, preset, "minimum").await;
    }

    let committee = CiphernodesCommitteeSize::Minimum.values();
    let started = Instant::now();
    let row = RlkGenerationCircuitData::generate_sample(preset, committee.clone())
        .expect("valid RLK row 0");
    assert_eq!(row.row_index, 0);
    println!("RLK row generation time: {:?}", started.elapsed());
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let prover = ZkProver::new(&backend);
    let limb_vk = load_vk_artifacts(
        &prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir),
        CircuitName::RlkGenerationLimb,
    )
    .expect("recursive RLK limb VK");
    let limb_vk_hash: [u8; 32] = hex::decode(limb_vk.key_hash.trim_start_matches("0x"))
        .expect("RLK limb VK hash hex")
        .try_into()
        .expect("RLK limb VK hash field");

    let started = Instant::now();
    let proofs = prove_rlk_generation_row(
        &prover,
        preset,
        &row,
        &limb_vk_hash,
        "secure-rlk-row",
        &artifacts_dir,
    )
    .expect("five RLK limbs and terminal proof");
    println!(
        "RLK limb and terminal proving time: {:?}",
        started.elapsed()
    );

    assert_eq!(proofs.limb_proofs.len(), preset.metadata().num_moduli);
    assert_eq!(proofs.limb_proofs.len(), 5);
    for (limb_index, proof) in proofs.limb_proofs.iter().enumerate() {
        assert_eq!(proof.circuit, CircuitName::RlkGenerationLimb);
        let started = Instant::now();
        assert!(prover
            .verify_proof_with_variant(
                proof,
                "secure-rlk-row",
                limb_index as u64,
                CircuitVariant::Recursive,
                &artifacts_dir,
            )
            .expect("RLK limb verification"));
        println!(
            "RLK limb {limb_index} verification time: {:?}",
            started.elapsed()
        );
    }

    assert_eq!(proofs.terminal_proof.circuit, CircuitName::RlkGeneration);
    let started = Instant::now();
    assert!(prover
        .verify_proof_with_variant(
            &proofs.terminal_proof,
            "secure-rlk-row",
            0,
            CircuitVariant::Recursive,
            &artifacts_dir,
        )
        .expect("RLK terminal verification"));
    println!("RLK terminal verification time: {:?}", started.elapsed());

    let configs = RlkGenerationConfigs::compute(preset, &committee).expect("RLK constants");
    let actual = (0..6)
        .map(|field_index| extract_field(&proofs.terminal_proof.public_signals, field_index))
        .collect::<Vec<_>>();
    let expected = vec![
        BigInt::from(row.row_index),
        compute_sc_sk_secret_root_commitment(&row.sk, configs.bits.sk_bit, 512),
        compute_rlk_r_commitment(&row.r, configs.bits.r_bit),
        compute_rlk_d0_commitment(&row.d0, configs.bits.d_bit),
        compute_rlk_d2_commitment(&row.d2, configs.bits.d_bit),
        BigInt::from_bytes_be(Sign::Plus, &limb_vk_hash),
    ];
    assert_eq!(actual, expected);

    let recursive_dir = prover.circuits_dir(CircuitVariant::Recursive, &artifacts_dir);
    let leaf_dir = recursive_dir.join(CircuitName::RlkGenerationLimb.dir_path());
    let terminal_dir = recursive_dir.join(CircuitName::RlkGeneration.dir_path());
    std::fs::copy(
        terminal_dir.join("rlk_generation.vk"),
        leaf_dir.join("rlk_generation_limb.vk"),
    )
    .expect("substitute wrong limb VK");
    let wrong_vk = finalize_rlk_generation_row(
        &prover,
        preset,
        &row,
        &proofs.limb_proofs,
        &limb_vk_hash,
        "secure-rlk-wrong-vk",
        &artifacts_dir,
    );
    match wrong_vk {
        Err(error) => println!("wrong-VK terminal rejected before verification: {error}"),
        Ok(proof) => {
            assert!(
                !prover
                    .verify_proof_with_variant(
                        &proof,
                        "secure-rlk-wrong-vk",
                        0,
                        CircuitVariant::Recursive,
                        &artifacts_dir,
                    )
                    .expect("wrong-VK terminal verification must execute"),
                "a terminal proof built with the wrong limb VK must not verify"
            );
            println!("wrong-VK terminal proof rejected during verification");
        }
    }
}
