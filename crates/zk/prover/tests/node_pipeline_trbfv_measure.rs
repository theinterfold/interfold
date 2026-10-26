// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Gated measurement of one node's trBFV DKG proving pipeline on secure-8192 (party 0).
//!
//! At the committee in `MEASURE_COMMITTEE` (`small` by default, or `minimum`) the node proves C0,
//! C1 (`pk_generation`), the single-proof C2a/C2b, every C3 proof of the node, C4a/C4b as
//! recipient, and the node fold (C2ab || C3a chain || C3b chain, C3ab, C4ab, `node_fold`), as
//! `generate_shares.rs` and `multithread.rs` request them. An optional test measures threshold
//! decryption (`MEASURE_DECRYPTION=1`, aggregator side with `MEASURE_AGGREGATOR=1`).
//! Output format and parallelism: `common/node_pipeline_measure.rs`.
//!
//! Run with the matching active artifacts (`pnpm build:circuits --preset secure-8192 --committee
//! small`), `MEASURE_RUN=1`, `--release -- --nocapture --test-threads=1`.

mod common;
#[allow(dead_code)]
#[path = "common/node_fold_witness.rs"]
mod node_fold_witness;
#[allow(dead_code)]
#[path = "common/node_pipeline_measure.rs"]
mod pipeline;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitName;
use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_zk_config::DkgInputType;
use e3_zk_prover::{
    generate_c3_chonk_chain, DkgShareDecryptionCircuit as ShareDecryptionCircuit, NodeDkgFoldInput,
    PkAggregationCircuit, PkCircuit, PkGenerationCircuit, Provable, ShareComputationCircuit,
    ShareEncryptionCircuit,
};
use e3_zk_witness::dkg::share_computation::Inputs as ShareComputationInputs;
use fhe::bfv::{PublicKey, SecretKey};
use pipeline::{measure, note, prep, Phases, PARTY_ID};
use rand::rng;

const PRESET: BfvPreset = BfvPreset::SecureThreshold8192;

const NODE_LEAVES: &[CircuitName] = &[
    CircuitName::PkBfv,
    CircuitName::PkGeneration,
    CircuitName::SkShareComputation,
    CircuitName::ESmShareComputation,
    // C2 is proven through these chunk circuits; the two names above are the final circuits.
    CircuitName::SkShareComputationChain,
    CircuitName::SkShareComputationChainLast,
    CircuitName::ESmShareComputationChain,
    CircuitName::ESmShareComputationChainLast,
    CircuitName::ShareEncryption,
    // C4 is proven through its three limb circuits; `DkgShareDecryption` is the final circuit.
    CircuitName::DkgShareDecryptionLimb0,
    CircuitName::DkgShareDecryptionLimb1,
    CircuitName::DkgShareDecryptionLimb2,
    CircuitName::DkgShareDecryption,
];

const NODE_FOLDS: &[CircuitName] = &[
    CircuitName::C2abFold,
    CircuitName::C3ChonkApp,
    CircuitName::C3ChonkInitKernel,
    CircuitName::C3ChonkTailKernel,
    CircuitName::C3ChonkHidingKernel,
    CircuitName::C3ChonkTube,
    CircuitName::C3ChonkAccumulate,
    CircuitName::C3abFold,
    CircuitName::C4abFold,
    CircuitName::NodeFold,
];

#[tokio::test]
async fn trbfv_node_dkg_pipeline_measure() {
    let Some((committee_size, committee_name)) = pipeline::gate(PRESET, None) else {
        return;
    };
    pipeline::install_bb_trace();
    let committee = committee_size.values();
    let bb = find_bb().await.expect("bb");
    let (backend, _temp) = setup_test_prover(&bb).await;
    let prover = pipeline::prover(&backend);
    // The directory the production handlers prove from for this preset and committee.
    let artifacts_dir = prover.resolve_artifacts_dir(PRESET, &committee_name);
    pipeline::stage(&backend, &artifacts_dir, NODE_LEAVES, NODE_FOLDS).await;

    // Native witness material, outside the proving total.
    let (dkg_sk, dkg_pk) = prep("dkg key", || {
        let (_, dkg_params) = build_pair_for_preset(PRESET).expect("DKG parameters");
        let mut dkg_rng = rng();
        let sk = SecretKey::random(&dkg_params, &mut dkg_rng);
        let pk = PublicKey::new(&sk, &mut dkg_rng);
        (sk, pk)
    });
    // One key sample drives C1 and both C2 witnesses, so their commitments correlate.
    let (key_data, share_sk, share_esm) = prep("own key and shares", || {
        let (key_data, esi, secret_key) =
            node_fold_witness::pk_generation_sample_with_esi(PRESET, committee.clone())
                .expect("correlated key data");
        let share_sk = node_fold_witness::share_computation_sk_from_pk(
            PRESET,
            committee.clone(),
            &key_data,
            &secret_key,
        )
        .expect("C2a data");
        let share_esm = node_fold_witness::share_computation_esm_from_esi(
            PRESET,
            committee.clone(),
            &key_data,
            &esi,
        )
        .expect("C2b data");
        (key_data, share_sk, share_esm)
    });
    let c0_config = e3_zk_config::dkg::pk::Configs::for_preset(PRESET).expect("C0 configuration");
    let c1_config =
        e3_zk_config::threshold::pk_generation::Configs::for_preset(PRESET, committee_size)
            .expect("C1 configuration");
    let c2_config =
        e3_zk_config::dkg::share_computation::Configs::for_preset(PRESET, committee_size)
            .expect("C2 configuration");
    let c4_config =
        e3_zk_config::dkg::share_decryption::Configs::for_preset(PRESET).expect("C4 configuration");
    let (sk_inputs, esm_inputs) = prep("own C2 inputs", || {
        (
            ShareComputationInputs::compute(&c2_config, &share_sk).expect("C2a inputs"),
            ShareComputationInputs::compute(&c2_config, &share_esm).expect("C2b inputs"),
        )
    });
    note("C4 senders other than party 0 use native samples; only their ciphertexts enter C4");
    let (c4a_ciphertexts, c4b_ciphertexts) = prep("C4 sender ciphertexts", || {
        pipeline::external_c4_ciphertexts(PRESET, &committee, &dkg_pk)
    });
    let c4a_data = pipeline::c4_data(PRESET, &dkg_sk, &sk_inputs, c4a_ciphertexts);
    let c4b_data = pipeline::c4_data(PRESET, &dkg_sk, &esm_inputs, c4b_ciphertexts);
    note("every C3 recipient uses party 0's DKG key; production uses each recipient's C0 key (same circuit cost)");
    note("trBFV has one smudging noise per dealer (gen_esi_sss), so C3b has one proof per slot like C3a");

    let mut phases = Phases::new("node");

    let c0_proof = phases.run("c0", || {
        measure("c0", || {
            PkCircuit.prove(&prover, &c0_config, &dkg_pk, "measure-c0", &artifacts_dir)
        })
    });

    let c1_proof = phases.run("c1", || {
        measure("c1", || {
            PkGenerationCircuit.prove(&prover, &c1_config, &key_data, "measure-c1", &artifacts_dir)
        })
    });
    drop(key_data);

    // The trBFV path proves C2 as one proof per secret (handle_share_computation_proof).
    let (c2a_proof, c2b_proof) = phases.run("c2", || {
        let c2a = measure("c2a", || {
            ShareComputationCircuit.prove(
                &prover,
                &c2_config,
                &share_sk,
                "measure-c2a",
                &artifacts_dir,
            )
        });
        let c2b = measure("c2b", || {
            ShareComputationCircuit.prove(
                &prover,
                &c2_config,
                &share_esm,
                "measure-c2b",
                &artifacts_dir,
            )
        });
        (c2a, c2b)
    });
    drop((share_sk, share_esm));

    let (c3a_proofs, c3b_proofs, c3_slots) = phases.run("c3", || {
        let (c3a, slots_a) = pipeline::prove_c3_set(
            &prover,
            PRESET,
            &committee,
            &sk_inputs,
            &dkg_pk,
            DkgInputType::SecretKey,
            "c3a",
            &artifacts_dir,
        );
        let (c3b, slots_b) = pipeline::prove_c3_set(
            &prover,
            PRESET,
            &committee,
            &esm_inputs,
            &dkg_pk,
            DkgInputType::SmudgingNoise,
            "c3b",
            &artifacts_dir,
        );
        assert_eq!(slots_a, slots_b);
        println!("STEP c3 proofs={}", c3a.len() + c3b.len());
        (c3a, c3b, slots_a)
    });

    let (c4a_proof, c4b_proof) = phases.run("c4", || {
        let c4a = measure("c4a", || {
            ShareDecryptionCircuit.prove(
                &prover,
                &c4_config,
                &c4a_data,
                "measure-c4a",
                &artifacts_dir,
            )
        });
        let c4b = measure("c4b", || {
            ShareDecryptionCircuit.prove(
                &prover,
                &c4_config,
                &c4b_data,
                "measure-c4b",
                &artifacts_dir,
            )
        });
        (c4a, c4b)
    });
    drop((c4a_data, c4b_data));

    phases.run("node_folds", || {
        pipeline::prove_node_fold(
            &prover,
            &NodeDkgFoldInput {
                c0_proof: &c0_proof,
                c1_proof: &c1_proof,
                c2a_proof: &c2a_proof,
                c2b_proof: &c2b_proof,
                c3a_inner_proofs: &c3a_proofs,
                c3b_inner_proofs: &c3b_proofs,
                c3_slot_indices_a: &c3_slots,
                c3_slot_indices_b: &c3_slots,
                c3_total_slots: committee.n * PRESET.metadata().num_moduli,
                c4a_proof: &c4a_proof,
                c4b_proof: &c4b_proof,
                party_id: PARTY_ID as u64,
            },
            &artifacts_dir,
        )
    });

    phases.finish();
}

/// C3 Chonk stack size: proves one secret's C3 set once, then times the C3 chain for every app
/// build listed in `MEASURE_C3_APPS` (comma-separated directories, each holding a built
/// `c3_chonk_app.{json,vk_recursive,vk_recursive_hash}` with its own `C3_CHONK_LEAVES`). Needs
/// `MEASURE_C3_STACKS=1`.
#[tokio::test]
async fn trbfv_c3_chonk_stack_measure() {
    let Some((committee_size, committee_name)) = pipeline::gate(PRESET, Some("MEASURE_C3_STACKS"))
    else {
        return;
    };
    let apps: Vec<std::path::PathBuf> = std::env::var("MEASURE_C3_APPS")
        .expect("MEASURE_C3_APPS lists the app builds to compare")
        .split(',')
        .map(std::path::PathBuf::from)
        .collect();
    pipeline::install_bb_trace();
    let committee = committee_size.values();
    let bb = find_bb().await.expect("bb");
    let (backend, _temp) = setup_test_prover(&bb).await;
    let prover = pipeline::prover(&backend);
    let artifacts_dir = prover.resolve_artifacts_dir(PRESET, &committee_name);
    pipeline::stage(
        &backend,
        &artifacts_dir,
        &[CircuitName::ShareEncryption],
        &[
            CircuitName::C3ChonkApp,
            CircuitName::C3ChonkInitKernel,
            CircuitName::C3ChonkTailKernel,
            CircuitName::C3ChonkHidingKernel,
            CircuitName::C3ChonkTube,
            CircuitName::C3ChonkAccumulate,
        ],
    )
    .await;

    let dkg_pk = prep("dkg key", || {
        let (_, dkg_params) = build_pair_for_preset(PRESET).expect("DKG parameters");
        let mut dkg_rng = rng();
        PublicKey::new(&SecretKey::random(&dkg_params, &mut dkg_rng), &mut dkg_rng)
    });
    let sk_inputs = prep("own C2a inputs", || {
        let (key_data, _, secret_key) =
            node_fold_witness::pk_generation_sample_with_esi(PRESET, committee.clone())
                .expect("key data");
        let share_sk = node_fold_witness::share_computation_sk_from_pk(
            PRESET,
            committee.clone(),
            &key_data,
            &secret_key,
        )
        .expect("C2a data");
        let config =
            e3_zk_config::dkg::share_computation::Configs::for_preset(PRESET, committee_size)
                .expect("C2 configuration");
        ShareComputationInputs::compute(&config, &share_sk).expect("C2a inputs")
    });
    let (c3_proofs, c3_slots) = measure("c3_set", || {
        Ok::<_, String>(pipeline::prove_c3_set(
            &prover,
            PRESET,
            &committee,
            &sk_inputs,
            &dkg_pk,
            DkgInputType::SecretKey,
            "c3a",
            &artifacts_dir,
        ))
    });
    let total_slots = committee.n * PRESET.metadata().num_moduli;
    println!(
        "STEP c3 proofs={} total_slots={total_slots}",
        c3_proofs.len()
    );

    let app_dir = backend
        .circuits_dir
        .join(&artifacts_dir)
        .join("default")
        .join(CircuitName::C3ChonkApp.dir_path());
    for app in &apps {
        let name = CircuitName::C3ChonkApp.as_str();
        for (from, to) in [
            ("json", "json"),
            ("vk_recursive", "vk"),
            ("vk_recursive_hash", "vk_hash"),
        ] {
            std::fs::copy(
                app.join(format!("{name}.{from}")),
                app_dir.join(format!("{name}.{to}")),
            )
            .unwrap_or_else(|e| panic!("stage {} app: {e}", app.display()));
        }
        let label = app
            .file_name()
            .map_or("app".into(), |n| n.to_string_lossy().into_owned());
        measure(&format!("c3_chain {label}"), || {
            generate_c3_chonk_chain(
                &prover,
                &c3_proofs,
                &c3_slots,
                total_slots,
                &format!("measure-c3-{label}"),
                &artifacts_dir,
            )
        });
    }
}

/// C3 proving throughput: proves the same `MEASURE_C3_COUNT` (default 24) C3 slots with 1, 2 and 4
/// proofs at a time, splitting `MEASURE_THREADS` (default 16) bb threads evenly between them. Needs
/// `MEASURE_C3_CONCURRENCY=1`.
#[tokio::test]
async fn trbfv_c3_concurrency_measure() {
    let Some((committee_size, committee_name)) =
        pipeline::gate(PRESET, Some("MEASURE_C3_CONCURRENCY"))
    else {
        return;
    };
    let count: usize = std::env::var("MEASURE_C3_COUNT")
        .map(|v| v.parse().expect("MEASURE_C3_COUNT"))
        .unwrap_or(24);
    let threads: usize = std::env::var("MEASURE_THREADS")
        .map(|v| v.parse().expect("MEASURE_THREADS"))
        .unwrap_or(16);
    pipeline::install_bb_trace();
    let committee = committee_size.values();
    let bb = find_bb().await.expect("bb");
    let (backend, _temp) = setup_test_prover(&bb).await;
    let prover = pipeline::prover(&backend);
    let artifacts_dir = prover.resolve_artifacts_dir(PRESET, &committee_name);
    pipeline::stage(
        &backend,
        &artifacts_dir,
        &[CircuitName::ShareEncryption],
        &[],
    )
    .await;

    let dkg_pk = prep("dkg key", || {
        let (_, dkg_params) = build_pair_for_preset(PRESET).expect("DKG parameters");
        let mut dkg_rng = rng();
        PublicKey::new(&SecretKey::random(&dkg_params, &mut dkg_rng), &mut dkg_rng)
    });
    let sk_inputs = prep("own C2a inputs", || {
        let (key_data, _, secret_key) =
            node_fold_witness::pk_generation_sample_with_esi(PRESET, committee.clone())
                .expect("key data");
        let share_sk = node_fold_witness::share_computation_sk_from_pk(
            PRESET,
            committee.clone(),
            &key_data,
            &secret_key,
        )
        .expect("C2a data");
        let config =
            e3_zk_config::dkg::share_computation::Configs::for_preset(PRESET, committee_size)
                .expect("C2 configuration");
        ShareComputationInputs::compute(&config, &share_sk).expect("C2a inputs")
    });
    let slots_per_party = PRESET.metadata().num_moduli;
    let config =
        e3_zk_config::dkg::share_encryption::Configs::for_preset(PRESET).expect("C3 configuration");
    let data: Vec<_> = prep("C3 witness data", || {
        (slots_per_party..slots_per_party + count)
            .map(|slot| {
                node_fold_witness::share_encryption_for_slot(
                    PRESET,
                    &dkg_pk,
                    &sk_inputs,
                    slot,
                    DkgInputType::SecretKey,
                )
                .expect("C3 witness data")
            })
            .collect()
    });

    for parallel in [1usize, 2, 4] {
        let per_proof = (threads / parallel).max(1);
        // Every bb process reads its thread count from the environment it inherits.
        std::env::set_var("HARDWARE_CONCURRENCY", per_proof.to_string());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(parallel)
            .build()
            .expect("pool");
        let label = format!("c3_x{parallel}_t{per_proof}");
        measure(&label, || {
            pool.install(|| {
                use rayon::prelude::*;
                data.par_iter()
                    .enumerate()
                    .map(|(i, d)| {
                        ShareEncryptionCircuit.prove(
                            &prover,
                            &config,
                            d,
                            &format!("measure-{label}-{i}"),
                            &artifacts_dir,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
        });
    }
    std::env::set_var("HARDWARE_CONCURRENCY", threads.to_string());
}

/// Threshold decryption on the trBFV preset: the node's C6, and with `MEASURE_AGGREGATOR=1` the
/// aggregator's C6 fold chain and C7.
#[tokio::test]
async fn trbfv_decryption_measure() {
    let Some((committee_size, committee_name)) = pipeline::gate(PRESET, Some("MEASURE_DECRYPTION"))
    else {
        return;
    };
    pipeline::install_bb_trace();
    let committee = committee_size.values();
    let bb = find_bb().await.expect("bb");
    let (backend, _temp) = setup_test_prover(&bb).await;
    let prover = pipeline::prover(&backend);
    let artifacts_dir = prover.resolve_artifacts_dir(PRESET, &committee_name);
    let aggregator = pipeline::env_flag("MEASURE_AGGREGATOR");
    let leaves: &[CircuitName] = if aggregator {
        &[
            CircuitName::ThresholdShareDecryption,
            CircuitName::DecryptedSharesAggregation,
        ]
    } else {
        &[CircuitName::ThresholdShareDecryption]
    };
    let folds: &[CircuitName] = if aggregator {
        &[
            CircuitName::C6ChonkApp,
            CircuitName::C6ChonkInitKernel,
            CircuitName::C6ChonkTailKernel,
            CircuitName::C6ChonkHidingKernel,
            CircuitName::C6ChonkTube,
            CircuitName::C6ChonkRoot,
        ]
    } else {
        &[]
    };
    pipeline::stage(&backend, &artifacts_dir, leaves, folds).await;
    pipeline::run_decryption(&prover, PRESET, &committee, &artifacts_dir);
}

/// The aggregator's trBFV DKG proof: C5 (`pk_aggregation`) over the `H` honest parties' public key
/// shares, as `aggregation_proofs.rs` requests it. The Π_DKG fold over the nodes' `node_fold`
/// proofs (`nodes_fold` chain and `dkg_aggregator`) is not proved here.
#[tokio::test]
async fn trbfv_aggregator_pk_aggregation_measure() {
    let Some((committee_size, committee_name)) = pipeline::gate(PRESET, Some("MEASURE_AGGREGATOR"))
    else {
        return;
    };
    pipeline::install_bb_trace();
    let bb = find_bb().await.expect("bb");
    let (backend, _temp) = setup_test_prover(&bb).await;
    let prover = pipeline::prover(&backend);
    let artifacts_dir = prover.resolve_artifacts_dir(PRESET, &committee_name);
    pipeline::stage(&backend, &artifacts_dir, &[CircuitName::PkAggregation], &[]).await;
    let config =
        e3_zk_config::threshold::pk_aggregation::Configs::for_preset(PRESET, committee_size)
            .expect("C5 configuration");
    let data = prep("H public key shares", || {
        e3_zk_samples::threshold::pk_aggregation::generate(&config).expect("C5 sample")
    });

    let mut phases = Phases::new("aggregator");
    phases.run("c5", || {
        measure("c5", || {
            PkAggregationCircuit.prove(&prover, &config, &data, "measure-c5", &artifacts_dir)
        })
    });
    phases.finish();
}
