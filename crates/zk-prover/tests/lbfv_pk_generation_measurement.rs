// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Stage-by-stage cost of one party's l-BFV public-key generation, up to the row proofs.
//!
//! `task_costs.sh --prove` cannot reach the row terminal: `zk_cli` refuses to fabricate recursive
//! proof inputs, so the aggregation step has to be driven with real limb proofs. That is what this
//! measurement does - it proves every limb, then the terminal that recursively verifies them, and
//! reports each stage.
//!
//! Run with artifacts staged:
//!   INTERFOLD_SECURE_16384_ARTIFACTS=<dir> \
//!     cargo test -p e3-zk-prover --test lbfv_pk_generation_measurement -- --nocapture --ignored

mod common;

use std::time::Instant;

use common::{
    active_bin_preset, compiled_circuit_artifacts_available, find_bb,
    require_minimum_circuits_for_preset, setup_compiled_circuit_for_preset, setup_test_prover,
};
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::threshold::pk_generation::{
    LbfvPartySecretsCircuit, LbfvPartySecretsCircuitData, LbfvPkGenerationCircuitData,
};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{
    load_staged_lbfv_pk_generation_limb_vk_hash, prove_lbfv_pk_generation_row, Provable, ZkProver,
};

/// Circuits this measurement needs staged. `lbfv_party_secrets` is proved on its own; the limb and
/// the terminal are driven together by `prove_lbfv_pk_generation_row`.
const CIRCUITS: [&str; 3] = [
    "lbfv_party_secrets",
    "lbfv_pk_generation_limb",
    "lbfv_pk_generation",
];

/// GADGET_DIM at secure-16384. One public-key row per gadget row.
const ROWS: u32 = 5;

fn secs(start: Instant) -> f64 {
    start.elapsed().as_secs_f64()
}

#[tokio::test]
#[ignore = "proves 25 limbs plus 5 recursive terminals; run deliberately"]
async fn lbfv_pk_generation_stage_costs() {
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
        println!("skipping: l-BFV public-key generation artifacts are not staged");
        return;
    }

    let (backend, _temp) = setup_test_prover(&bb).await;
    for circuit in CIRCUITS {
        setup_compiled_circuit_for_preset(&backend, "threshold", circuit, preset, "minimum").await;
    }

    let committee = CiphernodesCommitteeSize::Minimum.values();
    let artifacts_dir = preset.artifacts_dir_for_committee("minimum");
    let prover = ZkProver::new(&backend);

    println!("\n=== l-BFV public-key generation, one party, secure-16384/minimum ===\n");

    // Stage 1: the party's secrets. One proof, no recursion.
    let secrets_sample = LbfvPartySecretsCircuitData::generate_sample(preset, committee.clone())
        .expect("valid l-BFV party secrets");
    let started = Instant::now();
    let secrets_proof = LbfvPartySecretsCircuit
        .prove(
            &prover,
            &preset,
            &secrets_sample,
            "lbfv-party-secrets",
            &artifacts_dir,
        )
        .expect("party-secrets proof");
    let secrets_s = secs(started);
    println!("party secrets        1 proof    {secrets_s:>8.2}s");

    let started = Instant::now();
    assert!(
        LbfvPartySecretsCircuit
            .verify(
                &prover,
                &secrets_proof,
                "lbfv-party-secrets",
                0,
                &artifacts_dir,
            )
            .expect("party-secrets verification"),
        "party-secrets proof must verify"
    );
    println!("party secrets verify            {:>8.2}s", secs(started));

    // Stage 2: every row. Each call proves L limbs, then the terminal that verifies them, so the
    // difference between the two is the cost of the aggregation step itself.
    let limb_vk_hash = load_staged_lbfv_pk_generation_limb_vk_hash(&prover, &artifacts_dir)
        .expect("staged public-key limb VK hash");

    let mut rows_total = 0.0;
    for row_index in 0..ROWS {
        let sample = LbfvPkGenerationCircuitData::generate_sample_for_row(
            preset,
            committee.clone(),
            row_index,
        )
        .expect("valid l-BFV public-key generation row");
        let started = Instant::now();
        let proofs = prove_lbfv_pk_generation_row(
            &prover,
            preset,
            &sample,
            &limb_vk_hash,
            "lbfv-pk-generation-measurement",
            &artifacts_dir,
        )
        .expect("row proofs");
        let row_s = secs(started);
        rows_total += row_s;
        println!(
            "row {row_index}                {} limb + 1 terminal   {row_s:>8.2}s",
            proofs.limb_proofs.len()
        );
    }

    println!("\n---");
    println!("party secrets                   {secrets_s:>8.2}s");
    println!("all {ROWS} rows (limbs + terminals) {rows_total:>8.2}s");
    println!(
        "TOTAL to {ROWS} row proofs          {:>8.2}s",
        secrets_s + rows_total
    );
    println!(
        "\nStops at {ROWS} row proofs. Folding them into a single public-key generation proof\n\
         costs a further 6.5M gates (lbfv_pk_fold_kernel + 4 x lbfv_pk_fold, measurement-only):\n\
         sequential folding verifies the accumulator at every step, so 5 rows take 9 recursive\n\
         verifications, not 5. See `task_costs.sh --task pk-fold`.\n"
    );
}
