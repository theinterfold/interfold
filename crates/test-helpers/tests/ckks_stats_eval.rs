// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Workflow-level e2e for the salary-survey statistics mode on the
//! on-chain ParamSet-3 statistics preset, exercising the REAL
//! `ckks_stats_eval` binary:
//!
//! 1. full serialized DKG (e3-trckks job payloads) over the params every
//!    node derives for ParamSet 3;
//! 2. the multiparty relin-key ceremony for the SINGLE multiplication
//!    level the packed statistics policy needs (level 0), the joint key
//!    WRITTEN TO DISK exactly as the node shell lays it out
//!    (`rlk_level_0.bin`);
//! 3. slot-replicated, cap-normalized encrypted salaries written to disk;
//! 4. `ckks_stats_eval` run as a subprocess on those files — the same
//!    invocation the demo server makes;
//! 5. threshold decryption of the binary's ONE output ciphertext through
//!    the serialized payloads, asserting mean and variance match the
//!    plaintext-side computation (individual salaries never decrypt).

use e3_trckks::dkg::{aggregate_collected_shares, share_poly_to_bytes, ShareMatrices};
use e3_trckks::threshold_decryption::{
    calculate_decryption_share, calculate_threshold_decryption, CalculateDecryptionShareRequest,
    CalculateThresholdDecryptionRequest,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksSecretKey};
use fhe::trckks::{CkksCrp, CkksRelinKeyGenerator, CkksRelinKeyShare, R1Aggregated, R2, TRCKKS};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::RngCore;
use std::process::Command;
use std::sync::Arc;

const N_PARTIES: u64 = 5;
const THRESHOLD: u64 = 2;
const SMUDGING_BITS: usize = 20;

#[test]
fn stats_eval_binary_on_param_set_3() {
    let mut rng = rand::rng();
    // The EXACT params every ciphernode derives for on-chain ParamSet 3.
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(3).unwrap();
    let params_bytes = params.to_bytes();
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params_bytes), N_PARTIES, THRESHOLD);

    let dir = std::env::temp_dir().join(format!(
        "ckks-stats-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // ── 1+2. DKG + relin ceremony from shared member secrets ────────────
    // The relin key must be for the SAME joint secret as the pk (the lean
    // DKG job API doesn't expose per-member secrets), so the committee is
    // built from explicit member secrets used for both protocols — dealt
    // shares still travel through the serialized `ShareMatrices` payloads
    // and decryption through the serialized job payloads.
    let mut crp_seed = [0u8; 32];
    rng.fill_bytes(&mut crp_seed);
    let sks: Vec<_> = (0..N_PARTIES)
        .map(|_| CkksSecretKey::random(&params, &mut rng))
        .collect();
    let crp_pk = CkksCrp::from_seed(&params, crp_seed).unwrap();
    let pk_shares: Vec<_> = sks
        .iter()
        .map(|sk| fhe::trckks::CkksPublicKeyShare::new(sk, crp_pk.clone(), &mut rng).unwrap())
        .collect();
    let pk = fhe::trckks::CkksPublicKeyShare::aggregate(&pk_shares).unwrap();
    let trckks = TRCKKS::new(N_PARTIES as usize, THRESHOLD as usize, params.clone()).unwrap();
    let mut sk_dealt = Vec::new();
    let mut es_dealt = Vec::new();
    for sk_i in &sks {
        let sk_poly = trckks.coeffs_to_poly(sk_i.coeffs.as_ref()).unwrap();
        sk_dealt.push(ShareMatrices::from_arrays(
            &trckks
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .unwrap(),
        ));
        let es = trckks
            .generate_smudging_error(SMUDGING_BITS, &mut rng)
            .unwrap();
        let es_poly = trckks.smudging_to_poly(&es).unwrap();
        es_dealt.push(ShareMatrices::from_arrays(
            &trckks
                .generate_secret_shares_from_poly(es_poly, &mut rng)
                .unwrap(),
        ));
    }
    let member_shares: Vec<(ArcBytes, ArcBytes)> = (0..N_PARTIES as usize)
        .map(|j| {
            let sk = aggregate_collected_shares(&config, &sk_dealt, j).unwrap();
            let es = aggregate_collected_shares(&config, &es_dealt, j).unwrap();
            (share_poly_to_bytes(&sk), share_poly_to_bytes(&es))
        })
        .collect();

    // Ceremony: ONLY level 0 (the packed statistics policy squares and
    // relinearizes there), written to disk in the node shell's layout.
    let level = 0usize;
    let mut rlk_seed = [0u8; 32];
    rng.fill_bytes(&mut rlk_seed);
    let len = params.moduli().len() - level;
    let crp = CkksCrp::vec_from_seed_leveled(&params, rlk_seed, len, level).unwrap();
    let generators: Vec<_> = sks
        .iter()
        .map(|sk| CkksRelinKeyGenerator::new_leveled(sk, &crp, level, &mut rng).unwrap())
        .collect();
    let r1: Vec<_> = generators
        .iter()
        .map(|g| g.round_1(&mut rng).unwrap())
        .collect();
    let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
    let r2: Vec<_> = generators
        .iter()
        .map(|g| g.round_2(&r1_agg, &mut rng).unwrap())
        .collect();
    let rlk = CkksRelinKeyShare::<R2>::aggregate_into_key(r2).unwrap();
    std::fs::write(dir.join(format!("rlk_level_{level}.bin")), rlk.to_bytes()).unwrap();

    // ── 3. Slot-replicated, cap-normalized encrypted salaries ───────────
    let salaries = [52000.0f64, 61000.0, 48500.0, 75000.0, 58000.0];
    let cap = 200000.0f64;
    let slots = params.degree() / 2;
    let encoder = CkksEncoder::new(&params);
    let mut input_files = Vec::new();
    for (i, v) in salaries.iter().enumerate() {
        let ct = pk
            .try_encrypt(
                &encoder.encode(&vec![*v / cap; slots], 0).unwrap(),
                &mut rng,
            )
            .unwrap();
        let path = dir.join(format!("salary_{i}.bin"));
        std::fs::write(&path, ct.to_bytes()).unwrap();
        input_files.push(path);
    }

    // ── 4. Run the REAL eval binary ─────────────────────────────────────
    let out_path = dir.join("stats.bin");
    let commit_path = dir.join("stats_commitment.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_ckks_stats_eval"))
        .arg("--params")
        .arg(hex::encode(&params_bytes))
        .arg("--inputs")
        .arg(
            input_files
                .iter()
                .map(|p| p.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
        .arg("--rlk-dir")
        .arg(&dir)
        .arg("--output")
        .arg(&out_path)
        .arg("--commitment-output")
        .arg(&commit_path)
        .output()
        .expect("failed to spawn ckks_stats_eval");
    assert!(
        output.status.success(),
        "eval binary failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let out_ct_bytes = std::fs::read(&out_path).unwrap();
    // Commitment binds the exact evaluated ciphertext.
    let commitment = std::fs::read(&commit_path).unwrap();
    assert_eq!(
        commitment,
        alloy::primitives::keccak256(&out_ct_bytes).as_slice()
    );
    // Sanity: the packed output sits at level 1 (one rescale after the
    // level-0 relinearized squaring).
    let out_ct = CkksCiphertext::from_bytes(&out_ct_bytes, &params).unwrap();
    assert_eq!(out_ct.level, 1);

    // ── 5. Threshold decryption via the serialized payloads ─────────────
    let ct_arc = ArcBytes::from_bytes(&out_ct_bytes);
    let parties: Vec<u64> = (1..=THRESHOLD + 1).collect();
    let shares: Vec<ArcBytes> = parties
        .iter()
        .map(|&j| {
            let (sk, es) = &member_shares[(j - 1) as usize];
            calculate_decryption_share(CalculateDecryptionShareRequest {
                name: format!("party-{j}"),
                trckks_config: config.clone(),
                ciphertext: ct_arc.clone(),
                sk_poly_sum: sk.clone(),
                es_poly_sum: es.clone(),
            })
            .unwrap()
            .decryption_share
        })
        .collect();
    let opened = calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
        trckks_config: config.clone(),
        ciphertext: ct_arc,
        decryption_shares: shares,
        party_ids: parties,
    })
    .unwrap()
    .values;

    // The opening reveals ONLY the aggregates: S*sum/cap in slot 0 and
    // S*sumsq/cap^2 in slot 1 (S = 10^4, the eval binary's default
    // output scale).
    let s_out = 10_000.0f64;
    let n = salaries.len() as f64;
    let sum = opened[0] / s_out * cap;
    let sumsq = opened[1] / s_out * cap * cap;
    let mean = sum / n;
    let variance = sumsq / n - mean * mean;

    let true_mean = salaries.iter().sum::<f64>() / n;
    let true_var = salaries
        .iter()
        .map(|x| (x - true_mean).powi(2))
        .sum::<f64>()
        / n;
    assert!(
        (mean - true_mean).abs() / true_mean < 0.001,
        "mean {mean} vs {true_mean}"
    );
    // Variance is magnified by the squares; Lagrange smudging noise adds
    // on top — allow ~1% relative.
    assert!(
        (variance - true_var).abs() / true_var < 0.01,
        "variance {variance} vs {true_var}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
