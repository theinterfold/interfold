// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Workflow-level e2e for the private credit-scoring v2 app on the
//! on-chain ParamSet-4 credit preset, exercising the REAL
//! `ckks_credit_eval` binary:
//!
//! 1. full serialized DKG (e3-trckks job payloads) over the params every
//!    node derives for ParamSet 4, then TWO per-level multiparty relin
//!    ceremonies (levels 1 and 2 — `RelinCeremonyPlan::PerLevel([1, 2])`,
//!    through the wire framing) whose joint keys are written to a key
//!    directory exactly as the ciphernode shell writes them
//!    (`rlk_level_1.bin`, `rlk_level_2.bin`);
//! 2. three applicants each encrypt TWO slot-encoded ciphertexts at
//!    their slot `i`: the public model's logit `z_i = ⟨w, x_i⟩ + b` and
//!    an output mask `m_i ∈ [0, 1024)`, written to disk;
//! 3. `ckks_credit_eval` run as a subprocess on those files with
//!    `--rlk-dir` — the invocation the E3 program makes;
//! 4. threshold decryption of the binary's ONE output ciphertext through
//!    the serialized decryption-share payloads (at the OPENING level 3),
//!    asserting each applicant recovers `σ_cubic(z_i)` within 1e-2 after
//!    subtracting its mask, and that every opened raw value is > 0.5
//!    from every applicant's true score (the masks dominate);
//! 5. the flooding bound `CkksSmudgingBoundCalculator` derives for this
//!    depth-2 (two ct×ct) circuit shape at `MIN_SECURE_LAMBDA` (printed
//!    next to the demo's 20 bits — run with `--nocapture`).

use e3_fhe_params::ckks_presets::{
    ckks_opening_level_for_param_set, relin_ceremony_plan_for_param_set, RelinCeremonyPlan,
    CREDIT_RELIN_LEVELS,
};
use e3_trckks::dkg::{aggregate_collected_shares, share_poly_to_bytes, ShareMatrices};
use e3_trckks::policy::{
    credit_slot_vector, credit_v2_unmask, sigmoid_cubic, RelinKeys, CREDIT_FEATURES,
    CREDIT_LOGIT_BOUND, CREDIT_OUTPUT_MASK_BOUND,
};
use e3_trckks::threshold_decryption::{
    calculate_decryption_share, calculate_threshold_decryption, CalculateDecryptionShareRequest,
    CalculateThresholdDecryptionRequest,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksRelinearizationKey, CkksSecretKey};
use fhe::trbfv::{Lambda, MIN_SECURE_LAMBDA};
use fhe::trckks::{
    CkksCircuitShape, CkksCrp, CkksRelinKeyGenerator, CkksRelinKeyShare,
    CkksSmudgingBoundCalculator, CkksSmudgingConfig, R1Aggregated, R1, R2, TRCKKS,
};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::{Rng, RngCore};
use std::process::Command;
use std::sync::Arc;

const N_PARTIES: u64 = 5;
const THRESHOLD: u64 = 2;
const SMUDGING_BITS: usize = 20;

#[test]
fn credit_eval_binary_on_param_set_4() {
    let mut rng = rand::rng();
    // The EXACT params every ciphernode derives for on-chain ParamSet 4.
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(4).unwrap();
    assert_eq!(
        relin_ceremony_plan_for_param_set(4).unwrap(),
        RelinCeremonyPlan::PerLevel(CREDIT_RELIN_LEVELS.to_vec()),
        "credit v2 multiplies ct × ct at levels 1 and 2"
    );
    let params_bytes = params.to_bytes();
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params_bytes), N_PARTIES, THRESHOLD);

    let dir = std::env::temp_dir().join(format!(
        "ckks-credit-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // ── 1a. Serialized DKG ──────────────────────────────────────────────
    let t0 = std::time::Instant::now();
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
    let dkg_ms = t0.elapsed().as_millis();

    // ── 1b. Two per-level ceremonies → key directory ────────────────────
    let t1 = std::time::Instant::now();
    let rlk_dir = dir.join("relin-keys");
    std::fs::create_dir_all(&rlk_dir).unwrap();
    for &level in &CREDIT_RELIN_LEVELS {
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        let crp_len = params.moduli().len() - level;
        let crp = CkksCrp::vec_from_seed_leveled(&params, rlk_seed, crp_len, level).unwrap();
        let generators: Vec<_> = sks
            .iter()
            .map(|sk| CkksRelinKeyGenerator::new_leveled(sk, &crp, level, &mut rng).unwrap())
            .collect();
        let r1: Vec<_> = generators
            .iter()
            .map(|g| {
                let bytes = g.round_1(&mut rng).unwrap().to_bytes();
                CkksRelinKeyShare::<R1>::from_bytes(&bytes, &params).unwrap()
            })
            .collect();
        let r1_agg = Arc::new(CkksRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
        let r2: Vec<_> = generators
            .iter()
            .map(|g| {
                let bytes = g.round_2(&r1_agg, &mut rng).unwrap().to_bytes();
                CkksRelinKeyShare::<R2>::from_bytes(&bytes, &params).unwrap()
            })
            .collect();
        let key_bytes = CkksRelinKeyShare::<R2>::aggregate_into_key_with_r1(r2, r1_agg)
            .unwrap()
            .to_bytes();
        let key = CkksRelinearizationKey::from_bytes(&key_bytes, &params).unwrap();
        assert_eq!(key.level(), level);
        std::fs::write(rlk_dir.join(RelinKeys::level_key_file(level)), &key_bytes).unwrap();
    }
    let ceremony_ms = t1.elapsed().as_millis();
    // The loader the program uses reads them back at the right levels.
    let loaded = RelinKeys::load_from_dir(&rlk_dir, &params, &CREDIT_RELIN_LEVELS).unwrap();
    assert!(loaded.covers_levels_through(2));

    // ── 2. Applicants: (logit, mask) slot pairs ─────────────────────────
    let weights: [f64; CREDIT_FEATURES] = [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2];
    let bias = -0.8f64;
    let applicants = 3usize;
    let slots = params.slots();
    let encoder = CkksEncoder::new(&params);
    let mut logits = Vec::new();
    let mut masks = Vec::new();
    let mut input_files = Vec::new();
    for i in 0..applicants {
        let x: [f64; CREDIT_FEATURES] = std::array::from_fn(|_| rng.random_range(0.0f64..=1.0));
        let z: f64 = weights.iter().zip(&x).map(|(w, a)| w * a).sum::<f64>() + bias;
        assert!(z.abs() <= CREDIT_LOGIT_BOUND);
        let mask = (rng.random_range(0u32..(1 << 20)) as f64) / 1024.0;
        assert!(mask < CREDIT_OUTPUT_MASK_BOUND);
        for (tag, v) in [("z", z), ("m", mask)] {
            let pt = encoder
                .encode(&credit_slot_vector(v, i, slots).unwrap(), 0)
                .unwrap();
            let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
            let path = dir.join(format!("applicant_{i}_{tag}.bin"));
            std::fs::write(&path, ct.to_bytes()).unwrap();
            input_files.push(path);
        }
        logits.push(z);
        masks.push(mask);
    }

    // ── 3. Run the REAL eval binary ─────────────────────────────────────
    let t2 = std::time::Instant::now();
    let out_path = dir.join("scores.bin");
    let commit_path = dir.join("scores_commitment.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_ckks_credit_eval"))
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
        .arg(&rlk_dir)
        .arg("--output")
        .arg(&out_path)
        .arg("--commitment-output")
        .arg(&commit_path)
        .output()
        .expect("failed to spawn ckks_credit_eval");
    assert!(
        output.status.success(),
        "eval binary failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let eval_ms = t2.elapsed().as_millis();
    let out_ct_bytes = std::fs::read(&out_path).unwrap();
    let commitment = std::fs::read(&commit_path).unwrap();
    assert_eq!(
        commitment,
        alloy::primitives::keccak256(&out_ct_bytes).as_slice()
    );
    // The packed output sits at the OPENING level (three rescales) with
    // two components (both products relinearized) — the level the C6/C7
    // ps4 configs are generated at.
    let out_ct = CkksCiphertext::from_bytes(&out_ct_bytes, &params).unwrap();
    assert_eq!(out_ct.level, ckks_opening_level_for_param_set(4).unwrap());
    assert_eq!(out_ct.len(), 2);

    // ── 4. Threshold decryption via the serialized share payloads ───────
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
    assert!(opened.len() >= applicants + 1);

    let true_scores: Vec<f64> = logits.iter().map(|z| sigmoid_cubic(*z)).collect();
    for i in 0..applicants {
        // Only applicant i (holding m_i) can unmask slot i.
        let got = credit_v2_unmask(opened[i], masks[i]);
        assert!(
            (got - true_scores[i]).abs() < 1e-2,
            "applicant {i}: unmasked {got} vs σ_cubic({}) = {}",
            logits[i],
            true_scores[i]
        );
        // The opened raw value is far from EVERY applicant's true score.
        for (k, s) in true_scores.iter().enumerate() {
            assert!(
                (opened[i] - s).abs() > 0.5,
                "opened {} (applicant {i}) within 0.5 of score {s} (applicant {k})",
                opened[i]
            );
        }
    }
    // Unused slot opens as σ_cubic(0) + 0 = 0.5.
    assert!((opened[applicants] - 0.5).abs() < 1e-2);

    // ── 5. Flooding bound for this circuit shape ────────────────────────
    // Depth 3 in rescales (one-hot alignment + z² + z³) with two ct×ct
    // products; operands bounded by the logit bound; inputs by the mask
    // range; the opened value is a masked probability so 1e-2 absolute
    // error is the declared tolerance.
    let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
        params: params.clone(),
        n_parties: N_PARTIES as usize,
        circuit: CkksCircuitShape {
            num_additions: applicants,
            depth: out_ct.level,
            mult_operand_bound: CREDIT_LOGIT_BOUND,
        },
        level: out_ct.level,
        input_bound: CREDIT_OUTPUT_MASK_BOUND,
        precision_loss: 1e-2,
        lambda: Lambda::secure(MIN_SECURE_LAMBDA).unwrap(),
    });
    let b_c_bits = calc.circuit_noise_bound().bits();
    let required_bits = b_c_bits as usize + MIN_SECURE_LAMBDA;
    println!(
        "credit v2 timings: DKG {dkg_ms} ms, two per-level ceremonies {ceremony_ms} ms, \
         eval binary {eval_ms} ms"
    );
    match calc.calculate_sm_bits() {
        Ok(bits) => println!(
            "credit ParamSet 4 (depth {}, two ct×ct, {applicants} applicants): flooding bound \
             needs {bits} sm_bits at lambda={MIN_SECURE_LAMBDA} (demo uses {SMUDGING_BITS})",
            out_ct.level
        ),
        Err(e) => println!(
            "credit ParamSet 4 (depth {}, two ct×ct, {applicants} applicants): B_C = 2^{b_c_bits}, \
             so B_sm = 2^lambda * B_C needs {required_bits} sm_bits at lambda={MIN_SECURE_LAMBDA} — \
             INFEASIBLE under the demo params ({e}); demo uses {SMUDGING_BITS} bits",
            out_ct.level
        ),
    }

    std::fs::remove_dir_all(&dir).ok();
}
