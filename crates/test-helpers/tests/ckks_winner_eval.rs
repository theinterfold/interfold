// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Workflow-level e2e for the leak-free WINNER mode on the on-chain
//! ParamSet-2 sign-extraction ladder, exercising the REAL
//! `ckks_auction_eval` binary:
//!
//! 1. full serialized DKG (e3-trckks job payloads) over the ladder params
//!    every node derives for ParamSet 2;
//! 2. the multiparty relin-key ceremony for every sign-map multiplication
//!    level, joint keys WRITTEN TO DISK exactly as the node shell lays
//!    them out (`rlk_level_{level}.bin`);
//! 3. slot-replicated encrypted bids (with a 2% gap) written to disk;
//! 4. `ckks_auction_eval --mode winner` run as a subprocess on those
//!    files — the same invocation the demo server makes;
//! 5. threshold decryption of the binary's output through the serialized
//!    payloads, asserting the winner is correct AND the opening contains
//!    ONLY saturated ±1 signs (no bid-difference magnitudes).

use e3_trckks::dkg::{aggregate_collected_shares, share_poly_to_bytes, ShareMatrices};
use e3_trckks::threshold_decryption::{
    calculate_decryption_share, calculate_threshold_decryption, CalculateDecryptionShareRequest,
    CalculateThresholdDecryptionRequest,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksSecretKey};
use fhe::trckks::{CkksCrp, R1Aggregated, R2, TRCKKS};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::RngCore;
use std::process::Command;
use std::sync::Arc;

const N_PARTIES: u64 = 5;
const THRESHOLD: u64 = 2;
const SMUDGING_BITS: usize = 20;
const ITERATIONS: usize = e3_fhe_params::ckks_presets::SIGN_EXTRACTION_ITERATIONS;

#[test]
fn winner_mode_eval_binary_on_param_set_2_ladder() {
    let mut rng = rand::rng();
    // The EXACT params every ciphernode derives for on-chain ParamSet 2.
    let params = e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(2).unwrap();
    let params_bytes = params.to_bytes();
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params_bytes), N_PARTIES, THRESHOLD);

    let dir = std::env::temp_dir().join(format!(
        "ckks-winner-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // ── 1+2. DKG + relin ceremony from shared member secrets ────────────
    // The relin key must be for the SAME joint secret as the pk, and the
    // lean DKG job API doesn't expose per-member secrets — so the
    // committee is built from explicit member secrets used for both
    // protocols (exactly like e2e_sign_extraction_policy). Dealt shares
    // still travel through the serialized `ShareMatrices` payloads and
    // decryption through the serialized job payloads.
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

    // Ceremony: ONE two-round HYBRID ceremony (ParamSet 2 carries special
    // primes), its single joint key written to disk in the node shell's
    // layout (`rlk_hybrid.bin`).
    assert!(params.hybrid_enabled(), "ParamSet 2 is hybrid");
    {
        use fhe::trckks::{CkksHybridRelinKeyGenerator, CkksHybridRelinKeyShare};
        let mut rlk_seed = [0u8; 32];
        rng.fill_bytes(&mut rlk_seed);
        let crp = CkksCrp::vec_from_seed_qp(&params, rlk_seed).unwrap();
        let generators: Vec<_> = sks
            .iter()
            .map(|sk| CkksHybridRelinKeyGenerator::new(sk, &crp, &mut rng).unwrap())
            .collect();
        let r1: Vec<_> = generators
            .iter()
            .map(|g| g.round_1(&mut rng).unwrap())
            .collect();
        let r1_agg = Arc::new(CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(r1).unwrap());
        let r2: Vec<_> = generators
            .iter()
            .map(|g| g.round_2(&r1_agg, &mut rng).unwrap())
            .collect();
        let rlk = CkksHybridRelinKeyShare::<R2>::aggregate_into_key(r2).unwrap();
        std::fs::write(dir.join("rlk_hybrid.bin"), rlk.to_bytes()).unwrap();
    }

    // ── 3. Slot-replicated encrypted bids (2% gap: 402 vs 382/1000) ────
    let bids = [220.5f64, 815.0, 74.25, 402.0, 382.0];
    let bound = 1000.0;
    let slots = params.degree() / 2;
    let encoder = CkksEncoder::new(&params);
    let mut bid_files = Vec::new();
    for (i, b) in bids.iter().enumerate() {
        let ct = pk
            .try_encrypt(&encoder.encode(&vec![*b; slots], 0).unwrap(), &mut rng)
            .unwrap();
        let path = dir.join(format!("bid_{i}.bin"));
        std::fs::write(&path, ct.to_bytes()).unwrap();
        bid_files.push(path);
    }

    // ── 4. Run the REAL eval binary in winner mode ──────────────────────
    let out_path = dir.join("winner.bin");
    let commit_path = dir.join("winner_commitment.bin");
    let output = Command::new(env!("CARGO_BIN_EXE_ckks_auction_eval"))
        .arg("--params")
        .arg(hex::encode(&params_bytes))
        .arg("--bids")
        .arg(
            bid_files
                .iter()
                .map(|p| p.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
        .arg("--output")
        .arg(&out_path)
        .arg("--commitment-output")
        .arg(&commit_path)
        .arg("--mode")
        .arg("winner")
        .arg("--rlk-dir")
        .arg(&dir)
        .arg("--bound")
        .arg(bound.to_string())
        .arg("--iterations")
        .arg(ITERATIONS.to_string())
        .output()
        .expect("failed to spawn ckks_auction_eval");
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
    // Sanity: the output really is a ladder ciphertext at the final level.
    let out_ct = CkksCiphertext::from_bytes(&out_ct_bytes, &params).unwrap();
    assert_eq!(out_ct.level, 1 + 3 * ITERATIONS);

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

    // Winner assertions: every pair slot is the CORRECT sign and is
    // SATURATED (±1): the output leaks the order and nothing else.
    let pairs: Vec<(usize, usize)> = (0..bids.len())
        .flat_map(|i| ((i + 1)..bids.len()).map(move |j| (i, j)))
        .collect();
    for (p, &(a, b)) in pairs.iter().enumerate() {
        assert_eq!(
            opened[p] > 0.0,
            bids[a] > bids[b],
            "pair {p} ({a},{b}): opened {} for bids {} vs {}",
            opened[p],
            bids[a],
            bids[b]
        );
        assert!(
            (opened[p].abs() - 1.0).abs() < 0.05,
            "pair {p} not binarized: {} (gap {}) — magnitude leak!",
            opened[p],
            (bids[a] - bids[b]).abs()
        );
    }
    // Dominance: bidder 1 (815.0) wins every comparison.
    let mut wins = vec![0usize; bids.len()];
    for (p, &(a, b)) in pairs.iter().enumerate() {
        if opened[p] > 0.0 {
            wins[a] += 1;
        } else {
            wins[b] += 1;
        }
    }
    assert_eq!(wins[1], bids.len() - 1, "bidder 1 must win all comparisons");

    std::fs::remove_dir_all(&dir).ok();
}
