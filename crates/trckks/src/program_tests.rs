// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Program-level tests: the slot-batched auction bracket over real E3
//! rounds — each round is ONE policy computation + ONE threshold opening —
//! plus the canonical fixed-point on-chain encoding.

use super::program::*;
use crate::config::insecure_512_params;
use crate::dkg::{
    aggregate_collected_shares, aggregate_pk_shares, gen_pk_share_and_sk_sss, share_poly_to_bytes,
    GenPkShareAndSkSssRequest,
};
use crate::threshold_decryption::{
    calculate_decryption_share, calculate_threshold_decryption, CalculateDecryptionShareRequest,
    CalculateThresholdDecryptionRequest,
};
use crate::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksEncoder;
use fhe_traits::Serialize as FheSerialize;
use rand::RngCore;

const N_PARTIES: u64 = 5;
const THRESHOLD: u64 = 2;
const SMUDGING_BITS: usize = 20;

struct Committee {
    config: TrCkksConfig,
    pk: fhe::ckks::CkksPublicKey,
    member_shares: Vec<(ArcBytes, ArcBytes)>,
}

fn run_dkg(config: &TrCkksConfig, crp_seed: [u8; 32]) -> Committee {
    let mut rng = rand::rng();
    let responses: Vec<_> = (0..N_PARTIES)
        .map(|_| {
            gen_pk_share_and_sk_sss(
                &mut rng,
                GenPkShareAndSkSssRequest {
                    trckks_config: config.clone(),
                    crp_seed,
                    smudging_bits: SMUDGING_BITS,
                },
            )
            .unwrap()
        })
        .collect();
    let pk_bytes: Vec<_> = responses.iter().map(|r| r.pk_share.clone()).collect();
    let pk = aggregate_pk_shares(config, crp_seed, &pk_bytes).unwrap();
    let sk_dealt: Vec<_> = responses.iter().map(|r| r.sk_sss.clone()).collect();
    let es_dealt: Vec<_> = responses.iter().map(|r| r.es_sss.clone()).collect();
    let member_shares = (0..N_PARTIES as usize)
        .map(|j| {
            let sk = aggregate_collected_shares(config, &sk_dealt, j).unwrap();
            let es = aggregate_collected_shares(config, &es_dealt, j).unwrap();
            (share_poly_to_bytes(&sk), share_poly_to_bytes(&es))
        })
        .collect();
    Committee {
        config: config.clone(),
        pk,
        member_shares,
    }
}

/// ONE threshold opening (= one E3 decryption request).
fn threshold_open(committee: &Committee, ct_bytes: &ArcBytes) -> Vec<f64> {
    let parties: Vec<u64> = (1..=THRESHOLD + 1).collect();
    let shares: Vec<ArcBytes> = parties
        .iter()
        .map(|&j| {
            let (sk, es) = &committee.member_shares[(j - 1) as usize];
            calculate_decryption_share(CalculateDecryptionShareRequest {
                name: format!("party-{j}"),
                trckks_config: committee.config.clone(),
                ciphertext: ct_bytes.clone(),
                sk_poly_sum: sk.clone(),
                es_poly_sum: es.clone(),
            })
            .unwrap()
            .decryption_share
        })
        .collect();
    calculate_threshold_decryption(CalculateThresholdDecryptionRequest {
        trckks_config: committee.config.clone(),
        ciphertext: ct_bytes.clone(),
        decryption_shares: shares,
        party_ids: parties,
    })
    .unwrap()
    .values
}

/// Single-shot mode: ALL pairwise comparisons in ONE ciphertext / ONE
/// threshold opening — the whole auction resolves from one decryption.
#[test]
fn all_pairs_auction_in_one_opening() {
    let params = insecure_512_params().unwrap();
    let config = TrCkksConfig::new(
        ArcBytes::from_bytes(&params.to_bytes()),
        N_PARTIES,
        THRESHOLD,
    );
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let committee = run_dkg(&config, seed);
    let mut rng = rand::rng();
    let encoder = CkksEncoder::new(&params);

    let bids = [312.5f64, 875.25, 640.0, 99.99, 405.75, 733.5, 128.0, 501.25];
    let slots = params.degree() / 2;
    let cts: Vec<ArcBytes> = bids
        .iter()
        .map(|b| {
            let replicated = vec![*b; slots];
            let ct = committee
                .pk
                .try_encrypt(&encoder.encode(&replicated, 0).unwrap(), &mut rng)
                .unwrap();
            ArcBytes::from_bytes(&ct.to_bytes())
        })
        .collect();

    // k=8 -> 28 pairs, well under the 256-slot capacity.
    let round = AuctionRound::all_pairs(bids.len());
    assert_eq!(round.pairs.len(), 28);
    let round_ct = auction_round_policy(&config, &cts, &round, &mut rng).unwrap();
    let signs = threshold_open(&committee, &round_ct); // the ONE opening

    let (winner, second) = winner_from_all_pairs(&round, bids.len(), &signs).unwrap();
    let mut sorted = bids.to_vec();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(bids[winner], sorted[0], "wrong winner");
    assert_eq!(bids[second], sorted[1], "wrong second");
}

/// 8-bidder slot-batched Vickrey auction: winner + clearing price in a
/// logarithmic number of threshold openings (vs 14 for the sequential
/// tournament), each round ONE ciphertext / ONE opening.
#[test]
fn slot_batched_auction_in_log_rounds() {
    let params = insecure_512_params().unwrap();
    let config = TrCkksConfig::new(
        ArcBytes::from_bytes(&params.to_bytes()),
        N_PARTIES,
        THRESHOLD,
    );
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let committee = run_dkg(&config, seed);
    let mut rng = rand::rng();
    let encoder = CkksEncoder::new(&params);

    let bids = [312.5f64, 875.25, 640.0, 99.99, 405.75, 733.5, 128.0, 501.25];
    // Bidders encrypt their bid REPLICATED across all slots — the
    // rotation-free packing requirement (see program.rs module docs).
    let slots = params.degree() / 2;
    let cts: Vec<ArcBytes> = bids
        .iter()
        .map(|b| {
            let replicated = vec![*b; slots];
            let ct = committee
                .pk
                .try_encrypt(&encoder.encode(&replicated, 0).unwrap(), &mut rng)
                .unwrap();
            ArcBytes::from_bytes(&ct.to_bytes())
        })
        .collect();

    let mut bracket = AuctionBracket::new(bids.len());
    let mut openings = 0usize;
    let outcome = loop {
        let round = bracket.next_round().expect("bracket must make progress");
        let round_ct = auction_round_policy(&config, &cts, &round, &mut rng).unwrap();
        let signs = threshold_open(&committee, &round_ct); // ONE opening
        openings += 1;
        if let Some(result) = bracket.apply_round(&round, &signs).unwrap() {
            break result;
        }
        assert!(openings < 16, "bracket failed to terminate");
    };

    let (winner, second) = outcome;
    let mut sorted = bids.to_vec();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(bids[winner], sorted[0], "wrong winner");
    assert_eq!(bids[second], sorted[1], "wrong second (clearing price bid)");

    // Round count: winner bracket log2(8)=3 + candidate bracket over 3
    // losers (2 rounds) = 5 openings, vs 14 sequential comparisons.
    assert!(
        openings <= 6,
        "expected <= 6 openings for 8 bidders, used {openings}"
    );

    // Final round: open ONLY the second-highest bid (the clearing price) —
    // one more opening; the winning bid itself is never decrypted.
    let clearing = threshold_open(&committee, &cts[second]);
    assert!(
        (clearing[0] - sorted[1]).abs() < 0.05,
        "clearing price {} vs {}",
        clearing[0],
        sorted[1]
    );
}

#[test]
fn fixed_point_encoding_roundtrip_and_bounds() {
    let values = [640.0f64, -0.05, 123456.789, 0.0];
    let bytes = encode_fixed_point_output(&values, 6).unwrap();
    assert_eq!(bytes.len(), values.len() * 16);
    let back = decode_fixed_point_output(&bytes, 6).unwrap();
    for (a, b) in values.iter().zip(&back) {
        assert!((a - b).abs() < 1e-6, "{a} vs {b}");
    }

    // Truncation is canonical: sub-decimal noise does not change bytes.
    let noisy = encode_fixed_point_output(&[640.000000_4], 6).unwrap();
    let clean = encode_fixed_point_output(&[640.0], 6).unwrap();
    assert_eq!(noisy, clean, "sub-decimal noise must not leak on-chain");

    // Guards.
    assert!(encode_fixed_point_output(&[f64::NAN], 6).is_err());
    assert!(encode_fixed_point_output(&[1e38], 6).is_err());
    assert!(decode_fixed_point_output(&[0u8; 15], 6).is_err());
}

/// Cross-language fixture: these exact bytes are decoded by the solidity
/// `CkksFixedPointLib` test (packages/interfold-contracts). If this
/// encoding changes, BOTH sides must be updated together.
#[test]
fn solidity_fixture_vector() {
    let bytes = encode_fixed_point_output(&[640.0, -0.05, 123456.78], 2).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "0000000000000000000000000000fa00\
         fffffffffffffffffffffffffffffffb\
         00000000000000000000000000bc614e",
        "solidity fixture drifted — update CkksFixedPointLib.spec.ts too"
    );
}
