// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Full-committee lifecycle tests for the CKKS keyshare workflow: every
//! party runs the real workflow functions over real serialized payloads —
//! the exact per-party steps the actor shell will drive.

use super::workflow::*;
use e3_fhe::{CkksFhe, SchemeParams};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParametersBuilder};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::{Rng, RngCore};
use std::sync::{Arc, Mutex};

const N_PARTIES: usize = 5;
const THRESHOLD: usize = 2;
const SMUDGING_BITS: usize = 20;

fn make_fhe() -> (CkksFhe, Arc<fhe::ckks::CkksParameters>) {
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()
        .unwrap();
    let rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    // Every node derives the same CRP from the E3's public seed.
    let encoded = params.to_bytes();
    let fhe = CkksFhe::from_encoded(&encoded, seed, N_PARTIES, THRESHOLD, rng).unwrap();
    (fhe, params)
}

/// Run the DKG exactly as n actor shells would: generate, broadcast dealt
/// rows, collect, finalize.
fn run_committee_dkg(fhe: &CkksFhe) -> Vec<ReadyForDecryption> {
    // Phase 1: every party generates its material.
    let materials: Vec<_> = (1..=N_PARTIES as u64)
        .map(|_| fhe.generate_keyshare(SMUDGING_BITS).unwrap())
        .collect();

    // Phase 2: dealt-share broadcast. Party d sends row r to party r.
    let mut states: Vec<CollectingKeyshares> = (1..=N_PARTIES as u64)
        .map(|pid| CollectingKeyshares {
            party_id: pid,
            n_parties: N_PARTIES,
            own: materials[(pid - 1) as usize].clone(),
            received: Vec::new(),
        })
        .collect();
    for (d, material) in materials.iter().enumerate() {
        let dealer_id = (d + 1) as u64;
        for recipient in 1..=N_PARTIES as u64 {
            let share = dealt_row_for(material, dealer_id, recipient).unwrap();
            states[(recipient - 1) as usize].received.push(share);
        }
    }

    // Phase 3: every party finalizes.
    states
        .iter()
        .map(|s| build_ready_for_decryption(fhe, s).unwrap())
        .collect()
}

#[test]
fn scheme_dispatch_decodes_both_schemes() {
    let (_, ckks_params) = make_fhe();
    let ckks_bytes = ckks_params.to_bytes();
    assert!(matches!(
        SchemeParams::from_encoded(&ckks_bytes).unwrap(),
        SchemeParams::Ckks(_)
    ));

    // BFV params travel ABI-encoded on-chain (encode_bfv_params), which is
    // what E3Requested carries — use the real chain encoding.
    let bfv_params = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(512)
        .set_plaintext_modulus(4096)
        .set_moduli_sizes(&[45, 45])
        .build_arc()
        .unwrap();
    let bfv_bytes = e3_fhe_params::encode_bfv_params(&bfv_params);
    assert!(matches!(
        SchemeParams::from_encoded(&bfv_bytes).unwrap(),
        SchemeParams::Bfv(_)
    ));

    // Garbage rejected.
    assert!(SchemeParams::from_encoded(&[0u8; 16]).is_err());
}

/// DKG lifecycle: all parties converge on the same joint public key.
#[test]
fn committee_dkg_converges() {
    let (fhe, _) = make_fhe();
    let ready = run_committee_dkg(&fhe);
    for r in &ready[1..] {
        assert_eq!(
            r.public_key, ready[0].public_key,
            "parties disagree on the joint public key"
        );
    }
}

/// Full E3 lifecycle: DKG -> user encrypts -> homomorphic sum (the compute
/// step) -> t+1 decryption shares -> plaintext aggregation.
#[test]
fn full_e3_lifecycle_sum() {
    let (fhe, params) = make_fhe();
    let ready = run_committee_dkg(&fhe);

    // User side: encrypt under the joint pk.
    let pk = fhe::ckks::CkksPublicKey::from_bytes(&ready[0].public_key, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let mut rng = rand::rng();
    let inputs = [12.5f64, -3.25, 40.0];
    let cts: Vec<CkksCiphertext> = inputs
        .iter()
        .map(|v| {
            pk.try_encrypt(&encoder.encode(&[*v], 0).unwrap(), &mut rng)
                .unwrap()
        })
        .collect();

    // Compute step (program server / Secure Process): homomorphic sum.
    let mut acc = cts[0].clone();
    for ct in &cts[1..] {
        acc = acc.try_add(ct).unwrap();
    }
    let ciphertext_output = acc.to_bytes();

    // t+1 parties publish decryption shares (CiphertextOutputPublished).
    let reconstructing: Vec<u64> = vec![1, 3, 5];
    let shares: Vec<(u64, ArcBytes)> = reconstructing
        .iter()
        .map(|&pid| {
            let share =
                build_decryption_share(&fhe, &ready[(pid - 1) as usize], &ciphertext_output)
                    .unwrap();
            (pid, ArcBytes::from_bytes(&share))
        })
        .collect();

    // Aggregator combines.
    let values = aggregate_plaintext(&fhe, shares, &ciphertext_output).unwrap();
    let expected: f64 = inputs.iter().sum();
    assert!(
        (values[0] - expected).abs() < 0.2,
        "sum {} vs {expected}",
        values[0]
    );
}

/// The auction as the E3 computation: masked comparisons, winner + clearing
/// price — through the SAME workflow functions the actor shell drives.
#[test]
fn full_e3_lifecycle_auction() {
    let (fhe, params) = make_fhe();
    let ready = run_committee_dkg(&fhe);

    let pk = fhe::ckks::CkksPublicKey::from_bytes(&ready[0].public_key, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let mut rng = rand::rng();

    let bids = [312.5f64, 875.25, 640.0, 899.99, 405.75];
    let cts: Vec<CkksCiphertext> = bids
        .iter()
        .map(|b| {
            pk.try_encrypt(&encoder.encode(&[*b], 0).unwrap(), &mut rng)
                .unwrap()
        })
        .collect();

    // One threshold opening through the full share->aggregate path.
    let open = |ct: &CkksCiphertext| -> f64 {
        let out = ct.to_bytes();
        let parties: Vec<u64> = vec![1, 2, 4];
        let shares: Vec<(u64, ArcBytes)> = parties
            .iter()
            .map(|&pid| {
                let s = build_decryption_share(&fhe, &ready[(pid - 1) as usize], &out).unwrap();
                (pid, ArcBytes::from_bytes(&s))
            })
            .collect();
        aggregate_plaintext(&fhe, shares, &out).unwrap()[0]
    };

    let mut compare = |i: usize, j: usize| -> bool {
        let diff = cts[i].try_sub(&cts[j]).unwrap();
        let mask = encoder.encode(&[rng.random_range(1.0f64..8.0)], 0).unwrap();
        let mut masked = diff.try_mul_plaintext(&mask).unwrap();
        masked.rescale().unwrap();
        open(&masked) > 0.0
    };

    let mut winner = 0usize;
    let mut candidates = Vec::new();
    for i in 1..bids.len() {
        if compare(i, winner) {
            candidates.push(winner);
            winner = i;
        } else {
            candidates.push(i);
        }
    }
    let mut second = candidates[0];
    for &c in &candidates[1..] {
        if compare(c, second) {
            second = c;
        }
    }
    let clearing_price = open(&cts[second]);

    let mut sorted = bids.to_vec();
    sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
    assert_eq!(bids[winner], sorted[0], "wrong winner");
    assert!(
        (clearing_price - sorted[1]).abs() < 0.05,
        "clearing price {clearing_price} vs {}",
        sorted[1]
    );
}

/// Duplicate dealer and short collection are rejected.
#[test]
fn dkg_validation_rejects_bad_collections() {
    let (fhe, _) = make_fhe();
    let material = fhe.generate_keyshare(SMUDGING_BITS).unwrap();
    let share = dealt_row_for(&material, 1, 1).unwrap();

    // Short collection.
    let short = CollectingKeyshares {
        party_id: 1,
        n_parties: N_PARTIES,
        own: material.clone(),
        received: vec![share.clone()],
    };
    assert!(build_ready_for_decryption(&fhe, &short).is_err());

    // Duplicate dealer.
    let dup = CollectingKeyshares {
        party_id: 1,
        n_parties: 2,
        own: material.clone(),
        received: vec![share.clone(), share],
    };
    assert!(build_ready_for_decryption(&fhe, &dup).is_err());

    // Out-of-range recipient.
    assert!(dealt_row_for(&material, 1, N_PARTIES as u64 + 1).is_err());
}
