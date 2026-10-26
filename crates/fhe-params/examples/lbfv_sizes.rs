// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Measures an l-BFV preset with fhe.rs: the key and ciphertext sizes, the time of one
//! ciphertext-by-ciphertext multiplication and one relinearization, and a threshold check.
//!
//! The threshold check builds a committee key from three parties, multiplies eight SIMD
//! ciphertexts in a tree of depth 3 (each product relinearized), and decrypts the product with
//! two of the three parties' decryption shares, with smudging noise as the protocol adds it. The
//! decrypted slots must equal the slot-wise product of the eight inputs. A preset without SIMD
//! slots checks the constant term of the polynomial products instead.
//!
//! ```text
//! cargo run --release -p e3-fhe-params --example lbfv_sizes -- secure_threshold_16384_simd
//! ```

use e3_fhe_params::{
    build_pair_for_preset, generate_smudging_error, lbfv_crs_seed, lbfv_urs_seed, BfvPreset,
};
use fhe::aggregate::AggregateIter;
use fhe::bfv::{Ciphertext, CommonRandomPolyVec, Encoding, Plaintext, SecretKey};
use fhe::trbfv::{SecretKeyShare, ShareManager, SmudgingShare};
use fhe::trlbfv::{aggregate_relinearization_key, LBFVPublicKey, PublicKeyShare, RelinKeyShare};
use fhe_math::rq::Poly;
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize};
use ndarray::Array2;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;
use std::time::Instant;

const REPEATS: usize = 5;
/// Committee of the threshold check: three parties, any two reconstruct.
const PARTIES: usize = 3;
const THRESHOLD: usize = 1;
/// Number of factors of the product: a tree of depth 3.
const FACTORS: usize = 8;

fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("timings are finite"));
    samples[samples.len() / 2]
}

/// The shares that party `receiver` holds: one `(moduli, degree)` matrix per dealer.
fn collect_shares(
    dealt: &[Vec<Array2<u64>>],
    receiver: usize,
    moduli: usize,
    degree: usize,
) -> Result<Vec<Array2<u64>>, Box<dyn std::error::Error>> {
    dealt
        .iter()
        .map(|per_modulus| {
            let data: Vec<u64> = (0..moduli)
                .flat_map(|m| {
                    per_modulus[m]
                        .row(receiver)
                        .iter()
                        .copied()
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(Array2::from_shape_vec((moduli, degree), data)?)
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::args()
        .nth(1)
        .ok_or("usage: lbfv_sizes <preset name, e.g. secure_threshold_16384_simd>")?;
    let preset = BfvPreset::from_name(&name)?;
    let (params, _) = build_pair_for_preset(preset)?;
    let degree = params.degree();
    let plaintext_modulus = params.plaintext();
    let simd = preset.is_simd();
    let crs = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_crs_seed(preset).ok_or("the preset has no l-BFV CRS")?,
    )?;
    let urs = CommonRandomPolyVec::from_seed(
        &params,
        lbfv_urs_seed(preset).ok_or("the preset has no l-BFV URS")?,
    )?;
    let mut rng = ChaCha8Rng::seed_from_u64(17);

    // Part 1: one party, sizes and timings.
    let started = Instant::now();
    let secret_key = SecretKey::random(&params, &mut rng);
    let public_key_share = PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng)?;
    let public_key: LBFVPublicKey = [public_key_share].into_iter().aggregate()?;
    let public_key_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let rlk_share = RelinKeyShare::contribution_with_crp(&secret_key, &urs, &crs, 0, 0, &mut rng)?;
    let rlk = aggregate_relinearization_key(&[rlk_share], &public_key)?;
    let rlk_seconds = started.elapsed().as_secs_f64();

    let plaintext = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
    let mut encrypt = Vec::new();
    let mut ciphertext = public_key.try_encrypt(&plaintext, &mut rng)?;
    for _ in 0..REPEATS {
        let started = Instant::now();
        ciphertext = public_key.try_encrypt(&plaintext, &mut rng)?;
        encrypt.push(started.elapsed().as_secs_f64());
    }

    let mut multiply = Vec::new();
    let mut relinearize = Vec::new();
    let mut square = Ciphertext::zero(&params);
    for _ in 0..REPEATS {
        let started = Instant::now();
        square = &ciphertext * &ciphertext;
        multiply.push(started.elapsed().as_secs_f64());
        let started = Instant::now();
        rlk.relinearizes(&mut square)?;
        relinearize.push(started.elapsed().as_secs_f64());
    }
    let decoded = Vec::<u64>::try_decode(&secret_key.try_decrypt(&square)?, Encoding::poly())?;
    assert_eq!(
        decoded.first(),
        Some(&9),
        "the squared ciphertext must decrypt"
    );

    let kib = |bytes: usize| bytes as f64 / 1024.0;
    println!("preset: {name}");
    println!("degree: {degree}");
    println!("plaintext_modulus: {plaintext_modulus}");
    println!("moduli: {}", params.moduli().len());
    println!(
        "ciphertext_bytes: {} ({:.2} KiB)",
        ciphertext.to_bytes().len(),
        kib(ciphertext.to_bytes().len())
    );
    println!(
        "public_key_bytes: {} ({:.2} KiB)",
        public_key.to_bytes().len(),
        kib(public_key.to_bytes().len())
    );
    println!(
        "relinearization_key_bytes: {} ({:.2} KiB)",
        rlk.to_bytes().len(),
        kib(rlk.to_bytes().len())
    );
    println!("public_key_generation_seconds: {public_key_seconds:.3}");
    println!("relinearization_key_generation_seconds: {rlk_seconds:.3}");
    println!("encrypt_seconds_median: {:.4}", median(encrypt));
    println!("multiply_seconds_median: {:.4}", median(multiply));
    println!("relinearize_seconds_median: {:.4}", median(relinearize));
    println!("repeats: {REPEATS}");

    // Part 2: a committee key and a depth-3 product, decrypted by a quorum.
    let sks: Vec<SecretKey> = (0..PARTIES)
        .map(|_| SecretKey::random(&params, &mut rng))
        .collect();
    let public_key: LBFVPublicKey = sks
        .iter()
        .map(|sk| PublicKeyShare::contribute_with_crp(sk, &crs, &mut rng))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .aggregate()?;
    let rlk_shares = sks
        .iter()
        .map(|sk| RelinKeyShare::contribution_with_crp(sk, &urs, &crs, 0, 0, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;
    let rlk = aggregate_relinearization_key(&rlk_shares, &public_key)?;

    // The joint secret key, for noise measurement only. The decryption below never uses it.
    let joint_coefficients: Vec<i64> = (0..degree)
        .map(|i| sks.iter().map(|sk| sk.coeffs[i]).sum())
        .collect();
    let joint_key = SecretKey::new(joint_coefficients, &params);

    // The message: slot-wise values, or a constant polynomial where the preset has no slots.
    let factor_values: Vec<Vec<u64>> = (0..FACTORS)
        .map(|_| {
            if simd {
                (0..degree)
                    .map(|_| rng.random_range(1..plaintext_modulus))
                    .collect()
            } else {
                vec![rng.random_range(1..plaintext_modulus)]
            }
        })
        .collect();
    let encoding = || {
        if simd {
            Encoding::simd()
        } else {
            Encoding::poly()
        }
    };
    let mut level: Vec<Ciphertext> = factor_values
        .iter()
        .map(|values| {
            let plaintext = Plaintext::try_encode(values, encoding(), &params)?;
            public_key.try_encrypt(&plaintext, &mut rng)
        })
        .collect::<Result<_, _>>()?;
    let mut expected = factor_values[0].clone();
    for values in &factor_values[1..] {
        for (product, value) in expected.iter_mut().zip(values) {
            *product = ((*product as u128 * *value as u128) % plaintext_modulus as u128) as u64;
        }
    }

    let noise_bits = |ct: &Ciphertext| -> Result<usize, Box<dyn std::error::Error>> {
        // SAFETY: `measure_noise` only reads the key and the ciphertext.
        Ok(unsafe { joint_key.measure_noise(ct)? })
    };
    let modulus_bits: u64 = params
        .moduli()
        .iter()
        .map(|q| 64 - q.leading_zeros() as u64)
        .sum();
    println!(
        "committee_parties: {PARTIES} (any {} reconstruct)",
        THRESHOLD + 1
    );
    println!("ciphertext_modulus_bits: {modulus_bits}");
    println!("fresh_noise_bits: {}", noise_bits(&level[0])?);

    let started = Instant::now();
    let mut depth = 0;
    while level.len() > 1 {
        depth += 1;
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut product = &pair[0] * &pair[1];
            rlk.relinearizes(&mut product)?;
            next.push(product);
        }
        println!("noise_bits_after_depth_{depth}: {}", noise_bits(&next[0])?);
        level = next;
    }
    let product_seconds = started.elapsed().as_secs_f64();
    let product = Arc::new(level.remove(0));
    println!("depth_3_product_seconds: {product_seconds:.3}");

    // Shamir shares of each secret key and of one smudging polynomial per party.
    let manager = ShareManager::new(PARTIES, THRESHOLD, params.clone())?;
    let defaults = preset
        .search_defaults()
        .ok_or("the preset has no search defaults")?;
    let lambda = preset.lambda()?;
    let moduli = params.moduli().len();
    let mut sk_dealt = Vec::new();
    let mut esi_dealt = Vec::new();
    for sk in &sks {
        let sk_poly = manager.coeffs_to_poly_level0(sk.coeffs.as_ref())?;
        sk_dealt.push(
            manager
                .generate_secret_key_shares(sk_poly, &mut rng)?
                .into_transport(),
        );
        let esi = generate_smudging_error(
            params.clone(),
            PARTIES,
            defaults.z as usize,
            defaults.mult_depth,
            lambda,
            &mut rng,
        )?;
        let esi_poly = Poly::from_bigints(&esi, params.context_at_level(0)?)?;
        esi_dealt.push(
            manager
                .generate_secret_key_shares(esi_poly, &mut rng)?
                .into_transport(),
        );
    }

    // Parties 1 and 3 (of 1..=3) answer; party 2 stays silent.
    let quorum = [0usize, 2];
    let mut decryption_shares = Vec::new();
    for receiver in quorum {
        let sk_aggregate = manager.aggregate_secret_key_shares(
            collect_shares(&sk_dealt, receiver, moduli, degree)?
                .into_iter()
                .map(SecretKeyShare::from_transport)
                .collect(),
        )?;
        let esi_aggregate = manager.aggregate_smudging_shares(
            collect_shares(&esi_dealt, receiver, moduli, degree)?
                .into_iter()
                .map(SmudgingShare::from_transport)
                .collect(),
        )?;
        decryption_shares.push(manager.decryption_share(
            Arc::clone(&product),
            &sk_aggregate,
            esi_aggregate,
        )?);
    }
    let parties: Vec<usize> = quorum.iter().map(|party| party + 1).collect();
    let plaintext =
        manager.decrypt_from_shares(decryption_shares, parties, Arc::clone(&product))?;
    let decrypted = Vec::<u64>::try_decode(&plaintext, encoding())?;
    let checked = expected.len();
    let matching = decrypted
        .iter()
        .zip(&expected)
        .filter(|(left, right)| left == right)
        .count();
    println!(
        "threshold_decrypt_checked_{}: {checked}",
        if simd { "slots" } else { "coefficients" }
    );
    println!("threshold_decrypt_matching: {matching}");
    if matching != checked {
        return Err("the threshold decryption differs from the product of the inputs".into());
    }
    println!("threshold_decrypt_check: ok");
    Ok(())
}
