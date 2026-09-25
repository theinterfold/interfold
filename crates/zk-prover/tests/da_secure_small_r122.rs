// SPDX-License-Identifier: LGPL-3.0-only
//
//! r122 - the `DecryptionAggregator` (DA) PRODUCTION-FIELD anchor.
//!
//! The DA is the top-level final on-chain proof of the decryption tail: it
//! transitively verifies a `c6_fold` UltraHonkProof + a C7 UltraHonkProof
//! (both non-ZK), plus the cross-asserts ct-uniformity, per-slot
//! d_commitment match (C6 -> C7), party_id validity + strictly-increasing
//! ordering, common domain, committeeHash, and the vk-hash bind.
//!
//! THE GAP THIS ROUND CLOSES: r117 RAN-compiled the DA at secure-8192/small
//! (1,493,885 g / 9,526 ACIR) as part of its "re-pin chain" closure;
//! r119/r120/r121 RAN-proved the C6/C5/C7 LEAVES + the c6_fold chain at
//! min only. Nobody had ever RAN-PROVED the DA itself at any committee -
//! the final on-chain proof was compile-anchored only. This leg RAN-converts
//! it at the production committee (N=19/T=9/H=10/L=3) by assembling one
//! coherent shared TRBFV world: 10 C6 inners + 1 C7 derived from the SAME
//! 19-party sk/esi/ciphertext, so every DA cross-assert holds by
//! construction (exactly as production would supply it to
//! `prove_decryption_aggregation_jobs` -> `CircuitVariant::Evm`).
//!
//! COHERENCE: all 10 C6 inners share (a) the SAME ciphertext -> uniform
//! `ct_commitment` column, (b) the SAME (domain_hi, domain_lo) public
//! [stand-in (1,2), not the production keccak domain], and (c) C6 inner i's
//! `d_share` is the SAME poly as C7's i-th row `d_share_poly` -> the DA's
//! per-slot d_commitment cross-match (`c6_fold.out_d[i] ==
//! c7.expected_d_commitments[i]`) holds by construction. The vk-hash bind
//! (`compute_vk_hash([c6_fold_key_hash, c7_key_hash])`) holds automatically
//! because the vk hashes come from the STAGED artifacts (see
//! `crates/tests/tests/integration.rs:700-749` for the staging map).
//!
//! DOMAIN STAND-IN (HONEST): (domain_hi, domain_lo) = (1, 2) for all 10
//! inners. The production keccak-derived domain binds the proof to (chainId,
//! interfold addr, e3_id, committee hash, ct output hash, committee pk) to
//! prevent cross-deployment replay. The DA cross-assert is "all C6 leaves in
//! the fold share ONE domain; the DA publishes that domain publicly" - a
//! consistency bind, exercised IDENTICALLY by the (1,2) stand-in. Every
//! OTHER cross-assert runs on real RAN data. This is the ONE
//! intentionally-simplified input; the wall and RAM of the DA proof are
//! domain-invariant.
//!
//! STAGE TREE (produced by poc/r122/stage_da_secure_small_r122.py):
//!     $E3_R122_STAGE_ROOT/secure-8192/small/
//!         recursive/threshold/share_decryption/{.json,.vk,.vk_hash}
//!         default/recursive_aggregation/{c6_fold,c6_fold_kernel}/{...}
//!         default/threshold/decrypted_shares_aggregation/{...}
//!         default/recursive_aggregation/decryption_aggregator/decryption_aggregator.json
//!         evm/recursive_aggregation/decryption_aggregator/{.json,.vk,.vk_hash}
//!
//! RUN:
//!     E3_R122_STAGE_ROOT=$(pwd)/poc/r122/root \
//!         cargo test --release -p e3-zk-prover --test da_secure_small_r122 -- --nocapture
#![allow(dead_code, unused_imports)]
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::Address;
use common::{find_bb, setup_test_prover};
use e3_events::CircuitVariant;
use e3_fhe_params::{
    build_pair_for_preset, create_deterministic_crp_from_default_seed, BfvPreset,
};
use e3_polynomial::CrtPolynomial;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::circuit::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::threshold::share_decryption::{
    ShareDecryptionCircuit, ShareDecryptionCircuitData,
};
use e3_zk_helpers::{CiphernodesCommittee, CiphernodesCommitteeSize};
use e3_zk_prover::{
    prove_decryption_aggregation_jobs, DecryptionAggregationJob, Provable, ZkProver,
};
use fhe::bfv::{Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::mbfv::{AggregateIter, PublicKeyShare};
use fhe::trbfv::{Lambda, ShareManager, TRBFV};
use fhe_math::rq::{Poly, PowerBasis};
use fhe_traits::{FheDecoder, FheEncoder, FheEncrypter};
use ndarray::Array2;
use rand::{CryptoRng, RngCore};

/// SMALL committee: N=19, T=9, H=10, L=3.
const N: usize = 19; // N_PARTIES (full committee)
const SLOTS: usize = 10; // T + 1 = 10 (one C6 slot per honest party)

fn stage_root() -> PathBuf {
    match std::env::var("E3_R122_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!(
            "E3_R122_STAGE_ROOT unset - run poc/r122/stage_da_secure_small_r122.py first"
        ),
    }
}

async fn copy_dir(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut rd = tokio::fs::read_dir(src).await?;
    while let Some(e) = rd.next_entry().await? {
        let t = e.path();
        let target = dst.join(e.file_name());
        if t.is_dir() {
            Box::pin(copy_dir(&t, &target)).await?;
        } else {
            tokio::fs::copy(&t, &target).await?;
        }
    }
    Ok(())
}

/// Medium helper: build the shared 19-party world (1 ct, per-receiver
/// aggregated sk/es, 10 d_shares), C7-decoding as sanity.
///
/// Mirrors the C7 sample (decrypted_shares_aggregation::sample::generate_sample)
/// for the shared ct + 10 d_shares, and for the per-receiver 19-sender
/// DKG-aggregated sk/es (which is what each C6 inner's `s`/`e` witness must be
/// for the C7/Lagrange-at-zero recovery to hold over the 10 d_shares).
#[allow(clippy::type_complexity)]
fn build_shared_world(
    preset: BfvPreset,
    committee: CiphernodesCommittee,
) -> (
    Ciphertext,
    Vec<CrtPolynomial>,             // sk_poly_sum per i in 0..SLOTS (Crt)
    Vec<CrtPolynomial>,             // es_poly_sum per i in 0..SLOTS (Crt)
    Vec<Poly<PowerBasis>>,          // d_share per i in 0..SLOTS (PBN)
    PublicKey,
    Vec<u64>,                       // decoded message
) {
    let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
    let sd = preset.search_defaults().expect("preset search_defaults");
    let lambda: Lambda = preset.lambda().unwrap();
    let n: usize = N;
    let t: usize = committee.threshold; // = 9
    let num_moduli = threshold_params.moduli().len();
    let degree = threshold_params.degree();

    let trbfv = TRBFV::new(n, t, threshold_params.clone()).expect("TRBFV::new");
    let crp = create_deterministic_crp_from_default_seed(&threshold_params);

    // (1) 19 parties: per j, sk_j / pk_j / sk_sss_j / esi_sss_j
    //     (sk_sss_j: [num_moduli, degree]; row i = j's share of sk for receiver i)
    //     (same shape for esi_sss_j)
    let mut pk_shares: Vec<PublicKeyShare> = Vec::with_capacity(n);
    let mut sk_sss: Vec<Vec<Array2<u64>>> = Vec::with_capacity(n);
    let mut esi_sss: Vec<Vec<Array2<u64>>> = Vec::with_capacity(n);
    for _j in 0..n {
        let sk_j = SecretKey::random(&threshold_params, &mut rand::rng());
        let pk_j = PublicKeyShare::new(&sk_j, crp.clone(), &mut rand::rng())
            .expect("pk_share::new");
        let sk_sss_j = {
            let mut sm_j = ShareManager::new(n, t, threshold_params.clone()).unwrap();
            let sk_poly = sm_j.coeffs_to_poly_level0(sk_j.coeffs.as_ref()).unwrap();
            sm_j.generate_secret_shares_from_poly(sk_poly, &mut rand::rng()).unwrap()
        };
        // esi_sss_j: secure smudging-error shares (C7 sample does this per party;
        // we use sd.z = 1 ciphertext to keep it a 1-ct world).
        let esi_sss_j = {
            let mut sm_j = ShareManager::new(n, t, threshold_params.clone()).unwrap();
            let esi_bigints = trbfv
                .generate_smudging_error(sd.z as usize, lambda, &mut rand::rng())
                .expect("esi draw");
            let esi_bigints_bi: Vec<num_bigint::BigInt> = esi_bigints
                .iter()
                .cloned()
                .collect();
            let esi_poly = sm_j.bigints_to_poly(&esi_bigints_bi).expect("esi -> poly");
            sm_j.generate_secret_shares_from_poly(esi_poly, &mut rand::rng())
                .expect("esi -> sss")
        };
        pk_shares.push(pk_j);
        sk_sss.push(sk_sss_j);
        esi_sss.push(esi_sss_j);
    }

    // (2) Aggregate the ONE shared public key (from pk_shares) for the 1 shared ct.
    let pk: PublicKey = pk_shares.iter().cloned().aggregate().expect("agg pk");

    // (3) ONE shared ciphertext: pattern message tiled (C7 sample style).
    let pattern: Vec<u64> = vec![
        2, 1, 5, 2, 1, 2, 3, 2, 4, 3, 3, 3, 2, 3, 3, 1, 2, 3, 4, 6, 1, 5, 1, 1, 2, 1, 2,
    ];
    let message: Vec<u64> = (0..(pattern.len() as isize).min(degree as isize))
        .map(|i| pattern[i as usize % pattern.len()])
        .collect();
    let ct_pt = Plaintext::try_encode(&message, Encoding::poly(), &threshold_params)
        .expect("encode pt");
    let ct: Ciphertext = pk.try_encrypt(&ct_pt, &mut rand::rng()).expect("encrypt 1 ct");
    let ct_arg = Arc::new(ct.clone());

    // (4) For each honest party i in 0..SLOTS, build its per-receiver DKG-
    //     aggregated sk and es (sum over all 19 senders, C7-style).
    let mut sk_sums: Vec<Poly<PowerBasis>> = Vec::with_capacity(SLOTS);
    let mut es_sums: Vec<Poly<PowerBasis>> = Vec::with_capacity(SLOTS);
    for i in 0..SLOTS {
        let sm_i = ShareManager::new(n, t, threshold_params.clone()).unwrap();
        let mut sk_rows: Vec<Array2<u64>> = Vec::with_capacity(n);
        let mut es_rows: Vec<Array2<u64>> = Vec::with_capacity(n);
        for j in 0..n {
            let mut sk_flat: Vec<u64> = Vec::with_capacity(num_moduli * degree);
            let mut es_flat: Vec<u64> = Vec::with_capacity(num_moduli * degree);
            for m in 0..num_moduli {
                let sk_row = sk_sss[j][m].row(i);
                let es_row = esi_sss[j][m].row(i);
                sk_flat.extend(sk_row.iter().copied());
                es_flat.extend(es_row.iter().copied());
            }
            sk_rows.push(Array2::from_shape_vec((num_moduli, degree), sk_flat).expect("sk mat"));
            es_rows.push(Array2::from_shape_vec((num_moduli, degree), es_flat).expect("es mat"));
        }
        sk_sums.push(sm_i.aggregate_collected_shares(&sk_rows).expect("sk sum"));
        es_sums.push(sm_i.aggregate_collected_shares(&es_rows).expect("es sum"));
    }

    // (5) Per-honest-party d_share (the SAME list feeds BOTH C6 inners [row i]
    //     AND the C7 d_share_polys).
    let mut d_shares: Vec<Poly<PowerBasis>> = Vec::with_capacity(SLOTS);
    for i in 0..SLOTS {
        let d = trbfv
            .decryption_share(
                Arc::clone(&ct_arg),
                sk_sums[i].clone().into_ntt(),
                es_sums[i].clone(),
            )
            .expect("d_share");
        d_shares.push(d);
    }

    // (6) Sanity decode: if the world is broken (sk/es/ct mismatch), the
    //     T+1 d_shares won't reconstruct the message. This would have
    //     surfaced as a C7 witness failure downstream anyway, but eagerly
    //     detecting here saves a wasted 10-min prove build.
    let decoding_parties: Vec<usize> = (1..=SLOTS).collect(); // 1..=T+1 normalized; 0-based index i corresponds to party i+1
    let decoded = {
        let sm_dec = ShareManager::new(n, t, threshold_params.clone()).expect("SM dec");
        sm_dec.decrypt_from_shares(
            d_shares.clone(),
            decoding_parties,
            Arc::clone(&ct_arg),
        )
        .expect("decrypt_from_shares")
    };
    let decoded_msg: Vec<u64> =
        Vec::<u64>::try_decode(&decoded, Encoding::poly()).expect("decode msg");
    assert!(
        !decoded_msg.iter().all(|x| *x == 0),
        "world's decoded message is all-zero (structural sk/es/ct mismatch)"
    );

    (
        ct,
        sk_sums
            .iter()
            .map(|p| CrtPolynomial::from_fhe_polynomial(p))
            .collect(),
        es_sums
            .iter()
            .map(|p| CrtPolynomial::from_fhe_polynomial(p))
            .collect(),
        d_shares,
        pk,
        decoded_msg,
    )
}

#[tokio::test]
async fn da_secure_small_proves_and_verifies() {
    let Some(bb) = find_bb().await else { println!("skipping: bb not found"); return; };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join("small");
    assert!(
        preset_tree.is_dir(),
        "stage tree {} missing - run poc/r122/stage_da_secure_small_r122.py first",
        preset_tree.display()
    );

    let (backend, _temp) = setup_test_prover(&bb).await;
    copy_dir(
        &preset_tree,
        &backend.circuits_dir.join("secure-8192").join("small"),
    )
    .await
    .expect("stage handoff to backend circuits_dir");

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    assert_eq!(committee.n, N, "Small N=19");
    assert_eq!(committee.h, SLOTS, "Small H=10");
    assert_eq!(committee.threshold, SLOTS - 1, "Small T=9");
    let ad = preset.artifacts_dir_for_committee("small");
    assert_eq!(ad, "secure-8192/small");

    // ---- build shared world (everything downstream derives from this) ----
    let t0 = Instant::now();
    let (ct, sk_sums, es_sums, d_shares, pk, message_vec) =
        build_shared_world(preset, committee);
    let build = t0.elapsed().as_secs_f64();
    println!(
        "shared world OK: d_shares.len={} message_vec.len={} build={:.2}s",
        d_shares.len(), message_vec.len(), build
    );

    let prover = ZkProver::new(&backend);
    let mut walls: Vec<(String, f64)> = Vec::new();

    // ---- 10 C6 inners (Recursive variant), from the SAME shared world ----
    let mut c6_inners = Vec::with_capacity(SLOTS);
    let mut c6_wall: f64 = 0.0;
    for i in 0..SLOTS {
        let e3 = format!("e3-r122-c6i-{}", i);
        let sample = ShareDecryptionCircuitData {
            ciphertext: ct.clone(),
            public_key: pk.clone(),
            s: sk_sums[i].clone(),
            e: es_sums[i].clone(),
            d_share: CrtPolynomial::from_fhe_polynomial(&d_shares[i]),
            domain_hi: 1,
            domain_lo: 2,
        };
        let ti = Instant::now();
        let inner = ShareDecryptionCircuit
            .prove_with_variant(
                &prover, &preset, &sample, &e3, CircuitVariant::Recursive, &ad,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "C6 inner #{} FAILED at secure/small (r97-class witness breach \
                     - the C6 secure/small witness does not satisfy the circuit \
                     at T=9/L=3): {:?}",
                    i, e
                )
            });
        let wi = ti.elapsed().as_secs_f64();
        c6_wall += wi;
        c6_inners.push(inner);
        println!("  c6 inner {}/10 PROVED shared-world T=9/H=10/L=3 ({:.2}s)", i + 1, wi);
        let _ = prover.cleanup(&e3);
    }
    walls.push(("C6 inners x10 (Recursive, shared) total".into(), c6_wall));

    // ---- 1 C7 (Default variant) on the SAME 10 d_shares ----
    let e3_c7 = "e3-r122-c7";
    let c7_sample = DecryptedSharesAggregationCircuitData {
        committee: CiphernodesCommittee { n: N, h: SLOTS, threshold: SLOTS - 1 },
        d_share_polys: d_shares.clone(),
        reconstructing_parties: (1..=SLOTS).collect(),
        message_vec,
    };
    let ti = Instant::now();
    let c7_proof = DecryptedSharesAggregationCircuit
        .prove_with_variant(&prover, &preset, &c7_sample, e3_c7, CircuitVariant::Default, &ad)
        .unwrap_or_else(|e| panic!("C7 PROVE FAILED at secure/small: {:?}", e));
    let c7_wall = ti.elapsed().as_secs_f64();
    walls.push(("C7 (Default, shared)".into(), c7_wall));
    println!("  c7 PROVED shared-world T=9/H=10/L=3 ({:.2}s)", c7_wall);
    let _ = prover.cleanup(e3_c7);

    // ---- The production DecryptionAggregator (CircuitVariant::Evm) ----
    // 19 committee addresses (N) - on-chain topNodes. Arbitrary but distinct
    // (DA only binds them into an in-circuit keccak hash; the exact values are
    // not security-relevant for this anchor).
    let addresses: Vec<Address> = (0..N)
        .map(|i| Address::with_last_byte((0xA0u8).wrapping_add(i as u8)))
        .collect();
    let slot_indices: Vec<u32> = (0..SLOTS as u32).collect();
    let job = DecryptionAggregationJob {
        c6_inner_proofs: &c6_inners,
        c6_slot_indices: &slot_indices,
        c7_proof: &c7_proof,
    };
    let ti = Instant::now();
    let da_proofs = prove_decryption_aggregation_jobs(
        &prover,
        SLOTS,
        std::slice::from_ref(&job),
        &addresses,
        "e3-r122-da",
        preset,
        CiphernodesCommitteeSize::Small,
    )
    .unwrap_or_else(|e| {
        panic!(
            "DecryptionAggregator EVM prove FAILED - a DA cross-assert did not \
             hold at secure/small. The coherence gap is most likely between a \
             C6 inner's d_commitment and the C7's expected d_commitment (or \
             ct_commitment uniformity, or party_id ordering, or a vk-hash \
             bind): {:?}",
            e
        )
    });
    let da_wall = ti.elapsed().as_secs_f64();
    walls.push(("DecryptionAggregator (Evm, production API)".into(), da_wall));
    println!("  DecryptionAggregator EVM PROVED ({:.2}s)", da_wall);
    let _ = prover.cleanup("e3-r122-da");

    // ---- verify the DA EVM proof (on-chain verifier path) ----
    let ti = Instant::now();
    let ok = prover
        .verify_proof_with_variant(
            &da_proofs[0], "e3-r122-da", 1, CircuitVariant::Evm, &ad,
        )
        .expect("DA EVM verify");
    let verify_wall = ti.elapsed().as_secs_f64();
    assert!(ok, "DA EVM verify ok=false at secure/small: vk/proof incoherent");
    assert_eq!(
        da_proofs[0].circuit,
        e3_events::CircuitName::DecryptionAggregator,
        "DA proof circuit identity must be DecryptionAggregator"
    );
    walls.push(("DA EVM verify (ok=true)".into(), verify_wall));
    println!("  DA EVM verify ok=true ({:.4}s)", verify_wall);

    let total: f64 = walls.iter().map(|(_, s)| *s).sum::<f64>() + build;
    println!();
    for (label, s) in &walls {
        println!("  {:<48} {:>8.2}s", label, s);
    }
    println!(
        "\nDecryptionAggregator PRODUCTION-FIELD ANCHOR GREEN @secure-8192/small \
         (N=19/T=9/H=10/L=3).\n  Build shared world {:.2}s; leg compute {:.2}s @4c \
         (7.8 GiB / 30-60m budget).\n  FIRST RAN-prove of the DecryptionAggregator \
         (the on-chain final decryption proof) at any committee on box-1.",
        build, total
    );
}