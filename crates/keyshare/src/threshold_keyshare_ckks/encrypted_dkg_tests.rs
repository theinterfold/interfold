// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Encrypted-transport CKKS DKG tests: the full committee lifecycle where
//! every dealt row travels BFV-encrypted inside the real
//! [`e3_events::ThresholdShare`] event struct, decrypted by each recipient
//! with their ephemeral DKG key — exactly the wire discipline of the BFV
//! flow.

use super::encrypted_dkg::*;
use super::workflow::ReadyForDecryption;
use e3_fhe::CkksFhe;
use e3_fhe_params::{BfvParamSet, BfvPreset};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::{PublicKey, SecretKey};
use fhe::ckks::{CkksCiphertext, CkksEncoder, CkksParametersBuilder, CkksPublicKey};
use fhe_traits::{DeserializeParametrized, Serialize as FheSerialize};
use rand::RngCore;
use std::sync::{Arc, Mutex};

const N_PARTIES: usize = 5;
const THRESHOLD: usize = 2;
const SMUDGING_BITS: usize = 20;

#[test]
fn encrypted_transport_dkg_end_to_end() {
    // CKKS committee params + shared CRP.
    // CKKS moduli must fit inside the DKG transport preset's plaintext
    // modulus (0xffffee001): dealt share coefficients travel as BFV
    // plaintexts. Use the BFV threshold moduli, like the insecure CKKS
    // circuit preset does.
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_scale(2f64.powi(26))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe =
        CkksFhe::from_encoded(&params.to_bytes(), seed, N_PARTIES, THRESHOLD, shared_rng).unwrap();

    // Share-transport BFV params (the DKG counterpart preset, as the actor
    // uses via `meta.params_preset.dkg_counterpart()`).
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    let mut rng = rand::rng();

    // Each member's ephemeral DKG keypair (the EncryptionKey round).
    let sk_bfv: Vec<SecretKey> = (0..N_PARTIES)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<PublicKey> = sk_bfv
        .iter()
        .map(|sk| PublicKey::new(sk, &mut rng))
        .collect();

    // Phase 1+2: every member generates material and broadcasts ONE
    // ThresholdShare with per-recipient encrypted rows.
    let materials: Vec<_> = (0..N_PARTIES)
        .map(|_| fhe.generate_keyshare(SMUDGING_BITS).unwrap())
        .collect();
    let broadcasts: Vec<_> = materials
        .iter()
        .enumerate()
        .map(|(i, m)| {
            Arc::new(
                build_encrypted_threshold_share(
                    m,
                    (i + 1) as u64,
                    &pk_bfv,
                    &enc_params,
                    params.moduli(),
                    &mut rng,
                )
                .unwrap(),
            )
        })
        .collect();

    // Phase 3: every member decrypts its rows and finalizes.
    let ready: Vec<ReadyForDecryption> = (0..N_PARTIES)
        .map(|i| {
            finalize_from_threshold_shares(
                &fhe,
                (i + 1) as u64,
                &materials[i],
                &broadcasts,
                &sk_bfv[i],
                &enc_params,
            )
            .unwrap()
        })
        .collect();

    // All parties agree on the joint pk.
    for r in &ready[1..] {
        assert_eq!(r.public_key, ready[0].public_key, "joint pk mismatch");
    }

    // And the key actually works: encrypt -> homomorphic add -> threshold
    // decrypt with t+1 shares through the workflow functions.
    let pk = CkksPublicKey::from_bytes(&ready[0].public_key, &params).unwrap();
    let encoder = CkksEncoder::new(&params);
    let values = [21.5f64, -4.25];
    let cts: Vec<CkksCiphertext> = values
        .iter()
        .map(|v| {
            pk.try_encrypt(&encoder.encode(&[*v], 0).unwrap(), &mut rng)
                .unwrap()
        })
        .collect();
    let sum_ct = cts[0].try_add(&cts[1]).unwrap();
    let out = sum_ct.to_bytes();

    let reconstructing = [1u64, 3, 5];
    let shares: Vec<(u64, ArcBytes)> = reconstructing
        .iter()
        .map(|&pid| {
            let s = super::workflow::build_decryption_share(&fhe, &ready[(pid - 1) as usize], &out)
                .unwrap();
            (pid, ArcBytes::from_bytes(&s))
        })
        .collect();
    let decoded = super::workflow::aggregate_plaintext(&fhe, shares, &out).unwrap();
    let expected: f64 = values.iter().sum();
    // Tolerance: Lagrange coefficients amplify smudging noise
    // subset-dependently (observed ~1.25 error on occasional subsets at
    // these insecure demo params) — the whole-unit gap to a WRONG value
    // is what matters, so 2.0 gives flake-free headroom.
    assert!(
        (decoded[0] - expected).abs() < 2.0,
        "decrypted {} vs {expected}",
        decoded[0]
    );
}

#[test]
fn wrong_recipient_cannot_decrypt_rows() {
    // CKKS moduli must fit inside the DKG transport preset's plaintext
    // modulus (0xffffee001): dealt share coefficients travel as BFV
    // plaintexts. Use the BFV threshold moduli, like the insecure CKKS
    // circuit preset does.
    let params = CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_scale(2f64.powi(26))
        .build_arc()
        .unwrap();
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let shared_rng = Arc::new(Mutex::new(
        <rand_chacha::ChaCha20Rng as rand::SeedableRng>::from_seed(rand::random::<[u8; 32]>()),
    ));
    let fhe =
        CkksFhe::from_encoded(&params.to_bytes(), seed, N_PARTIES, THRESHOLD, shared_rng).unwrap();
    let enc_params = BfvParamSet::from(BfvPreset::InsecureDkg512).build_arc();
    let mut rng = rand::rng();
    let sk_bfv: Vec<SecretKey> = (0..N_PARTIES)
        .map(|_| SecretKey::random(&enc_params, &mut rng))
        .collect();
    let pk_bfv: Vec<PublicKey> = sk_bfv
        .iter()
        .map(|sk| PublicKey::new(sk, &mut rng))
        .collect();

    let material = fhe.generate_keyshare(SMUDGING_BITS).unwrap();
    let share = build_encrypted_threshold_share(
        &material,
        1,
        &pk_bfv,
        &enc_params,
        params.moduli(),
        &mut rng,
    )
    .unwrap();

    // Party 2 decrypting with party 3's key: BFV decryption noise makes the
    // rows garbage; the honest recovery is party 2's own key. We can't
    // assert a hard failure (BFV decrypt of a wrong-key ct still returns
    // bytes), but the decrypted rows must NOT match the dealt plaintext.
    let (sk_rows_with_wrong_key, _) = decrypt_dealt_rows(
        &share,
        2,
        None,
        &sk_bfv[2], // party 3's key, wrong for slot 1
        &enc_params,
        512,
    )
    .unwrap();
    let true_row: Vec<Vec<u64>> = material
        .sk_sss
        .iter()
        .map(|flat| flat[material.cols..2 * material.cols].to_vec())
        .collect();
    assert_ne!(
        sk_rows_with_wrong_key, true_row,
        "wrong key must not recover the dealt row"
    );

    // Own slot is skipped in the broadcast: no ciphertext for the dealer.
    assert!(decrypt_dealt_rows(&share, 1, None, &sk_bfv[0], &enc_params, 512).is_err());
}
