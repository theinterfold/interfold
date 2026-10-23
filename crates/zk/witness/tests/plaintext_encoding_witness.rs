// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The `k1` witness of user data encryption is `[Q_MOD_T * m]_t` of the raw plaintext polynomial,
//! whatever the plaintext encoding: poly witnesses are unchanged and SIMD plaintexts are accepted.

use e3_fhe_params::{build_pair_for_preset, BfvPreset};
use e3_zk_samples::threshold::user_data_encryption::public_key_on_protocol_crs;
use e3_zk_witness::threshold::user_data_encryption::UserDataEncryptionCircuitData;
use fhe::bfv::{BfvParameters, Encoding, Plaintext, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use num_bigint::BigInt;
use std::sync::Arc;

/// Encryption data in each encoding the parameters allow, with the `k1` it must produce.
///
/// The expected values come from fhe.rs. A poly plaintext uses the poly decode. A SIMD plaintext
/// is encrypted and decrypted; the decrypted plaintext stores no encoding, so it yields both the
/// raw polynomial and, with `Encoding::simd()`, the slots.
fn cases(
    params: &Arc<BfvParameters>,
) -> Vec<(&'static str, UserDataEncryptionCircuitData, Vec<BigInt>)> {
    let t = params.plaintext();
    let n = params.degree();
    let q = BigInt::from(params.context_at_level(0).unwrap().modulus().clone());
    let q_mod_t = &q % t;
    // `k1 = [q * m]_t`, descending as the circuit takes it.
    let expected_k1 = |m: &[u64]| -> Vec<BigInt> {
        m.iter()
            .rev()
            .map(|c| (BigInt::from(*c) * &q_mod_t) % t)
            .collect()
    };

    let mut rng = rand::rng();
    let secret_key = SecretKey::random(params, &mut rng);
    let public_key = public_key_on_protocol_crs(params, &secret_key, &mut rng).unwrap();
    let mut cases = Vec::new();

    // A full-length polynomial, so that no coefficient is trivially zero.
    let values: Vec<u64> = (0..n as u64).map(|i| (i * 7 + 3) % t).collect();
    let poly = Plaintext::try_encode(&values, Encoding::poly(), params).unwrap();
    let decoded = Vec::<u64>::try_decode(&poly, Encoding::poly()).unwrap();
    assert_eq!(decoded, values);
    cases.push((
        "poly",
        UserDataEncryptionCircuitData {
            public_key: public_key.clone(),
            plaintext: poly,
        },
        expected_k1(&decoded),
    ));

    let slots: Vec<u64> = (0..n as u64).map(|i| (i * 31 + 5) % t).collect();
    if let Ok(simd) = Plaintext::try_encode(&slots, Encoding::simd(), params) {
        let ciphertext = public_key.try_encrypt(&simd, &mut rng).unwrap();
        let decrypted = secret_key.try_decrypt(&ciphertext).unwrap();
        assert_eq!(
            Vec::<u64>::try_decode(&decrypted, Encoding::simd()).unwrap(),
            slots
        );
        let coefficients = Vec::<u64>::try_decode(&decrypted, Encoding::poly()).unwrap();
        assert_ne!(coefficients, slots, "SIMD slots must differ from the poly");
        cases.push((
            "simd",
            UserDataEncryptionCircuitData {
                public_key,
                plaintext: simd,
            },
            expected_k1(&coefficients),
        ));
    }
    cases
}

fn check(
    preset: BfvPreset,
    expected_cases: usize,
    prepare: impl Fn(&Arc<BfvParameters>, &UserDataEncryptionCircuitData) -> Vec<BigInt>,
) {
    let (params, _) = build_pair_for_preset(preset).unwrap();
    let cases = cases(&params);
    assert_eq!(cases.len(), expected_cases);
    for (encoding, data, expected) in cases {
        assert_eq!(
            prepare(&params, &data),
            expected,
            "{preset:?} {encoding} k1"
        );
    }
}

fn trbfv_k1(params: &Arc<BfvParameters>, data: &UserDataEncryptionCircuitData) -> Vec<BigInt> {
    let config = e3_zk_config::threshold::user_data_encryption::Configs::new(params).unwrap();
    let (_, inputs) =
        e3_zk_witness::threshold::user_data_encryption::encrypt_and_prepare(&config, data).unwrap();
    inputs.k1.coefficients().to_vec()
}

fn chunked_k1(params: &Arc<BfvParameters>, data: &UserDataEncryptionCircuitData) -> Vec<BigInt> {
    let config =
        e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(params).unwrap();
    let (ciphertext, material) = e3_zk_witness::encrypt_with_intermediates(
        &data.public_key,
        &data.plaintext,
        &mut rand::rng(),
    )
    .unwrap();
    let inputs = e3_zk_witness::threshold::user_data_encryption_chunked::Inputs::compute(
        &config,
        data,
        &ciphertext,
        &material,
    )
    .unwrap();
    inputs.k1.coefficients().to_vec()
}

/// The poly witness is the one the poly decode gave, and a SIMD plaintext gives
/// `[Q_MOD_T * m]_t` of its raw polynomial instead of an encoding mismatch.
#[test]
fn trbfv_k1_matches_q_mod_t_times_the_raw_polynomial() {
    check(BfvPreset::InsecureThreshold64, 1, trbfv_k1);
    check(BfvPreset::InsecureThresholdSimd, 2, trbfv_k1);
}

#[test]
fn chunked_k1_matches_q_mod_t_times_the_raw_polynomial() {
    check(BfvPreset::InsecureThresholdLbfv, 1, chunked_k1);
    check(BfvPreset::InsecureThresholdSimd, 2, chunked_k1);
}
