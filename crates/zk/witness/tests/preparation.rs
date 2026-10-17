// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial;
use e3_zk_config::{dkg as dkg_config, threshold as config, DkgInputType};
use e3_zk_witness::{dkg, threshold};
use fhe::bfv::Ciphertext;
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::BigInt;
use num_traits::Zero;

#[test]
fn c0_binds_public_key_material_to_the_supplied_configuration() {
    let preset = BfvPreset::InsecureThreshold64;
    let config = dkg_config::pk::Configs::for_preset(preset).unwrap();
    let key = e3_zk_samples::dkg::pk::generate(&config.params).unwrap();
    assert!(dkg::pk::Inputs::compute(&config, &key).is_ok());
    let mut oversized = key.clone();
    oversized.c = Ciphertext::new(
        vec![key.c[0].clone(), key.c[1].clone(), key.c[1].clone()],
        &config.params,
    )
    .unwrap();
    assert!(dkg::pk::Inputs::compute(&config, &oversized)
        .unwrap_err()
        .to_string()
        .contains("two components"));
    let mut altered = key.clone();
    altered.params = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(config.params.degree())
        .set_plaintext_modulus(config.params.plaintext())
        .set_moduli(config.params.moduli())
        .set_variance(config.params.variance() + 1)
        .set_error1_variance(config.params.get_error1_variance().clone())
        .build_arc()
        .unwrap();
    assert!(dkg::pk::Inputs::compute(&config, &altered)
        .unwrap_err()
        .to_string()
        .contains("public_key parameters"));
}

#[test]
fn malformed_c1_c2_c5_shapes_return_errors_before_computation() {
    let preset = BfvPreset::InsecureThreshold64;
    let committee = CiphernodesCommitteeSize::Minimum;
    let c1 = config::pk_generation::Configs::for_preset(preset, committee).unwrap();
    let sample = e3_zk_samples::threshold::pk_generation::generate(&c1).unwrap();
    assert!(threshold::pk_generation::Inputs::compute(&c1, &sample).is_ok());
    for extra in [false, true] {
        for field in ["pk0_share", "sk", "eek", "e_sm", "e_sm_lifted"] {
            let mut bad = sample.clone();
            if field == "e_sm_lifted" {
                let mut coefficients = bad.e_sm_lifted.coefficients().to_vec();
                if extra {
                    coefficients.push(BigInt::zero());
                } else {
                    coefficients.pop();
                }
                bad.e_sm_lifted = Polynomial::new(coefficients);
            } else {
                let crt = match field {
                    "pk0_share" => &mut bad.pk0_share,
                    "sk" => &mut bad.sk,
                    "eek" => &mut bad.eek,
                    _ => &mut bad.e_sm,
                };
                if extra {
                    crt.limbs.push(crt.limbs[0].clone());
                } else {
                    crt.limbs.pop();
                }
            }
            let error = threshold::pk_generation::Inputs::compute(&c1, &bad).unwrap_err();
            assert!(error.to_string().contains(field), "{field}: {error}");
            if field != "e_sm_lifted" && !extra {
                let mut bad = sample.clone();
                let crt = match field {
                    "pk0_share" => &mut bad.pk0_share,
                    "sk" => &mut bad.sk,
                    "eek" => &mut bad.eek,
                    _ => &mut bad.e_sm,
                };
                crt.limbs[0] = Polynomial::new(vec![BigInt::zero(); c1.params.degree() - 1]);
                assert!(threshold::pk_generation::Inputs::compute(&c1, &bad)
                    .unwrap_err()
                    .to_string()
                    .contains(&format!("{field}[0]")));
            }
        }
    }
    let c2 = dkg_config::share_computation::Configs::for_preset(preset, committee).unwrap();
    let mut sample =
        e3_zk_samples::dkg::share_computation::generate(&c2, preset, DkgInputType::SecretKey)
            .unwrap();
    assert!(dkg::share_computation::Inputs::compute(&c2, &sample).is_ok());
    let original = sample.secret_sss.clone();
    for dimensions in [
        (committee.values().n - 1, c2.params.degree()),
        (committee.values().n, c2.params.degree() - 1),
        (committee.values().n, c2.params.degree() + 1),
    ] {
        sample.secret_sss = original.clone();
        sample.secret_sss[0] = ndarray::Array2::from_elem(dimensions, BigInt::zero());
        assert!(dkg::share_computation::Inputs::compute(&c2, &sample)
            .unwrap_err()
            .to_string()
            .contains("secret_sss"));
    }
    sample.secret_sss = original;
    sample.secret_sss.pop();
    assert!(dkg::share_computation::Inputs::compute(&c2, &sample)
        .unwrap_err()
        .to_string()
        .contains("secret_sss"));
    sample.secret.limbs[0] = Polynomial::new(vec![BigInt::zero(); c2.params.degree() - 1]);
    assert!(dkg::share_computation::Inputs::compute(&c2, &sample)
        .unwrap_err()
        .to_string()
        .contains("secret[0]"));

    let c5 = config::pk_aggregation::Configs::for_preset(preset, committee).unwrap();
    let sample = e3_zk_samples::threshold::pk_aggregation::generate(&c5).unwrap();
    assert!(threshold::pk_aggregation::Inputs::compute(&c5, &sample).is_ok());
    for extra in [false, true] {
        let mut bad = sample.clone();
        if extra {
            bad.pk0_shares.push(bad.pk0_shares[0].clone());
        } else {
            bad.pk0_shares.pop();
        }
        assert!(threshold::pk_aggregation::Inputs::compute(&c5, &bad)
            .unwrap_err()
            .to_string()
            .contains("expected H="));
    }
    let mut bad = sample.clone();
    bad.pk0_shares[0].limbs[0] = Polynomial::new(vec![BigInt::zero(); c5.params.degree() - 1]);
    assert!(threshold::pk_aggregation::Inputs::compute(&c5, &bad)
        .unwrap_err()
        .to_string()
        .contains("pk0_shares[0][0]"));
    let mut bad = sample;
    bad.public_key = e3_zk_samples::threshold::user_data_encryption::generate(
        &BfvPreset::SecureThreshold8192.build_pair().unwrap().0,
    )
    .unwrap()
    .public_key;
    assert!(threshold::pk_aggregation::Inputs::compute(&c5, &bad)
        .unwrap_err()
        .to_string()
        .contains("public_key parameters"));
}

#[test]
fn zero_products_prepare_full_circuit_shapes_without_changing_polynomial_zero() {
    let preset = BfvPreset::InsecureThreshold64;
    let committee = CiphernodesCommitteeSize::Minimum;
    let c1 = config::pk_generation::Configs::for_preset(preset, committee).unwrap();
    let zero = Polynomial::new(vec![BigInt::zero(); c1.params.degree()]);
    let crt = CrtPolynomial::new(vec![zero.clone(); c1.params.moduli().len()]);
    assert_eq!(zero.mul(&zero).coefficients(), &[BigInt::zero()]);
    let input = threshold::pk_generation::PkGenerationCircuitData {
        pk0_share: crt.clone(),
        eek: crt.clone(),
        e_sm: crt.clone(),
        sk: crt.clone(),
        e_sm_lifted: zero,
    };
    let witness = threshold::pk_generation::Inputs::compute(&c1, &input).unwrap();
    assert!(witness
        .ris
        .limbs
        .iter()
        .all(|p| p.is_zero() && p.coefficients().len() == c1.params.degree()));

    let c6 = config::share_decryption::Configs::new(&c1.params).unwrap();
    let poly = Poly::<PowerBasis>::zero(c6.params.context_at_level(0).unwrap());
    let mut input = threshold::share_decryption::ShareDecryptionCircuitData {
        ciphertext: Ciphertext::new(vec![poly.clone().into_ntt(), poly.into_ntt()], &c6.params)
            .unwrap(),
        s: crt.clone(),
        e: crt.clone(),
        d_share: crt,
        domain_hi: 0,
        domain_lo: 0,
    };
    let witness = threshold::share_decryption::Inputs::compute(&c6, &input).unwrap();
    assert!(witness
        .r
        .limbs
        .iter()
        .all(|p| p.is_zero() && p.coefficients().len() == c6.params.degree()));
    let (_, dkg_params) = preset.build_pair().unwrap();
    let wrong_poly = Poly::<PowerBasis>::zero(dkg_params.context_at_level(0).unwrap()).into_ntt();
    let original_ciphertext = input.ciphertext.clone();
    input.ciphertext = Ciphertext::new(vec![wrong_poly.clone(), wrong_poly], &dkg_params).unwrap();
    assert!(threshold::share_decryption::Inputs::compute(&c6, &input)
        .unwrap_err()
        .to_string()
        .contains("ciphertext[0]"));
    input.ciphertext = original_ciphertext;
    for field in ["s", "e", "d_share"] {
        let original = match field {
            "s" => input.s.clone(),
            "e" => input.e.clone(),
            _ => input.d_share.clone(),
        };
        for extra in [false, true] {
            let target = match field {
                "s" => &mut input.s,
                "e" => &mut input.e,
                _ => &mut input.d_share,
            };
            *target = original.clone();
            if extra {
                target.limbs.push(target.limbs[0].clone());
            } else {
                target.limbs.pop();
            }
            assert!(threshold::share_decryption::Inputs::compute(&c6, &input)
                .unwrap_err()
                .to_string()
                .contains(field));
        }
        *match field {
            "s" => &mut input.s,
            "e" => &mut input.e,
            _ => &mut input.d_share,
        } = original;
    }
    input.d_share.limbs[0] = Polynomial::new(vec![BigInt::zero(); c6.params.degree() - 1]);
    assert!(threshold::share_decryption::Inputs::compute(&c6, &input)
        .unwrap_err()
        .to_string()
        .contains("d_share[0]"));
}

#[test]
fn c6_c7_native_prefix_commitments_agree_and_c7_pads_short_messages() {
    let preset = BfvPreset::InsecureThreshold64;
    let committee = CiphernodesCommitteeSize::Small;
    let mut c7 =
        config::decrypted_shares_aggregation::Configs::for_preset(preset, committee).unwrap();
    let mut c6 = config::share_decryption::Configs::new(&c7.params).unwrap();
    let sample =
        e3_zk_samples::threshold::decrypted_shares_aggregation::generate(&c7, preset).unwrap();
    assert_eq!(sample.d_share_polys.len(), 10);
    assert_eq!(committee.values().h, 14);
    let native = CrtPolynomial::from_fhe_polynomial(&sample.d_share_polys[0]);
    let zero = CrtPolynomial::new(vec![
        Polynomial::new(vec![
            BigInt::zero();
            c6.params.degree()
        ]);
        c6.params.moduli().len()
    ]);
    let c6_data = threshold::share_decryption::ShareDecryptionCircuitData {
        ciphertext: Ciphertext::new(
            vec![
                sample.d_share_polys[0].clone().into_ntt(),
                Poly::<PowerBasis>::zero(c6.params.context_at_level(0).unwrap()).into_ntt(),
            ],
            &c6.params,
        )
        .unwrap(),
        s: zero.clone(),
        e: zero,
        d_share: native.clone(),
        domain_hi: 0,
        domain_lo: 0,
    };
    let mut prior_commitment = None;
    for width in [c7.max_msg_non_zero_coeffs, 7] {
        c6.max_msg_non_zero_coeffs = width;
        c7.max_msg_non_zero_coeffs = width;
        let a = threshold::share_decryption::Inputs::compute(&c6, &c6_data).unwrap();
        let b = threshold::decrypted_shares_aggregation::Inputs::compute(&c7, &sample).unwrap();
        assert_eq!(a.d_native_trunc, b.decryption_shares[0]);
        for (actual, full) in a.d_native_trunc.limbs.iter().zip(&native.limbs) {
            assert_eq!(actual.coefficients(), &full.coefficients()[..width]);
        }
        let commitment = e3_zk_witness::compute_threshold_decryption_share_commitment(
            &a.d_native_trunc,
            c6.bits.d_native_bit,
            width,
        );
        assert_eq!(commitment, b.expected_d_commitments[0]);
        if let Some(prior) = prior_commitment {
            assert_ne!(
                commitment, prior,
                "the configured prefix width must affect its commitment"
            );
        }
        prior_commitment = Some(commitment);
        let mut short = sample.clone();
        short.message_vec = vec![2, 1];
        let padded = threshold::decrypted_shares_aggregation::Inputs::compute(&c7, &short).unwrap();
        let mut expected = vec![BigInt::from(2), BigInt::from(1)];
        expected.resize(width, BigInt::zero());
        assert_eq!(padded.message.coefficients(), expected);
    }
    for ids in [
        vec![0, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        vec![1, 1, 3, 4, 5, 6, 7, 8, 9, 10],
        vec![2, 1, 3, 4, 5, 6, 7, 8, 9, 10],
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, committee.values().n + 1],
    ] {
        let mut bad = sample.clone();
        bad.reconstructing_parties = ids;
        assert!(
            threshold::decrypted_shares_aggregation::Inputs::compute(&c7, &bad)
                .unwrap_err()
                .to_string()
                .contains("strictly increasing")
        );
    }
    let (other, _) = BfvPreset::SecureThreshold8192.build_pair().unwrap();
    let mut bad = sample.clone();
    bad.d_share_polys[0] = Poly::<PowerBasis>::zero(other.context_at_level(0).unwrap());
    assert!(
        threshold::decrypted_shares_aggregation::Inputs::compute(&c7, &bad)
            .unwrap_err()
            .to_string()
            .contains("context and shape")
    );
    c7.max_msg_non_zero_coeffs = c7.params.degree() + 1;
    c6.max_msg_non_zero_coeffs = c6.params.degree() + 1;
    assert!(
        threshold::decrypted_shares_aggregation::Inputs::compute(&c7, &sample)
            .unwrap_err()
            .to_string()
            .contains("exceeds the polynomial degree")
    );
    assert!(threshold::share_decryption::Inputs::compute(&c6, &c6_data)
        .unwrap_err()
        .to_string()
        .contains("exceeds the polynomial degree"));
}
