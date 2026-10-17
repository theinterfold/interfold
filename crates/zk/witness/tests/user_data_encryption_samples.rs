// SPDX-License-Identifier: LGPL-3.0-only

//! Sample-backed encryption preparation and conversion checks.

use e3_fhe_params::{build_pair_for_preset, utils::calculate_bit_width, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_polynomial_fhe::FromFhePolynomial as _;
use e3_zk_config::field::get_zkp_modulus;
use e3_zk_config::threshold::user_data_encryption::Configs;
use e3_zk_witness::threshold::user_data_encryption::{
    bfv_ciphertext_to_greco, bfv_public_key_to_greco, compute_ciphertext_commitment,
    encrypt_and_prepare, Inputs,
};
use e3_zk_witness::WitnessError;
use fhe::bfv::{Ciphertext, Encoding};
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;

#[test]
fn test_bound_and_bits_computation_consistency() {
    let bounds = Configs::for_preset(BfvPreset::InsecureThreshold64)
        .map(|config| config.bounds)
        .unwrap();
    let bits = Configs::for_preset(BfvPreset::InsecureThreshold64)
        .map(|config| config.bits)
        .unwrap();
    let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
    let expected_bits = calculate_bit_width(max_pk_bound);
    assert_eq!(
        max_pk_bound.clone(),
        BigUint::from(
            (e3_fhe_params::constants::insecure_64::threshold::MODULI
                .iter()
                .max()
                .unwrap()
                - 1)
                / 2
        )
    );
    assert_eq!(bits.pk_bit, expected_bits);
}

#[test]
fn insecure_e0_bound_matches_error1_sampler() {
    let preset = BfvPreset::InsecureThreshold64;
    let bounds = Configs::for_preset(preset)
        .map(|config| config.bounds)
        .unwrap();
    let bits = Configs::for_preset(preset)
        .map(|config| config.bits)
        .unwrap();
    // B_Enc of the insecure-64 search: ⌊B_Enc(B_Enc+1)/3⌋ is its error1 variance.
    assert_eq!(bounds.e0_bound, BigUint::from(194560u32));
    assert_eq!(bounds.e1_bound, BigUint::from(20u32));
    assert_eq!(bits.e0_bit, 18);
}

#[test]
fn exact_encryption_material_is_repeatable_and_closes_both_reduced_identities() {
    use fhe_traits::{FheDecoder, Serialize};
    for preset in [
        BfvPreset::InsecureThreshold64,
        BfvPreset::SecureThreshold8192,
    ] {
        let config = Configs::for_preset(preset).unwrap();
        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&config.params).unwrap();
        let (ciphertext, material) = sample
            .public_key
            .try_encrypt_with_intermediates(&sample.plaintext, &mut rand::rng())
            .unwrap();
        let bytes = ciphertext.to_bytes();
        let inputs = Inputs::compute(&config, &sample, &ciphertext, &material).unwrap();
        let again = Inputs::compute(&config, &sample, &ciphertext, &material).unwrap();
        assert_eq!(inputs.to_json(), again.to_json());
        assert_eq!(ciphertext.to_bytes(), bytes);
        let mut message = Vec::<u64>::try_decode(&sample.plaintext, Encoding::poly()).unwrap();
        let q = BigInt::from(config.params.context_at_level(0).unwrap().modulus().clone());
        let t = BigInt::from(config.params.plaintext());
        let expected_k1: Vec<_> = message
            .drain(..)
            .rev()
            .map(|m| (BigInt::from(m) * &q) % &t)
            .collect();
        assert_eq!(inputs.k1.coefficients(), expected_k1);
        let mut lifted_e0 = Polynomial::from_fhe_polynomial(material.error_0());
        lifted_e0.reverse();
        lifted_e0.center(&q);
        let mut field_e0 = inputs.e0.clone();
        field_e0.center(&get_zkp_modulus());
        assert_eq!(field_e0, lifted_e0);
        let mut different_residue = false;
        for (i, &qi) in config.params.moduli().iter().enumerate() {
            let qi = BigInt::from(qi);
            // Independent monic long division checks the circuit's integer equations.
            let ct0_hat = reduce_by_long_division(
                &inputs.pk0is.limbs[i].mul(&inputs.u),
                config.params.degree(),
            )
            .add(&lifted_e0)
            .add(&inputs.k1.scalar_mul(&BigInt::from(config.k0is[i])))
            .add(&inputs.ct0_r.limbs[i].scalar_mul(&qi));
            let ct1_hat = reduce_by_long_division(
                &inputs.pk1is.limbs[i].mul(&inputs.u),
                config.params.degree(),
            )
            .add(&inputs.e1)
            .add(&inputs.ct1_r.limbs[i].scalar_mul(&qi));
            assert_eq!(ct0_hat, inputs.ct0is.limbs[i]);
            assert_eq!(ct1_hat, inputs.ct1is.limbs[i]);
            let mut residue =
                CrtPolynomial::from_fhe_polynomial(material.error_0()).limbs[i].clone();
            residue.reverse();
            residue.center(&qi);
            different_residue |= residue != lifted_e0;
            if residue != lifted_e0 {
                assert_ne!(ct0_hat.sub(&lifted_e0).add(&residue), inputs.ct0is.limbs[i]);
            }
        }
        if preset == BfvPreset::SecureThreshold8192 {
            assert!(
                different_residue,
                "secure e0 must exercise the lifted-residue carry correction"
            );
        }
        for (i, limb) in inputs.ct0_r.limbs.iter().enumerate() {
            let bound = BigInt::from(config.bounds.ct0_r_bounds[i].clone());
            for (j, coefficient) in limb.coefficients().iter().enumerate() {
                assert!(
                    coefficient.abs() <= bound,
                    "{preset:?} ct0_r[{i}][{j}] = {coefficient} exceeds {bound}"
                );
            }
        }
    }
}

fn reduce_by_long_division(poly: &Polynomial, n: usize) -> Polynomial {
    let mut coefficients = poly.coefficients().to_vec();
    for index in 0..coefficients.len().saturating_sub(n) {
        let leading = coefficients[index].clone();
        coefficients[index] -= &leading;
        coefficients[index + n] -= leading;
    }
    let mut tail = vec![BigInt::from(0); n];
    let count = n.min(coefficients.len());
    tail[n - count..].clone_from_slice(&coefficients[coefficients.len() - count..]);
    Polynomial::new(tail)
}

#[test]
fn test_bfv_public_key_to_greco() {
    let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();
    let sample =
        e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
    let (_, inputs) = encrypt_and_prepare(
        &Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap(),
        &sample,
    )
    .unwrap();
    let (actual_pk0is, actual_pk1is) =
        bfv_public_key_to_greco(&threshold_params, &sample.public_key).unwrap();
    assert_eq!(actual_pk0is, inputs.pk0is);
    assert_eq!(actual_pk1is, inputs.pk1is);
}

/// Both components must stay centered, and conversion must not modify the ciphertext.
#[test]
fn conversion_centers_both_components_and_is_repeatable() {
    let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();
    let sample =
        e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
    let (ciphertext, _) = encrypt_and_prepare(
        &Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap(),
        &sample,
    )
    .unwrap();
    let moduli = threshold_params.moduli();
    let (ct0is, ct1is) = bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();
    for crt in [&ct0is, &ct1is] {
        assert_eq!(crt.limbs.len(), moduli.len());
        for (limb, qi) in crt.limbs.iter().zip(moduli.iter()) {
            let half = BigInt::from(*qi) / BigInt::from(2u64);
            let low = -half.clone();
            for coefficient in limb.coefficients() {
                assert!(
                    *coefficient > low && *coefficient <= half,
                    "coefficient {coefficient} outside (-q/2, q/2] for q={qi}"
                );
            }
        }
    }
    let (again0, again1) = bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();
    assert_eq!(ct0is.limbs, again0.limbs);
    assert_eq!(ct1is.limbs, again1.limbs);
}

/// An extra component must not share the commitment of its two-component prefix.
#[test]
fn ciphertext_with_more_than_two_components_is_rejected() {
    let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();
    let sample =
        e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
    let (ciphertext, _) = encrypt_and_prepare(
        &Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap(),
        &sample,
    )
    .unwrap();
    let padded = Ciphertext::new(
        vec![
            ciphertext[0].clone(),
            ciphertext[1].clone(),
            ciphertext[1].clone(),
        ],
        &threshold_params,
    )
    .unwrap();
    assert_eq!(padded.len(), 3);
    assert!(matches!(
        bfv_ciphertext_to_greco(&threshold_params, &padded),
        Err(WitnessError::UnexpectedCiphertextComponents(3))
    ));
    assert!(matches!(
        compute_ciphertext_commitment(&threshold_params, &padded),
        Err(WitnessError::UnexpectedCiphertextComponents(3))
    ));
    assert!(bfv_ciphertext_to_greco(&threshold_params, &ciphertext).is_ok());
}

#[test]
fn test_bfv_ciphertext_to_greco() {
    let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();
    let sample =
        e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
    let (ciphertext, inputs) = encrypt_and_prepare(
        &Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap(),
        &sample,
    )
    .unwrap();
    let (actual_ct0is, actual_ct1is) =
        bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();
    assert_eq!(actual_ct0is, inputs.ct0is);
    assert_eq!(actual_ct1is, inputs.ct1is);
}
