// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#[cfg(test)]
mod tests {
    use e3_zk_witness::threshold::user_data_encryption_chunked::utils::*;
    use e3_zk_witness::WitnessError;
    use fhe::bfv::Ciphertext;

    use e3_fhe_params::{build_pair_for_preset, BfvPreset};

    use e3_zk_witness::threshold::user_data_encryption_chunked::Inputs;
    use fhe_traits::DeserializeParametrized;
    use num_bigint::BigInt;

    #[test]
    fn test_bfv_public_key_to_greco() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();
        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();

        let config =
            e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&threshold_params)
                .unwrap();
        let (ct, material) = e3_zk_witness::encrypt_with_intermediates(
            &sample.public_key,
            &sample.plaintext,
            &mut rand::rng(),
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample, &ct, &material).unwrap();

        // Convert using our function
        let (actual_pk0is, actual_pk1is) =
            bfv_public_key_to_greco(&threshold_params, &sample.public_key).unwrap();

        // Verify the structure matches
        assert_eq!(actual_pk0is, inputs.pk0is);
        assert_eq!(actual_pk1is, inputs.pk1is);
    }

    /// Centering must hold for both components, and converting twice must give the same answer.
    ///
    /// The conversion reads the ciphertext by reference and centers a copy, so nothing it does can
    /// leave a component centered-twice or half-centered. Asserted rather than reasoned about,
    /// because the failure would be silent: a coefficient outside (-q/2, q/2] still commits to
    /// *something*, and the circuit would reject the ballot with no indication why.
    #[test]
    fn conversion_centers_both_components_and_is_repeatable() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();
        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
        let config =
            e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&threshold_params)
                .unwrap();
        let (ct, material) = e3_zk_witness::encrypt_with_intermediates(
            &sample.public_key,
            &sample.plaintext,
            &mut rand::rng(),
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample, &ct, &material).unwrap();
        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

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

        // Idempotent in the sense that matters: the input is untouched, so a second conversion of
        // the same ciphertext produces an identical result rather than centering again.
        let (again0, again1) = bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();
        assert_eq!(ct0is.limbs, again0.limbs);
        assert_eq!(ct1is.limbs, again1.limbs);
    }

    /// The commitment covers `c[0]` and `c[1]` only. Without a component-count check, a
    /// ciphertext padded with a third polynomial commits to the same value as its two-component
    /// prefix, so two different serialized ciphertexts would share one commitment. Threshold
    /// decryption then rejects the padded ciphertext and the round fails.
    #[test]
    fn ciphertext_with_more_than_two_components_is_rejected() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();
        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();
        let config =
            e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&threshold_params)
                .unwrap();
        let (ct, material) = e3_zk_witness::encrypt_with_intermediates(
            &sample.public_key,
            &sample.plaintext,
            &mut rand::rng(),
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample, &ct, &material).unwrap();
        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

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

        // The two-component original still converts, so the check rejects only the padding.
        assert!(bfv_ciphertext_to_greco(&threshold_params, &ciphertext).is_ok());
    }

    #[test]
    fn test_bfv_ciphertext_to_greco() {
        let (threshold_params, _) = build_pair_for_preset(BfvPreset::InsecureThreshold).unwrap();

        let sample =
            e3_zk_samples::threshold::user_data_encryption::generate(&threshold_params).unwrap();

        let config =
            e3_zk_config::threshold::user_data_encryption_chunked::Configs::new(&threshold_params)
                .unwrap();
        let (ct, material) = e3_zk_witness::encrypt_with_intermediates(
            &sample.public_key,
            &sample.plaintext,
            &mut rand::rng(),
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample, &ct, &material).unwrap();

        let ciphertext = Ciphertext::from_bytes(&inputs.ciphertext, &threshold_params).unwrap();

        // Convert using our function
        let (actual_ct0is, actual_ct1is) =
            bfv_ciphertext_to_greco(&threshold_params, &ciphertext).unwrap();

        // Verify the structure matches
        assert_eq!(actual_ct0is, inputs.ct0is);
        assert_eq!(actual_ct1is, inputs.ct1is);
    }
}
