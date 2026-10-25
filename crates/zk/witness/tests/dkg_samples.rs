// SPDX-License-Identifier: LGPL-3.0-only

//! Sample-backed checks of the production DKG witness APIs.

mod share_computation {
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::dkg::share_computation::Configs;
    use e3_zk_config::DkgInputType;
    use e3_zk_witness::dkg::share_computation::Inputs;

    #[test]
    fn input_committee_must_match_the_supplied_configuration() {
        let preset = BfvPreset::InsecureThreshold64;
        let matching = Configs::for_preset(preset, CiphernodesCommitteeSize::Minimum).unwrap();
        let sample = e3_zk_samples::dkg::share_computation::generate(
            &matching,
            preset,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let mismatched = Configs::for_preset(preset, CiphernodesCommitteeSize::Micro).unwrap();
        let error = Inputs::compute(&mismatched, &sample).unwrap_err();
        assert!(error.to_string().contains("secret_sss"));
        let inputs = Inputs::compute(&matching, &sample).unwrap();
        assert_eq!(
            inputs.y[0][0].len(),
            1 + CiphernodesCommitteeSize::Minimum.values().n
        );
    }

    #[test]
    fn test_input_smudging_noise_secret_consistency() {
        let config = Configs::for_preset(
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Small,
        )
        .unwrap();
        let sample = e3_zk_samples::dkg::share_computation::generate(
            &config,
            BfvPreset::InsecureThreshold64,
            DkgInputType::SmudgingNoise,
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample).unwrap();
        let degree = inputs.secret_crt.limb(0).coefficients().len();
        let num_moduli = inputs.secret_crt.limbs.len();
        for coeff_idx in 0..degree {
            for mod_idx in 0..num_moduli {
                let secret_coeff =
                    inputs.secret_crt.limb(mod_idx).coefficients()[coeff_idx].clone();
                let y_secret = inputs.y[coeff_idx][mod_idx][0].clone();
                assert_eq!(secret_coeff, y_secret,
                    "secret consistency: secret_crt[{mod_idx}][{coeff_idx}] must equal y[{coeff_idx}][{mod_idx}][0]");
            }
        }
    }
}

mod share_decryption {
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_fhe_params::{
        build_pair_for_preset,
        utils::{compute_modulus_bit, compute_msg_bit},
    };
    use e3_polynomial::Polynomial;
    use e3_zk_config::dkg::share_decryption::Configs;
    use e3_zk_config::DkgInputType;
    use e3_zk_witness::{
        compute_share_encryption_commitment_from_message, dkg::share_decryption::Inputs,
    };
    use fhe::bfv::Encoding;
    use fhe_traits::{FheDecoder, FheDecrypter};

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let (threshold_params, dkg_params) =
            build_pair_for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let config = Configs::new(&threshold_params, &dkg_params).unwrap();
        let bits = &config.bits;
        assert_eq!(bits.msg_bit, compute_msg_bit(&dkg_params));
        assert_eq!(bits.agg_bit, compute_modulus_bit(&threshold_params));
    }

    #[test]
    fn test_input_decryption_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let config = Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let sample = e3_zk_samples::dkg::share_decryption::generate(
            &config,
            BfvPreset::InsecureThreshold64,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample).unwrap();
        assert_eq!(
            inputs.expected_commitments.len(),
            sample.honest_ciphertexts.len()
        );
        assert_eq!(
            inputs.decrypted_shares.len(),
            sample.honest_ciphertexts.len()
        );
    }

    /// A malformed own-share row must fail at the witness boundary, not as a Noir input error.
    #[test]
    fn own_share_rows_must_carry_the_configured_degree() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let preset = BfvPreset::InsecureThreshold64;
        let config = Configs::for_preset(preset).unwrap();
        let mut sample = e3_zk_samples::dkg::share_decryption::generate(
            &config,
            preset,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        sample.own_plaintext_share[0].pop();
        let error = Inputs::compute(&config, &sample).unwrap_err();
        assert!(error.to_string().contains("own_plaintext_share[0]"));
    }

    /// Check row ordering for both external ciphertexts and the own plaintext slot.
    #[test]
    fn test_commitment_ordering_consistency() {
        let committee = CiphernodesCommitteeSize::Small.values();
        let preset = BfvPreset::InsecureThreshold64;
        let config = Configs::for_preset(preset).unwrap();
        let sample = e3_zk_samples::dkg::share_decryption::generate(
            &config,
            preset,
            committee,
            DkgInputType::SecretKey,
        )
        .unwrap();
        let threshold_params = &config.threshold_params;
        let dkg_params = &config.params;
        let threshold_l = threshold_params.moduli().len();
        let msg_bit = compute_msg_bit(&dkg_params);
        let inputs = Inputs::compute(&config, &sample).unwrap();
        assert_eq!(
            inputs.expected_commitments.len(),
            sample.honest_ciphertexts.len()
        );
        for (party_idx, slot) in sample.honest_ciphertexts.iter().enumerate() {
            for mod_idx in 0..threshold_l {
                let share_coeffs = match slot {
                    Some(party_cts) => {
                        let decrypted_pt =
                            sample.secret_key.try_decrypt(&party_cts[mod_idx]).unwrap();
                        Vec::<u64>::try_decode(&decrypted_pt, Encoding::poly()).unwrap()
                    }
                    None => sample.own_plaintext_share[mod_idx].clone(),
                };
                // C2 commits to shares in highest-degree-first order.
                let mut reversed = share_coeffs.clone();
                reversed.reverse();
                let direct_commitment = compute_share_encryption_commitment_from_message(
                    &Polynomial::from_u64_vector(reversed),
                    msg_bit,
                );
                assert_eq!(
                    inputs.expected_commitments[party_idx][mod_idx], direct_commitment,
                    "expected_commitments[{}][{}] doesn't match direct computation",
                    party_idx, mod_idx
                );
            }
        }
    }
}

mod share_encryption {
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::utils::calculate_bit_width;
    use e3_fhe_params::BfvPreset;
    use e3_polynomial::Polynomial;
    use e3_zk_config::dkg::share_encryption::Configs;
    use e3_zk_config::DkgInputType;
    use e3_zk_witness::dkg::share_encryption::Inputs;
    use fhe::bfv::{Encoding, Plaintext};
    use fhe_traits::{FheDecoder, FheEncoder};
    use num_bigint::{BigInt, BigUint};

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let config = Configs::for_preset(BfvPreset::InsecureThreshold64).unwrap();
        let bounds = &config.bounds;
        let bits = &config.bits;
        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(max_pk_bound);
        assert_eq!(
            max_pk_bound.clone(),
            BigUint::from(
                (e3_fhe_params::constants::insecure_64::dkg::MODULI
                    .iter()
                    .max()
                    .unwrap()
                    - 1)
                    / 2
            )
        );
        assert_eq!(bits.pk_bit, expected_bits);
        assert_eq!(
            bounds.msg_bound,
            BigUint::from(
                BfvPreset::InsecureThreshold64
                    .build_pair()
                    .unwrap()
                    .1
                    .plaintext()
            )
        );
    }

    #[test]
    fn test_input_message_consistency() {
        let sd = BfvPreset::InsecureThreshold64.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold64.build_pair().unwrap();
        let config = Configs::new(&dkg_params).unwrap();
        let sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold64,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let inputs = Inputs::compute(&config, &sample).unwrap();
        let expected_message = Polynomial::from_u64_vector(
            Vec::<u64>::try_decode(&sample.plaintext, Encoding::poly()).unwrap(),
        );
        let mut expected = expected_message;
        expected.reverse();
        assert_eq!(inputs.message.coefficients(), expected.coefficients());
    }

    #[test]
    fn generated_share_encryption_witness_respects_ct0_r_bounds() {
        let preset = BfvPreset::InsecureThreshold64;
        let (threshold_params, dkg_params) = preset.build_pair().unwrap();
        let config = Configs::new(&dkg_params).unwrap();
        let sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            preset,
            CiphernodesCommitteeSize::Minimum.values(),
            DkgInputType::SecretKey,
            preset.search_defaults().unwrap().z,
        )
        .unwrap();
        let bounds = &config.bounds;
        let inputs = Inputs::compute(&config, &sample).unwrap();
        for (i, limb) in inputs.ct0_r.limbs.iter().enumerate() {
            let bound = BigInt::from(bounds.ct0_r_bounds[i].clone());
            for (j, coefficient) in limb.coefficients().iter().enumerate() {
                assert!(
                    coefficient.magnitude() <= bound.magnitude(),
                    "ct0_r[{i}][{j}] = {coefficient} outside [-{bound}, {bound}]"
                );
            }
        }
    }

    #[test]
    fn plaintext_with_a_foreign_degree_is_rejected() {
        let (threshold_params, dkg_params) = BfvPreset::InsecureThreshold64.build_pair().unwrap();
        let config = Configs::new(&dkg_params).unwrap();
        let mut sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Minimum.values(),
            DkgInputType::SecretKey,
            0,
        )
        .unwrap();
        let (_, foreign_params) = BfvPreset::SecureThreshold8192.build_pair().unwrap();
        sample.plaintext = Plaintext::try_encode(
            &vec![0u64; foreign_params.degree()],
            Encoding::poly(),
            &foreign_params,
        )
        .unwrap();
        let error = Inputs::compute(&config, &sample).unwrap_err();
        assert!(error.to_string().contains("configured polynomial degree"));
    }

    /// The insecure DKG preset has a single modulus, so a level-1 plaintext requires the
    /// two-modulus secure preset. Above level zero, the shorter context pairs with the full limb
    /// vectors and truncates the witness without an error.
    #[test]
    fn plaintext_above_level_zero_is_rejected() {
        let preset = BfvPreset::SecureThreshold8192;
        let (threshold_params, dkg_params) = preset.build_pair().unwrap();
        let config = Configs::new(&dkg_params).unwrap();
        let mut sample = e3_zk_samples::dkg::share_encryption::generate(
            &threshold_params,
            &dkg_params,
            preset,
            CiphernodesCommitteeSize::Minimum.values(),
            DkgInputType::SecretKey,
            0,
        )
        .unwrap();
        let row = Vec::<u64>::try_decode(&sample.plaintext, Encoding::poly()).unwrap();
        sample.plaintext =
            Plaintext::try_encode(&row, Encoding::poly_at_level(1), &dkg_params).unwrap();
        let error = Inputs::compute(&config, &sample).unwrap_err();
        assert!(error.to_string().contains("level zero"));
    }
}
