// SPDX-License-Identifier: LGPL-3.0-only

//! Sample-backed checks of the production threshold witness APIs.

mod decrypted_shares_aggregation {
    use e3_committee::CiphernodesCommitteeSize;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::threshold::decrypted_shares_aggregation::Configs;
    use e3_zk_witness::threshold::decrypted_shares_aggregation::Inputs;

    #[test]
    fn an_extra_polynomial_or_party_id_is_refused() {
        let preset = BfvPreset::InsecureThreshold64;
        let config = Configs::for_preset(preset, CiphernodesCommitteeSize::Small).unwrap();
        let sample =
            e3_zk_samples::threshold::decrypted_shares_aggregation::generate(&config, preset)
                .unwrap();
        // T+2 polynomials with T+1 party IDs must fail.
        let mut oversized = sample.clone();
        oversized
            .d_share_polys
            .push(oversized.d_share_polys[0].clone());
        let error = Inputs::compute(&config, &oversized)
            .unwrap_err()
            .to_string();
        assert!(error.contains("d_share_polys.len()"), "{error}");
        // T+1 polynomials with T+2 party IDs must fail.
        let mut extra_party = sample.clone();
        extra_party.reconstructing_parties.push(99);
        let error = Inputs::compute(&config, &extra_party)
            .unwrap_err()
            .to_string();
        assert!(error.contains("reconstructing_parties.len()"), "{error}");
        Inputs::compute(&config, &sample).unwrap();
        let mut missing = sample.clone();
        missing.d_share_polys.pop();
        missing.reconstructing_parties.pop();
        assert!(Inputs::compute(&config, &missing)
            .unwrap_err()
            .to_string()
            .contains("d_share_polys.len()"));
    }

    #[test]
    fn test_full_computation_with_sample() {
        let preset = BfvPreset::InsecureThreshold64;
        let committee = CiphernodesCommitteeSize::Small.values();
        let configs = Configs::for_preset(preset, CiphernodesCommitteeSize::Small).unwrap();
        let input =
            e3_zk_samples::threshold::decrypted_shares_aggregation::generate(&configs, preset)
                .unwrap();
        let out = Inputs::compute(&configs, &input).unwrap();
        assert_eq!(out.decryption_shares.len(), committee.threshold + 1);
        assert_eq!(out.expected_d_commitments.len(), committee.threshold + 1);
        assert_eq!(out.party_ids.len(), committee.threshold + 1);
        assert_eq!(
            out.message.coefficients().len(),
            configs.max_msg_non_zero_coeffs
        );
        assert_eq!(
            out.decryption_shares[0].limbs.len(),
            configs.params.moduli().len()
        );
        assert!(configs.bits.d_native_bit > 0);
        assert!(configs.bits.q_bit > 0);
        assert!(configs.bits.k_bit > configs.bits.q_bit);
        assert!(configs.bits.t_bit > 0);
        assert!(configs.bits.q_total_bit >= configs.bits.q_bit);
    }
}

mod share_decryption {
    use e3_fhe_params::{build_pair_for_preset, utils::calculate_bit_width, DEFAULT_BFV_PRESET};
    use e3_polynomial::CrtPolynomial;
    use e3_polynomial_fhe::FromFhePolynomial as _;
    use e3_zk_config::threshold::share_decryption::Configs;
    use e3_zk_witness::threshold::share_decryption::Inputs;
    use num_bigint::BigUint;

    /// Centered residues carry the modulus width, independently of quotient bounds.
    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let (threshold_params, _) = build_pair_for_preset(DEFAULT_BFV_PRESET).unwrap();
        let config = Configs::new(&threshold_params).unwrap();
        let bits = &config.bits;
        let max_q = *threshold_params.moduli().iter().max().unwrap();
        let expected_bit = calculate_bit_width(&((BigUint::from(max_q) - 1u32) / 2u32));
        assert_eq!(bits.d_bit, expected_bit);
        assert_eq!(bits.ct_bit, expected_bit);
        assert_eq!(bits.sk_bit, expected_bit);
        assert_eq!(bits.e_sm_bit, expected_bit);
    }

    #[test]
    fn test_d_native_bit_matches_moduli_and_covers_centered_d_bit() {
        let (threshold_params, _) = build_pair_for_preset(DEFAULT_BFV_PRESET).unwrap();
        let config = Configs::new(&threshold_params).unwrap();
        let bits = &config.bits;
        assert_eq!(
            bits.d_native_bit,
            e3_fhe_params::utils::compute_native_crt_coeff_bit(threshold_params.moduli())
        );
        assert!(bits.d_native_bit >= bits.d_bit);
    }

    /// Compare native truncated commitments with raw-share and serialized-share commitments.
    #[test]
    fn test_d_commitment_matches_inputs_compute() {
        use e3_committee::CiphernodesCommitteeSize;
        use e3_zk_witness::compute_threshold_decryption_share_commitment;
        use fhe_math::rq::{Poly, PowerBasis};
        use fhe_traits::{DeserializeWithContext, Serialize as FheSer};
        use num_traits::ToPrimitive;
        let preset = DEFAULT_BFV_PRESET;
        let committee = CiphernodesCommitteeSize::Small.values();
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let config = Configs::new(&threshold_params).unwrap();
        let sample =
            e3_zk_samples::threshold::share_decryption::generate(&config.params, preset, committee)
                .unwrap();
        let bits = &config.bits;
        let inputs = Inputs::compute(&config, &sample).unwrap();
        let from_d_native = compute_threshold_decryption_share_commitment(
            &inputs.d_native_trunc,
            bits.d_native_bit,
            config.max_msg_non_zero_coeffs,
        );
        let from_raw_share = compute_threshold_decryption_share_commitment(
            &sample.d_share,
            bits.d_native_bit,
            config.max_msg_non_zero_coeffs,
        );
        assert_eq!(from_d_native, from_raw_share);
        let raw: Vec<Vec<u64>> = sample
            .d_share
            .limbs
            .iter()
            .map(|l| {
                l.coefficients()
                    .iter()
                    .map(|c| c.to_u64().unwrap())
                    .collect()
            })
            .collect();
        let n = raw[0].len();
        let mut arr = ndarray::Array2::<u64>::zeros((raw.len(), n));
        for (i, limb) in raw.iter().enumerate() {
            for (j, &v) in limb.iter().enumerate() {
                arr[[i, j]] = v;
            }
        }
        let ctx = threshold_params.context_at_level(0).unwrap();
        let mut poly = Poly::<PowerBasis>::zero(ctx);
        poly.set_coefficients(arr);
        let poly_rt = Poly::<PowerBasis>::from_bytes(&poly.to_bytes(), ctx).unwrap();
        let crt_rt = CrtPolynomial::from_fhe_polynomial(&poly_rt);
        let from_bytes = compute_threshold_decryption_share_commitment(
            &crt_rt,
            bits.d_native_bit,
            config.max_msg_non_zero_coeffs,
        );
        assert_eq!(from_d_native, from_bytes);
    }
}
