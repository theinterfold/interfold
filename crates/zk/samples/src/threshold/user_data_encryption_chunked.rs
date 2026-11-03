// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pub use super::user_data_encryption::generate;

#[cfg(test)]
mod tests {
    use super::*;
    use e3_fhe_params::utils::calculate_bit_width;
    use e3_fhe_params::{build_pair_for_preset, utils::compute_k0is};
    use e3_polynomial::Polynomial;
    use e3_zk_config::field::get_zkp_modulus;
    use e3_zk_config::threshold::user_data_encryption_chunked::Configs;
    use e3_zk_witness::threshold::user_data_encryption::UserDataEncryptionCircuitData;
    use e3_zk_witness::threshold::user_data_encryption_chunked::Inputs;
    use e3_zk_witness::WitnessError;
    use num_bigint::{BigInt, BigUint};
    use num_traits::Signed;

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let bounds = Configs::for_preset(BfvPreset::InsecureThreshold)
            .map(|c| c.bounds)
            .unwrap();
        let bits = Configs::for_preset(BfvPreset::InsecureThreshold)
            .map(|c| c.bits)
            .unwrap();

        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(max_pk_bound);

        assert_eq!(max_pk_bound.clone(), BigUint::from(36028797018956544u64));
        assert_eq!(bits.pk_bit, expected_bits);
    }

    /// Evaluate a descending-coefficient polynomial at `x` modulo `p`.
    fn eval_mod(poly: &Polynomial, x: &BigInt, p: &BigInt) -> BigInt {
        poly.coefficients()
            .iter()
            .fold(BigInt::from(0), |acc, c| (acc * x + c) % p)
    }

    /// The witness satisfies the ct0 identity the chunked circuits check, with the committed,
    /// lifted `e0` in every CRT limb (IF-006): `ct0_i = pk0_i * u + e0 + k1 * k0_i + r1_i * q_i +
    /// r2_i * (X^N + 1)` at a point, and every `r1` coefficient stays within its bound.
    #[test]
    fn reduced_identities_hold_on_lbfv_presets() {
        for preset in [
            BfvPreset::InsecureThresholdLbfv,
            BfvPreset::SecureThreshold16384,
        ] {
            let sample = generate(&Configs::for_preset(preset).unwrap().params).unwrap();
            let bounds = Configs::for_preset(preset).map(|c| c.bounds).unwrap();
            let inputs = prepare(preset, &sample).unwrap();
            let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
            let moduli = threshold_params.moduli();
            let k0is = compute_k0is(moduli, threshold_params.plaintext()).unwrap();
            let n = threshold_params.degree() as u32;

            let p = get_zkp_modulus();
            let x = BigInt::from(0x1234_5678_9abc_def1_u64);
            let e0 = eval_mod(&inputs.e0, &x, &p);
            let e1 = eval_mod(&inputs.e1, &x, &p);
            let k1 = eval_mod(&inputs.k1, &x, &p);
            for (limb, qi) in moduli.iter().enumerate() {
                // The circuits check both identities reduced modulo X^N + 1.
                assert_eq!(inputs.r1is.limb(limb).coefficients().len(), n as usize);
                assert_eq!(inputs.p1is.limb(limb).coefficients().len(), n as usize);
                let pk0u = negacyclic_mul(inputs.pk0is.limb(limb), &inputs.u, n as usize).unwrap();
                let rhs = eval_mod(&pk0u, &x, &p)
                    + &e0
                    + &k1 * BigInt::from(k0is[limb])
                    + eval_mod(inputs.r1is.limb(limb), &x, &p) * BigInt::from(*qi);
                let lhs = eval_mod(inputs.ct0is.limb(limb), &x, &p);
                assert_eq!(
                    ((rhs - lhs) % &p + &p) % &p,
                    BigInt::from(0),
                    "{preset:?} ct0 identity fails in limb {limb}"
                );

                let pk1u = negacyclic_mul(inputs.pk1is.limb(limb), &inputs.u, n as usize).unwrap();
                let rhs = eval_mod(&pk1u, &x, &p)
                    + &e1
                    + eval_mod(inputs.p1is.limb(limb), &x, &p) * BigInt::from(*qi);
                let lhs = eval_mod(inputs.ct1is.limb(limb), &x, &p);
                assert_eq!(
                    ((rhs - lhs) % &p + &p) % &p,
                    BigInt::from(0),
                    "{preset:?} ct1 identity fails in limb {limb}"
                );
                let p1_bound = BigInt::from(bounds.p1_bounds[limb].clone());
                for coefficient in inputs.p1is.limb(limb).coefficients() {
                    assert!(
                        coefficient.abs() <= p1_bound,
                        "{preset:?} p1 limb {limb} coefficient {coefficient} exceeds {p1_bound}"
                    );
                }

                let low = BigInt::from(bounds.r1_low_bounds[limb].clone());
                let up = BigInt::from(bounds.r1_up_bounds[limb].clone());
                for coefficient in inputs.r1is.limb(limb).coefficients() {
                    assert!(
                        -&low <= *coefficient && *coefficient <= up,
                        "{preset:?} r1 limb {limb} coefficient {coefficient} exceeds [-{low}, {up}]"
                    );
                }

                // The ct commit circuits pin both legs to the centered residue.
                let half: BigInt = (BigInt::from(*qi) - 1) / 2;
                let neg_half: BigInt = -half.clone();
                for ct in [inputs.ct0is.limb(limb), inputs.ct1is.limb(limb)] {
                    for coefficient in ct.coefficients() {
                        assert!(
                            neg_half <= *coefficient && *coefficient <= half,
                            "{preset:?} ct limb {limb} coefficient {coefficient} is not centered"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn secure_8192_sample_fits_user_data_encryption_bounds() {
        let config = Configs::for_preset(BfvPreset::SecureThreshold8192).unwrap();
        let sample = generate(&config.params).unwrap();
        let inputs = prepare(BfvPreset::SecureThreshold8192, &sample).unwrap();
        let bounds = config.bounds;

        for (limb_index, (limb, (low, up))) in inputs
            .r1is
            .limbs
            .iter()
            .zip(bounds.r1_low_bounds.iter().zip(bounds.r1_up_bounds.iter()))
            .enumerate()
        {
            let low = BigInt::from(low.clone());
            let up = BigInt::from(up.clone());
            for coefficient in limb.coefficients() {
                assert!(
                    -&low <= *coefficient && *coefficient <= up,
                    "r1 limb {limb_index} coefficient {coefficient} exceeds [-{low}, {up}]"
                );
            }
        }
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let constants = Configs::for_preset(BfvPreset::InsecureThreshold).unwrap();
        let json = serde_json::json!({"n": constants.n, "l": constants.l, "moduli": constants.moduli, "bits": constants.bits, "bounds": constants.bounds});
        let bits: e3_zk_config::threshold::user_data_encryption_chunked::Bits =
            serde_json::from_value(json["bits"].clone()).unwrap();
        let bounds: e3_zk_config::threshold::user_data_encryption_chunked::Bounds =
            serde_json::from_value(json["bounds"].clone()).unwrap();
        assert_eq!(json["n"], constants.n);
        assert_eq!(json["l"], constants.l);
        assert_eq!(bits, constants.bits);
        assert_eq!(bounds, constants.bounds);
    }

    fn prepare(
        _preset: BfvPreset,
        data: &UserDataEncryptionCircuitData,
    ) -> Result<Inputs, WitnessError> {
        let config = Configs::new(&data.public_key.params)?;
        let (ct, intermediates) = e3_zk_witness::encrypt_with_intermediates(
            &data.public_key,
            &data.plaintext,
            &mut rand::rng(),
        )?;
        Inputs::compute(&config, data, &ct, &intermediates)
    }

    fn negacyclic_mul(
        a: &Polynomial,
        b: &Polynomial,
        n: usize,
    ) -> Result<Polynomial, WitnessError> {
        let product = a.mul(b);
        let mut coefficients = vec![BigInt::from(0); 2 * n - 1];
        let offset = coefficients.len() - product.coefficients().len();
        coefficients[offset..].clone_from_slice(product.coefficients());
        for i in 0..n - 1 {
            let leading = coefficients[i].clone();
            coefficients[i + n] -= leading;
        }
        Ok(Polynomial::new(coefficients[n - 1..].to_vec()))
    }
}
