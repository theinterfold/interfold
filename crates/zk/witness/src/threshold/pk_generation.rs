// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit input data, witness preparation, and canonical Noir encoding.

use crate::encoding::crt_polynomial_to_toml_json;
use crate::encoding::polynomial_to_toml_json;
use crate::negacyclic::{exact_reduction_quotient, product_for_fold};
use crate::WitnessError;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use e3_zk_config::threshold::pk_generation::crp::deterministic_crp_crt_polynomial;
use e3_zk_config::threshold::pk_generation::Configs;
use num_bigint::BigInt;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct PkGenerationCircuitData {
    pub pk0_share: CrtPolynomial,
    pub eek: CrtPolynomial,
    pub e_sm: CrtPolynomial,
    /// Smudging noise reconstructed modulo Q, before centering. C1 range-checks this against
    /// `e_sm_bound`; the CRT limbs in `e_sm` cannot carry that bound because it exceeds every q_i.
    pub e_sm_lifted: Polynomial,
    pub sk: CrtPolynomial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub eek: Polynomial,
    pub sk: Polynomial,
    pub e_sm: CrtPolynomial,
    pub e_sm_lifted: Polynomial,
    pub e_sm_quotients: CrtPolynomial,
    pub ris: CrtPolynomial,
    pub pk0is: CrtPolynomial,
}

impl Inputs {
    pub fn compute(config: &Configs, data: &PkGenerationCircuitData) -> Result<Self, WitnessError> {
        let threshold_params = &config.params;
        for (name, value) in [
            ("pk0_share", &data.pk0_share),
            ("eek", &data.eek),
            ("e_sm", &data.e_sm),
            ("sk", &data.sk),
        ] {
            crate::validation::crt(name, value, threshold_params)?;
        }
        crate::validation::polynomial("e_sm_lifted", &data.e_sm_lifted, threshold_params.degree())?;

        let n = threshold_params.degree();
        let l = threshold_params.moduli().len();
        let a = deterministic_crp_crt_polynomial(&threshold_params)?;
        crate::encoding::verify_crt_shapes(
            &[&data.pk0_share, &a, &data.eek, &data.e_sm, &data.sk],
            l,
            n,
        )
        .map_err(|e| WitnessError::Other(format!("C1 CRT shape mismatch: {e}")))?;

        let moduli = threshold_params.moduli();
        let n = threshold_params.degree() as u64;

        // Smudging noise over the integers, in the same reversed+centered layout as the limbs.
        let ctx = threshold_params.context_at_level(0)?;
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let mut e_sm_lifted = data.e_sm_lifted.clone();
        e_sm_lifted.reverse();
        e_sm_lifted.center(&modulus_q);

        // Perform the main computation logic
        let results: Vec<(Polynomial, Polynomial, Polynomial, Polynomial)> = (
            moduli,
            &data.pk0_share.limbs,
            a.limbs,
            &data.eek.limbs,
            &data.e_sm.limbs,
            &data.sk.limbs,
        )
            .into_par_iter()
            .map(|(qi, pk0_share, a, eek, e_sm, sk)| {
                let qi = BigInt::from(*qi);
                let mut pk0_share = pk0_share.clone();
                let mut eek = eek.clone();
                let mut e_sm = e_sm.clone();
                let mut sk = sk.clone();
                pk0_share.reverse();
                pk0_share.center(&qi);

                eek.reverse();
                eek.center(&qi);

                e_sm.reverse();
                e_sm.center(&qi);

                sk.reverse();
                sk.center(&qi);

                // Calculate pk0_share_hat = -a * sk + eek
                let pk0_share_hat = {
                    let mut exp = a.neg();
                    exp = product_for_fold(&exp, &sk, n as usize);

                    assert_eq!((exp.coefficients().len() as u64) - 1, 2 * (n - 1));

                    exp.add(&eek)
                };

                assert_eq!((pk0_share_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

                // The circuit checks the identity reduced modulo X^N + 1, so the cyclotomic quotient's
                // term is identically zero and `r2` is gone. `r` is then pinned by the identity itself:
                //   pk0i == (-(a * sk) + eek mod X^N + 1) + qi * r
                // so folding the already-computed `pk0_share_hat` and dividing gives `r` directly.
                let (reduced_hat, r) =
                    exact_reduction_quotient(&pk0_share, &pk0_share_hat, n as usize, &qi)?;

                // Check the derived witness against the integer identity.
                assert!(
                pk0_share
                    .sub(&reduced_hat.add(&r.scalar_mul(&qi)))
                    .is_zero(),
                "reduced pk0 identity must hold: pk0i == -(a * sk) + eek + qi * r (mod X^N + 1)"
            );

                // e_sm_quotient = (e_sm_lifted - e_sm[i]) / q_i, the witness the circuit uses to tie
                // the committed residue back to the bounded lifted value.
                let diff = e_sm_lifted.sub(&e_sm);
                let e_sm_quotient = diff.div_exact(&qi)?;

                Ok((r, pk0_share, e_sm, e_sm_quotient))
            })
            .collect::<Result<Vec<_>, WitnessError>>()?;

        let mut r = CrtPolynomial::new(vec![]);
        let mut pk0_share = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);
        let mut e_sm_quotients = CrtPolynomial::new(vec![]);

        let mut sk = data.sk.limbs[0].clone();
        let mut eek = data.eek.limbs[0].clone();

        sk.reverse();
        sk.center(&BigInt::from(moduli[0]));
        eek.reverse();
        eek.center(&BigInt::from(moduli[0]));

        for (ri, pk0_sharei, e_smi, e_sm_quotienti) in results {
            r.add_limb(ri);
            pk0_share.add_limb(pk0_sharei);
            e_sm.add_limb(e_smi);
            e_sm_quotients.add_limb(e_sm_quotienti);
        }

        Ok(Inputs {
            eek,
            sk,
            e_sm,
            e_sm_lifted,
            e_sm_quotients,
            ris: r,
            pk0is: pk0_share,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "eek": polynomial_to_toml_json(&self.eek),
            "sk": polynomial_to_toml_json(&self.sk),
            "e_sm": crt_polynomial_to_toml_json(&self.e_sm),
            "e_sm_lifted": polynomial_to_toml_json(&self.e_sm_lifted),
            "e_sm_quotients": crt_polynomial_to_toml_json(&self.e_sm_quotients),
            "ris": crt_polynomial_to_toml_json(&self.ris),
        })
    }
}

#[cfg(test)]
mod tests {
    use e3_fhe_params::build_pair_for_preset;
    use e3_fhe_params::BfvPreset;
    use e3_zk_config::threshold::pk_generation::Configs;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let preset = BfvPreset::InsecureThreshold;
        use e3_committee::CiphernodesCommitteeSize;
        let config = Configs::for_preset(preset, CiphernodesCommitteeSize::Micro).unwrap();
        let bits = &config.bits;

        // pk_bit uses compute_modulus_bit: (max(qi) - 1) / 2 for centered representation
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let expected_bit = e3_fhe_params::utils::compute_modulus_bit(&threshold_params);

        assert_eq!(bits.pk_bit, expected_bit);
    }
}
mod lbfv;
pub use lbfv::*;
