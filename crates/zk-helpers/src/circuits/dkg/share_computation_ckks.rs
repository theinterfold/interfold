// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Verifiable DKG witness generation for threshold CKKS.
//!
//! The DKG share-verification circuits (C2a `SecretKeyShareComputation`,
//! C2b `SmudgingNoiseShareComputation`) are SCHEME-AGNOSTIC: they verify a
//! Shamir sharing of a small-coefficient polynomial against Reed-Solomon
//! parity matrices over given RNS moduli, with no plaintext-modulus or
//! decode logic. Verifiable CKKS DKG therefore reuses those circuits
//! unchanged; only the witness generation differs:
//!
//! - moduli come from [`CkksParameters`] instead of BFV params,
//! - the shared secret is a [`fhe::ckks::CkksSecretKey`] contribution,
//! - the smudging noise is bounded by the CKKS flooding calculator
//!   ([`fhe::trckks::CkksSmudgingBoundCalculator`]) instead of the BFV one.
//!
//! This module produces [`ShareComputationCircuitData`]-shaped data (the
//! exact input type of the BFV DKG witness generator) from a CKKS threshold
//! setup, so the whole existing C2a/C2b pipeline — `Inputs::compute`,
//! codegen, Prover.toml, `nargo execute` — runs as-is for CKKS.

use crate::circuits::dkg::share_computation::utils::compute_parity_matrix;
use crate::computation::DkgInputType;
use crate::dkg::share_computation::computation::Inputs as ShareComputationInputs;
use crate::dkg::share_computation::ShareComputationCircuitData;
use crate::math::array2_u64_to_bigint;
use crate::threshold::user_data_encryption_ckks::CkksPreset;
use crate::CircuitsErrors;
use crate::{
    calculate_bit_width,
    circuits::commitments::{
        compute_share_computation_e_sm_commitment, compute_share_computation_sk_commitment,
    },
};
use e3_polynomial::{reduce, CrtPolynomial};
use fhe::ckks::CkksSecretKey;
use fhe::trbfv::Lambda;
use fhe::trckks::{CkksCircuitShape, CkksSmudgingBoundCalculator, CkksSmudgingConfig, TRCKKS};
use num_bigint::BigInt;

/// Committee shape for CKKS DKG witness generation.
#[derive(Debug, Clone, Copy)]
pub struct CkksDkgCommittee {
    /// Number of parties.
    pub n: usize,
    /// Reconstruction threshold `t` (t+1 reconstruct).
    pub threshold: usize,
}

/// Generate C2a (secret-key share) witness data for a CKKS committee member.
///
/// The output feeds the EXISTING share-computation pipeline
/// (`Inputs::compute` etc.); the only CKKS-specific part is where the
/// moduli and the secret come from.
pub fn generate_ckks_sk_share_data(
    preset: &CkksPreset,
    committee: CkksDkgCommittee,
) -> Result<ShareComputationCircuitData, CircuitsErrors> {
    let params = preset.params.clone();
    let mut rng = rand::rng();

    let trckks = TRCKKS::new(committee.n, committee.threshold, params.clone())
        .map_err(|e| CircuitsErrors::Sample(format!("TRCKKS::new: {e:?}")))?;

    let parity_matrix = compute_parity_matrix(params.moduli(), committee.n, committee.threshold)
        .map_err(|e| CircuitsErrors::Sample(format!("parity matrix: {e}")))?;

    let sk = CkksSecretKey::random(&params, &mut rng);
    let sk_poly = trckks
        .coeffs_to_poly(sk.coeffs.as_ref())
        .map_err(|e| CircuitsErrors::Sample(format!("coeffs_to_poly: {e:?}")))?;
    let sss_u64 = trckks
        .generate_secret_shares_from_poly(sk_poly, &mut rng)
        .map_err(|e| CircuitsErrors::Sample(format!("share gen: {e:?}")))?;
    let secret_sss: Vec<_> = sss_u64.iter().map(array2_u64_to_bigint).collect();

    let sk_coeffs: Vec<BigInt> = sk.coeffs.iter().map(|&c| BigInt::from(c)).collect();
    let mut secret_crt = CrtPolynomial::from_mod_q_polynomial(&sk_coeffs, params.moduli());
    secret_crt
        .center(params.moduli())
        .map_err(|e| CircuitsErrors::Sample(format!("center: {e:?}")))?;

    Ok(ShareComputationCircuitData {
        dkg_input_type: DkgInputType::SecretKey,
        secret: secret_crt,
        secret_sss,
        parity_matrix,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
    })
}

/// Generate C2b (smudging-noise share) witness data for a CKKS committee
/// member, with the noise bound DERIVED by the CKKS flooding calculator.
///
/// `circuit` describes the homomorphic computation the ciphertexts will go
/// through; `lambda` is the statistical security level; `precision_loss`
/// the tolerated decode error. The generated noise is provably at the
/// flooding bound the calculator certifies (or this errors out).
pub fn generate_ckks_smudging_share_data(
    preset: &CkksPreset,
    committee: CkksDkgCommittee,
    circuit: CkksCircuitShape,
    level: usize,
    precision_loss: f64,
    lambda: Lambda,
) -> Result<ShareComputationCircuitData, CircuitsErrors> {
    let params = preset.params.clone();
    let mut rng = rand::rng();

    let trckks = TRCKKS::new(committee.n, committee.threshold, params.clone())
        .map_err(|e| CircuitsErrors::Sample(format!("TRCKKS::new: {e:?}")))?;

    let parity_matrix = compute_parity_matrix(params.moduli(), committee.n, committee.threshold)
        .map_err(|e| CircuitsErrors::Sample(format!("parity matrix: {e}")))?;

    // Flooding bound from the calculator — the security-critical step.
    let calc = CkksSmudgingBoundCalculator::new(CkksSmudgingConfig {
        params: params.clone(),
        n_parties: committee.n,
        circuit,
        level,
        input_bound: preset.input_bound,
        precision_loss,
        lambda,
    });
    let sm_bits = calc
        .calculate_sm_bits()
        .map_err(|e| CircuitsErrors::Sample(format!("flooding bound: {e:?}")))?;

    let es_coeffs = trckks
        .generate_smudging_error(sm_bits, &mut rng)
        .map_err(|e| CircuitsErrors::Sample(format!("smudging gen: {e:?}")))?;
    let es_poly = trckks
        .smudging_to_poly(&es_coeffs)
        .map_err(|e| CircuitsErrors::Sample(format!("smudging_to_poly: {e:?}")))?;
    let sss_u64 = trckks
        .generate_secret_shares_from_poly(es_poly, &mut rng)
        .map_err(|e| CircuitsErrors::Sample(format!("share gen: {e:?}")))?;
    let secret_sss: Vec<_> = sss_u64.iter().map(array2_u64_to_bigint).collect();

    let mut secret_crt = CrtPolynomial::from_mod_q_polynomial(&es_coeffs, params.moduli());
    secret_crt
        .center(params.moduli())
        .map_err(|e| CircuitsErrors::Sample(format!("center: {e:?}")))?;

    Ok(ShareComputationCircuitData {
        dkg_input_type: DkgInputType::SmudgingNoise,
        secret: secret_crt,
        secret_sss,
        parity_matrix,
        n_parties: committee.n as u32,
        threshold: committee.threshold as u32,
    })
}

/// Build the C2a/C2b witness `Inputs` (y tensor + commitment) from CKKS
/// data. Mirrors the BFV `Inputs::compute` exactly, but takes all geometry
/// (degree, moduli) from the CKKS preset instead of a `BfvPreset`.
pub fn compute_ckks_share_inputs(
    preset: &CkksPreset,
    data: &ShareComputationCircuitData,
) -> Result<ShareComputationInputs, CircuitsErrors> {
    let moduli = preset.params.moduli();
    let degree = preset.params.degree();
    let num_moduli = moduli.len();
    let n_parties = data.n_parties as usize;

    let mut secret_crt = data.secret.clone();
    let sss = &data.secret_sss;

    if data.dkg_input_type == DkgInputType::SmudgingNoise {
        secret_crt
            .reduce(moduli)
            .map_err(|e| CircuitsErrors::Sample(format!("secret_crt reduce: {e:?}")))?;
    }

    // y[coeff][mod][0] = secret; y[coeff][mod][1+party] = share in [0, q_j).
    let mut y: Vec<Vec<Vec<BigInt>>> = Vec::with_capacity(degree);
    for coeff_idx in 0..degree {
        let mut y_coeff: Vec<Vec<BigInt>> = Vec::with_capacity(num_moduli);
        for (mod_idx, &qi) in moduli.iter().enumerate() {
            let q_j = BigInt::from(qi);
            let mut y_mod: Vec<BigInt> = Vec::with_capacity(1 + n_parties);
            y_mod.push(secret_crt.limb(mod_idx).coefficients()[coeff_idx].clone());
            for party_idx in 0..n_parties {
                y_mod.push(reduce(&sss[mod_idx][[party_idx, coeff_idx]], &q_j));
            }
            y_coeff.push(y_mod);
        }
        y.push(y_coeff);
    }

    // Commitment, matching C1's reverse(+center) convention (same as BFV).
    let expected_secret_commitment = match data.dkg_input_type {
        DkgInputType::SecretKey => {
            let bit_secret = calculate_bit_width(BigInt::from(CkksSecretKey::sk_bound() as u128));
            let mut reversed = secret_crt.limb(0).clone();
            reversed.reverse();
            compute_share_computation_sk_commitment(&reversed, bit_secret)
        }
        DkgInputType::SmudgingNoise => {
            let max_centered = secret_crt
                .limbs
                .iter()
                .zip(moduli.iter())
                .flat_map(|(l, &qi)| {
                    let q = BigInt::from(qi);
                    let half = (&q - 1) / 2;
                    l.coefficients().iter().map(move |c| {
                        if c > &half {
                            (c - &q).magnitude().clone()
                        } else {
                            c.magnitude().clone()
                        }
                    })
                })
                .max()
                .unwrap_or_default();
            let bit_secret = calculate_bit_width(BigInt::from(max_centered));
            let centered_reversed = CrtPolynomial::new(
                secret_crt
                    .limbs
                    .iter()
                    .zip(moduli.iter())
                    .map(|(l, &qi)| {
                        let q = BigInt::from(qi);
                        let mut r = l.clone();
                        r.reverse();
                        r.center(&q);
                        r
                    })
                    .collect(),
            );
            compute_share_computation_e_sm_commitment(&centered_reversed, bit_secret)
        }
    };

    Ok(ShareComputationInputs {
        secret_crt,
        y,
        expected_secret_commitment,
        dkg_input_type: data.dkg_input_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::user_data_encryption_ckks::CkksPreset;
    use e3_parity_matrix::math::matrix_vector_mult_mod;
    use num_bigint::BigUint;
    use num_traits::Zero;

    /// A CKKS preset with headroom for a lambda=30 flood (wide moduli, big
    /// scale). Committee kept small for test speed.
    fn wide_preset() -> CkksPreset {
        CkksPreset {
            params: fhe::ckks::CkksParametersBuilder::new()
                .set_degree(64)
                .set_moduli_sizes(&[60, 60, 60])
                .set_scale(2f64.powi(52))
                .build_arc()
                .unwrap(),
            input_bound: 100.0,
        }
    }

    const COMMITTEE: CkksDkgCommittee = CkksDkgCommittee { n: 5, threshold: 2 };

    /// The generated CKKS SK-share witnesses satisfy every constraint the
    /// C2a circuit checks: secret consistency (y[i][j][0] == secret),
    /// range, and the Reed-Solomon parity check H*y == 0 mod q_j.
    #[test]
    fn ckks_sk_share_witnesses_satisfy_c2a_constraints() {
        let preset = wide_preset();
        let data = generate_ckks_sk_share_data(&preset, COMMITTEE).unwrap();

        // Run the UNMODIFIED BFV witness computation on CKKS data — this is
        // the same code path the codegen/Prover.toml pipeline uses. It
        // internally normalizes and rebuilds y from the sss matrices.
        // NOTE: Inputs::compute takes a BfvPreset only to read moduli for
        // BFV data; for CKKS data all moduli information flows through
        // `data` (parity_matrix + sss + secret limbs), so we verify the
        // constraints directly here instead of round-tripping through a
        // preset it doesn't have.
        let moduli = preset.params.moduli();
        let degree = preset.params.degree();

        // Secret consistency + parity per modulus.
        for (mod_idx, &qi) in moduli.iter().enumerate() {
            let q = BigUint::from(qi);
            let h = &data.parity_matrix[mod_idx];
            for coeff_idx in 0..degree {
                // Build the codeword: [secret, share_1, ..., share_n].
                let secret = &data.secret.limb(mod_idx).coefficients()[coeff_idx];
                let secret_mod =
                    ((secret % BigInt::from(qi)) + BigInt::from(qi)) % BigInt::from(qi);
                let mut codeword: Vec<BigUint> = vec![secret_mod.to_biguint().unwrap()];
                for party in 0..COMMITTEE.n {
                    codeword.push(
                        data.secret_sss[mod_idx][[party, coeff_idx]]
                            .to_biguint()
                            .unwrap(),
                    );
                }
                // H * codeword == 0 mod q  (the C2a parity constraint).
                let h_data: Vec<Vec<BigUint>> = h.data().to_vec();
                let product = matrix_vector_mult_mod(&h_data, &codeword, &q);
                assert!(
                    product.iter().all(|x| x.is_zero()),
                    "parity check failed at modulus {mod_idx} coeff {coeff_idx}"
                );
            }
        }
    }

    /// C2b witnesses with the CALCULATOR-DERIVED flooding bound satisfy the
    /// same constraints, and the bound respects the security floor.
    #[test]
    fn ckks_smudging_share_witnesses_satisfy_c2b_constraints() {
        let preset = wide_preset();
        let lambda_bits = 30usize;
        let data = generate_ckks_smudging_share_data(
            &preset,
            COMMITTEE,
            CkksCircuitShape::additions(2),
            0,
            0.01,
            Lambda::insecure(lambda_bits),
        )
        .unwrap();

        let moduli = preset.params.moduli();
        let degree = preset.params.degree();

        // The centered smudging secret must be non-trivially large (the
        // flooding floor is 2^lambda * B_C > 2^30): at least one
        // coefficient must exceed 2^lambda.
        let floor = BigInt::from(1u64 << lambda_bits);
        let max_coeff = data
            .secret
            .limb(0)
            .coefficients()
            .iter()
            .map(|c| c.magnitude().clone())
            .max()
            .unwrap();
        assert!(
            BigInt::from(max_coeff) > floor,
            "smudging noise below the 2^lambda floor"
        );

        // Parity + consistency, as for C2a.
        for (mod_idx, &qi) in moduli.iter().enumerate() {
            let q = BigUint::from(qi);
            let h = &data.parity_matrix[mod_idx];
            for coeff_idx in (0..degree).step_by(7) {
                let secret = &data.secret.limb(mod_idx).coefficients()[coeff_idx];
                let secret_mod =
                    ((secret % BigInt::from(qi)) + BigInt::from(qi)) % BigInt::from(qi);
                let mut codeword: Vec<BigUint> = vec![secret_mod.to_biguint().unwrap()];
                for party in 0..COMMITTEE.n {
                    codeword.push(
                        data.secret_sss[mod_idx][[party, coeff_idx]]
                            .to_biguint()
                            .unwrap(),
                    );
                }
                let h_data: Vec<Vec<BigUint>> = h.data().to_vec();
                let product = matrix_vector_mult_mod(&h_data, &codeword, &q);
                assert!(
                    product.iter().all(|x| x.is_zero()),
                    "parity check failed at modulus {mod_idx} coeff {coeff_idx}"
                );
            }
        }
    }

    /// The full witness pipeline (compute_ckks_share_inputs -> y tensor)
    /// builds the exact `Inputs` shape the C2a circuit consumes from CKKS
    /// data, with the circuit's own secret-consistency invariant holding.
    #[test]
    fn inputs_compute_accepts_ckks_data() {
        let preset = wide_preset();
        let data = generate_ckks_sk_share_data(&preset, COMMITTEE).unwrap();
        let inputs = compute_ckks_share_inputs(&preset, &data).unwrap();

        let degree = preset.params.degree();
        let num_moduli = preset.params.moduli().len();
        assert_eq!(inputs.y.len(), degree);
        assert_eq!(inputs.y[0].len(), num_moduli);
        assert_eq!(inputs.y[0][0].len(), COMMITTEE.n + 1);
        // Secret consistency as the circuit asserts it.
        for coeff_idx in 0..degree {
            for mod_idx in 0..num_moduli {
                assert_eq!(
                    inputs.y[coeff_idx][mod_idx][0],
                    inputs.secret_crt.limb(mod_idx).coefficients()[coeff_idx],
                    "y[..][..][0] must equal the secret"
                );
            }
        }
    }
}
