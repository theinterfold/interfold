// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C8-CKKS (HYBRID gadget), PER-DIGIT split: witness builder for the Noir
//! circuit `relin_round1_hybrid_ckks_digit`.
//!
//! The whole-share proof ([`super::relin_round1_hybrid_ckks`]) needs
//! `D * LT` rows in ONE statement — 13 × 41 = 533 rows at the ParamSet-2
//! shape, which OOMs `nargo compile`. This module proves ONE gadget digit
//! per proof (its `LT` rows) and binds the `D` proofs by the PUBLIC
//! `s`/`u` commitments (`compute_share_computation_sk_commitment`, the
//! same values the whole-share circuit outputs). The digit index is a
//! public input; the circuit reads that digit's gadget row from the
//! config table, so the `D` proofs cover the whole share with no row
//! chosen by the prover.
//!
//! Verifier contract for one party's share: `D` proofs, all with the same
//! `(s_commitment, u_commitment)`, digits `0..D` each exactly once, and
//! per-digit `share_commitment` outputs equal to
//! `compute_ciphertext_commitment(h0[j], h1[j], BIT_H)` over the published
//! share ([`digit_share_commitment`]).

use crate::circuits::commitments::{
    compute_ciphertext_commitment, compute_share_computation_sk_commitment,
};
use crate::circuits::computation::Computation;
use crate::circuits::errors::CircuitsErrors;
use crate::circuits::threshold::relin_round1_hybrid_ckks::{
    gadget_matrix, qp_moduli, qp_to_crt, Bits, Bounds, CkksHybridRelinRound1Data, Configs,
};
use crate::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use crate::crt_polynomial_to_toml_json;
use crate::polynomial_to_toml_json;
use crate::{cyclotomic_polynomial, decompose_residue};
use e3_polynomial::{CrtPolynomial, Polynomial};
use num_bigint::BigInt;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};

/// Circuit identifier for the per-digit CKKS hybrid relin round-1 proof
/// (Noir circuit `relin_round1_hybrid_ckks_digit`).
#[derive(Debug)]
pub struct CkksHybridRelinRound1DigitCircuit;

impl crate::registry::Circuit for CkksHybridRelinRound1DigitCircuit {
    const NAME: &'static str = "relin-round1-hybrid-ckks-digit";
    const PREFIX: &'static str = "RELIN_ROUND1_HYBRID_CKKS";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// The per-digit circuit witness. All `LT`-limb `CrtPolynomial`s are in
/// the `Q·P` limb order of digit `digit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitInputs {
    pub digit: usize,
    pub a: CrtPolynomial,
    pub s: Polynomial,
    pub u: Polynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub r1_h0: CrtPolynomial,
    pub r2_h0: CrtPolynomial,
    pub r1_h1: CrtPolynomial,
    pub r2_h1: CrtPolynomial,
    pub h0: CrtPolynomial,
    pub h1: CrtPolynomial,
    pub s_commitment: BigInt,
    pub u_commitment: BigInt,
    pub share_commitment: BigInt,
}

fn small_poly(coeffs: &[i64]) -> Polynomial {
    let mut c: Vec<BigInt> = coeffs.iter().map(|&x| BigInt::from(x)).collect();
    c.reverse();
    Polynomial::new(c)
}

impl DigitInputs {
    /// Prover.toml JSON (public inputs first, in the circuit's `main` order).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "s_commitment": self.s_commitment.to_string(),
            "u_commitment": self.u_commitment.to_string(),
            "digit": self.digit.to_string(),
            "a": crt_polynomial_to_toml_json(&self.a),
            "s": polynomial_to_toml_json(&self.s),
            "u": polynomial_to_toml_json(&self.u),
            "e0": polynomial_to_toml_json(&self.e0),
            "e1": polynomial_to_toml_json(&self.e1),
            "r1_h0": crt_polynomial_to_toml_json(&self.r1_h0),
            "r2_h0": crt_polynomial_to_toml_json(&self.r2_h0),
            "r1_h1": crt_polynomial_to_toml_json(&self.r1_h1),
            "r2_h1": crt_polynomial_to_toml_json(&self.r2_h1),
            "h0": crt_polynomial_to_toml_json(&self.h0),
            "h1": crt_polynomial_to_toml_json(&self.h1),
        })
    }
}

/// Build the witness of digit `digit` of one party's round-1 share (the
/// `LT` rows `h0[digit][l]`, `h1[digit][l]`), with the native congruence
/// pre-check of the whole-share builder.
pub fn compute_digit_inputs(
    preset: &CkksPreset,
    data: &CkksHybridRelinRound1Data,
    digit: usize,
) -> Result<DigitInputs, CircuitsErrors> {
    let params = &preset.params;
    let moduli_u64 = qp_moduli(params)?;
    let moduli: Vec<BigInt> = moduli_u64.iter().copied().map(BigInt::from).collect();
    let l = params.moduli().len();
    let lt = moduli.len();
    let d = params.dnum();
    let n = params.degree() as u64;
    let nn = n as usize;

    if digit >= d {
        return Err(CircuitsErrors::Other(format!(
            "digit {digit} out of range (dnum = {d})"
        )));
    }
    if data.crp.len() != d
        || data.share.h0().len() != d
        || data.share.h1().len() != d
        || data.e0_coeffs.len() != d
        || data.e1_coeffs.len() != d
    {
        return Err(CircuitsErrors::Other(format!(
            "C8-CKKS hybrid needs one CRP/h0/h1/e0/e1 per gadget digit (dnum = {d})"
        )));
    }
    for c in [
        &data.sk_coeffs,
        &data.u_coeffs,
        &data.e0_coeffs[digit],
        &data.e1_coeffs[digit],
    ] {
        if c.len() != nn {
            return Err(CircuitsErrors::Other(
                "C8-CKKS hybrid secret polynomials must have N coefficients".to_string(),
            ));
        }
    }

    let gadget = gadget_matrix(params)?;
    let cyclo = cyclotomic_polynomial(n);
    let s_poly = small_poly(&data.sk_coeffs);
    let u_poly = small_poly(&data.u_coeffs);
    let e0_poly = small_poly(&data.e0_coeffs[digit]);
    let e1_poly = small_poly(&data.e1_coeffs[digit]);

    let a_crt = qp_to_crt(&data.crp[digit], &moduli_u64, l)?;
    let h0_crt = qp_to_crt(&data.share.h0()[digit], &moduli_u64, l)?;
    let h1_crt = qp_to_crt(&data.share.h1()[digit], &moduli_u64, l)?;

    let native_check = |lhs: &Polynomial,
                        hat: &Polynomial,
                        ql: &BigInt,
                        limb: usize,
                        leg: &str|
     -> Result<(), CircuitsErrors> {
        let mut nat = hat.coefficients().to_vec();
        nat.reverse();
        nat.resize(2 * nn, BigInt::from(0));
        for ii in (nn..2 * nn).rev() {
            let c = nat[ii].clone();
            nat[ii] = BigInt::from(0);
            nat[ii - nn] -= c;
        }
        nat.truncate(nn);
        let mut lhs_nat = lhs.coefficients().to_vec();
        lhs_nat.reverse();
        for (ii, (x, y)) in nat.iter().zip(lhs_nat.iter()).enumerate() {
            if (((x - y) % ql) + ql) % ql != BigInt::from(0) {
                return Err(CircuitsErrors::Other(format!(
                    "C8-CKKS hybrid share inconsistent at digit {digit} limb {limb} coeff {ii}: \
                     {leg} relation does not hold (mod q)"
                )));
            }
        }
        Ok(())
    };

    #[allow(clippy::type_complexity)]
    let mut results: Vec<
        Result<(usize, Polynomial, Polynomial, Polynomial, Polynomial), CircuitsErrors>,
    > = (0..lt)
        .par_bridge()
        .map(|limb| {
            let ql = &moduli[limb];
            let g_jl = &gadget[digit * lt + limb];
            let a_limb = a_crt.limb(limb);
            let h0_limb = h0_crt.limb(limb);
            let h1_limb = h1_crt.limb(limb);

            let h0_hat = a_limb
                .neg()
                .mul(&u_poly)
                .add(&s_poly.scalar_mul(g_jl))
                .add(&e0_poly);
            native_check(h0_limb, &h0_hat, ql, limb, "h0")?;
            let (r1_h0, r2_h0) = decompose_residue(h0_limb, &h0_hat, ql, &cyclo, n);

            let h1_hat = a_limb.mul(&s_poly).add(&e1_poly);
            native_check(h1_limb, &h1_hat, ql, limb, "h1")?;
            let (r1_h1, r2_h1) = decompose_residue(h1_limb, &h1_hat, ql, &cyclo, n);
            Ok((limb, r1_h0, r2_h0, r1_h1, r2_h1))
        })
        .collect();
    results.sort_by_key(|r| r.as_ref().map(|(i, ..)| *i).unwrap_or(usize::MAX));

    let mut r1_h0 = CrtPolynomial::new(vec![]);
    let mut r2_h0 = CrtPolynomial::new(vec![]);
    let mut r1_h1 = CrtPolynomial::new(vec![]);
    let mut r2_h1 = CrtPolynomial::new(vec![]);
    for r in results {
        let (_limb, a1, a2, b1, b2) = r?;
        r1_h0.add_limb(a1);
        r2_h0.add_limb(a2);
        r1_h1.add_limb(b1);
        r2_h1.add_limb(b2);
    }

    let bounds = Bounds::compute(preset.clone(), &())?;
    let bits = Bits::compute(preset.clone(), &bounds)?;
    let s_commitment = compute_share_computation_sk_commitment(&s_poly, bits.sk_bit);
    let u_commitment = compute_share_computation_sk_commitment(&u_poly, bits.u_bit);
    let share_commitment = compute_ciphertext_commitment(&h0_crt, &h1_crt, bits.h_bit);

    Ok(DigitInputs {
        digit,
        a: a_crt,
        s: s_poly,
        u: u_poly,
        e0: e0_poly,
        e1: e1_poly,
        r1_h0,
        r2_h0,
        r1_h1,
        r2_h1,
        h0: h0_crt,
        h1: h1_crt,
        s_commitment,
        u_commitment,
        share_commitment,
    })
}

/// The per-digit share commitment a VERIFIER recomputes from a published
/// share (no secrets): `compute_ciphertext_commitment(h0[digit], h1[digit],
/// BIT_H)`. Must equal the digit proof's public output.
pub fn digit_share_commitment(
    preset: &CkksPreset,
    share: &fhe::trckks::CkksHybridRelinKeyShare<fhe::trckks::R1>,
    digit: usize,
) -> Result<BigInt, CircuitsErrors> {
    let params = &preset.params;
    let moduli = qp_moduli(params)?;
    let l = params.moduli().len();
    let h0 = qp_to_crt(&share.h0()[digit], &moduli, l)?;
    let h1 = qp_to_crt(&share.h1()[digit], &moduli, l)?;
    let bounds = Bounds::compute(preset.clone(), &())?;
    let bits = Bits::compute(preset.clone(), &bounds)?;
    Ok(compute_ciphertext_commitment(&h0, &h1, bits.h_bit))
}

/// All `dnum` per-digit share commitments of a published round-1 share
/// (public bytes only), in digit order — what a VERIFIER recomputes from
/// the reassembled `RelinCeremonyShare` payload and compares with each
/// digit proof's `share_commitment` output. Big-endian 32-byte field
/// encoding (Barretenberg `public_signals`).
pub fn digit_share_commitments_from_bytes(
    preset: &CkksPreset,
    share_bytes: &[u8],
) -> Result<Vec<[u8; 32]>, CircuitsErrors> {
    let share = fhe::trckks::CkksHybridRelinKeyShare::<fhe::trckks::R1>::from_bytes(
        share_bytes,
        &preset.params,
    )
    .map_err(|e| CircuitsErrors::Other(format!("hybrid R1 share decode: {e}")))?;
    (0..preset.params.dnum())
        .map(|j| {
            let c = digit_share_commitment(preset, &share, j)?;
            let (_, be) = c.to_bytes_be();
            let mut out = [0u8; 32];
            let start = 32usize.saturating_sub(be.len());
            out[start..].copy_from_slice(&be[..be.len().min(32)]);
            Ok(out)
        })
        .collect()
}

/// All `D` digit witnesses of one share (one Prover.toml each).
pub fn compute_all_digit_inputs(
    preset: &CkksPreset,
    data: &CkksHybridRelinRound1Data,
) -> Result<Vec<DigitInputs>, CircuitsErrors> {
    (0..preset.params.dnum())
        .map(|j| compute_digit_inputs(preset, data, j))
        .collect()
}

/// Codegen: emits `circuits/lib/src/configs/ckks_relin_round1_hybrid_ps<N>.nr`
/// — the SAME constants/globals as the whole-share config (the per-digit
/// circuit reads the same `Configs<D, LT>` table), in a per-param-set module.
pub fn generate_configs_nr_for_param_set(param_set: u8, configs: &Configs) -> String {
    super::relin_round1_hybrid_ckks::generate_configs_nr(configs).replace(
        "// (example gen_ckks_c8_hybrid_prover). Do not hand-edit.",
        &format!(
            "// (example gen_ckks_c8_hybrid_digit_prover --param-set {param_set}). Do not hand-edit.\n\
             // CKKS on-chain ParamSet {param_set}: D={} digits x LT={} limbs of Q.P.",
            configs.d, configs.lt
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::threshold::relin_round1_hybrid_ckks::{
        compute_round_1_share, sample_round_1_secrets, Inputs as WholeInputs,
    };
    use fhe::ckks::{CkksParametersBuilder, CkksSecretKey};
    use fhe::trckks::CkksCrp;

    fn preset() -> CkksPreset {
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[45, 40, 40, 40])
            .set_special_moduli_sizes(&[60, 60])
            .set_scale(2f64.powi(40))
            .build_arc()
            .unwrap();
        CkksPreset {
            params,
            input_bound: 1000.0,
        }
    }

    fn data(preset: &CkksPreset) -> CkksHybridRelinRound1Data {
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let crp = CkksCrp::vec_from_seed_qp(&params, [3u8; 32]).unwrap();
        let (u, e0, e1) = sample_round_1_secrets(&params, &mut rng);
        let share = compute_round_1_share(&params, &crp, sk.coeffs.as_ref(), &u, &e0, &e1).unwrap();
        CkksHybridRelinRound1Data {
            crp,
            share,
            sk_coeffs: sk.coeffs.to_vec(),
            u_coeffs: u,
            e0_coeffs: e0,
            e1_coeffs: e1,
        }
    }

    /// The D digit witnesses are exactly the whole-share witness sliced
    /// per digit: same rows, same quotients, same s/u commitments; the
    /// per-digit share commitment matches the verifier-side recompute.
    #[test]
    fn digit_witnesses_slice_the_whole_share_witness() {
        let preset = preset();
        let data = data(&preset);
        let whole = WholeInputs::compute(preset.clone(), &data).unwrap();
        let digits = compute_all_digit_inputs(&preset, &data).unwrap();
        let lt = qp_moduli(&preset.params).unwrap().len();
        assert_eq!(digits.len(), preset.params.dnum());
        for (j, dj) in digits.iter().enumerate() {
            assert_eq!(dj.digit, j);
            assert_eq!(dj.s_commitment, whole.s_commitment);
            assert_eq!(dj.u_commitment, whole.u_commitment);
            assert_eq!(dj.e0, whole.e0.limbs[j]);
            assert_eq!(dj.e1, whole.e1.limbs[j]);
            for l in 0..lt {
                assert_eq!(dj.a.limb(l), whole.a.limb(j * lt + l));
                assert_eq!(dj.h0.limb(l), whole.h0.limb(j * lt + l));
                assert_eq!(dj.h1.limb(l), whole.h1.limb(j * lt + l));
                assert_eq!(dj.r1_h0.limb(l), whole.r1_h0.limb(j * lt + l));
                assert_eq!(dj.r2_h0.limb(l), whole.r2_h0.limb(j * lt + l));
                assert_eq!(dj.r1_h1.limb(l), whole.r1_h1.limb(j * lt + l));
                assert_eq!(dj.r2_h1.limb(l), whole.r2_h1.limb(j * lt + l));
            }
            assert_eq!(
                dj.share_commitment,
                digit_share_commitment(&preset, &data.share, j).unwrap()
            );
        }
        // Verifier-side recompute from the WIRE bytes matches every digit
        // witness output, in the 32-byte public-signal encoding.
        let from_bytes =
            digit_share_commitments_from_bytes(&preset, &data.share.to_bytes()).unwrap();
        assert_eq!(from_bytes.len(), preset.params.dnum());
        for (j, dj) in digits.iter().enumerate() {
            let (_, be) = dj.share_commitment.to_bytes_be();
            let mut expected = [0u8; 32];
            expected[32 - be.len()..].copy_from_slice(&be);
            assert_eq!(from_bytes[j], expected, "digit {j}");
        }
        assert!(digit_share_commitments_from_bytes(&preset, b"junk").is_err());
    }

    /// A tampered digit (flipped share coefficient in digit 1) is rejected
    /// for digit 1 only; digit 0 still verifies — and an out-of-range
    /// digit errors.
    #[test]
    fn tampered_digit_is_rejected_attributably() {
        let preset = preset();
        let mut bad = data(&preset);
        bad.e0_coeffs[1][7] += 1; // share was computed with the original e0
        assert!(compute_digit_inputs(&preset, &bad, 0).is_ok());
        let err = compute_digit_inputs(&preset, &bad, 1).unwrap_err();
        assert!(format!("{err:?}").contains("digit 1"), "{err:?}");
        assert!(compute_digit_inputs(&preset, &bad, 99).is_err());
    }
}
