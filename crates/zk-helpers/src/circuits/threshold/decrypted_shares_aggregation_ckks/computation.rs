// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounds, configs, bits, and input computation for the CKKS decrypted
//! shares aggregation circuit. Reuses the BFV aggregation `utils` (Lagrange
//! at zero, CRT reconstruction); drops the BFV decode-related fields
//! (delta/q_mod_t/q_inverse_mod_t) since CKKS has no modular decode.

use crate::calculate_bit_width;
use crate::circuits::commitments::compute_threshold_decryption_share_commitment;
use crate::get_zkp_modulus;
use crate::threshold::decrypted_shares_aggregation::utils;
use crate::threshold::decrypted_shares_aggregation_ckks::circuit::{
    DecryptedSharesAggregationCkksCircuit, DecryptedSharesAggregationCkksCircuitData,
};
use crate::threshold::share_decryption_ckks::moduli_at_level;
use crate::threshold::user_data_encryption_ckks::CkksPreset;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_polynomial::reduce;
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe_math::rq::{Poly, PowerBasis};
use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

/// Coefficient window the C7-CKKS circuit binds.
///
/// CKKS has NO sparse-message assumption: `u_global = Δ·m + e` occupies every
/// one of the N ring coefficients (slot encoding spreads each value over the
/// whole vector; coefficient encoding uses them directly). So the window is
/// the ring degree, and it MUST equal the width C6-CKKS hashes into
/// `d_commitment` (`SHARE_DECRYPTION_CKKS_N` = degree) or the C6→C7 link is
/// structurally broken: the two circuits would hash different windows of the
/// same share and `expected_d_commitments` could never match.
///
/// The BFV value (100) was inherited here and was wrong for CKKS: it bound
/// only 100 of 512 coefficients and produced a `d_commitment` C6 never emits.
pub fn max_msg_non_zero_coeffs_for(preset: &CkksPreset) -> usize {
    preset.params.degree()
}

/// Output of [`CircuitComputation::compute`].
#[derive(Debug)]
pub struct DecryptedSharesAggregationCkksComputationOutput {
    pub bits: Bits,
    pub inputs: Inputs,
}

impl CircuitComputation for DecryptedSharesAggregationCkksCircuit {
    type Preset = CkksPreset;
    type Data = DecryptedSharesAggregationCkksCircuitData;
    type Output = DecryptedSharesAggregationCkksComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bits = Bits::compute(preset.clone(), &())?;
        let inputs = Inputs::compute(preset, data)?;
        Ok(DecryptedSharesAggregationCkksComputationOutput { bits, inputs })
    }
}

/// Bit widths used by the circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bits {
    /// Native `[0, q_l)` width for hashing share coefficients (C6/C7-CKKS
    /// `d_commitment`).
    pub d_native_bit: u32,
}

impl Bits {
    /// Native width over the moduli that remain at `level`.
    pub fn compute_at_level(preset: &CkksPreset, level: usize) -> Result<Self, CircuitsErrors> {
        let mut d_native_bit = 0u32;
        for qi in moduli_at_level(preset, level)? {
            d_native_bit = d_native_bit.max(calculate_bit_width(BigInt::from(qi) - 1));
        }
        Ok(Bits { d_native_bit })
    }
}

impl Computation for Bits {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Level-0 width (the full chain); see [`Bits::compute_at_level`].
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        Bits::compute_at_level(&preset, 0)
    }
}

/// Circuit config: moduli plus bit widths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    /// Level the configs were derived at (`l` moduli remain there).
    pub level: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: Bits,
    pub max_msg_non_zero_coeffs: usize,
}

impl Configs {
    /// The circuit constants over the moduli that remain at `level` —
    /// the opening-level rule: C7 proves the reconstruction of shares
    /// computed over the OPENED ciphertext, whose limbs are those of its
    /// level, not the full chain.
    pub fn compute_at_level(preset: &CkksPreset, level: usize) -> Result<Self, CircuitsErrors> {
        let moduli = moduli_at_level(preset, level)?;
        let bits = Bits::compute_at_level(preset, level)?;
        Ok(Configs {
            level,
            l: moduli.len(),
            moduli,
            bits,
            max_msg_non_zero_coeffs: max_msg_non_zero_coeffs_for(preset),
        })
    }
}

impl Computation for Configs {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Level-0 constants (the full chain); see [`Configs::compute_at_level`].
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        Configs::compute_at_level(&preset, 0)
    }
}

/// Inputs for the CKKS aggregation circuit. Mirrors the BFV `Inputs` minus
/// `message` (the recovered `u_global` IS the public output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public `d` commitments (one per party), matching C6 outputs.
    pub expected_d_commitments: Vec<BigInt>,
    /// One CrtPolynomial per party (secret witness).
    pub decryption_shares: Vec<CrtPolynomial>,
    /// Party IDs (1-based).
    pub party_ids: Vec<BigInt>,
    /// The reconstructed ring element (public witness).
    pub u_global: Polynomial,
    /// CRT quotient polynomials per modulus (secret witnesses).
    pub crt_quotients: CrtPolynomial,
    /// E3 decryption domain words (public inputs; see circuit data).
    pub domain_hi: BigInt,
    pub domain_lo: BigInt,
}

fn truncate_to_max_coeffs(v: &[BigInt], max_len: usize) -> Vec<BigInt> {
    v.iter().take(max_len).cloned().collect()
}

fn truncate_crt_to_max_coeffs(crt: CrtPolynomial, max_len: usize) -> CrtPolynomial {
    let limbs = crt
        .limbs
        .iter()
        .map(|limb| Polynomial::new(truncate_to_max_coeffs(limb.coefficients(), max_len)))
        .collect();
    CrtPolynomial::new(limbs)
}

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = DecryptedSharesAggregationCkksCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let threshold = data.threshold;
        let max_msg_non_zero_coeffs = max_msg_non_zero_coeffs_for(&preset);

        let d_share_polys: Vec<Poly<PowerBasis>> = data.d_share_polys.clone();
        if d_share_polys.len() < threshold + 1 {
            return Err(CircuitsErrors::Other(format!(
                "d_share_polys.len() {} < threshold + 1 ({})",
                d_share_polys.len(),
                threshold + 1,
            )));
        }

        // The shares may be at a rescaled level: derive moduli/degree from
        // the share context itself, not from level 0.
        let share_ctx = d_share_polys[0].ctx();
        let moduli: Vec<u64> = share_ctx.moduli().to_vec();
        let num_moduli = moduli.len();
        let degree = share_ctx.degree;
        // The shares' level is the full chain minus the limbs they drop;
        // every width below (the `d_commitment` hash) comes from THAT
        // level's configs so C6 output == C7 input.
        let full = preset.params.moduli().len();
        if num_moduli == 0 || num_moduli > full {
            return Err(CircuitsErrors::Other(format!(
                "share context has {num_moduli} moduli; params have {full}"
            )));
        }
        let level = full - num_moduli;
        let configs = Configs::compute_at_level(&preset, level)?;
        if configs.moduli != moduli {
            return Err(CircuitsErrors::Other(format!(
                "share moduli are not the params' level-{level} chain"
            )));
        }

        let mut decryption_shares: Vec<CrtPolynomial> = Vec::with_capacity(d_share_polys.len());
        for d_share in &d_share_polys {
            decryption_shares.push(CrtPolynomial::from_fhe_polynomial(d_share));
        }

        let party_ids: Vec<BigInt> = data
            .reconstructing_parties
            .iter()
            .map(|&x| BigInt::from(x))
            .collect();

        // u^{(l)} per modulus via Lagrange at zero.
        let reconstructing_parties = &data.reconstructing_parties;
        let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();
        for (m, &modulus) in moduli.iter().enumerate().take(num_moduli) {
            let mut u_modulus_coeffs = Vec::with_capacity(degree);
            for coeff_idx in 0..degree {
                let shares: Vec<BigInt> = (0..=threshold)
                    .map(|party_idx| {
                        let coeffs = d_share_polys[party_idx].coefficients();
                        BigInt::from(coeffs.row(m)[coeff_idx])
                    })
                    .collect();
                u_modulus_coeffs.push(utils::lagrange_recover_at_zero(
                    reconstructing_parties,
                    &shares,
                    modulus,
                )?);
            }
            u_per_modulus.push(u_modulus_coeffs);
        }

        // u_global per coefficient via CRT reconstruction.
        let mut u_global_vec: Vec<BigInt> = Vec::with_capacity(degree);
        for coeff_idx in 0..degree {
            let rests: Vec<u64> = u_per_modulus.iter().map(|row| row[coeff_idx]).collect();
            u_global_vec.push(BigInt::from(utils::crt_reconstruct(&rests, &moduli)?));
        }

        // CRT quotients: r^{(m)} = (u_global - u^{(m)}) / q_m.
        let mut crt_quotients_limbs: Vec<Polynomial> = Vec::with_capacity(num_moduli);
        for (m, u_modulus) in u_per_modulus.iter().enumerate().take(num_moduli) {
            let q_m_bigint = BigInt::from(moduli[m]);
            let mut r_m_coeffs = Vec::with_capacity(degree);
            for (coeff_idx, u_global_val) in u_global_vec.iter().enumerate().take(degree) {
                let diff = u_global_val - BigInt::from(u_modulus[coeff_idx]);
                if !(&diff % &q_m_bigint).is_zero() {
                    return Err(CircuitsErrors::Other(format!(
                        "CRT quotient not exact at m={m} coeff={coeff_idx}"
                    )));
                }
                r_m_coeffs.push(&diff / &q_m_bigint);
            }
            crt_quotients_limbs.push(Polynomial::new(r_m_coeffs));
        }
        let crt_quotients = CrtPolynomial::new(crt_quotients_limbs);

        // Truncate everything to the circuit's coefficient window.
        let decryption_shares: Vec<CrtPolynomial> = decryption_shares
            .into_iter()
            .map(|crt| truncate_crt_to_max_coeffs(crt, max_msg_non_zero_coeffs))
            .collect();
        let u_global_trunc = truncate_to_max_coeffs(&u_global_vec, max_msg_non_zero_coeffs);
        let crt_quotients = truncate_crt_to_max_coeffs(crt_quotients, max_msg_non_zero_coeffs);

        let zkp_modulus = get_zkp_modulus();
        let party_ids: Vec<BigInt> = party_ids.iter().map(|c| reduce(c, &zkp_modulus)).collect();
        let u_global = Polynomial::new(
            u_global_trunc
                .iter()
                .map(|c| reduce(c, &zkp_modulus))
                .collect(),
        );

        let expected_d_commitments: Vec<BigInt> = decryption_shares
            .iter()
            .map(|share| {
                compute_threshold_decryption_share_commitment(
                    share,
                    configs.bits.d_native_bit,
                    max_msg_non_zero_coeffs,
                )
            })
            .collect();

        Ok(Inputs {
            expected_d_commitments,
            decryption_shares,
            party_ids,
            u_global,
            crt_quotients,
            domain_hi: BigInt::from(data.domain_hi),
            domain_lo: BigInt::from(data.domain_lo),
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::bigint_1d_to_json_values;
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let decryption_shares_json: Vec<Vec<serde_json::Value>> = self
            .decryption_shares
            .iter()
            .map(crt_polynomial_to_toml_json)
            .collect();

        Ok(serde_json::json!({
            "expected_d_commitments": bigint_1d_to_json_values(&self.expected_d_commitments),
            "decryption_shares": decryption_shares_json,
            "party_ids": bigint_1d_to_json_values(&self.party_ids),
            "u_global": polynomial_to_toml_json(&self.u_global),
            "crt_quotients": crt_polynomial_to_toml_json(&self.crt_quotients),
            "domain_hi": self.domain_hi.to_string(),
            "domain_lo": self.domain_lo.to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::user_data_encryption_ckks::insecure_512_ckks;
    use fhe::ckks::{CkksEncoder, CkksSecretKey};
    use fhe::trckks::TRCKKS;

    const N_PARTIES: usize = 5;
    const THRESHOLD: usize = 2;

    /// Real threshold-CKKS pipeline: trusted-dealer style share generation
    /// (exercises the same Shamir/Lagrange math as the DKG), encryption,
    /// share computation, then the witness generator's Lagrange + CRT must
    /// reproduce what `TRCKKS::decrypt` computes.
    #[test]
    fn inputs_match_threshold_decryption() {
        let mut rng = rand::rng();
        let preset = insecure_512_ckks().unwrap();
        let params = preset.params.clone();
        let trckks = TRCKKS::new(N_PARTIES, THRESHOLD, params.clone()).unwrap();

        // Single-dealer key (the aggregation math is identical to full DKG).
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();

        let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref()).unwrap();
        let sk_shares_mats = trckks
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();
        let es = trckks.generate_smudging_error(20, &mut rng).unwrap();
        let es_poly = trckks.smudging_to_poly(&es).unwrap();
        let es_shares_mats = trckks
            .generate_secret_shares_from_poly(es_poly, &mut rng)
            .unwrap();

        // Encrypt a value.
        let encoder = CkksEncoder::new(&params);
        let pt = encoder.encode(&[42.5], 0).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();

        // T+1 parties compute decryption shares.
        let parties: Vec<usize> = vec![1, 3, 5];
        let mut d_share_polys = Vec::new();
        for &j in &parties {
            let sk_share = trckks.share_row_to_poly(&sk_shares_mats, j - 1).unwrap();
            let es_share = trckks.share_row_to_poly(&es_shares_mats, j - 1).unwrap();
            let d = trckks
                .decryption_share(&ct, sk_share.into_ntt(), es_share)
                .unwrap();
            d_share_polys.push(d);
        }

        // Reference: the library's own threshold decryption.
        let pt_ref = trckks
            .decrypt(d_share_polys.clone(), parties.clone(), &ct)
            .unwrap();
        let values_ref = encoder.decode(&pt_ref).unwrap();
        // Tolerance: 20-bit smudging noise against scale 2^26 leaves ~0.3
        // of absolute error in this insecure dev preset.
        assert!(
            (values_ref[0] - 42.5).abs() < 0.5,
            "sanity: {}",
            values_ref[0]
        );

        // Witness generator on the same shares.
        let data = DecryptedSharesAggregationCkksCircuitData {
            threshold: THRESHOLD,
            d_share_polys,
            reconstructing_parties: parties,
            // Test domain words (C6-CKKS tests use the same 1/2 pair).
            domain_hi: 1,
            domain_lo: 2,
        };
        let out = DecryptedSharesAggregationCkksCircuit::compute(preset, &data).unwrap();

        assert_eq!(out.inputs.decryption_shares.len(), THRESHOLD + 1);
        assert_eq!(out.inputs.expected_d_commitments.len(), THRESHOLD + 1);
        // The window is the full ring degree (C6/C7 hash the same N coeffs).
        assert_eq!(out.inputs.u_global.coefficients().len(), params.degree());
        assert_eq!(out.inputs.crt_quotients.limbs.len(), params.moduli().len());
        assert!(out.bits.d_native_bit > 0);

        // C6 -> C7 LINK (regression for the structural break): the
        // `d_commitment` that C6-CKKS emits and the aggregator recomputes
        // over ALL N coefficients (`transitions.rs`
        // `verify_ckks_shares_match_c6_commitments`) MUST be the very value
        // C7 receives as `expected_d_commitments[i]`. With the inherited BFV
        // window of 100 these could never be equal.
        for (i, d) in data.d_share_polys.iter().enumerate() {
            let crt = CrtPolynomial::from_fhe_polynomial(d);
            let c6_style = compute_threshold_decryption_share_commitment(
                &crt,
                out.bits.d_native_bit,
                params.degree(),
            );
            assert_eq!(
                c6_style, out.inputs.expected_d_commitments[i],
                "C6 d_commitment != C7 expected_d_commitments for party index {i}"
            );
        }

        // Soundness inputs the circuit range-checks: the honest quotients
        // must lie in [0, Q/q_l) and u_global in [0, Q).
        let q_full = params
            .moduli()
            .iter()
            .fold(BigInt::from(1), |acc, q| acc * BigInt::from(*q));
        for u in out.inputs.u_global.coefficients() {
            assert!(
                u >= &BigInt::from(0) && u < &q_full,
                "u_global not canonical"
            );
        }
        for (m, q) in params.moduli().iter().enumerate() {
            let bound = &q_full / BigInt::from(*q);
            for r in out.inputs.crt_quotients.limbs[m].coefficients() {
                assert!(r >= &BigInt::from(0) && r < &bound, "quotient out of range");
            }
        }

        // Cross-check: the witness generator's Lagrange+CRT reconstruction
        // must agree with the library's own threshold decryption. Compare
        // u_global mod q_m against the reference plaintext's RNS rows.
        // (Coefficient-wise decode isn't meaningful here: the canonical
        // embedding spreads slot values across all coefficients.)
        let pt_poly = pt_ref.poly().clone().into_power_basis();
        let pt_coeffs = pt_poly.coefficients();
        let moduli = params.moduli();
        for (m, &qm) in moduli.iter().enumerate() {
            let qm_big = BigInt::from(qm);
            for (i, u_val) in out
                .inputs
                .u_global
                .coefficients()
                .iter()
                .take(params.degree())
                .enumerate()
            {
                let expected = BigInt::from(pt_coeffs.row(m)[i]);
                let got = ((u_val % &qm_big) + &qm_big) % &qm_big;
                assert_eq!(got, expected, "u_global mismatch at modulus {m} coeff {i}");
            }
        }
    }
}
