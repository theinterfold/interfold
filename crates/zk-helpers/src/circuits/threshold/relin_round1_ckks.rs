// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C8-CKKS: relinearization ceremony round-1 share proof for CKKS.
//!
//! Proves one party's round-1 share of the two-round CRP-based
//! relinearization key protocol (Multiparty BFV, Protocol 2 — applied
//! unchanged to CKKS) is well formed. For decomposition index `i` and
//! CKKS limb `j`, over centered power-basis coefficients:
//!
//! `h0[i][j] = -a[i][j]*u + (g_i mod q_j)*s + e0[i]  (mod q_j, mod x^N+1)`
//! `h1[i][j] = a[i][j]*s + e1[i]                     (mod q_j, mod x^N+1)`
//!
//! where `a[i]` are the public CRP polynomials
//! ([`fhe::trckks::CkksCrp::vec_from_seed_leveled`]), `g_i` is the i-th
//! garner constant of the RNS basis ([`fhe_math::rns::RnsContext`]),
//! `s` is the party's secret key share, and `u` the ephemeral secret
//! reused in round 2. The `g_i mod q_j` values are PUBLIC constants
//! emitted into the generated Noir config.
//!
//! LEVEL NOTE: this module fixes the key level to 0 (the transport-
//! compatible demo shape). The garner constants change per level, so a
//! leveled deployment must regenerate the config (and constants) for
//! each level it runs the ceremony at.

use crate::circuits::commitments::{
    compute_ciphertext_commitment, compute_share_computation_sk_commitment,
};
use crate::circuits::computation::Computation;
use crate::circuits::errors::CircuitsErrors;
use crate::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use crate::crt_polynomial_to_toml_json;
use crate::polynomial_to_toml_json;
use crate::{calculate_bit_width, cyclotomic_polynomial, decompose_residue};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::trckks::{CkksCrp, CkksRelinKeyShare, R1};
use fhe_math::rns::RnsContext;
use fhe_math::rq::{Ntt, Poly};
use num_bigint::{BigInt, BigUint};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};

/// The key level this circuit is generated for (see module note).
pub const RELIN_ROUND1_LEVEL: usize = 0;

/// Witness data for one party's C8-CKKS proof.
pub struct CkksRelinRound1Data {
    /// The public CRP polynomials (one per RNS modulus at the key level).
    pub crp: Vec<CkksCrp>,
    /// This party's published round-1 share.
    pub share: CkksRelinKeyShare<R1>,
    /// This party's secret key share coefficients (small, |c| <= 1).
    pub sk_coeffs: Vec<i64>,
    /// The ephemeral secret `u` (NTT form, from the generator).
    pub u: Poly<Ntt>,
    /// Error polynomials for the h0 leg, one per decomposition index.
    pub e0s: Vec<Poly<Ntt>>,
    /// Error polynomials for the h1 leg, one per decomposition index.
    pub e1s: Vec<Poly<Ntt>>,
}

/// Circuit identifier for CKKS relin round-1 share proof (Noir circuit
/// `relin_round1_ckks`, C8-CKKS).
#[derive(Debug)]
pub struct CkksRelinRound1Circuit;

impl crate::registry::Circuit for CkksRelinRound1Circuit {
    const NAME: &'static str = "relin-round1-ckks";
    const PREFIX: &'static str = "RELIN_ROUND1_CKKS";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    /// `g_i mod q_j` (in `[0, q_j)`), flattened at `i * L + j`.
    pub garner: Vec<BigInt>,
    pub bits: Bits,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub a_bit: u32,
    pub sk_bit: u32,
    pub u_bit: u32,
    pub e_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub h_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub sk_bound: BigInt,
    pub u_bound: BigInt,
    pub e_bound: BigInt,
    pub r1_bounds: Vec<BigInt>,
    pub r2_bounds: Vec<BigInt>,
}

impl Computation for Bounds {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Same derivation family as C1/C6: r2 in `±(q_j-1)/2`; r1 from the
    /// magnitude of the lifted expression divided by `q_j`. The h0 leg
    /// dominates: `|h0_hat| <= N*u_bound*qi_bound + q_j*sk_bound*N_terms`
    /// — but `g_i*s` is a SCALAR multiple, so its coefficients are at
    /// most `(q_j - 1) * sk_bound < 2*qi_bound + ...`; we take the safe
    /// envelope `((N*u_bound + 2*sk_bound + 4)*qi_bound + e_bound)/q_j`
    /// which also covers the h1 leg (`a*s` convolution).
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let n = BigInt::from(params.degree());
        let sk_bound = BigInt::from(fhe::ckks::CkksSecretKey::sk_bound() as i64);
        // `u` is sampled by the generator with `Poly::small(ctx, variance)`
        // — the SAME distribution as the errors — so its bound is
        // 2*variance, NOT the sk CBD(0.5) bound of 1.
        let e_bound = BigInt::from((params.variance() * 2) as u64);
        let u_bound = e_bound.clone();

        let mut r1_bounds = Vec::new();
        let mut r2_bounds = Vec::new();
        for &qi in params.moduli() {
            let qi_bigint = BigInt::from(qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);
            r2_bounds.push(qi_bound.clone());
            r1_bounds.push(
                ((&n * &u_bound + BigInt::from(2) * &sk_bound + BigInt::from(4)) * &qi_bound
                    + &e_bound)
                    / &qi_bigint,
            );
        }
        Ok(Bounds {
            sk_bound,
            u_bound,
            e_bound,
            r1_bounds,
            r2_bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = CkksPreset;
    type Data = Bounds;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let modulus_bit = preset
            .params
            .moduli()
            .iter()
            .map(|&q| calculate_bit_width(BigInt::from((q - 1) / 2)))
            .max()
            .unwrap_or(0);
        let max_bit = |bounds: &[BigInt]| {
            bounds
                .iter()
                .map(|b| calculate_bit_width(b.clone()))
                .max()
                .unwrap_or(0)
        };
        Ok(Bits {
            a_bit: modulus_bit,
            sk_bit: calculate_bit_width(data.sk_bound.clone()),
            u_bit: calculate_bit_width(data.u_bound.clone()),
            e_bit: calculate_bit_width(data.e_bound.clone()),
            r1_bit: max_bit(&data.r1_bounds),
            r2_bit: max_bit(&data.r2_bounds),
            h_bit: modulus_bit,
        })
    }
}

/// `g_i mod q_j` (plain representatives in `[0, q_j)`), flattened at
/// `i * L + j`. The Z-identity the witness satisfies uses these exact
/// integers, so circuit constants and witness computation must agree.
fn garner_matrix(moduli: &[u64]) -> Result<Vec<BigInt>, CircuitsErrors> {
    let rns =
        RnsContext::new(moduli).map_err(|e| CircuitsErrors::Other(format!("rns context: {e}")))?;
    let l = moduli.len();
    let mut out = Vec::with_capacity(l * l);
    for i in 0..l {
        let g: &BigUint = rns
            .get_garner(i)
            .ok_or_else(|| CircuitsErrors::Other(format!("missing garner {i}")))?;
        let g = BigInt::from(g.clone());
        for &qj in moduli {
            out.push(&g % BigInt::from(qj));
        }
    }
    Ok(out)
}

impl Computation for Configs {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        Ok(Configs {
            n: preset.params.degree(),
            l: preset.params.moduli().len(),
            moduli: preset.params.moduli().to_vec(),
            garner: garner_matrix(preset.params.moduli())?,
            bits,
            bounds,
        })
    }
}

/// The circuit witness inputs. All `L*L`-limb `CrtPolynomial`s are ordered
/// `idx = i * L + j` (decomposition index major, limb minor).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub a: CrtPolynomial,
    pub s: Polynomial,
    pub u: Polynomial,
    pub e0: CrtPolynomial,
    pub e1: CrtPolynomial,
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

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = CkksRelinRound1Data;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        // Level is fixed at 0 for now (see module doc note); the garner
        // constants baked into the config are level-0 values.
        if data.share.level() != RELIN_ROUND1_LEVEL {
            return Err(CircuitsErrors::Other(format!(
                "C8-CKKS is generated for level {RELIN_ROUND1_LEVEL}, share is at level {}",
                data.share.level()
            )));
        }
        let moduli_u64: Vec<u64> = params.moduli().to_vec();
        let moduli: Vec<BigInt> = moduli_u64.iter().copied().map(BigInt::from).collect();
        let l = moduli.len();
        let n = params.degree() as u64;

        if data.crp.len() != l
            || data.share.h0().len() != l
            || data.share.h1().len() != l
            || data.e0s.len() != l
            || data.e1s.len() != l
        {
            return Err(CircuitsErrors::Other(
                "C8-CKKS needs one CRP/h0/h1/e0/e1 per RNS modulus".to_string(),
            ));
        }

        let garner = garner_matrix(&moduli_u64)?;
        let cyclo = cyclotomic_polynomial(n);

        // Small secret polynomials: single copy each (limb-independent by
        // the smallness bounds), descending-degree layout.
        let small_from_ntt = |p: &Poly<Ntt>| -> Polynomial {
            let mut poly = CrtPolynomial::from_fhe_polynomial(p).limb(0).clone();
            poly.center(&moduli[0]);
            poly.reverse();
            poly
        };
        let s_poly = {
            let mut coeffs: Vec<BigInt> = data.sk_coeffs.iter().map(|&c| BigInt::from(c)).collect();
            coeffs.reverse();
            Polynomial::new(coeffs)
        };
        let u_poly = small_from_ntt(&data.u);
        let e0_polys: Vec<Polynomial> = data.e0s.iter().map(&small_from_ntt).collect();
        let e1_polys: Vec<Polynomial> = data.e1s.iter().map(&small_from_ntt).collect();

        // CRT limbs of the public/committed polynomials (NTT -> power
        // basis handled by from_fhe_polynomial), reversed + centered.
        let to_crt = |p: &Poly<Ntt>| -> Result<CrtPolynomial, CircuitsErrors> {
            let mut crt = CrtPolynomial::from_fhe_polynomial(p);
            crt.reverse();
            crt.center(&moduli_u64)
                .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
            Ok(crt)
        };

        // Flattened (i, j) tasks: for each decomposition index i, each limb j.
        struct Task {
            idx: usize,
            qj: BigInt,
            g_ij: BigInt,
            a_limb: Polynomial,
            h0_limb: Polynomial,
            h1_limb: Polynomial,
        }
        let mut tasks = Vec::with_capacity(l * l);
        for i in 0..l {
            let a_crt = to_crt(data.crp[i].poly())?;
            let h0_crt = to_crt(&data.share.h0()[i])?;
            let h1_crt = to_crt(&data.share.h1()[i])?;
            #[allow(clippy::needless_range_loop)]
            // j indexes moduli AND garner AND three CRT limb sets
            for j in 0..l {
                let idx = i * l + j;
                tasks.push(Task {
                    idx,
                    qj: moduli[j].clone(),
                    g_ij: garner[idx].clone(),
                    a_limb: a_crt.limb(j).clone(),
                    h0_limb: h0_crt.limb(j).clone(),
                    h1_limb: h1_crt.limb(j).clone(),
                });
            }
        }

        // Native congruence pre-check BEFORE decompose_residue so a bad
        // share fails attributably instead of panicking in the helper.
        let native_check = |lhs: &Polynomial,
                            hat: &Polynomial,
                            qj: &BigInt,
                            idx: usize,
                            leg: &str|
         -> Result<(), CircuitsErrors> {
            let nn = n as usize;
            let mut nat = hat.coefficients().to_vec();
            nat.reverse(); // stored reversed (descending degree)
            nat.resize(2 * nn, BigInt::from(0));
            for ii in (nn..2 * nn).rev() {
                let c = nat[ii].clone();
                nat[ii] = BigInt::from(0);
                nat[ii - nn] -= c;
            }
            nat.truncate(nn);
            let mut lhs_nat = lhs.coefficients().to_vec();
            lhs_nat.reverse();
            for (ii, (a, b)) in nat.iter().zip(lhs_nat.iter()).enumerate() {
                let df = (((a - b) % qj) + qj) % qj;
                if df != BigInt::from(0) {
                    return Err(CircuitsErrors::Other(format!(
                        "C8-CKKS share inconsistent at index {idx} coeff {ii}: \
                         {leg} relation does not hold (mod q)"
                    )));
                }
            }
            Ok(())
        };

        #[allow(clippy::type_complexity)]
        let mut results: Vec<
            Result<
                (
                    usize,
                    Polynomial,
                    Polynomial,
                    Polynomial,
                    Polynomial,
                    Polynomial,
                    Polynomial,
                    Polynomial,
                ),
                CircuitsErrors,
            >,
        > = tasks
            .into_iter()
            .par_bridge()
            .map(|t| {
                let i = t.idx / l;
                // h0_hat = -a*u + g_ij*s + e0[i]  (lifted to Z)
                let h0_hat = t
                    .a_limb
                    .neg()
                    .mul(&u_poly)
                    .add(&s_poly.scalar_mul(&t.g_ij))
                    .add(&e0_polys[i]);
                native_check(&t.h0_limb, &h0_hat, &t.qj, t.idx, "h0")?;
                let (r1_h0, r2_h0) = decompose_residue(&t.h0_limb, &h0_hat, &t.qj, &cyclo, n);

                // h1_hat = a*s + e1[i]  (lifted to Z)
                let h1_hat = t.a_limb.mul(&s_poly).add(&e1_polys[i]);
                native_check(&t.h1_limb, &h1_hat, &t.qj, t.idx, "h1")?;
                let (r1_h1, r2_h1) = decompose_residue(&t.h1_limb, &h1_hat, &t.qj, &cyclo, n);

                Ok((
                    t.idx, t.a_limb, t.h0_limb, t.h1_limb, r1_h0, r2_h0, r1_h1, r2_h1,
                ))
            })
            .collect();
        results.sort_by_key(|r| r.as_ref().map(|(i, ..)| *i).unwrap_or(usize::MAX));

        let mut a = CrtPolynomial::new(vec![]);
        let mut h0 = CrtPolynomial::new(vec![]);
        let mut h1 = CrtPolynomial::new(vec![]);
        let mut r1_h0 = CrtPolynomial::new(vec![]);
        let mut r2_h0 = CrtPolynomial::new(vec![]);
        let mut r1_h1 = CrtPolynomial::new(vec![]);
        let mut r2_h1 = CrtPolynomial::new(vec![]);
        for result in results {
            let (_idx, ai, h0i, h1i, r1h0i, r2h0i, r1h1i, r2h1i) = result?;
            a.add_limb(ai);
            h0.add_limb(h0i);
            h1.add_limb(h1i);
            r1_h0.add_limb(r1h0i);
            r2_h0.add_limb(r2h0i);
            r1_h1.add_limb(r1h1i);
            r2_h1.add_limb(r2h1i);
        }

        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        let s_commitment = compute_share_computation_sk_commitment(&s_poly, bits.sk_bit);
        let u_commitment = compute_share_computation_sk_commitment(&u_poly, bits.u_bit);
        let share_commitment = compute_ciphertext_commitment(&h0, &h1, bits.h_bit);

        Ok(Inputs {
            a,
            s: s_poly,
            u: u_poly,
            e0: CrtPolynomial::new(e0_polys),
            e1: CrtPolynomial::new(e1_polys),
            r1_h0,
            r2_h0,
            r1_h1,
            r2_h1,
            h0,
            h1,
            s_commitment,
            u_commitment,
            share_commitment,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "a": crt_polynomial_to_toml_json(&self.a),
            "s": polynomial_to_toml_json(&self.s),
            "u": polynomial_to_toml_json(&self.u),
            "e0": crt_polynomial_to_toml_json(&self.e0),
            "e1": crt_polynomial_to_toml_json(&self.e1),
            "r1_h0": crt_polynomial_to_toml_json(&self.r1_h0),
            "r2_h0": crt_polynomial_to_toml_json(&self.r2_h0),
            "r1_h1": crt_polynomial_to_toml_json(&self.r1_h1),
            "r2_h1": crt_polynomial_to_toml_json(&self.r2_h1),
            "h0": crt_polynomial_to_toml_json(&self.h0),
            "h1": crt_polynomial_to_toml_json(&self.h1),
        }))
    }
}

/// Codegen: emits `circuits/lib/src/configs/ckks_relin_round1.nr`.
pub fn generate_configs_nr(configs: &Configs) -> String {
    let join = |it: &mut dyn Iterator<Item = String>| it.collect::<Vec<_>>().join(", ");
    let qis = join(&mut configs.moduli.iter().map(|q| q.to_string()));
    let garner = join(&mut configs.garner.iter().map(|g| g.to_string()));
    let r1b = join(&mut configs.bounds.r1_bounds.iter().map(|b| b.to_string()));
    let r2b = join(&mut configs.bounds.r2_bounds.iter().map(|b| b.to_string()));
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers relin_round1_ckks codegen
// (example gen_ckks_c8_prover). Do not hand-edit.
//
// GARNER holds the level-0 constants `g_i mod q_j` at index `i * L + j`;
// they change per level, so leveled ceremonies need a regenerated config.

use crate::core::threshold::relin_round1_ckks::Configs as RelinRound1Configs;

/************************************
-------------------------------------
relin_round1_ckks (CIRCUIT 8-CKKS)
-------------------------------------
************************************/

pub global RELIN_ROUND1_CKKS_N: u32 = {n};
pub global RELIN_ROUND1_CKKS_L: u32 = {l};
pub global RELIN_ROUND1_CKKS_QIS: [Field; RELIN_ROUND1_CKKS_L] = [{qis}];
pub global RELIN_ROUND1_CKKS_GARNER: [Field; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L] =
    [{garner}];

pub global RELIN_ROUND1_CKKS_BIT_A: u32 = {a_bit};
pub global RELIN_ROUND1_CKKS_BIT_SK: u32 = {sk_bit};
pub global RELIN_ROUND1_CKKS_BIT_U: u32 = {u_bit};
pub global RELIN_ROUND1_CKKS_BIT_E: u32 = {e_bit};
pub global RELIN_ROUND1_CKKS_BIT_R1: u32 = {r1_bit};
pub global RELIN_ROUND1_CKKS_BIT_R2: u32 = {r2_bit};
pub global RELIN_ROUND1_CKKS_BIT_H: u32 = {h_bit};

pub global RELIN_ROUND1_CKKS_SK_BOUND: Field = {sk_bound};
pub global RELIN_ROUND1_CKKS_U_BOUND: Field = {u_bound};
pub global RELIN_ROUND1_CKKS_E_BOUND: Field = {e_bound};
pub global RELIN_ROUND1_CKKS_R1_BOUNDS: [Field; RELIN_ROUND1_CKKS_L] = [{r1b}];
pub global RELIN_ROUND1_CKKS_R2_BOUNDS: [Field; RELIN_ROUND1_CKKS_L] = [{r2b}];

pub global RELIN_ROUND1_CKKS_CONFIGS: RelinRound1Configs<RELIN_ROUND1_CKKS_L> = RelinRound1Configs::new(
    RELIN_ROUND1_CKKS_QIS,
    RELIN_ROUND1_CKKS_GARNER,
    RELIN_ROUND1_CKKS_SK_BOUND,
    RELIN_ROUND1_CKKS_U_BOUND,
    RELIN_ROUND1_CKKS_E_BOUND,
    RELIN_ROUND1_CKKS_R1_BOUNDS,
    RELIN_ROUND1_CKKS_R2_BOUNDS,
);
"#,
        n = configs.n,
        l = configs.l,
        qis = qis,
        garner = garner,
        a_bit = configs.bits.a_bit,
        sk_bit = configs.bits.sk_bit,
        u_bit = configs.bits.u_bit,
        e_bit = configs.bits.e_bit,
        r1_bit = configs.bits.r1_bit,
        r2_bit = configs.bits.r2_bit,
        h_bit = configs.bits.h_bit,
        sk_bound = configs.bounds.sk_bound,
        u_bound = configs.bounds.u_bound,
        e_bound = configs.bounds.e_bound,
        r1b = r1b,
        r2b = r2b,
    )
}

/// Native check of the circuit's core constraints for every `(i, j)`:
/// both round-1 relations hold mod `q_j`, mod `x^N + 1`. Runs the whole
/// witness pipeline, so it also exercises the quotient decomposition.
pub fn verify_ckks_relin_round1_constraints(
    preset: &CkksPreset,
    data: &CkksRelinRound1Data,
) -> Result<(), CircuitsErrors> {
    let _ = Inputs::compute(preset.clone(), data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::ckks::CkksSecretKey;
    use fhe::trckks::CkksRelinKeyGenerator;

    fn preset() -> CkksPreset {
        crate::threshold::user_data_encryption_ckks::insecure_512_ckks().unwrap()
    }

    fn real_data(preset: &CkksPreset) -> CkksRelinRound1Data {
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let crp =
            CkksCrp::vec_from_seed_leveled(&params, [3u8; 32], params.moduli().len(), 0).unwrap();
        let generator = CkksRelinKeyGenerator::new(&sk, &crp, &mut rng).unwrap();
        let (share, e0s, e1s) = generator.round_1_extended(&mut rng).unwrap();
        let u = generator.u_poly().clone();
        drop(generator);
        CkksRelinRound1Data {
            crp,
            share,
            sk_coeffs: sk.coeffs.to_vec(),
            u,
            e0s,
            e1s,
        }
    }

    /// Real round-1 output satisfies the C8-CKKS constraints end to end;
    /// bounds hold for every witness polynomial.
    #[test]
    fn ckks_relin_round1_witnesses_satisfy_c8_constraints() {
        let preset = preset();
        let data = real_data(&preset);
        let inputs = Inputs::compute(preset.clone(), &data).expect("real share verifies");

        // Range sanity on the quotients against the emitted bounds.
        let bounds = Bounds::compute(preset.clone(), &()).unwrap();
        let l = preset.params.moduli().len();
        for idx in 0..l * l {
            let j = idx % l;
            for c in inputs.r1_h0.limb(idx).coefficients() {
                assert!(
                    c.magnitude() <= bounds.r1_bounds[j].magnitude(),
                    "r1_h0 exceeds bound"
                );
            }
            for c in inputs.r2_h0.limb(idx).coefficients() {
                assert!(
                    c.magnitude() <= bounds.r2_bounds[j].magnitude(),
                    "r2_h0 exceeds bound"
                );
            }
            for c in inputs.r1_h1.limb(idx).coefficients() {
                assert!(
                    c.magnitude() <= bounds.r1_bounds[j].magnitude(),
                    "r1_h1 exceeds bound"
                );
            }
            for c in inputs.r2_h1.limb(idx).coefficients() {
                assert!(
                    c.magnitude() <= bounds.r2_bounds[j].magnitude(),
                    "r2_h1 exceeds bound"
                );
            }
        }
        for c in inputs.s.coefficients() {
            assert!(
                c.magnitude() <= bounds.sk_bound.magnitude(),
                "s exceeds bound"
            );
        }
        for c in inputs.u.coefficients() {
            assert!(
                c.magnitude() <= bounds.u_bound.magnitude(),
                "u exceeds bound"
            );
        }
    }

    /// A tampered witness (one secret-key coefficient flipped) must be
    /// rejected by the native congruence pre-check, not by a panic: the
    /// published share no longer matches the claimed secrets.
    #[test]
    fn ckks_relin_round1_tampered_share_is_rejected() {
        let preset = preset();
        let mut bad = real_data(&preset);
        bad.sk_coeffs[3] += 1;
        let err = verify_ckks_relin_round1_constraints(&preset, &bad)
            .expect_err("tampered witness must be rejected");
        assert!(
            format!("{err:?}").contains("relation does not hold"),
            "expected attributable congruence failure, got {err:?}"
        );
    }
}
