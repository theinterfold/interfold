// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C8-CKKS (HYBRID gadget): relinearization ceremony round-1 share proof
//! for CKKS parameters with special primes.
//!
//! Proves one party's round-1 share of the two-round CRP-based HYBRID
//! relinearization key protocol
//! ([`fhe::trckks::CkksHybridRelinKeyGenerator::round_1`]) is well
//! formed. For gadget digit `j` and limb `l` of `Q·P` (the `L`
//! ciphertext moduli followed by the `k` special primes; `LT = L + k`),
//! over centered power-basis coefficients:
//!
//! `h0[j][l] = -a[j][l]*u + ((P·g_j) mod q_l)*s + e0[j]  (mod q_l, mod x^N+1)`
//! `h1[j][l] = a[j][l]*s + e1[j]                          (mod q_l, mod x^N+1)`
//!
//! where `a[j]` are the public CRPs over `Q·P`
//! ([`fhe::trckks::CkksCrp::vec_from_seed_qp`]), `g_j` is the CRT gadget
//! of digit `j` (`g_j = (Q/D_j)·[(Q/D_j)^{-1}]_{D_j}`, [`hybrid_gadget`]
//! replicates fhe.rs `ckks/hybrid.rs::HybridParams::new` exactly), `s`
//! is the party's secret key share, and `u` the ephemeral secret reused
//! in round 2. `P·g_j ≡ 0` on every special-prime limb. The `(P·g_j) mod
//! q_l` values are PUBLIC constants emitted into the generated Noir
//! config; one config serves EVERY level (the whole point of hybrid).
//!
//! HONEST SCOPE: fhe.rs's hybrid generator has no `round_1_extended`
//! returning `(share, e0s, e1s)` nor a `u` accessor (unlike the
//! per-level `CkksRelinKeyGenerator`), so a witness for a share the
//! generator produced cannot be assembled from outside fhe.rs. The
//! builder therefore takes the secrets explicitly
//! ([`CkksHybridRelinRound1Data`]); tests and the config/witness example
//! recompute a share from sampled `u`, `e0`, `e1` with the public gadget
//! math ([`compute_round_1_share`]) and prove THAT. Equality of the
//! gadget with fhe.rs is pinned by checking a REAL
//! `CkksHybridRelinKeyGenerator::round_1` share against the recomputed
//! constants (`h1 − a·s` and `h0 + a·u_unknown`… see the tests: the
//! `h1` leg needs no `u`, and the `h0` leg is checked through the key
//! identity `b + a·s = P·g·s² + e` on a single-key
//! `CkksHybridRelinKey`). The fhe.rs API needed to close the gap:
//! `CkksHybridRelinKeyGenerator::{round_1_extended, u_poly}`.

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
use fhe::ckks::CkksQpPoly;
use fhe::trckks::{CkksHybridRelinKeyShare, R1};
use num_bigint::{BigInt, BigUint};
use num_traits::One;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};

/// Witness data for one party's C8-CKKS (hybrid) proof.
pub struct CkksHybridRelinRound1Data {
    /// The public CRPs over `Q·P` (one per gadget digit).
    pub crp: Vec<CkksQpPoly>,
    /// This party's published round-1 share.
    pub share: CkksHybridRelinKeyShare<R1>,
    /// This party's secret key share coefficients (small, |c| <= 1).
    pub sk_coeffs: Vec<i64>,
    /// The ephemeral secret `u` coefficients (CBD with the parameter
    /// variance).
    pub u_coeffs: Vec<i64>,
    /// Error coefficients for the h0 leg, one poly per digit.
    pub e0_coeffs: Vec<Vec<i64>>,
    /// Error coefficients for the h1 leg, one poly per digit.
    pub e1_coeffs: Vec<Vec<i64>>,
}

/// Circuit identifier for the CKKS hybrid relin round-1 share proof (Noir
/// circuit `relin_round1_hybrid_ckks`, C8-CKKS hybrid).
#[derive(Debug)]
pub struct CkksHybridRelinRound1Circuit;

impl crate::registry::Circuit for CkksHybridRelinRound1Circuit {
    const NAME: &'static str = "relin-round1-hybrid-ckks";
    const PREFIX: &'static str = "RELIN_ROUND1_HYBRID_CKKS";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    /// Gadget digits `dnum`.
    pub d: usize,
    /// `L + k` limbs of `Q·P`.
    pub lt: usize,
    /// `[q_0, …, q_{L-1}, p_0, …, p_{k-1}]`.
    pub moduli: Vec<u64>,
    /// `(P·g_j) mod q_l` (in `[0, q_l)`), flattened at `j * LT + l`.
    pub gadget: Vec<BigInt>,
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

/// The moduli of `Q·P` in the circuit's limb order: ciphertext moduli
/// then special primes. Errors when the params carry no special primes.
pub fn qp_moduli(params: &fhe::ckks::CkksParameters) -> Result<Vec<u64>, CircuitsErrors> {
    if !params.hybrid_enabled() {
        return Err(CircuitsErrors::Other(
            "C8-CKKS hybrid needs parameters with special primes".to_string(),
        ));
    }
    let mut m = params.moduli().to_vec();
    m.extend_from_slice(params.special_moduli());
    Ok(m)
}

/// The hybrid gadget constants `P·g_j mod Q` per digit, computed EXACTLY
/// as fhe.rs `ckks/hybrid.rs::HybridParams::new` does: digits are
/// `alpha = ceil(L / dnum)` consecutive limbs (the last may be shorter),
/// `g_j = (Q/D_j)·[(Q/D_j)^{-1}]_{D_j}`, and the key constant is
/// `(g_j · P) mod Q`.
pub fn hybrid_gadget(params: &fhe::ckks::CkksParameters) -> Result<Vec<BigUint>, CircuitsErrors> {
    let q_moduli = params.moduli();
    let dnum = params.dnum();
    if dnum == 0 {
        return Err(CircuitsErrors::Other(
            "hybrid key switching is not enabled".to_string(),
        ));
    }
    let alpha = params.digit_size();
    let q_big = q_moduli
        .iter()
        .fold(BigUint::one(), |acc, q| acc * BigUint::from(*q));
    let p_big = params
        .special_moduli()
        .iter()
        .fold(BigUint::one(), |acc, p| acc * BigUint::from(*p));
    let mut out = Vec::with_capacity(dnum);
    for j in 0..dnum {
        let range = j * alpha..((j + 1) * alpha).min(q_moduli.len());
        let d_j = q_moduli[range]
            .iter()
            .fold(BigUint::one(), |acc, q| acc * BigUint::from(*q));
        let q_over_d = &q_big / &d_j;
        let inv = q_over_d.modinv(&d_j).ok_or_else(|| {
            CircuitsErrors::Other("digit product not invertible (moduli not coprime)".to_string())
        })?;
        let g_j = (&q_over_d * inv) % &q_big;
        out.push((&g_j * &p_big) % &q_big);
    }
    Ok(out)
}

/// `(P·g_j) mod q_l` (plain representatives in `[0, q_l)`), flattened at
/// `j * LT + l` over the `Q·P` limb order. Zero on the special-prime
/// limbs (`P ≡ 0 mod p_i`). The Z-identity the witness satisfies uses
/// these exact integers, so circuit constants and witness computation
/// must agree.
pub fn gadget_matrix(params: &fhe::ckks::CkksParameters) -> Result<Vec<BigInt>, CircuitsErrors> {
    let gadget = hybrid_gadget(params)?;
    let moduli = qp_moduli(params)?;
    let l = params.moduli().len();
    let mut out = Vec::with_capacity(gadget.len() * moduli.len());
    for g in &gadget {
        let g = BigInt::from(g.clone());
        for (idx, &m) in moduli.iter().enumerate() {
            if idx < l {
                out.push(&g % BigInt::from(m));
            } else {
                // `P·g_j` is a multiple of every special prime.
                out.push(BigInt::from(0));
            }
        }
    }
    Ok(out)
}

impl Computation for Bounds {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Same envelope as the per-level C8 (`relin_round1_ckks`), per limb
    /// of `Q·P`: r2 in `±(q_l-1)/2`; r1 from the magnitude of the lifted
    /// expression divided by `q_l`. The scalar `gadget·s` term is at most
    /// `(q_l - 1)·sk_bound` per coefficient, covered by the
    /// `2·sk_bound·qi_bound` term of
    /// `((N·u_bound + 2·sk_bound + 4)·qi_bound + e_bound)/q_l`, which also
    /// covers the h1 leg (`a·s` convolution). Special-prime limbs use the
    /// same formula with their own (60-bit) modulus.
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let n = BigInt::from(params.degree());
        let sk_bound = BigInt::from(fhe::ckks::CkksSecretKey::sk_bound() as i64);
        // `u` and both errors are CBD with the parameter variance
        // (`CkksQpPoly::small`): bound 2·variance.
        let e_bound = BigInt::from((params.variance() * 2) as u64);
        let u_bound = e_bound.clone();

        let mut r1_bounds = Vec::new();
        let mut r2_bounds = Vec::new();
        for &qi in &qp_moduli(params)? {
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
        let modulus_bit = qp_moduli(&preset.params)?
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

impl Computation for Configs {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        let moduli = qp_moduli(&preset.params)?;
        Ok(Configs {
            n: preset.params.degree(),
            d: preset.params.dnum(),
            lt: moduli.len(),
            moduli,
            gadget: gadget_matrix(&preset.params)?,
            bits,
            bounds,
        })
    }
}

/// The circuit witness inputs. All `D*LT`-limb `CrtPolynomial`s are
/// ordered `idx = j * LT + l` (digit major, `Q·P` limb minor).
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

/// A `Q·P` element as `L + k` power-basis limbs (reversed + centered).
pub fn qp_to_crt(
    p: &CkksQpPoly,
    moduli: &[u64],
    l: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    let mut q = CrtPolynomial::from_fhe_polynomial(p.q());
    let mut pp = CrtPolynomial::from_fhe_polynomial(p.p());
    q.reverse();
    pp.reverse();
    q.center(&moduli[..l])
        .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
    pp.center(&moduli[l..])
        .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
    let mut limbs: Vec<Polynomial> = (0..l).map(|i| q.limb(i).clone()).collect();
    limbs.extend((0..moduli.len() - l).map(|i| pp.limb(i).clone()));
    Ok(CrtPolynomial::new(limbs))
}

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = CkksHybridRelinRound1Data;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let moduli_u64 = qp_moduli(params)?;
        let moduli: Vec<BigInt> = moduli_u64.iter().copied().map(BigInt::from).collect();
        let l = params.moduli().len();
        let lt = moduli.len();
        let d = params.dnum();
        let n = params.degree() as u64;

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
        for c in [&data.sk_coeffs, &data.u_coeffs]
            .into_iter()
            .chain(data.e0_coeffs.iter())
            .chain(data.e1_coeffs.iter())
        {
            if c.len() != n as usize {
                return Err(CircuitsErrors::Other(
                    "C8-CKKS hybrid secret polynomials must have N coefficients".to_string(),
                ));
            }
        }

        let gadget = gadget_matrix(params)?;
        let cyclo = cyclotomic_polynomial(n);

        // Small secret polynomials: single copy each, descending-degree
        // layout (the SAME integers reduce on every limb of Q·P).
        let small = |coeffs: &[i64]| -> Polynomial {
            let mut c: Vec<BigInt> = coeffs.iter().map(|&x| BigInt::from(x)).collect();
            c.reverse();
            Polynomial::new(c)
        };
        let s_poly = small(&data.sk_coeffs);
        let u_poly = small(&data.u_coeffs);
        let e0_polys: Vec<Polynomial> = data.e0_coeffs.iter().map(|c| small(c)).collect();
        let e1_polys: Vec<Polynomial> = data.e1_coeffs.iter().map(|c| small(c)).collect();

        struct Task {
            idx: usize,
            ql: BigInt,
            g_jl: BigInt,
            a_limb: Polynomial,
            h0_limb: Polynomial,
            h1_limb: Polynomial,
        }
        let mut tasks = Vec::with_capacity(d * lt);
        for j in 0..d {
            let a_crt = qp_to_crt(&data.crp[j], &moduli_u64, l)?;
            let h0_crt = qp_to_crt(&data.share.h0()[j], &moduli_u64, l)?;
            let h1_crt = qp_to_crt(&data.share.h1()[j], &moduli_u64, l)?;
            for (limb, ql) in moduli.iter().enumerate() {
                let idx = j * lt + limb;
                tasks.push(Task {
                    idx,
                    ql: ql.clone(),
                    g_jl: gadget[idx].clone(),
                    a_limb: a_crt.limb(limb).clone(),
                    h0_limb: h0_crt.limb(limb).clone(),
                    h1_limb: h1_crt.limb(limb).clone(),
                });
            }
        }

        // Native congruence pre-check BEFORE decompose_residue so a bad
        // share fails attributably instead of panicking in the helper.
        let native_check = |lhs: &Polynomial,
                            hat: &Polynomial,
                            ql: &BigInt,
                            idx: usize,
                            leg: &str|
         -> Result<(), CircuitsErrors> {
            let nn = n as usize;
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
            for (ii, (a, b)) in nat.iter().zip(lhs_nat.iter()).enumerate() {
                let df = (((a - b) % ql) + ql) % ql;
                if df != BigInt::from(0) {
                    return Err(CircuitsErrors::Other(format!(
                        "C8-CKKS hybrid share inconsistent at index {idx} coeff {ii}: \
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
                let j = t.idx / lt;
                // h0_hat = -a*u + gadget*s + e0[j]  (lifted to Z)
                let h0_hat = t
                    .a_limb
                    .neg()
                    .mul(&u_poly)
                    .add(&s_poly.scalar_mul(&t.g_jl))
                    .add(&e0_polys[j]);
                native_check(&t.h0_limb, &h0_hat, &t.ql, t.idx, "h0")?;
                let (r1_h0, r2_h0) = decompose_residue(&t.h0_limb, &h0_hat, &t.ql, &cyclo, n);

                // h1_hat = a*s + e1[j]  (lifted to Z)
                let h1_hat = t.a_limb.mul(&s_poly).add(&e1_polys[j]);
                native_check(&t.h1_limb, &h1_hat, &t.ql, t.idx, "h1")?;
                let (r1_h1, r2_h1) = decompose_residue(&t.h1_limb, &h1_hat, &t.ql, &cyclo, n);

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

/// Recompute one party's hybrid round-1 share from explicit secrets with
/// the PUBLIC gadget math — the exact arithmetic of fhe.rs
/// `CkksHybridRelinKeyGenerator::round_1`, over `Q·P`:
/// `h0[j] = -a_j·u + P·g_j·s + e0[j]`, `h1[j] = a_j·s + e1[j]`. Returns
/// the share in the wire framing (so it decodes as a
/// [`CkksHybridRelinKeyShare<R1>`]). Used by the witness tests and the
/// config/witness example because fhe.rs does not expose the generator's
/// sampled `u`/`e0`/`e1` (see the module docs).
pub fn compute_round_1_share(
    params: &std::sync::Arc<fhe::ckks::CkksParameters>,
    crp: &[CkksQpPoly],
    sk_coeffs: &[i64],
    u_coeffs: &[i64],
    e0_coeffs: &[Vec<i64>],
    e1_coeffs: &[Vec<i64>],
) -> Result<CkksHybridRelinKeyShare<R1>, CircuitsErrors> {
    use fhe_math::rq::{traits::TryConvertFrom, Ntt, Poly, PowerBasis};
    let err = |e: fhe::Error| CircuitsErrors::Other(e.to_string());
    let ctx_q = params.context_at_level(0).map_err(err)?.clone();
    let ctx_p = params.context_p().map_err(err)?.clone();
    let gadget = hybrid_gadget(params)?;
    let to_ntt = |ctx: &std::sync::Arc<fhe_math::rq::Context>, c: &[i64]| -> Poly<Ntt> {
        let mut p = Poly::<PowerBasis>::try_convert_from(c, ctx, false)
            .expect("small coefficients convert")
            .into_ntt();
        unsafe { p.allow_variable_time_computations() };
        p
    };
    let s_q = to_ntt(&ctx_q, sk_coeffs);
    let s_p = to_ntt(&ctx_p, sk_coeffs);
    let u_q = to_ntt(&ctx_q, u_coeffs);
    let u_p = to_ntt(&ctx_p, u_coeffs);
    let vt = |p: &Poly<Ntt>| {
        let mut p = p.clone();
        unsafe { p.allow_variable_time_computations() };
        p
    };
    let mut h0 = Vec::with_capacity(crp.len());
    let mut h1 = Vec::with_capacity(crp.len());
    for (j, a) in crp.iter().enumerate() {
        let (a_q, a_p) = (vt(a.q()), vt(a.p()));
        // h0 = -a*u + P*g_j*s + e0
        let mut h0_q = -&(&a_q * &u_q);
        h0_q += &(&s_q * &gadget[j]);
        h0_q += &to_ntt(&ctx_q, &e0_coeffs[j]);
        let mut h0_p = -&(&a_p * &u_p);
        h0_p += &to_ntt(&ctx_p, &e0_coeffs[j]);
        // h1 = a*s + e1
        let mut h1_q = &a_q * &s_q;
        h1_q += &to_ntt(&ctx_q, &e1_coeffs[j]);
        let mut h1_p = &a_p * &s_p;
        h1_p += &to_ntt(&ctx_p, &e1_coeffs[j]);
        h0.push((h0_q, h0_p));
        h1.push((h1_q, h1_p));
    }
    // Serialize in the hybrid wire framing (`0xfffffffe ‖ dnum ‖ L ‖ k ‖
    // (len ‖ poly)*`, h0 first then h1, each as `q` then `p`) and decode
    // through fhe.rs so the result IS a `CkksHybridRelinKeyShare<R1>`.
    use fhe_traits::Serialize as _;
    let mut out = Vec::new();
    out.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
    out.extend_from_slice(&(crp.len() as u32).to_le_bytes());
    out.extend_from_slice(&(params.moduli().len() as u32).to_le_bytes());
    out.extend_from_slice(&(params.special_moduli().len() as u32).to_le_bytes());
    let mut push = |p: &Poly<Ntt>| {
        let b = p.to_bytes();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&b);
    };
    for (q, p) in &h0 {
        push(q);
        push(p);
    }
    for (q, p) in &h1 {
        push(q);
        push(p);
    }
    CkksHybridRelinKeyShare::<R1>::from_bytes(&out, params).map_err(err)
}

/// Codegen: emits `circuits/lib/src/configs/ckks_relin_round1_hybrid.nr`.
pub fn generate_configs_nr(configs: &Configs) -> String {
    let join = |it: &mut dyn Iterator<Item = String>| it.collect::<Vec<_>>().join(", ");
    let qis = join(&mut configs.moduli.iter().map(|q| q.to_string()));
    let gadget = join(&mut configs.gadget.iter().map(|g| g.to_string()));
    let r1b = join(&mut configs.bounds.r1_bounds.iter().map(|b| b.to_string()));
    let r2b = join(&mut configs.bounds.r2_bounds.iter().map(|b| b.to_string()));
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers relin_round1_hybrid_ckks codegen
// (example gen_ckks_c8_hybrid_prover). Do not hand-edit.
//
// GADGET holds the constants `(P * g_j) mod q_l` at index `j * LT + l`
// over the Q.P limbs (L ciphertext moduli, then k special primes, where
// the entries are 0). ONE config serves every level: the hybrid key is
// generated once at level 0.

use crate::core::threshold::relin_round1_hybrid_ckks::Configs as RelinRound1HybridConfigs;

/************************************
-------------------------------------
relin_round1_hybrid_ckks (CIRCUIT 8-CKKS, hybrid gadget)
-------------------------------------
************************************/

pub global RELIN_ROUND1_HYBRID_CKKS_N: u32 = {n};
pub global RELIN_ROUND1_HYBRID_CKKS_D: u32 = {d};
pub global RELIN_ROUND1_HYBRID_CKKS_LT: u32 = {lt};
pub global RELIN_ROUND1_HYBRID_CKKS_QIS: [Field; RELIN_ROUND1_HYBRID_CKKS_LT] = [{qis}];
pub global RELIN_ROUND1_HYBRID_CKKS_GADGET: [Field; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT] =
    [{gadget}];

pub global RELIN_ROUND1_HYBRID_CKKS_BIT_A: u32 = {a_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_SK: u32 = {sk_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_U: u32 = {u_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_E: u32 = {e_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_R1: u32 = {r1_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_R2: u32 = {r2_bit};
pub global RELIN_ROUND1_HYBRID_CKKS_BIT_H: u32 = {h_bit};

pub global RELIN_ROUND1_HYBRID_CKKS_SK_BOUND: Field = {sk_bound};
pub global RELIN_ROUND1_HYBRID_CKKS_U_BOUND: Field = {u_bound};
pub global RELIN_ROUND1_HYBRID_CKKS_E_BOUND: Field = {e_bound};
pub global RELIN_ROUND1_HYBRID_CKKS_R1_BOUNDS: [Field; RELIN_ROUND1_HYBRID_CKKS_LT] = [{r1b}];
pub global RELIN_ROUND1_HYBRID_CKKS_R2_BOUNDS: [Field; RELIN_ROUND1_HYBRID_CKKS_LT] = [{r2b}];

pub global RELIN_ROUND1_HYBRID_CKKS_CONFIGS: RelinRound1HybridConfigs<RELIN_ROUND1_HYBRID_CKKS_D, RELIN_ROUND1_HYBRID_CKKS_LT> = RelinRound1HybridConfigs::new(
    RELIN_ROUND1_HYBRID_CKKS_QIS,
    RELIN_ROUND1_HYBRID_CKKS_GADGET,
    RELIN_ROUND1_HYBRID_CKKS_SK_BOUND,
    RELIN_ROUND1_HYBRID_CKKS_U_BOUND,
    RELIN_ROUND1_HYBRID_CKKS_E_BOUND,
    RELIN_ROUND1_HYBRID_CKKS_R1_BOUNDS,
    RELIN_ROUND1_HYBRID_CKKS_R2_BOUNDS,
);
"#,
        n = configs.n,
        d = configs.d,
        lt = configs.lt,
        qis = qis,
        gadget = gadget,
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

/// Native check of the circuit's core constraints for every `(j, l)`:
/// both round-1 relations hold mod `q_l`, mod `x^N + 1`. Runs the whole
/// witness pipeline, so it also exercises the quotient decomposition.
pub fn verify_ckks_hybrid_relin_round1_constraints(
    preset: &CkksPreset,
    data: &CkksHybridRelinRound1Data,
) -> Result<(), CircuitsErrors> {
    let _ = Inputs::compute(preset.clone(), data)?;
    Ok(())
}

/// Sample the secrets of one round-1 share the way the generator does:
/// `u`, `e0[j]`, `e1[j]` are CBD with the parameter variance.
pub fn sample_round_1_secrets<R: rand::RngCore + rand::CryptoRng>(
    params: &fhe::ckks::CkksParameters,
    rng: &mut R,
) -> (Vec<i64>, Vec<Vec<i64>>, Vec<Vec<i64>>) {
    let cbd = |rng: &mut R| {
        fhe_util::sample_vec_cbd(params.degree(), params.variance(), rng).expect("cbd")
    };
    let u = cbd(rng);
    let e0 = (0..params.dnum()).map(|_| cbd(rng)).collect();
    let e1 = (0..params.dnum()).map(|_| cbd(rng)).collect();
    (u, e0, e1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::ckks::{CkksParametersBuilder, CkksSecretKey};
    use fhe::trckks::{CkksCrp, CkksHybridRelinKeyGenerator};
    use std::sync::Arc;

    /// Small hybrid preset for unit tests: 4 ladder-shaped limbs + 2
    /// special primes (dnum = 2).
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

    fn recomputed_data(preset: &CkksPreset) -> CkksHybridRelinRound1Data {
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let crp = CkksCrp::vec_from_seed_qp(&params, [3u8; 32]).unwrap();
        let (u, e0, e1) = sample_round_1_secrets(&params, &mut rng);
        let share = compute_round_1_share(&params, &crp, sk.coeffs.as_ref(), &u, &e0, &e1)
            .expect("recomputed share");
        CkksHybridRelinRound1Data {
            crp,
            share,
            sk_coeffs: sk.coeffs.to_vec(),
            u_coeffs: u,
            e0_coeffs: e0,
            e1_coeffs: e1,
        }
    }

    /// The gadget constants replicate fhe.rs EXACTLY: a REAL
    /// `CkksHybridRelinKeyGenerator::round_1` share (fresh unknown `u`,
    /// `e0`, `e1`) satisfies `h1[j] − a_j·s = e1[j]` (small on every limb
    /// of Q·P — no gadget involved, pins the CRP/limb/NTT plumbing) AND
    /// the gadget identity `Σ_j digit_j(c)·g_j ≡ c (mod Q)` holds for the
    /// recomputed `g_j` (with `P·g_j = gadget·P^{-1}`… checked directly:
    /// `(P·g_j)·P^{-1} ≡ 1 (mod D_j)` and `≡ 0` on the other limbs), so
    /// the constants that scale `s` in `h0` are the generator's.
    #[test]
    fn hybrid_gadget_matches_fhe_rs() {
        let preset = preset();
        let params = preset.params.clone();
        let q_moduli = params.moduli();
        let p_big = params
            .special_moduli()
            .iter()
            .fold(BigUint::one(), |acc, p| acc * BigUint::from(*p));
        let gadget = hybrid_gadget(&params).unwrap();
        assert_eq!(gadget.len(), params.dnum());
        let alpha = params.digit_size();
        // (P·g_j)·P^{-1} ≡ 1 on digit j's limbs, 0 elsewhere.
        for (j, pg) in gadget.iter().enumerate() {
            for (i, &q) in q_moduli.iter().enumerate() {
                let qb = BigUint::from(q);
                let p_inv = (&p_big % &qb).modinv(&qb).unwrap();
                let v = (pg % &qb) * p_inv % &qb;
                let in_digit = (j * alpha..((j + 1) * alpha).min(q_moduli.len())).contains(&i);
                assert_eq!(v, BigUint::from(u64::from(in_digit)), "digit {j} limb {i}");
            }
        }
        // Plumbing against a REAL generator share: h1 − a·s is small.
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let crp = CkksCrp::vec_from_seed_qp(&params, [5u8; 32]).unwrap();
        let generator = CkksHybridRelinKeyGenerator::new(&sk, &crp, &mut rng).unwrap();
        let share = generator.round_1(&mut rng).unwrap();
        let moduli = qp_moduli(&params).unwrap();
        let l = q_moduli.len();
        let s_poly = {
            let mut c: Vec<BigInt> = sk.coeffs.iter().map(|&x| BigInt::from(x)).collect();
            c.reverse();
            Polynomial::new(c)
        };
        let cyclo = cyclotomic_polynomial(params.degree() as u64);
        let e_bound = BigInt::from((params.variance() * 2) as u64);
        for (j, (a_j, h1_j)) in crp.iter().zip(share.h1().iter()).enumerate() {
            let a_crt = qp_to_crt(a_j, &moduli, l).unwrap();
            let h1_crt = qp_to_crt(h1_j, &moduli, l).unwrap();
            for (limb, &ql) in moduli.iter().enumerate() {
                let ql = BigInt::from(ql);
                let mut diff = h1_crt
                    .limb(limb)
                    .sub(&a_crt.limb(limb).mul(&s_poly))
                    .reduce_by_cyclotomic(&cyclo)
                    .unwrap();
                diff.reduce(&ql);
                diff.center(&ql);
                for c in diff.coefficients() {
                    assert!(
                        c.magnitude() <= e_bound.magnitude(),
                        "digit {j} limb {limb}: h1 - a*s not small ({c})"
                    );
                }
            }
        }
    }

    /// A recomputed share (public gadget math, sampled secrets) decodes as
    /// a real `CkksHybridRelinKeyShare<R1>`, aggregates with a REAL
    /// generator share, and satisfies the C8-hybrid constraints end to
    /// end with every quotient inside the emitted bounds.
    #[test]
    fn ckks_hybrid_relin_round1_witnesses_satisfy_constraints() {
        let preset = preset();
        let data = recomputed_data(&preset);
        // Interoperates with fhe.rs aggregation (same shape/params).
        let mut rng = rand::rng();
        let sk2 = CkksSecretKey::random(&preset.params, &mut rng);
        let other = CkksHybridRelinKeyGenerator::new(&sk2, &data.crp, &mut rng)
            .unwrap()
            .round_1(&mut rng)
            .unwrap();
        fhe::trckks::CkksHybridRelinKeyShare::<fhe::trckks::R1Aggregated>::from_shares(vec![
            data.share.clone(),
            other,
        ])
        .expect("recomputed share aggregates with a real one");

        let inputs = Inputs::compute(preset.clone(), &data).expect("share verifies");
        let bounds = Bounds::compute(preset.clone(), &()).unwrap();
        let lt = qp_moduli(&preset.params).unwrap().len();
        let d = preset.params.dnum();
        assert_eq!(inputs.a.limbs.len(), d * lt);
        for idx in 0..d * lt {
            let l = idx % lt;
            for c in inputs.r1_h0.limb(idx).coefficients() {
                assert!(c.magnitude() <= bounds.r1_bounds[l].magnitude());
            }
            for c in inputs.r2_h0.limb(idx).coefficients() {
                assert!(c.magnitude() <= bounds.r2_bounds[l].magnitude());
            }
            for c in inputs.r1_h1.limb(idx).coefficients() {
                assert!(c.magnitude() <= bounds.r1_bounds[l].magnitude());
            }
            for c in inputs.r2_h1.limb(idx).coefficients() {
                assert!(c.magnitude() <= bounds.r2_bounds[l].magnitude());
            }
        }
        for c in inputs.u.coefficients() {
            assert!(c.magnitude() <= bounds.u_bound.magnitude());
        }
    }

    /// A tampered witness (one secret-key coefficient flipped) is
    /// rejected by the native congruence pre-check, attributably.
    #[test]
    fn ckks_hybrid_relin_round1_tampered_share_is_rejected() {
        let preset = preset();
        let mut bad = recomputed_data(&preset);
        bad.sk_coeffs[3] += 1;
        let err = verify_ckks_hybrid_relin_round1_constraints(&preset, &bad)
            .expect_err("tampered witness must be rejected");
        assert!(
            format!("{err:?}").contains("relation does not hold"),
            "expected attributable congruence failure, got {err:?}"
        );
        // And a wrong `u` (the h0 leg only) too.
        let mut bad_u = recomputed_data(&preset);
        bad_u.u_coeffs[0] += 1;
        let err = verify_ckks_hybrid_relin_round1_constraints(&preset, &bad_u).unwrap_err();
        assert!(format!("{err:?}").contains("h0 relation"));
    }

    /// The ParamSet-2 config (39 Q limbs + 3 P limbs… 38 + 3 = 41 limbs,
    /// dnum 13) is well formed: every gadget entry on a special-prime limb
    /// is 0, the digit-size math matches fhe.rs.
    #[test]
    fn param_set_2_hybrid_configs_shape() {
        let preset =
            crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set(2).unwrap();
        let configs = Configs::compute(preset.clone(), &()).unwrap();
        assert_eq!(configs.d, 13);
        assert_eq!(configs.lt, 38 + 3);
        assert_eq!(configs.gadget.len(), 13 * 41);
        let l = preset.params.moduli().len();
        for j in 0..configs.d {
            for lmb in l..configs.lt {
                assert_eq!(configs.gadget[j * configs.lt + lmb], BigInt::from(0));
            }
        }
        let nr = generate_configs_nr(&configs);
        assert!(nr.contains("RELIN_ROUND1_HYBRID_CKKS_D: u32 = 13"));
        let _ = Arc::clone(&preset.params);
    }

    /// STRONGEST fhe.rs-equality pin for the `h0` gadget constant: a full
    /// 2-party ceremony where party 1's round 1 is RECOMPUTED here (public
    /// gadget math) and party 2's comes from the real generator, then
    /// both round 2s from real generators — the aggregated
    /// `CkksHybridRelinKey` must relinearize a product correctly. A wrong
    /// `P·g_j` in the recomputed `h0` would yield a key that fails to
    /// decrypt the square.
    #[test]
    fn recomputed_round_1_yields_a_working_joint_key() {
        use fhe::ckks::{CkksEncoder, CkksHybridRelinKey};
        use fhe::trckks::{CkksHybridRelinKeyShare, R1Aggregated, R2};
        let preset = preset();
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let sk1 = CkksSecretKey::random(&params, &mut rng);
        let sk2 = CkksSecretKey::random(&params, &mut rng);
        let crp = CkksCrp::vec_from_seed_qp(&params, [7u8; 32]).unwrap();

        // Party 1: recomputed round 1 (our math) but the SAME u must be
        // used in round 2 — so party 1's round 2 is recomputed too:
        // h0' = h0_agg·s_1 + e, h1' = h1_agg·(u_1 − s_1) + e. Party 2 is
        // the real generator end to end.
        let (u1, e0, e1) = sample_round_1_secrets(&params, &mut rng);
        let r1_1 =
            compute_round_1_share(&params, &crp, sk1.coeffs.as_ref(), &u1, &e0, &e1).unwrap();
        let g2 = CkksHybridRelinKeyGenerator::new(&sk2, &crp, &mut rng).unwrap();
        let r1_2 = g2.round_1(&mut rng).unwrap();
        let r1_agg = Arc::new(
            CkksHybridRelinKeyShare::<R1Aggregated>::from_shares(vec![r1_1, r1_2]).unwrap(),
        );
        let r2_2 = g2.round_2(&r1_agg, &mut rng).unwrap();
        // Party 1 round 2 via the same public arithmetic.
        let r2_1 = {
            use fhe_math::rq::{traits::TryConvertFrom, Ntt, Poly, PowerBasis};
            use fhe_traits::Serialize as _;
            let ctx_q = params.context_at_level(0).unwrap().clone();
            let ctx_p = params.context_p().unwrap().clone();
            let to_ntt = |ctx: &Arc<fhe_math::rq::Context>, c: &[i64]| -> Poly<Ntt> {
                let mut p = Poly::<PowerBasis>::try_convert_from(c, ctx, false)
                    .unwrap()
                    .into_ntt();
                unsafe { p.allow_variable_time_computations() };
                p
            };
            let vt = |p: &Poly<Ntt>| {
                let mut p = p.clone();
                unsafe { p.allow_variable_time_computations() };
                p
            };
            let s_q = to_ntt(&ctx_q, sk1.coeffs.as_ref());
            let s_p = to_ntt(&ctx_p, sk1.coeffs.as_ref());
            let ums: Vec<i64> = u1
                .iter()
                .zip(sk1.coeffs.iter())
                .map(|(u, s)| u - s)
                .collect();
            let ums_q = to_ntt(&ctx_q, &ums);
            let ums_p = to_ntt(&ctx_p, &ums);
            let (mut e_q, mut e_p) = (vec![], vec![]);
            let mut out = Vec::new();
            out.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
            out.extend_from_slice(&(crp.len() as u32).to_le_bytes());
            out.extend_from_slice(&(params.moduli().len() as u32).to_le_bytes());
            out.extend_from_slice(&(params.special_moduli().len() as u32).to_le_bytes());
            let cbd = |rng: &mut rand::rngs::ThreadRng| {
                fhe_util::sample_vec_cbd(params.degree(), params.variance(), rng).unwrap()
            };
            for _ in 0..crp.len() {
                let e = cbd(&mut rng);
                e_q.push(to_ntt(&ctx_q, &e));
                e_p.push(to_ntt(&ctx_p, &e));
            }
            let mut push = |p: &Poly<Ntt>| {
                let b = p.to_bytes();
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(&b);
            };
            for (j, h) in r1_agg.h0().iter().enumerate() {
                let mut q = &vt(h.q()) * &s_q;
                q += &e_q[j];
                let mut p = &vt(h.p()) * &s_p;
                p += &e_p[j];
                push(&q);
                push(&p);
            }
            for h in r1_agg.h1().iter() {
                let e = cbd(&mut rng);
                let mut q = &vt(h.q()) * &ums_q;
                q += &to_ntt(&ctx_q, &e);
                let mut p = &vt(h.p()) * &ums_p;
                p += &to_ntt(&ctx_p, &e);
                push(&q);
                push(&p);
            }
            CkksHybridRelinKeyShare::<R2>::from_bytes(&out, &params).unwrap()
        };
        let key =
            CkksHybridRelinKeyShare::<R2>::aggregate_into_key_with_r1(vec![r2_1, r2_2], r1_agg)
                .unwrap();
        let key = CkksHybridRelinKey::from_bytes(&key.to_bytes(), &params).unwrap();

        // Joint secret decrypts a relinearized square.
        let joint: Vec<i64> = sk1
            .coeffs
            .iter()
            .zip(sk2.coeffs.iter())
            .map(|(a, b)| a + b)
            .collect();
        let sk = CkksSecretKey::new(joint, &params);
        let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();
        let encoder = CkksEncoder::new(&params);
        let x = 1.25f64;
        let ct = pk
            .try_encrypt(&encoder.encode(&[x], 0).unwrap(), &mut rng)
            .unwrap();
        let mut sq = ct.try_mul(&ct).unwrap();
        key.relinearizes(&mut sq).unwrap();
        sq.rescale().unwrap();
        let got = encoder.decode(&sk.try_decrypt(&sq).unwrap()).unwrap()[0];
        assert!((got - x * x).abs() < 1e-3, "{got} vs {}", x * x);
    }
}
