// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C1-CKKS: threshold public-key SHARE proof for CKKS.
//!
//! Proves one party's CKKS public-key contribution
//! (fhe.rs [`fhe::trckks::CkksPublicKeyShare::new`]) is well formed over
//! the CKKS moduli, from hidden `sk`, `e` and quotients:
//!
//! `pk0 = -a * sk + e  (mod q_i, mod x^N + 1)` for every limb `i`,
//!
//! where `a` is the E3's CRP ([`fhe::trckks::CkksCrp::from_seed`]). This
//! is the BFV C1 relation (`pk_generation.nr`) with CKKS constants and a
//! SEED-DERIVED CRP: `a` is a witness that the pk-share commitment binds
//! (`compute_ckks_threshold_pk_commitment(pk0 || a)`), where BFV C1 bakes
//! `CRP` into the config.
//!
//! Commitment contract (what the sibling links on):
//! - `sk_commitment = compute_share_computation_sk_commitment(sk, BIT_SK)`
//!   with `BIT_SK = calculate_bit_width(CkksSecretKey::sk_bound())` — the
//!   SAME function, domain (`DS_SHARE_COMPUTATION`) and bit width as the
//!   C2a-CKKS witness (`share_computation_ckks::compute_ckks_share_inputs`,
//!   `DkgInputType::SecretKey` arm) and the value C6-CKKS's
//!   `expected_sk_commitment`-shaped link expects for the dealer secret.
//! - `e_sm_commitment = compute_share_computation_e_sm_commitment(e_sm, BIT_E_SM)`
//!   over the SAME small integer polynomial reduced on every limb, with
//!   `BIT_E_SM = calculate_bit_width(2^CKKS_PK_GENERATION_SMUDGING_BITS)`.
//!   C2b-CKKS derives its bit width from the witness's maximum centered
//!   coefficient; a link on this value needs both sides on the bound-derived
//!   width (see `CKKS_PK_GENERATION_SMUDGING_BITS`).
//!
//! HONEST SCOPE (fhe.rs API gap, same as C8-hybrid): `CkksPublicKeyShare::new`
//! samples `e` internally and exposes neither it nor an `_extended` variant,
//! so a share the fork produced cannot be witnessed from outside fhe.rs. The
//! builder takes `e` explicitly ([`CkksPkGenerationData`]) and
//! [`compute_pk_share`] rebuilds the share with the public math (pinned
//! against a real `CkksPublicKeyShare::new` share: `p0 + a*s` is small).
//! Needed fhe.rs API: `CkksPublicKeyShare::new_extended(sk, crp, rng) ->
//! (share, e_coeffs)`.

use crate::circuits::commitments::{
    compute_ckks_threshold_pk_commitment, compute_share_computation_e_sm_commitment,
    compute_share_computation_sk_commitment,
};
use crate::circuits::computation::Computation;
use crate::circuits::errors::CircuitsErrors;
use crate::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use crate::{calculate_bit_width, crt_polynomial_to_toml_json, polynomial_to_toml_json};
use crate::{cyclotomic_polynomial, decompose_residue};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::ckks::{CkksParameters, CkksSecretKey};
use fhe::trckks::{CkksCrp, CkksPublicKeyShare};
use fhe_math::rq::{Ntt, Poly, PowerBasis};
use num_bigint::BigInt;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Smudging-noise magnitude (bits) the CKKS keyshare deals
/// (`generate_smudging_error(bits)` samples uniformly in `[-2^bits, 2^bits]`).
/// MUST equal the node's `CKKS_SMUDGING_BITS` (keyshare `ckks_shell.rs`);
/// the circuit's `e_sm_bound = 2^bits` is baked into every
/// `ckks_pk_generation_ps*.nr` config.
pub const CKKS_PK_GENERATION_SMUDGING_BITS: usize = 20;

/// Witness data for one party's C1-CKKS proof.
pub struct CkksPkGenerationData {
    /// The E3's CRP (`CkksCrp::from_seed(params, e3_seed)`).
    pub crp: CkksCrp,
    /// This party's public-key share (`pk0 = -a*sk + e`).
    pub pk_share: CkksPublicKeyShare,
    /// This party's secret contribution coefficients (CBD(0.5), |c| <= 1).
    pub sk_coeffs: Vec<i64>,
    /// The key-generation error `e` coefficients (CBD with the parameter
    /// variance, |c| <= 2*variance).
    pub e_coeffs: Vec<i64>,
    /// This party's smudging contribution coefficients (the C2b-CKKS
    /// witness, |c| <= 2^[`CKKS_PK_GENERATION_SMUDGING_BITS`]).
    pub e_sm_coeffs: Vec<i64>,
}

/// Circuit identifier for CKKS threshold public-key share generation
/// (Noir circuit `pk_generation_ckks`, C1-CKKS).
#[derive(Debug)]
pub struct CkksPkGenerationCircuit;

impl crate::registry::Circuit for CkksPkGenerationCircuit {
    const NAME: &'static str = "pk-generation-ckks";
    const PREFIX: &'static str = "PK_GENERATION_CKKS";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub eek_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub pk_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub eek_bound: BigInt,
    pub sk_bound: BigInt,
    pub e_sm_bound: BigInt,
    pub r1_bounds: Vec<BigInt>,
    pub r2_bounds: Vec<BigInt>,
}

impl Computation for Bounds {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Same envelope as BFV C1 over the CKKS moduli: `r2` in `±(q_i-1)/2`,
    /// `r1 = ((N + 2)*qi_bound + e_bound) / q_i` (the `a*sk` convolution
    /// with `|sk| <= 1` plus the residue slack).
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let n = BigInt::from(params.degree());
        let sk_bound = BigInt::from(CkksSecretKey::sk_bound() as i64);
        let eek_bound = BigInt::from((params.variance() * 2) as u64);
        let e_sm_bound = BigInt::from(1u64) << CKKS_PK_GENERATION_SMUDGING_BITS;

        let mut r1_bounds = Vec::new();
        let mut r2_bounds = Vec::new();
        for &qi in params.moduli() {
            let qi_bigint = BigInt::from(qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);
            r2_bounds.push(qi_bound.clone());
            r1_bounds.push(((&n + BigInt::from(2)) * &qi_bound + &eek_bound) / &qi_bigint);
        }
        Ok(Bounds {
            eek_bound,
            sk_bound,
            e_sm_bound,
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
        let max_bit = |bounds: &[BigInt]| {
            bounds
                .iter()
                .map(|b| calculate_bit_width(b.clone()))
                .max()
                .unwrap_or(0)
        };
        // Widest `(q_i - 1) / 2` — the CKKS analogue of `compute_modulus_bit`.
        let pk_bit = preset
            .params
            .moduli()
            .iter()
            .map(|&q| calculate_bit_width(BigInt::from((q - 1) / 2)))
            .max()
            .unwrap_or(0);
        Ok(Bits {
            eek_bit: calculate_bit_width(data.eek_bound.clone()),
            sk_bit: calculate_bit_width(data.sk_bound.clone()),
            e_sm_bit: calculate_bit_width(data.e_sm_bound.clone()),
            r1_bit: max_bit(&data.r1_bounds),
            r2_bit: max_bit(&data.r2_bounds),
            pk_bit,
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
        Ok(Configs {
            n: preset.params.degree(),
            l: preset.params.moduli().len(),
            moduli: preset.params.moduli().to_vec(),
            bits,
            bounds,
        })
    }
}

/// The circuit witness inputs (same field layout as BFV C1 plus the CRP `a`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub a: CrtPolynomial,
    pub eek: Polynomial,
    pub sk: Polynomial,
    pub e_sm: CrtPolynomial,
    pub r1is: CrtPolynomial,
    pub r2is: CrtPolynomial,
    pub pk0is: CrtPolynomial,
    pub sk_commitment: BigInt,
    pub pk_commitment: BigInt,
    pub e_sm_commitment: BigInt,
}

/// Descending-degree copy of small integer coefficients (the circuit's
/// `Polynomial<N>` layout).
fn small_poly(coeffs: &[i64]) -> Polynomial {
    let mut c: Vec<BigInt> = coeffs.iter().map(|&x| BigInt::from(x)).collect();
    c.reverse();
    Polynomial::new(c)
}

/// The share's `p0` polynomial (power basis) decoded from its wire bytes.
fn share_p0_power_basis(
    params: &Arc<CkksParameters>,
    pk_share: &CkksPublicKeyShare,
) -> Result<Poly<PowerBasis>, CircuitsErrors> {
    use fhe_traits::DeserializeWithContext;
    let ctx = params
        .context_at_level(0)
        .map_err(|e| CircuitsErrors::Other(format!("level-0 context: {e}")))?;
    let p0 = Poly::<Ntt>::from_bytes(&pk_share.p0_to_bytes(), ctx)
        .map_err(|e| CircuitsErrors::Other(format!("pk share p0 decode: {e}")))?;
    Ok(p0.into_power_basis())
}

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = CkksPkGenerationData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let moduli_u64 = params.moduli().to_vec();
        let moduli: Vec<BigInt> = moduli_u64.iter().copied().map(BigInt::from).collect();
        let n = params.degree() as u64;
        let nn = n as usize;

        for (name, c) in [
            ("sk", &data.sk_coeffs),
            ("e", &data.e_coeffs),
            ("e_sm", &data.e_sm_coeffs),
        ] {
            if c.len() != nn {
                return Err(CircuitsErrors::Other(format!(
                    "C1-CKKS {name} must have N = {nn} coefficients, got {}",
                    c.len()
                )));
            }
        }

        // CRP + share to reversed/centered CRT limbs (circuit layout).
        let mut a = CrtPolynomial::from_fhe_polynomial(&data.crp.poly().clone().into_power_basis());
        a.reverse();
        a.center(&moduli_u64)
            .map_err(|e| CircuitsErrors::Other(format!("crp center: {e}")))?;
        let mut pk0 =
            CrtPolynomial::from_fhe_polynomial(&share_p0_power_basis(params, &data.pk_share)?);
        pk0.reverse();
        pk0.center(&moduli_u64)
            .map_err(|e| CircuitsErrors::Other(format!("pk0 center: {e}")))?;

        let sk = small_poly(&data.sk_coeffs);
        let eek = small_poly(&data.e_coeffs);
        let e_sm_small = small_poly(&data.e_sm_coeffs);
        let cyclo = cyclotomic_polynomial(n);

        // Native congruence pre-check BEFORE decompose_residue so a bad
        // share fails attributably instead of panicking in the helper.
        let native_check = |lhs: &Polynomial,
                            hat: &Polynomial,
                            qi: &BigInt,
                            i: usize|
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
                if (((x - y) % qi) + qi) % qi != BigInt::from(0) {
                    return Err(CircuitsErrors::Other(format!(
                        "C1-CKKS share inconsistent at limb {i} coeff {ii}: \
                             pk0 != -a*sk + e (mod q)"
                    )));
                }
            }
            Ok(())
        };

        #[allow(clippy::type_complexity)]
        let mut results: Vec<
            Result<(usize, Polynomial, Polynomial, Polynomial), CircuitsErrors>,
        > = moduli
            .iter()
            .enumerate()
            .par_bridge()
            .map(|(i, qi)| {
                let a_i = a.limb(i);
                let pk0_i = pk0.limb(i);
                // pk0_hat = -a * sk + e  (lifted to Z)
                let pk0_hat = a_i.neg().mul(&sk).add(&eek);
                native_check(pk0_i, &pk0_hat, qi, i)?;
                let (r1, r2) = decompose_residue(pk0_i, &pk0_hat, qi, &cyclo, n);
                // e_sm reduced on this limb: the same small integers, centered.
                let mut e_sm_i = e_sm_small.clone();
                e_sm_i.reduce(qi);
                e_sm_i.center(qi);
                Ok((i, r1, r2, e_sm_i))
            })
            .collect();
        results.sort_by_key(|r| r.as_ref().map(|(i, ..)| *i).unwrap_or(usize::MAX));

        let mut r1is = CrtPolynomial::new(vec![]);
        let mut r2is = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);
        for r in results {
            let (_i, r1, r2, e_sm_i) = r?;
            r1is.add_limb(r1);
            r2is.add_limb(r2);
            e_sm.add_limb(e_sm_i);
        }

        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        let sk_commitment = compute_share_computation_sk_commitment(&sk, bits.sk_bit);
        let e_sm_commitment = compute_share_computation_e_sm_commitment(&e_sm, bits.e_sm_bit);
        let pk_commitment = compute_ckks_threshold_pk_commitment(&pk0, &a, bits.pk_bit);

        Ok(Inputs {
            a,
            eek,
            sk,
            e_sm,
            r1is,
            r2is,
            pk0is: pk0,
            sk_commitment,
            pk_commitment,
            e_sm_commitment,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "a": crt_polynomial_to_toml_json(&self.a),
            "eek": polynomial_to_toml_json(&self.eek),
            "sk": polynomial_to_toml_json(&self.sk),
            "e_sm": crt_polynomial_to_toml_json(&self.e_sm),
            "r1is": crt_polynomial_to_toml_json(&self.r1is),
            "r2is": crt_polynomial_to_toml_json(&self.r2is),
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
        }))
    }
}

/// The C1-CKKS `pk_commitment` an aggregator must find in a party's proof
/// for the pk-share bytes it received (`KeyshareCreated.pubkey`, the
/// serialized `p0` at level 0). Uses EXACTLY the witness builder's
/// derivation (`Inputs::compute`): reversed + centered `pk0` and CRP
/// limbs, `compute_ckks_threshold_pk_commitment` at `Bits::pk_bit`.
/// Returns the 32-byte big-endian field encoding Barretenberg emits in
/// `public_signals`.
pub fn compute_ckks_pk_commitment_from_share_bytes(
    preset: &CkksPreset,
    crp: &CkksCrp,
    pk_share_bytes: &[u8],
) -> Result<[u8; 32], CircuitsErrors> {
    use fhe_traits::DeserializeWithContext;
    let params = &preset.params;
    let moduli_u64 = params.moduli().to_vec();
    let ctx = params
        .context_at_level(0)
        .map_err(|e| CircuitsErrors::Other(format!("level-0 context: {e}")))?;
    let p0 = Poly::<Ntt>::from_bytes(pk_share_bytes, ctx)
        .map_err(|e| CircuitsErrors::Other(format!("pk share p0 decode: {e}")))?
        .into_power_basis();
    let mut pk0 = CrtPolynomial::from_fhe_polynomial(&p0);
    pk0.reverse();
    pk0.center(&moduli_u64)
        .map_err(|e| CircuitsErrors::Other(format!("pk0 center: {e}")))?;
    let mut a = CrtPolynomial::from_fhe_polynomial(&crp.poly().clone().into_power_basis());
    a.reverse();
    a.center(&moduli_u64)
        .map_err(|e| CircuitsErrors::Other(format!("crp center: {e}")))?;
    let bounds = Bounds::compute(preset.clone(), &())?;
    let bits = Bits::compute(preset.clone(), &bounds)?;
    let commitment = compute_ckks_threshold_pk_commitment(&pk0, &a, bits.pk_bit);
    let (_, be_bytes) = commitment.to_bytes_be();
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(be_bytes.len());
    padded[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);
    Ok(padded)
}

/// Rebuild a party's public-key share from explicit `sk` and `e` with the
/// PUBLIC math of fhe.rs `CkksPublicKeyShare::new` (`p0 = -a*s + e` over
/// the level-0 context, NTT domain). Returns a real
/// [`CkksPublicKeyShare`] (via `from_parts`) that aggregates with shares
/// the fork produced. Used because fhe.rs does not expose the sampled `e`
/// (see the module docs).
pub fn compute_pk_share(
    params: &Arc<CkksParameters>,
    crp: &CkksCrp,
    sk_coeffs: &[i64],
    e_coeffs: &[i64],
) -> Result<CkksPublicKeyShare, CircuitsErrors> {
    use fhe_math::rq::traits::TryConvertFrom;
    let ctx = params
        .context_at_level(0)
        .map_err(|e| CircuitsErrors::Other(format!("level-0 context: {e}")))?;
    let to_ntt = |c: &[i64]| -> Result<Poly<Ntt>, CircuitsErrors> {
        Ok(Poly::<PowerBasis>::try_convert_from(c, ctx, false)
            .map_err(|e| CircuitsErrors::Other(format!("small poly: {e}")))?
            .into_ntt())
    };
    let s = to_ntt(sk_coeffs)?;
    let e = to_ntt(e_coeffs)?;
    let mut p0 = -crp.poly();
    p0.disallow_variable_time_computations();
    p0 *= &s;
    p0 += &e;
    Ok(CkksPublicKeyShare::from_parts(
        params.clone(),
        p0,
        crp.clone(),
    ))
}

/// Sample the key-generation error the way `CkksPublicKeyShare::new` does
/// (CBD with the parameter variance).
pub fn sample_pk_share_error<R: rand::RngCore + rand::CryptoRng>(
    params: &CkksParameters,
    rng: &mut R,
) -> Vec<i64> {
    fhe_util::sample_vec_cbd(params.degree(), params.variance(), rng).expect("cbd sample")
}

/// Codegen: emits `circuits/lib/src/configs/ckks_pk_generation_ps{set}.nr`
/// (fmt-stable shape; regenerate-and-diff drift guard in the tests).
pub fn generate_configs_nr(param_set: u8, configs: &Configs) -> String {
    let join = |it: &mut dyn Iterator<Item = String>| it.collect::<Vec<_>>().join(", ");
    let qis = join(&mut configs.moduli.iter().map(|q| q.to_string()));
    let r1b = join(&mut configs.bounds.r1_bounds.iter().map(|b| b.to_string()));
    let r2b = join(&mut configs.bounds.r2_bounds.iter().map(|b| b.to_string()));
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers pk_generation_ckks codegen
// (example gen_ckks_c1_prover --param-set {param_set}). Do not hand-edit.
// CKKS on-chain ParamSet {param_set}: N={n}, L={l}.

use crate::core::threshold::pk_generation_ckks::Configs as PkGenerationCkksConfigs;

/************************************
-------------------------------------
pk_generation_ckks (CIRCUIT 1-CKKS, ParamSet {param_set})
-------------------------------------
************************************/

pub global PK_GENERATION_CKKS_N: u32 = {n};
pub global PK_GENERATION_CKKS_L: u32 = {l};
pub global PK_GENERATION_CKKS_QIS: [Field; PK_GENERATION_CKKS_L] = [{qis}];

pub global PK_GENERATION_CKKS_BIT_EEK: u32 = {eek_bit};
pub global PK_GENERATION_CKKS_BIT_SK: u32 = {sk_bit};
pub global PK_GENERATION_CKKS_BIT_E_SM: u32 = {e_sm_bit};
pub global PK_GENERATION_CKKS_BIT_R1: u32 = {r1_bit};
pub global PK_GENERATION_CKKS_BIT_R2: u32 = {r2_bit};
pub global PK_GENERATION_CKKS_BIT_PK: u32 = {pk_bit};

pub global PK_GENERATION_CKKS_EEK_BOUND: Field = {eek_bound};
pub global PK_GENERATION_CKKS_SK_BOUND: Field = {sk_bound};
pub global PK_GENERATION_CKKS_E_SM_BOUND: Field = {e_sm_bound};
pub global PK_GENERATION_CKKS_R1_BOUNDS: [Field; PK_GENERATION_CKKS_L] = [{r1b}];
pub global PK_GENERATION_CKKS_R2_BOUNDS: [Field; PK_GENERATION_CKKS_L] = [{r2b}];

pub global PK_GENERATION_CKKS_CONFIGS: PkGenerationCkksConfigs<PK_GENERATION_CKKS_N, PK_GENERATION_CKKS_L> = PkGenerationCkksConfigs::new(
    PK_GENERATION_CKKS_QIS,
    PK_GENERATION_CKKS_EEK_BOUND,
    PK_GENERATION_CKKS_SK_BOUND,
    PK_GENERATION_CKKS_E_SM_BOUND,
    PK_GENERATION_CKKS_R1_BOUNDS,
    PK_GENERATION_CKKS_R2_BOUNDS,
);
"#,
        param_set = param_set,
        n = configs.n,
        l = configs.l,
        qis = qis,
        eek_bit = configs.bits.eek_bit,
        sk_bit = configs.bits.sk_bit,
        e_sm_bit = configs.bits.e_sm_bit,
        r1_bit = configs.bits.r1_bit,
        r2_bit = configs.bits.r2_bit,
        pk_bit = configs.bits.pk_bit,
        eek_bound = configs.bounds.eek_bound,
        sk_bound = configs.bounds.sk_bound,
        e_sm_bound = configs.bounds.e_sm_bound,
        r1b = r1b,
        r2b = r2b,
    )
}

/// Native check of the circuit's core constraint (`pk0 == -a*sk + e` on
/// every limb) plus the witness bounds. Runs the whole witness pipeline so
/// a bad share fails attributably before a proof request is emitted.
pub fn verify_ckks_pk_generation_constraints(
    preset: &CkksPreset,
    data: &CkksPkGenerationData,
) -> Result<(), CircuitsErrors> {
    let inputs = Inputs::compute(preset.clone(), data)?;
    let bounds = Bounds::compute(preset.clone(), &())?;
    let check = |name: &str, p: &Polynomial, bound: &BigInt| -> Result<(), CircuitsErrors> {
        if p.coefficients()
            .iter()
            .any(|c| c.magnitude() > bound.magnitude())
        {
            return Err(CircuitsErrors::Other(format!(
                "C1-CKKS {name} coefficient exceeds bound {bound}"
            )));
        }
        Ok(())
    };
    check("sk", &inputs.sk, &bounds.sk_bound)?;
    check("e", &inputs.eek, &bounds.eek_bound)?;
    for (i, limb) in inputs.e_sm.limbs.iter().enumerate() {
        check(&format!("e_sm[{i}]"), limb, &bounds.e_sm_bound)?;
        check(
            &format!("r1[{i}]"),
            inputs.r1is.limb(i),
            &bounds.r1_bounds[i],
        )?;
        check(
            &format!("r2[{i}]"),
            inputs.r2is.limb(i),
            &bounds.r2_bounds[i],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
    use fhe::trckks::TRCKKS;

    fn sample_data(preset: &CkksPreset, seed: [u8; 32]) -> CkksPkGenerationData {
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let crp = CkksCrp::from_seed(&params, seed).unwrap();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let e = sample_pk_share_error(&params, &mut rng);
        let pk_share = compute_pk_share(&params, &crp, sk.coeffs.as_ref(), &e).unwrap();
        let trckks = TRCKKS::new(3, 1, params.clone()).unwrap();
        let e_sm: Vec<i64> = trckks
            .generate_smudging_error(CKKS_PK_GENERATION_SMUDGING_BITS, &mut rng)
            .unwrap()
            .iter()
            .map(|c| i64::try_from(c).unwrap())
            .collect();
        CkksPkGenerationData {
            crp,
            pk_share,
            sk_coeffs: sk.coeffs.to_vec(),
            e_coeffs: e,
            e_sm_coeffs: e_sm,
        }
    }

    /// The aggregator-side recomputation from the WIRE bytes equals the
    /// witness builder's `pk_commitment` (same fn, layout, bit width) and
    /// differs for another party's share.
    #[test]
    fn pk_commitment_from_share_bytes_matches_witness_builder() {
        for set in [0u8, 2, 3, 4, 5] {
            let preset = ckks_preset_for_param_set(set).unwrap();
            let data = sample_data(&preset, [3u8; 32]);
            let inputs = Inputs::compute(preset.clone(), &data).unwrap();
            let (_, be) = inputs.pk_commitment.to_bytes_be();
            let mut expected = [0u8; 32];
            expected[32 - be.len()..].copy_from_slice(&be);
            let recomputed = compute_ckks_pk_commitment_from_share_bytes(
                &preset,
                &data.crp,
                &data.pk_share.p0_to_bytes(),
            )
            .unwrap();
            assert_eq!(recomputed, expected, "param set {set}");
            let other = sample_data(&preset, [3u8; 32]);
            let other_c = compute_ckks_pk_commitment_from_share_bytes(
                &preset,
                &other.crp,
                &other.pk_share.p0_to_bytes(),
            )
            .unwrap();
            assert_ne!(other_c, expected, "param set {set}: distinct shares");
            assert!(
                compute_ckks_pk_commitment_from_share_bytes(&preset, &data.crp, b"junk").is_err()
            );
        }
    }

    /// `compute_pk_share` is fhe.rs's math: a REAL `CkksPublicKeyShare::new`
    /// share satisfies `p0 + a*s = e` small on every limb, and a
    /// recomputed share aggregates with a real one into a joint key that
    /// decrypts (round trip under the summed secret).
    #[test]
    fn recomputed_pk_share_matches_fhe_rs() {
        use fhe::ckks::{CkksEncoder, CkksSecretKey};
        let preset = ckks_preset_for_param_set(0).unwrap();
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let crp = CkksCrp::from_seed(&params, [9u8; 32]).unwrap();

        // Real share: p0 + a*s is small.
        let sk = CkksSecretKey::random(&params, &mut rng);
        let real = CkksPublicKeyShare::new(&sk, crp.clone(), &mut rng).unwrap();
        let p0 = share_p0_power_basis(&params, &real).unwrap();
        let mut p0_crt = CrtPolynomial::from_fhe_polynomial(&p0);
        p0_crt.reverse();
        p0_crt.center(params.moduli()).unwrap();
        let mut a_crt = CrtPolynomial::from_fhe_polynomial(&crp.poly().clone().into_power_basis());
        a_crt.reverse();
        a_crt.center(params.moduli()).unwrap();
        let s = small_poly(sk.coeffs.as_ref());
        let cyclo = cyclotomic_polynomial(params.degree() as u64);
        let e_bound = BigInt::from((params.variance() * 2) as u64);
        for (i, &q) in params.moduli().iter().enumerate() {
            let q = BigInt::from(q);
            let mut diff = p0_crt
                .limb(i)
                .add(&a_crt.limb(i).mul(&s))
                .reduce_by_cyclotomic(&cyclo)
                .unwrap();
            diff.reduce(&q);
            diff.center(&q);
            for c in diff.coefficients() {
                assert!(
                    c.magnitude() <= e_bound.magnitude(),
                    "limb {i}: p0 + a*s not small"
                );
            }
        }

        // Recomputed share + real share -> joint key that decrypts under s1 + s2.
        let sk2 = CkksSecretKey::random(&params, &mut rng);
        let e2 = sample_pk_share_error(&params, &mut rng);
        let recomputed = compute_pk_share(&params, &crp, sk2.coeffs.as_ref(), &e2).unwrap();
        let pk = CkksPublicKeyShare::aggregate(&[real, recomputed]).unwrap();
        let joint: Vec<i64> = sk
            .coeffs
            .iter()
            .zip(sk2.coeffs.iter())
            .map(|(a, b)| a + b)
            .collect();
        let joint_sk = CkksSecretKey::new(joint, &params);
        let encoder = CkksEncoder::new(&params);
        let pt = encoder.encode(&[3.5, -1.25], 0).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
        let dec = joint_sk.try_decrypt(&ct).unwrap();
        let vals = encoder.decode(&dec).unwrap();
        assert!(
            (vals[0] - 3.5).abs() < 1e-2 && (vals[1] + 1.25).abs() < 1e-2,
            "{vals:?}"
        );
    }

    /// Every param set's witness satisfies the constraints with quotients
    /// inside the emitted bounds; the sk commitment equals the C2a-CKKS
    /// dealer-secret commitment (same function, domain and bit width).
    #[test]
    fn ckks_pk_generation_witnesses_satisfy_constraints_per_param_set() {
        for set in [0u8, 2, 3, 4, 5] {
            let preset = ckks_preset_for_param_set(set).unwrap();
            let data = sample_data(&preset, [set; 32]);
            verify_ckks_pk_generation_constraints(&preset, &data)
                .unwrap_or_else(|e| panic!("param set {set}: {e:?}"));
            let inputs = Inputs::compute(preset.clone(), &data).unwrap();
            assert_eq!(inputs.a.limbs.len(), preset.params.moduli().len());

            // C2a-CKKS link: identical sk commitment derivation.
            let bit_secret = calculate_bit_width(BigInt::from(CkksSecretKey::sk_bound() as u128));
            let sk_coeffs: Vec<BigInt> = data.sk_coeffs.iter().map(|&c| BigInt::from(c)).collect();
            let mut secret_crt =
                CrtPolynomial::from_mod_q_polynomial(&sk_coeffs, preset.params.moduli());
            secret_crt.center(preset.params.moduli()).unwrap();
            let mut reversed = secret_crt.limb(0).clone();
            reversed.reverse();
            let c2a = compute_share_computation_sk_commitment(&reversed, bit_secret);
            assert_eq!(
                inputs.sk_commitment, c2a,
                "param set {set}: sk commitment link"
            );
        }
    }

    /// Tampered witnesses are rejected attributably: a flipped sk
    /// coefficient (congruence) and an oversized smudging coefficient (bound).
    #[test]
    fn ckks_pk_generation_tampered_witness_is_rejected() {
        let preset = ckks_preset_for_param_set(0).unwrap();
        let mut bad = sample_data(&preset, [1u8; 32]);
        bad.sk_coeffs[5] += 1;
        let err = verify_ckks_pk_generation_constraints(&preset, &bad).unwrap_err();
        assert!(format!("{err:?}").contains("inconsistent"), "{err:?}");

        let mut bad_sm = sample_data(&preset, [1u8; 32]);
        bad_sm.e_sm_coeffs[0] = 1i64 << (CKKS_PK_GENERATION_SMUDGING_BITS + 1);
        let err = verify_ckks_pk_generation_constraints(&preset, &bad_sm).unwrap_err();
        assert!(format!("{err:?}").contains("e_sm"), "{err:?}");
    }

    /// Checked-in configs match fresh codegen. `nargo fmt` re-wraps the
    /// long ParamSet-2 arrays, so the comparison is whitespace-insensitive
    /// (token-identical == same constants).
    #[test]
    fn checked_in_configs_match_codegen() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        // `nargo fmt` re-wraps long arrays and adds trailing commas; compare token
        // content (whitespace- and trailing-comma-insensitive == same constants).
        let strip = |s: &str| {
            s.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .replace(",]", "]")
        };
        for set in [0u8, 2, 3, 4, 5] {
            let preset = ckks_preset_for_param_set(set).unwrap();
            let configs = Configs::compute(preset, &()).unwrap();
            let expected = generate_configs_nr(set, &configs);
            let path = format!("{root}/circuits/lib/src/configs/ckks_pk_generation_ps{set}.nr");
            let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("{path}: {e} (run gen_ckks_c1_prover --param-set {set})")
            });
            assert_eq!(strip(&on_disk), strip(&expected), "drift in {path}");
        }
    }
}
