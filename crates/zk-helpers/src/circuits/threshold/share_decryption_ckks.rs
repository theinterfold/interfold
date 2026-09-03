// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! C6-CKKS: threshold decryption-share proof for CKKS.
//!
//! Proves one party's partial decryption share is consistent with the
//! evaluated ciphertext and the party's aggregated share polynomials:
//!
//! `d_i = ct0 + ct1 * sk_i + e_sm_i  (mod q_j, mod x^N + 1)`
//!
//! This is the SAME algebraic relation as BFV C6 (`share_decryption.nr`)
//! — CKKS's approximate semantics live entirely in the plaintext
//! interpretation, not the share equation — so the circuit core is reused
//! and only the constants (QIS over the CKKS moduli, bounds) change,
//! exactly like C2a/C2b-CKKS. The witness pipeline below mirrors the BFV
//! `share_decryption::computation` with CKKS parameters.
//!
//! Commitments: `expected_sk_commitment` / `expected_e_sm_commitment`
//! bind the aggregated share polynomials (aggregated-shares commitment
//! over the CKKS moduli); `ct_commitment` binds the evaluated ciphertext;
//! the public output is the truncated-`d` commitment C7-CKKS consumes.

use crate::circuits::commitments::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
};
use crate::circuits::computation::Computation;
use crate::circuits::errors::CircuitsErrors;
use crate::circuits::threshold::share_decryption::computation::d_native_trunc_from_centered_d;
use crate::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use crate::crt_polynomial_to_toml_json;
use crate::decompose_residue;
use crate::{calculate_bit_width, compute_native_crt_coeff_bit};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::ckks::CkksCiphertext;
use fhe_math::rq::Poly;
use itertools::izip;
use num_bigint::BigInt;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};

/// Witness data for one party's C6-CKKS proof.
pub struct CkksShareDecryptionData {
    /// The evaluated CKKS ciphertext being opened (2 components).
    pub ciphertext: CkksCiphertext,
    /// This party's aggregated sk share polynomial (PowerBasis).
    pub sk_poly: Poly<fhe_math::rq::PowerBasis>,
    /// This party's aggregated smudging share polynomial (PowerBasis).
    pub es_poly: Poly<fhe_math::rq::PowerBasis>,
    /// This party's computed decryption share (PowerBasis).
    pub d_share: Poly<fhe_math::rq::PowerBasis>,
    /// E3 decryption-domain limbs (bound into the proof context).
    pub domain_hi: u128,
    pub domain_lo: u128,
}

/// Circuit identifier for CKKS threshold share decryption (Noir circuit
/// `share_decryption_ckks`, C6-CKKS).
#[derive(Debug)]
pub struct CkksShareDecryptionCircuit;

impl crate::registry::Circuit for CkksShareDecryptionCircuit {
    const NAME: &'static str = "share-decryption-ckks";
    const PREFIX: &'static str = "SHARE_DECRYPTION_CKKS";
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
    pub ct_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub d_bit: u32,
    pub d_native_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub r1_bounds: Vec<BigInt>,
    pub r2_bounds: Vec<BigInt>,
}

impl Computation for Bounds {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    /// Same derivation as BFV C6 (`share_decryption::Bounds`), over the
    /// CKKS moduli: r2 in ±(q_j-1)/2, r1 from the product bound.
    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let n = BigInt::from(preset.params.degree());
        let mut r1_bounds = Vec::new();
        let mut r2_bounds = Vec::new();
        for &qi in preset.params.moduli() {
            let qi_bigint = BigInt::from(qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);
            r2_bounds.push(qi_bound.clone());
            r1_bounds.push((&qi_bound * &qi_bound * &n + BigInt::from(4) * &qi_bound) / &qi_bigint);
        }
        Ok(Bounds {
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
        let r1_bit = data
            .r1_bounds
            .iter()
            .map(|b| calculate_bit_width(b.clone()))
            .max()
            .unwrap_or(0);
        let r2_bit = data
            .r2_bounds
            .iter()
            .map(|b| calculate_bit_width(b.clone()))
            .max()
            .unwrap_or(0);
        let d_native_bit = compute_native_crt_coeff_bit(preset.params.moduli());
        Ok(Bits {
            ct_bit: r2_bit,
            sk_bit: r2_bit,
            e_sm_bit: r2_bit,
            r1_bit,
            r2_bit,
            d_bit: r2_bit,
            d_native_bit,
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

/// The circuit witness inputs (same field layout as BFV C6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub ct0: CrtPolynomial,
    pub ct1: CrtPolynomial,
    pub sk: CrtPolynomial,
    pub e_sm: CrtPolynomial,
    pub r1: CrtPolynomial,
    pub r2: CrtPolynomial,
    pub d: CrtPolynomial,
    pub d_native_trunc: CrtPolynomial,
    pub expected_sk_commitment: BigInt,
    pub expected_e_sm_commitment: BigInt,
    pub ct_commitment: BigInt,
    pub domain_hi: BigInt,
    pub domain_lo: BigInt,
}

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = CkksShareDecryptionData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        // C6 proves against the ciphertext's ACTUAL level context (post-
        // rescale ciphertexts carry fewer limbs); level-0 here for the
        // demo pipeline, but derive from the ciphertext to stay honest.
        let ct_level = data.ciphertext.level;
        let ctx = params
            .context_at_level(ct_level)
            .map_err(|e| CircuitsErrors::Other(format!("ct context: {e}")))?;
        let moduli: Vec<BigInt> = ctx.moduli().iter().copied().map(BigInt::from).collect();
        let moduli_u64: Vec<u64> = ctx.moduli().to_vec();
        let n = params.degree() as u64;

        if data.ciphertext.len() != 2 {
            return Err(CircuitsErrors::Other(format!(
                "C6-CKKS needs a 2-component ciphertext, got {} (relinearize first)",
                data.ciphertext.len()
            )));
        }

        // CKKS ciphertext components live in NTT form; the circuit (and the
        // native check) work over power-basis coefficients.
        let ct0_pb = data.ciphertext[0].clone().into_power_basis();
        let ct1_pb = data.ciphertext[1].clone().into_power_basis();
        let ct0 = CrtPolynomial::from_fhe_polynomial(&ct0_pb);
        let ct1 = CrtPolynomial::from_fhe_polynomial(&ct1_pb);
        let sk_crt = CrtPolynomial::from_fhe_polynomial(&data.sk_poly);
        let es_crt = CrtPolynomial::from_fhe_polynomial(&data.es_poly);
        let d_crt = CrtPolynomial::from_fhe_polynomial(&data.d_share);

        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64);
        cyclo[n as usize] = BigInt::from(1u64);

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
        > = izip!(
            moduli.clone(),
            ct0.limbs.clone(),
            ct1.limbs.clone(),
            sk_crt.limbs.clone(),
            es_crt.limbs.clone(),
            d_crt.limbs.clone(),
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, mut ct0, mut ct1, mut s, mut e, mut d_share))| {
            ct0.reverse();
            ct0.center(&qi);
            ct1.reverse();
            ct1.center(&qi);
            s.reverse();
            s.center(&qi);
            e.reverse();
            e.center(&qi);
            d_share.reverse();
            d_share.center(&qi);

            // d_hat = ct0 + ct1 * s + e  (lifted to Z, before residue split)
            let d_hat = {
                let ct1_s = ct1.mul(&s);
                ct0.add(&ct1_s).add(&e)
            };
            // Congruence check BEFORE decompose_residue: a bad share must
            // surface as an attributable error, not a panic (the helper
            // asserts internally on inconsistent inputs).
            {
                let nn = n as usize;
                let mut nat = d_hat.coefficients().to_vec();
                nat.reverse(); // stored reversed (descending degree)
                nat.resize(2 * nn, BigInt::from(0));
                for ii in (nn..2 * nn).rev() {
                    let c = nat[ii].clone();
                    nat[ii] = BigInt::from(0);
                    nat[ii - nn] -= c;
                }
                nat.truncate(nn);
                let mut dsv = d_share.coefficients().to_vec();
                dsv.reverse();
                for (ii, (a, b)) in nat.iter().zip(dsv.iter()).enumerate() {
                    let df = (((a - b) % &qi) + &qi) % &qi;
                    if df != BigInt::from(0) {
                        return Err(CircuitsErrors::Other(format!(
                            "C6-CKKS share inconsistent at limb {i} coeff {ii}: \
                             d != ct0 + ct1*sk + e_sm (mod q)"
                        )));
                    }
                }
            }
            let (r1, r2) = decompose_residue(&d_share, &d_hat, &qi, &cyclo, n);
            Ok((i, ct0, ct1, s, e, d_share, r2, r1))
        })
        .collect();
        results.sort_by_key(|r| r.as_ref().map(|(i, ..)| *i).unwrap_or(usize::MAX));

        let mut ct0 = CrtPolynomial::new(vec![]);
        let mut ct1 = CrtPolynomial::new(vec![]);
        let mut sk = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);
        let mut r1 = CrtPolynomial::new(vec![]);
        let mut r2 = CrtPolynomial::new(vec![]);
        let mut d = CrtPolynomial::new(vec![]);
        for result in results {
            let (_i, ct0i, ct1i, si, ei, di, r2i, r1i) = result?;
            ct0.add_limb(ct0i);
            ct1.add_limb(ct1i);
            sk.add_limb(si);
            e_sm.add_limb(ei);
            r1.add_limb(r1i);
            r2.add_limb(r2i);
            d.add_limb(di);
        }

        // Commitments over the CKKS moduli (bit width from the widest
        // modulus at this level — the CKKS analogue of compute_modulus_bit).
        let modulus_bit = moduli_u64
            .iter()
            .map(|&q| calculate_bit_width(BigInt::from((q - 1) / 2)))
            .max()
            .unwrap_or(0);
        let expected_sk_commitment = compute_aggregated_shares_commitment(&sk, modulus_bit);
        let expected_e_sm_commitment = compute_aggregated_shares_commitment(&e_sm, modulus_bit);

        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        let ct_commitment = compute_ciphertext_commitment(&ct0, &ct1, bits.ct_bit);

        // CKKS plaintexts occupy every coefficient slot, so the native
        // binding spans all N coefficients (BFV truncates to its sparse
        // message support instead).
        let d_native_trunc =
            d_native_trunc_from_centered_d(&d, &moduli_u64, n as usize, n as usize);

        Ok(Inputs {
            ct0,
            ct1,
            sk,
            e_sm,
            r1,
            r2,
            d,
            d_native_trunc,
            expected_sk_commitment,
            expected_e_sm_commitment,
            ct_commitment,
            domain_hi: BigInt::from(data.domain_hi),
            domain_lo: BigInt::from(data.domain_lo),
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "ct0": crt_polynomial_to_toml_json(&self.ct0),
            "ct1": crt_polynomial_to_toml_json(&self.ct1),
            "sk": crt_polynomial_to_toml_json(&self.sk),
            "e_sm": crt_polynomial_to_toml_json(&self.e_sm),
            "r1": crt_polynomial_to_toml_json(&self.r1),
            "r2": crt_polynomial_to_toml_json(&self.r2),
            "d": crt_polynomial_to_toml_json(&self.d),
            "d_native_trunc": crt_polynomial_to_toml_json(&self.d_native_trunc),
            "expected_sk_commitment": self.expected_sk_commitment.to_string(),
            "expected_e_sm_commitment": self.expected_e_sm_commitment.to_string(),
            "ct_commitment": self.ct_commitment.to_string(),
            "domain_hi": self.domain_hi.to_string(),
            "domain_lo": self.domain_lo.to_string(),
        }))
    }
}

/// Codegen: emits `circuits/lib/src/configs/ckks_share_decryption.nr` —
/// mirrors `share_decryption::codegen` for the CKKS moduli. Canonical
/// ParamSet-0 entry point; see [`generate_configs_nr_for_param_set`] for
/// the per-set configs.
pub fn generate_configs_nr(configs: &Configs) -> String {
    generate_configs_nr_for_param_set(0, configs)
}

/// Noir config module name for a CKKS on-chain `ParamSet`: the canonical
/// set 0 keeps `ckks_share_decryption` (and the `share_decryption_ckks`
/// bin package); other sets get `ckks_share_decryption_ps<N>` (bin
/// `share_decryption_ckks_ps<N>`).
pub fn config_module_for_param_set(param_set: u8) -> String {
    if param_set == 0 {
        "ckks_share_decryption".to_string()
    } else {
        format!("ckks_share_decryption_ps{param_set}")
    }
}

/// Bin package name for a CKKS on-chain `ParamSet` (see
/// [`config_module_for_param_set`]).
pub fn bin_package_for_param_set(param_set: u8) -> String {
    if param_set == 0 {
        "share_decryption_ckks".to_string()
    } else {
        format!("share_decryption_ckks_ps{param_set}")
    }
}

/// The C6-CKKS circuit constants for an on-chain `ParamSet` at LEVEL 0
/// (the full modulus chain). The witness builder proves against the
/// ciphertext's ACTUAL level; a ciphertext opened after `k` rescales has
/// `L - k` limbs and needs a config generated from that level's moduli.
pub fn configs_for_param_set(param_set: u8) -> Result<Configs, CircuitsErrors> {
    let preset = crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set(param_set)?;
    Configs::compute(preset, &())
}

/// Codegen for one on-chain `ParamSet`: same global names as the canonical
/// file (so every `share_decryption_ckks*` bin has an identical `main.nr`
/// body), different module.
pub fn generate_configs_nr_for_param_set(param_set: u8, configs: &Configs) -> String {
    let qis = configs
        .moduli
        .iter()
        .map(|q| q.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let r1b = configs
        .bounds
        .r1_bounds
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let r2b = configs
        .bounds
        .r2_bounds
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers share_decryption_ckks codegen
// (example gen_ckks_c6_prover --param-set {param_set}). Do not hand-edit.
// CKKS on-chain ParamSet {param_set}, level 0: N={n}, L={l}.

use crate::core::threshold::share_decryption::Configs as ShareDecryptionConfigs;

/************************************
-------------------------------------
share_decryption_ckks (CIRCUIT 6-CKKS, ParamSet {param_set})
-------------------------------------
************************************/

pub global SHARE_DECRYPTION_CKKS_N: u32 = {n};
pub global SHARE_DECRYPTION_CKKS_L: u32 = {l};
pub global SHARE_DECRYPTION_CKKS_QIS: [Field; SHARE_DECRYPTION_CKKS_L] = [{qis}];

pub global SHARE_DECRYPTION_CKKS_BIT_CT: u32 = {ct};
pub global SHARE_DECRYPTION_CKKS_BIT_SK: u32 = {sk};
pub global SHARE_DECRYPTION_CKKS_BIT_E_SM: u32 = {esm};
pub global SHARE_DECRYPTION_CKKS_BIT_R1: u32 = {r1};
pub global SHARE_DECRYPTION_CKKS_BIT_R2: u32 = {r2};
pub global SHARE_DECRYPTION_CKKS_BIT_D: u32 = {d};
pub global SHARE_DECRYPTION_CKKS_BIT_D_NATIVE: u32 = {dn};

pub global SHARE_DECRYPTION_CKKS_R1_BOUNDS: [Field; SHARE_DECRYPTION_CKKS_L] = [{r1b}];
pub global SHARE_DECRYPTION_CKKS_R2_BOUNDS: [Field; SHARE_DECRYPTION_CKKS_L] = [{r2b}];

pub global SHARE_DECRYPTION_CKKS_CONFIGS: ShareDecryptionConfigs<SHARE_DECRYPTION_CKKS_L> = ShareDecryptionConfigs::new(
    SHARE_DECRYPTION_CKKS_QIS,
    SHARE_DECRYPTION_CKKS_R1_BOUNDS,
    SHARE_DECRYPTION_CKKS_R2_BOUNDS,
);
"#,
        param_set = param_set,
        n = configs.n,
        l = configs.l,
        qis = qis,
        ct = configs.bits.ct_bit,
        sk = configs.bits.sk_bit,
        esm = configs.bits.e_sm_bit,
        r1 = configs.bits.r1_bit,
        r2 = configs.bits.r2_bit,
        d = configs.bits.d_bit,
        dn = configs.bits.d_native_bit,
    )
}

/// Native check of the circuit's core constraint: `d == ct0 + ct1*sk +
/// e_sm (mod q_j, mod x^N+1)` for every limb. Run before emitting a proof
/// request so a bad share fails attributably at the source.
pub fn verify_ckks_share_decryption_constraints(
    preset: &CkksPreset,
    data: &CkksShareDecryptionData,
) -> Result<(), CircuitsErrors> {
    let inputs = Inputs::compute(preset.clone(), data)?;
    let ct_level = data.ciphertext.level;
    let ctx = preset
        .params
        .context_at_level(ct_level)
        .map_err(|e| CircuitsErrors::Other(format!("ct context: {e}")))?;
    let n = preset.params.degree();

    for (limb_idx, &qi) in ctx.moduli().iter().enumerate() {
        let q = BigInt::from(qi);
        // Witness limbs are stored REVERSED (circuit layout); un-reverse to
        // natural coefficient order before doing ring arithmetic — the
        // x^N+1 fold is not reversal-invariant.
        let unrev = |p: &Polynomial| -> Vec<BigInt> {
            let mut v = p.coefficients().to_vec();
            v.reverse();
            v
        };
        let ct0 = unrev(inputs.ct0.limb(limb_idx));
        let ct1 = unrev(inputs.ct1.limb(limb_idx));
        let sk = unrev(inputs.sk.limb(limb_idx));
        let e = unrev(inputs.e_sm.limb(limb_idx));
        let d_coeffs = unrev(inputs.d.limb(limb_idx));

        // d_hat = ct0 + ct1*sk + e over Z[x] (schoolbook), then reduce
        // mod x^N+1 and q.
        let mut d_hat = vec![BigInt::from(0); 2 * n];
        for (i, a) in ct1.iter().enumerate() {
            for (j, b) in sk.iter().enumerate() {
                d_hat[i + j] += a * b;
            }
        }
        for (i, c) in ct0.iter().enumerate() {
            d_hat[i] += c;
        }
        for (i, c) in e.iter().enumerate() {
            d_hat[i] += c;
        }
        // reduce mod x^N + 1: coeff[i+N] contributes -coeff to i.
        for i in (n..d_hat.len()).rev() {
            let c = d_hat[i].clone();
            d_hat[i] = BigInt::from(0);
            d_hat[i - n] -= c;
        }
        d_hat.truncate(n);
        for (i, (dh, dc)) in d_hat.iter().zip(d_coeffs.iter()).enumerate() {
            let diff = (dh - dc) % &q;
            let diff = ((diff % &q) + &q) % &q;
            if diff != BigInt::from(0) {
                return Err(CircuitsErrors::Other(format!(
                    "C6-CKKS constraint failed at limb {limb_idx} coeff {i}: d != ct0+ct1*sk+e_sm (mod q)"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::ckks::{CkksEncoder, CkksSecretKey};
    use fhe::trckks::TRCKKS;

    fn preset() -> CkksPreset {
        crate::threshold::user_data_encryption_ckks::insecure_512_ckks().unwrap()
    }

    /// The per-param-set naming contract the node loads circuits by, and
    /// the per-set configs' level-0 shape (L limbs of that set).
    #[test]
    fn per_param_set_packages_and_configs() {
        assert_eq!(bin_package_for_param_set(0), "share_decryption_ckks");
        assert_eq!(config_module_for_param_set(0), "ckks_share_decryption");
        assert_eq!(bin_package_for_param_set(2), "share_decryption_ckks_ps2");
        assert_eq!(config_module_for_param_set(3), "ckks_share_decryption_ps3");
        for (set, l) in [(0u8, 2usize), (2, 38), (3, 3)] {
            let c = configs_for_param_set(set).unwrap();
            assert_eq!(c.l, l, "param set {set}");
            let nr = generate_configs_nr_for_param_set(set, &c);
            assert!(nr.contains(&format!("SHARE_DECRYPTION_CKKS_L: u32 = {l};")));
            assert!(nr.contains(&format!("ParamSet {set}")));
        }
        // Set 0's per-set codegen IS the canonical entry point's output.
        let c0 = configs_for_param_set(0).unwrap();
        assert_eq!(
            generate_configs_nr(&c0),
            generate_configs_nr_for_param_set(0, &c0)
        );
    }

    /// Checked-in per-set configs match fresh codegen (token-level, since
    /// `nargo fmt` re-wraps the 38-limb arrays).
    #[test]
    fn checked_in_per_set_configs_match_codegen() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let strip = |s: &str| {
            s.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .replace(",]", "]")
        };
        for set in [0u8, 2, 3] {
            let c = configs_for_param_set(set).unwrap();
            let module = config_module_for_param_set(set);
            let path = format!("{root}/circuits/lib/src/configs/{module}.nr");
            let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("{path}: {e} (run gen_ckks_c6_prover --param-set {set})")
            });
            assert_eq!(
                strip(&on_disk),
                strip(&generate_configs_nr_for_param_set(set, &c)),
                "drift in {path}"
            );
        }
    }

    /// A ParamSet-3 (3-limb) real share verifies through the generalized
    /// builder — the C6 pipeline is param-set-agnostic given the preset.
    #[test]
    fn ckks_decryption_share_witness_param_set_3() {
        let preset =
            crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set(3).unwrap();
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let trckks = TRCKKS::new(3, 1, params.clone()).unwrap();
        let sk = CkksSecretKey::random(&params, &mut rng);
        let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng).unwrap();
        let sk_mats = trckks
            .generate_secret_shares_from_poly(
                trckks.coeffs_to_poly(sk.coeffs.as_ref()).unwrap(),
                &mut rng,
            )
            .unwrap();
        let es = trckks.generate_smudging_error(20, &mut rng).unwrap();
        let es_mats = trckks
            .generate_secret_shares_from_poly(trckks.smudging_to_poly(&es).unwrap(), &mut rng)
            .unwrap();
        let ct = pk
            .try_encrypt(
                &CkksEncoder::new(&params).encode(&[1.5], 0).unwrap(),
                &mut rng,
            )
            .unwrap();
        let sk_share = trckks.share_row_to_poly(&sk_mats, 0).unwrap();
        let es_share = trckks.share_row_to_poly(&es_mats, 0).unwrap();
        let d_share = trckks
            .decryption_share(&ct, sk_share.clone().into_ntt(), es_share.clone())
            .unwrap();
        let data = CkksShareDecryptionData {
            ciphertext: ct,
            sk_poly: sk_share,
            es_poly: es_share,
            d_share,
            domain_hi: 1,
            domain_lo: 2,
        };
        verify_ckks_share_decryption_constraints(&preset, &data).expect("ps3 share verifies");
        let inputs = Inputs::compute(preset, &data).unwrap();
        assert_eq!(inputs.ct0.limbs.len(), 3);
    }

    /// Real DKG -> real decryption share -> witness satisfies the C6-CKKS
    /// core constraint; a tampered share is rejected.
    #[test]
    fn ckks_decryption_share_witnesses_satisfy_c6_constraints() {
        let preset = preset();
        let params = preset.params.clone();
        let mut rng = rand::rng();
        let (n_parties, threshold) = (3usize, 1usize);
        let trckks = TRCKKS::new(n_parties, threshold, params.clone()).unwrap();

        // Committee DKG (in-process): per-party secrets + dealt shares.
        let sks: Vec<CkksSecretKey> = (0..n_parties)
            .map(|_| CkksSecretKey::random(&params, &mut rng))
            .collect();
        let crp = fhe::trckks::CkksCrp::from_seed(&params, [7u8; 32]).unwrap();
        let pk_shares: Vec<_> = sks
            .iter()
            .map(|sk| fhe::trckks::CkksPublicKeyShare::new(sk, crp.clone(), &mut rng).unwrap())
            .collect();
        let pk = fhe::trckks::CkksPublicKeyShare::aggregate(&pk_shares).unwrap();

        let sk_mats: Vec<Vec<ndarray::Array2<u64>>> = sks
            .iter()
            .map(|sk| {
                let poly = trckks.coeffs_to_poly(sk.coeffs.as_ref()).unwrap();
                trckks
                    .generate_secret_shares_from_poly(poly, &mut rng)
                    .unwrap()
            })
            .collect();
        let es_mats: Vec<Vec<ndarray::Array2<u64>>> = (0..n_parties)
            .map(|_| {
                let es = trckks.generate_smudging_error(20, &mut rng).unwrap();
                let poly = trckks.smudging_to_poly(&es).unwrap();
                trckks
                    .generate_secret_shares_from_poly(poly, &mut rng)
                    .unwrap()
            })
            .collect();

        // Party 1 (x=1): collect row 0 of every dealer's matrices and let
        // the fork aggregate them (mod-q sum per limb).
        let row = 0usize;
        let collect_rows = |mats: &[Vec<ndarray::Array2<u64>>]| -> Poly<fhe_math::rq::PowerBasis> {
            let l = params.moduli().len();
            let degree = params.degree();
            let collected: Vec<ndarray::Array2<u64>> = mats
                .iter()
                .map(|dealer| {
                    let mut a = ndarray::Array2::<u64>::zeros((l, degree));
                    for (m, mat) in dealer.iter().enumerate() {
                        for c in 0..degree {
                            a[[m, c]] = mat[[row, c]];
                        }
                    }
                    a
                })
                .collect();
            trckks.aggregate_collected_shares(&collected).unwrap()
        };
        let sk_poly = collect_rows(&sk_mats);
        let es_poly = collect_rows(&es_mats);

        // Encrypt + evaluate a value, then compute the real share.
        let encoder = CkksEncoder::new(&params);
        let pt = encoder.encode(&[42.0], 0).unwrap();
        let ct = pk.try_encrypt(&pt, &mut rng).unwrap();

        let d_share = trckks
            .decryption_share(&ct, sk_poly.clone().into_ntt(), es_poly.clone())
            .unwrap();

        let data = CkksShareDecryptionData {
            ciphertext: ct,
            sk_poly,
            es_poly,
            d_share,
            domain_hi: 7,
            domain_lo: 13,
        };
        verify_ckks_share_decryption_constraints(&preset, &data).expect("real share verifies");

        // Tamper: add 1 to one coefficient of the share (public API:
        // coeffs_to_poly builds a level-0 PowerBasis poly).
        let mut bad = data;
        let mut unit = vec![0i64; params.degree()];
        unit[3] = 1;
        let unit_poly = trckks.coeffs_to_poly(&unit).unwrap();
        bad.d_share = &bad.d_share + &*unit_poly;
        assert!(
            verify_ckks_share_decryption_constraints(&preset, &bad).is_err(),
            "tampered share must be rejected"
        );
    }
}
