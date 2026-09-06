// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private-matching validity leg: witness builder and codegen for the
//! `ckks_matching_validity_ps5` circuit (Noir:
//! `lib::core::threshold::ckks_matching_validity`) and the ParamSet-5
//! Greco legs (`user_data_encryption_ckks_ct{0,1}_ps5`).
//!
//! A matching submission is TWO COEFFICIENT-encoded encryptions proven in
//! FIVE legs bound by shared commitments: Greco ct0 + ct1 for the VECTOR
//! ciphertext, Greco ct0 + ct1 for the MASK ciphertext, and this ONE
//! validity leg, which takes both message polynomials privately,
//! recomputes both `m_commitment`s (same packing width `BIT_M` / domain
//! separator as the ct0 legs) and proves the layout predicate.
//!
//! ## Coefficient layout (the policy's contract —
//! `e3_trckks::policy::coefficient_layout`)
//!
//! Party A (role 0, slot 0) and party B (role 1, slot 1) each encrypt,
//! COEFFICIENT-encoded at scale Δ (`c_k = round(Δ · v_k)`, no cosine
//! table, no slots):
//!
//! - `ct_vec = forward(a)` (A): `a_j` on coefficient `j + 1`, `j < K`;
//!   `ct_vec = reversed(b)` (B): `b_j` on coefficient `N − j − 1`;
//! - `ct_mask = mask(m)`: the integer `m_j ∈ [0, 1024)` on coefficient
//!   `j + 1`, `j < MASK_WIDTH`.
//!
//! Vector entries are fixed point over `2^FRAC_BITS`: `v_j = V_j / 2^16`,
//! `|v_j| ≤ 1` (cap-normalised by the app). With Δ = 2^40, `Δ · V_j / 2^16`
//! is an exact integer; the circuit still keeps the credit leg's slack
//! pattern (`|2^16 · c − Δ · V| ≤ 2^15 + SLACK`).
//!
//! The network opens `relin(forward(a) · reversed(b)) + mask(m_a) +
//! mask(m_b)`; coefficient 0 is `−⟨a, b⟩` (the `t^N ≡ −1` wrap — the app
//! negates).

use crate::circuits::computation::Computation;
use crate::threshold::ckks_app_validity::field_word_hex;
use crate::threshold::user_data_encryption_ckks::{
    ckks_preset_for_param_set, generate_toml, Bounds as GrecoBounds, CkksPreset,
    Inputs as GrecoInputs,
};
use crate::CircuitsErrors;
use e3_polynomial::Polynomial;
use fhe::ckks::{CkksEncoder, CkksParameters, CkksPlaintext, CkksPublicKey};
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, Zero};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// On-chain `ParamSet` value of the coefficient-encoded preset.
pub const MATCHING_PARAM_SET: u8 = 5;
/// Nargo package of the matching leg.
pub const MATCHING_CIRCUIT_PACKAGE: &str = "ckks_matching_validity_ps5";
/// Vector length every party packs (Noir `K`).
pub const K: usize = 16;
/// Cross-term mask width (Noir `MASK_WIDTH`): coefficients `1..=128`.
pub const MASK_WIDTH: usize = 128;
/// Mask entries are integers `< 2^MASK_BITS` (Noir `MASK_BITS`).
pub const MASK_BITS: u32 = 10;
/// Fixed-point fractional bits of vector entries (Noir `FRAC_BITS`).
pub const FRAC_BITS: u32 = 16;
/// `2^FRAC_BITS`.
pub const FRAC_SCALE: i64 = 1 << FRAC_BITS;
/// Per-coefficient slack of the encoding window (Noir `SLACK`).
pub const SLACK: u32 = 8;
/// `log2(N)` for the pinned degree.
pub const LOG_N: u32 = 9;
/// Number of public-input words of the matching leg (3 inputs + 2 outputs):
/// `[role, address, index, m_c_vec, m_c_mask]`.
pub const MATCHING_PUBLIC_INPUTS: usize = 5;
/// Word offsets in the public-input list.
pub const WORD_ROLE: usize = 0;
pub const WORD_ADDRESS: usize = 1;
pub const WORD_INDEX: usize = 2;
pub const WORD_M_VEC: usize = 3;
pub const WORD_M_MASK: usize = 4;

/// Which of the two layouts a party submits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Party A: `forward` layout, slot 0.
    A = 0,
    /// Party B: `reversed` layout, slot 1.
    B = 1,
}

impl Role {
    pub fn from_index(index: u32) -> Result<Self, CircuitsErrors> {
        match index {
            0 => Ok(Role::A),
            1 => Ok(Role::B),
            other => Err(CircuitsErrors::Other(format!(
                "matching has exactly two slots; got index {other}"
            ))),
        }
    }

    pub fn bit(self) -> u32 {
        self as u32
    }
}

/// The ParamSet-5 CKKS parameters.
pub fn matching_ckks_params() -> Result<Arc<CkksParameters>, CircuitsErrors> {
    e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(MATCHING_PARAM_SET)
        .map_err(|e| CircuitsErrors::Other(format!("ParamSet-5 CKKS params: {e}")))
}

/// The Greco preset for ParamSet 5 (`input_bound = 1024`).
pub fn matching_preset() -> Result<CkksPreset, CircuitsErrors> {
    ckks_preset_for_param_set(MATCHING_PARAM_SET)
}

/// Fixed-point vector entries `V_j` (`v_j = V_j / 2^16 ∈ [−1, 1]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vector(pub [i32; K]);

impl Vector {
    /// Round cap-normalised f64 entries into the fixed point.
    pub fn from_f64(v: &[f64; K]) -> Result<Self, CircuitsErrors> {
        let mut out = [0i32; K];
        for (j, x) in v.iter().enumerate() {
            if !x.is_finite() || x.abs() > 1.0 {
                return Err(CircuitsErrors::Other(format!(
                    "entry {j} = {x} is outside [-1, 1]"
                )));
            }
            out[j] = (x * FRAC_SCALE as f64).round() as i32;
        }
        Ok(Self(out))
    }

    /// The f64 entries (what the encoder takes).
    pub fn to_f64(&self) -> [f64; K] {
        std::array::from_fn(|j| self.0[j] as f64 / FRAC_SCALE as f64)
    }

    pub fn in_range(&self) -> bool {
        self.0.iter().all(|v| i64::from(*v).abs() <= FRAC_SCALE)
    }

    /// `⟨a, b⟩` in f64 (the oracle the tests compare the opening against).
    pub fn dot(&self, other: &Vector) -> f64 {
        self.to_f64()
            .iter()
            .zip(other.to_f64())
            .map(|(x, y)| x * y)
            .sum()
    }
}

/// Public parameters of the matching leg (baked into
/// `configs/ckks_matching_ps5.nr`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchingConfigs {
    pub n: usize,
    /// `delta` as an exact integer.
    pub delta: BigUint,
    /// The ct0 leg's `m_bound`.
    pub m_bound: BigUint,
    /// Packing width of `m` (`BIT_M` of the ct0 leg).
    pub m_bit: u32,
}

impl MatchingConfigs {
    pub fn compute(preset: &CkksPreset) -> Result<Self, CircuitsErrors> {
        let bounds = GrecoBounds::compute(preset.clone(), &())?;
        let bits =
            crate::threshold::user_data_encryption_ckks::Bits::compute(preset.clone(), &bounds)?;
        let scale = preset.params.scale();
        if scale.fract() != 0.0 || scale <= 0.0 || scale >= 2f64.powi(120) {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not an exact integer the matching leg can pin"
            )));
        }
        let n = preset.params.degree();
        if n != 1usize << LOG_N {
            return Err(CircuitsErrors::Other(format!(
                "matching leg is pinned to N = 2^{LOG_N}, got {n}"
            )));
        }
        // forward occupies 1..=K, reversed N-K..=N-1: they must not meet,
        // and the mask must cover the whole cross-term block 1..=2K.
        if 2 * K >= n || 2 * K > MASK_WIDTH || 2 * MASK_WIDTH >= n {
            return Err(CircuitsErrors::Other(
                "vector length / mask width violate the ParamSet-5 layout".into(),
            ));
        }
        let delta = BigUint::from(scale as u128);
        // The Greco bound must admit the largest coefficient: a mask entry
        // Δ · (2^MASK_BITS − 1).
        let max_coeff = &delta * BigUint::from((1u64 << MASK_BITS) - 1);
        if max_coeff > bounds.m_bound {
            return Err(CircuitsErrors::Other(format!(
                "Greco m_bound {} does not cover the largest mask coefficient {max_coeff}",
                bounds.m_bound
            )));
        }
        // Field soundness: 2^16 · |c| + Δ · 2^16 must stay far below 2^253.
        if bits.m_bit + FRAC_BITS + 2 >= 250 {
            return Err(CircuitsErrors::Other(format!(
                "m_bit {} + window too wide for an exact integer check",
                bits.m_bit
            )));
        }
        Ok(Self {
            n,
            delta,
            m_bound: bounds.m_bound,
            m_bit: bits.m_bit,
        })
    }
}

/// Errors from the native constraint pre-check, attributable to a field.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MatchingCheckError {
    #[error("entry {index} = {value} is outside |V| <= 2^{FRAC_BITS}")]
    EntryOutOfRange { index: usize, value: i32 },
    #[error("mask {index} = {value} is not in [0, 2^{MASK_BITS})")]
    MaskOutOfRange { index: usize, value: u32 },
    #[error("|m_{index}| = {value} of the {which} message exceeds m_bound {bound}")]
    CoefficientTooLarge {
        which: &'static str,
        index: usize,
        value: BigInt,
        bound: BigUint,
    },
    #[error("coefficient {index} of the {which} message is not the declared layout value (residual {residual})")]
    EncodingMismatch {
        which: &'static str,
        index: usize,
        residual: BigInt,
    },
    #[error("coefficient {index} of the {which} message must be zero (got {value})")]
    NonZeroCoefficient {
        which: &'static str,
        index: usize,
        value: BigInt,
    },
    #[error("{which} message polynomial has {got} coefficients, expected {want}")]
    WrongDegree {
        which: &'static str,
        got: usize,
        want: usize,
    },
    #[error("slot index {index} does not match role {role:?} (A = 0, B = 1)")]
    IndexRoleMismatch { index: u32, role: Role },
}

/// Witness of the matching leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingInputs {
    /// `forward(v)` / `reversed(v)` (circuit layout: reversed, centered) —
    /// the SAME `m` the vector ct0 leg carries.
    pub m_vec: Polynomial,
    /// `mask(m)` — the SAME `m` the mask ct0 leg carries.
    pub m_mask: Polynomial,
    /// The party's fixed-point vector.
    pub values: Vector,
    /// The party's cross-term mask (integers `< 1024`).
    pub mask: Vec<u32>,
    /// The party's role (A = forward, B = reversed).
    pub role: Role,
    /// The party's address as a big-endian 20-byte integer.
    pub address: BigUint,
    /// The party's slot index (assigned on-chain; equals the role bit).
    pub index: u32,
}

/// Coefficient `k` of a circuit-layout polynomial (`coeffs[n − 1 − k]`).
fn coeff(m: &Polynomial, k: usize) -> &BigInt {
    let n = m.coefficients().len();
    &m.coefficients()[n - 1 - k]
}

/// The coefficient position of vector entry `j` for `role`.
pub fn vector_position(n: usize, role: Role, j: usize) -> usize {
    match role {
        Role::A => j + 1,
        Role::B => n - j - 1,
    }
}

impl MatchingInputs {
    /// Native pre-check of exactly the constraints the Noir leg enforces,
    /// in the circuit's order.
    pub fn check(&self, configs: &MatchingConfigs) -> Result<(), MatchingCheckError> {
        let n = configs.n;
        for (index, v) in self.values.0.iter().enumerate() {
            if i64::from(*v).abs() > FRAC_SCALE {
                return Err(MatchingCheckError::EntryOutOfRange { index, value: *v });
            }
        }
        if self.index != self.role.bit() {
            return Err(MatchingCheckError::IndexRoleMismatch {
                index: self.index,
                role: self.role,
            });
        }
        if self.mask.len() != MASK_WIDTH {
            return Err(MatchingCheckError::WrongDegree {
                which: "mask vector",
                got: self.mask.len(),
                want: MASK_WIDTH,
            });
        }
        for (index, m) in self.mask.iter().enumerate() {
            if *m >= (1u32 << MASK_BITS) {
                return Err(MatchingCheckError::MaskOutOfRange { index, value: *m });
            }
        }
        for (which, m) in [("vector", &self.m_vec), ("mask", &self.m_mask)] {
            if m.coefficients().len() != n {
                return Err(MatchingCheckError::WrongDegree {
                    which,
                    got: m.coefficients().len(),
                    want: n,
                });
            }
        }
        let bound = BigInt::from(configs.m_bound.clone());
        let delta = BigInt::from(configs.delta.clone());
        let scale = BigInt::from(FRAC_SCALE);
        let slack = BigInt::from(SLACK);

        // Vector: c_{pos(j)} ≈ Δ · V_j / 2^16; every other coefficient 0.
        let mut live = vec![false; n];
        for (j, v) in self.values.0.iter().enumerate() {
            let k = vector_position(n, self.role, j);
            live[k] = true;
            let c = coeff(&self.m_vec, k);
            if c.abs() > bound {
                return Err(MatchingCheckError::CoefficientTooLarge {
                    which: "vector",
                    index: k,
                    value: c.clone(),
                    bound: configs.m_bound.clone(),
                });
            }
            let residual = &scale * c - &delta * BigInt::from(*v);
            if residual.abs() > BigInt::from(FRAC_SCALE / 2) + &slack {
                return Err(MatchingCheckError::EncodingMismatch {
                    which: "vector",
                    index: k,
                    residual,
                });
            }
        }
        for k in (0..n).filter(|k| !live[*k]) {
            let c = coeff(&self.m_vec, k);
            if !c.is_zero() {
                return Err(MatchingCheckError::NonZeroCoefficient {
                    which: "vector",
                    index: k,
                    value: c.clone(),
                });
            }
        }
        // Mask: c_{j+1} == Δ · m_j exactly.
        for (j, m) in self.mask.iter().enumerate() {
            let c = coeff(&self.m_mask, j + 1);
            let residual = c - &delta * BigInt::from(*m);
            if !residual.is_zero() {
                return Err(MatchingCheckError::EncodingMismatch {
                    which: "mask",
                    index: j + 1,
                    residual,
                });
            }
        }
        for k in (0..n).filter(|k| *k == 0 || *k > MASK_WIDTH) {
            let c = coeff(&self.m_mask, k);
            if !c.is_zero() {
                return Err(MatchingCheckError::NonZeroCoefficient {
                    which: "mask",
                    index: k,
                    value: c.clone(),
                });
            }
        }
        Ok(())
    }

    /// Prover.toml for the matching leg.
    pub fn to_toml(&self) -> Result<String, CircuitsErrors> {
        Ok(toml::to_string(&self.to_json())?)
    }

    /// The matching leg's inputs as JSON (the noir_js `InputMap` shape;
    /// also what `to_toml` serializes). Negative entries are emitted as
    /// the field element `p − |V|` in decimal.
    pub fn to_json(&self) -> serde_json::Value {
        use crate::polynomial_to_toml_json;
        let values: Vec<String> = self
            .values
            .0
            .iter()
            .map(|v| signed_field_decimal(i64::from(*v)))
            .collect();
        let mask: Vec<String> = self.mask.iter().map(|v| v.to_string()).collect();
        serde_json::json!({
            "m_vec": polynomial_to_toml_json(&self.m_vec),
            "m_mask": polynomial_to_toml_json(&self.m_mask),
            "values": values,
            "mask": mask,
            "role": self.role.bit().to_string(),
            "address": self.address.to_string(),
            "index": self.index.to_string(),
        })
    }
}

/// BN254 scalar field modulus.
fn bn254_r() -> BigInt {
    BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("bn254 r")
}

/// A signed integer as the decimal of its BN254 field representative.
pub fn signed_field_decimal(v: i64) -> String {
    signed_field_bigint(v).to_string()
}

/// A signed integer as its BN254 field representative (`p − |v|` when negative).
pub fn signed_field_bigint(v: i64) -> BigInt {
    if v >= 0 {
        BigInt::from(v)
    } else {
        bn254_r() + BigInt::from(v)
    }
}

/// One proven encryption of the submission (vector or mask).
#[derive(Debug, Clone)]
pub struct MatchingCiphertextLeg {
    pub ciphertext: Vec<u8>,
    /// Serves BOTH Greco bin packages of this ciphertext.
    pub greco_toml: String,
    /// The Greco message polynomial, for cross-leg assertions.
    pub greco_m: Polynomial,
}

/// The complete client-side submission: two ciphertexts, their Greco
/// witnesses, and the validity leg's witness.
#[derive(Debug, Clone)]
pub struct MatchingSubmission {
    pub vector: MatchingCiphertextLeg,
    pub mask: MatchingCiphertextLeg,
    pub matching_toml: String,
    pub matching_inputs: MatchingInputs,
}

/// The length-N coefficient vectors of one submission, in the policy's
/// layout (`e3_trckks::policy::coefficient_layout`, duplicated here so
/// zk-helpers stays free of the trckks dependency; the policy tests pin
/// the same indices).
pub fn layout_vectors(n: usize, role: Role, values: &Vector, mask: &[u32]) -> (Vec<f64>, Vec<f64>) {
    let vf = values.to_f64();
    let mut vec = vec![0.0f64; n];
    let mut msk = vec![0.0f64; n];
    for (j, v) in vf.iter().enumerate() {
        vec[vector_position(n, role, j)] = *v;
    }
    for (j, m) in mask.iter().enumerate() {
        msk[j + 1] = *m as f64;
    }
    (vec, msk)
}

/// COEFFICIENT-encodes a length-N vector at level 0 / scale Δ.
pub fn encode_coefficients(
    params: &Arc<CkksParameters>,
    values: &[f64],
) -> Result<CkksPlaintext, CircuitsErrors> {
    CkksEncoder::new(params)
        .encode_coefficients(values, 0, params.scale())
        .map_err(|e| CircuitsErrors::Other(format!("coefficient encoding: {e}")))
}

/// Greco inputs for ONE coefficient-encoded encryption with a
/// caller-supplied RNG. Does NOT run the matching pre-check.
pub fn matching_greco_inputs_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: &CkksPublicKey,
    values: &[f64],
    rng: &mut R,
) -> Result<GrecoInputs, CircuitsErrors> {
    let preset = matching_preset()?;
    let pt = encode_coefficients(&preset.params, values)?;
    GrecoInputs::compute_from_plaintext_with_rng(preset, public_key, &pt, rng)
}

/// Uniform cross-term mask: `MASK_WIDTH` integers in `[0, 2^MASK_BITS)`.
pub fn sample_mask<R: rand::RngCore>(rng: &mut R) -> Vec<u32> {
    (0..MASK_WIDTH)
        .map(|_| rng.next_u32() % (1u32 << MASK_BITS))
        .collect()
}

/// Builds a submission from TWO encryptions (fresh randomness per call).
pub fn build_matching_submission(
    public_key: CkksPublicKey,
    address: BigUint,
    role: Role,
    values: Vector,
    mask: Vec<u32>,
) -> Result<MatchingSubmission, CircuitsErrors> {
    build_matching_submission_with_rng(public_key, address, role, values, mask, &mut rand::rng())
}

/// [`build_matching_submission`] with a caller-supplied RNG: the vector
/// encryption draws first, then the mask (the order the SDK mirrors).
pub fn build_matching_submission_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: CkksPublicKey,
    address: BigUint,
    role: Role,
    values: Vector,
    mask: Vec<u32>,
    rng: &mut R,
) -> Result<MatchingSubmission, CircuitsErrors> {
    let preset = matching_preset()?;
    if !values.in_range() {
        return Err(CircuitsErrors::Other("entry outside [-1, 1]".into()));
    }
    if mask.len() != MASK_WIDTH {
        return Err(CircuitsErrors::Other(format!(
            "mask must have {MASK_WIDTH} entries; got {}",
            mask.len()
        )));
    }
    if let Some((j, m)) = mask.iter().enumerate().find(|(_, m)| **m >= 1 << MASK_BITS) {
        return Err(CircuitsErrors::Other(format!(
            "mask {j} = {m} is not in [0, 2^{MASK_BITS})"
        )));
    }
    let configs = MatchingConfigs::compute(&preset)?;
    let n = configs.n;
    let (vec, msk) = layout_vectors(n, role, &values, &mask);
    let greco_v = matching_greco_inputs_with_rng(&public_key, &vec, rng)?;
    let greco_m = matching_greco_inputs_with_rng(&public_key, &msk, rng)?;
    let matching_inputs = MatchingInputs {
        m_vec: greco_v.m.clone(),
        m_mask: greco_m.m.clone(),
        values,
        mask,
        role,
        address,
        index: role.bit(),
    };
    matching_inputs
        .check(&configs)
        .map_err(|e| CircuitsErrors::Other(format!("matching leg pre-check failed: {e}")))?;
    let matching_toml = matching_inputs.to_toml()?;
    let leg = |greco: GrecoInputs| -> Result<MatchingCiphertextLeg, CircuitsErrors> {
        let ciphertext = greco.ciphertext.clone();
        let greco_m = greco.m.clone();
        let greco_toml = generate_toml(greco)?;
        Ok(MatchingCiphertextLeg {
            ciphertext,
            greco_toml,
            greco_m,
        })
    };
    Ok(MatchingSubmission {
        vector: leg(greco_v)?,
        mask: leg(greco_m)?,
        matching_toml,
        matching_inputs,
    })
}

/// Recomputes a ct0 leg's `m_commitment` natively (must equal that leg's
/// third public output).
pub fn compute_m_commitment(m: &Polynomial, m_bit: u32) -> BigInt {
    crate::circuits::commitments::compute_user_data_encryption_m_commitment(m, m_bit)
}

/// The on-chain public-input words of the matching leg, in circuit order:
/// `[role, address, index, m_commitment_vec, m_commitment_mask]`.
pub fn public_input_words(inputs: &MatchingInputs, m_bit: u32) -> Vec<String> {
    let words = vec![
        field_word_hex(&BigInt::from(inputs.role.bit())),
        field_word_hex(&BigInt::from(inputs.address.clone())),
        field_word_hex(&BigInt::from(inputs.index)),
        field_word_hex(&compute_m_commitment(&inputs.m_vec, m_bit)),
        field_word_hex(&compute_m_commitment(&inputs.m_mask, m_bit)),
    ];
    debug_assert_eq!(words.len(), MATCHING_PUBLIC_INPUTS);
    words
}

/// Generated Noir configs for the matching leg (`configs/ckks_matching_ps5.nr`).
pub fn generate_matching_configs(configs: &MatchingConfigs) -> String {
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers ckks_matching_validity codegen
// (`cargo run -p e3-zk-helpers --example gen_ckks_matching_prover -- configs`).
// Do not hand-edit; regenerate-and-diff is enforced by
// `test_checked_in_matching_configs_match_codegen`.
// CKKS private-matching validity leg on ParamSet {ps}: N={n}, delta=2^{scale_bits},
// coefficient encoding (forward / reversed / mask layouts).

use crate::core::threshold::ckks_matching_validity::Configs as CkksMatchingValidityConfigs;

pub global CKKS_MATCHING_N: u32 = {n};
/// Packing width of `m` — MUST equal the ct0 leg's BIT_M so the
/// recomputed m_commitment matches.
pub global CKKS_MATCHING_BIT_M: u32 = {m_bit};
pub global CKKS_MATCHING_DELTA: Field = {delta};
pub global CKKS_MATCHING_M_BOUND: Field = {m_bound};

pub global CKKS_MATCHING_CONFIGS: CkksMatchingValidityConfigs =
    CkksMatchingValidityConfigs::new(CKKS_MATCHING_DELTA, CKKS_MATCHING_M_BOUND);
"#,
        ps = MATCHING_PARAM_SET,
        n = configs.n,
        scale_bits = configs.delta.bits() - 1,
        m_bit = configs.m_bit,
        delta = configs.delta,
        m_bound = configs.m_bound,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::ckks_app_validity::address_to_biguint;
    use fhe::ckks::CkksSecretKey;

    const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const DEMO_A: [f64; K] = [
        0.5, -0.25, 1.0, -1.0, 0.125, 0.0, 0.75, -0.5, 0.3, -0.7, 0.9, -0.1, 0.6, 0.2, -0.4, 0.05,
    ];
    const DEMO_B: [f64; K] = [
        0.4, 0.3, -0.2, 0.9, -1.0, 1.0, 0.1, 0.5, -0.6, 0.8, 0.25, 0.75, -0.35, 0.15, 0.95, -0.05,
    ];

    fn keypair() -> (CkksSecretKey, CkksPublicKey) {
        let preset = matching_preset().unwrap();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();
        (sk, pk)
    }

    fn demo_mask() -> Vec<u32> {
        (0..MASK_WIDTH as u32)
            .map(|j| (j * 37 + 11) % 1024)
            .collect()
    }

    fn demo_submission(role: Role) -> (MatchingSubmission, CkksSecretKey) {
        let (sk, pk) = keypair();
        let (addr, v) = match role {
            Role::A => (ALICE, DEMO_A),
            Role::B => (BOB, DEMO_B),
        };
        let sub = build_matching_submission(
            pk,
            address_to_biguint(addr).unwrap(),
            role,
            Vector::from_f64(&v).unwrap(),
            demo_mask(),
        )
        .unwrap();
        (sub, sk)
    }

    #[test]
    fn vector_fixed_point_round_trips() {
        let v = Vector::from_f64(&DEMO_A).unwrap();
        assert_eq!(v.0[0], 32768);
        assert_eq!(v.0[1], -16384);
        assert_eq!(v.0[2], 65536);
        assert_eq!(v.0[3], -65536);
        assert!(v.in_range());
        assert!(Vector::from_f64(&[1.5; K]).is_err());
        let b = Vector::from_f64(&DEMO_B).unwrap();
        let dot: f64 = DEMO_A.iter().zip(DEMO_B).map(|(x, y)| x * y).sum();
        assert!((v.dot(&b) - dot).abs() < 1e-4);
    }

    #[test]
    fn preset_is_the_fhe_params_shape() {
        let preset = matching_preset().unwrap();
        assert_eq!(preset.params.degree(), 512);
        assert_eq!(preset.params.moduli().len(), 3);
        assert_eq!(preset.params.scale(), 2f64.powi(40));
        assert_eq!(preset.input_bound, 1024.0);
        let configs = MatchingConfigs::compute(&preset).unwrap();
        assert_eq!(configs.m_bit, 51);
    }

    /// The layout helpers agree with `e3_trckks::policy::coefficient_layout`
    /// index for index (forward → j+1, reversed → N−j−1, mask → j+1).
    #[test]
    fn layout_matches_policy_contract() {
        let n = 512;
        let v = Vector::from_f64(&DEMO_A).unwrap();
        let (fwd, msk) = layout_vectors(n, Role::A, &v, &demo_mask());
        let (rev, _) = layout_vectors(n, Role::B, &v, &demo_mask());
        let vf = v.to_f64();
        for j in 0..K {
            assert_eq!(fwd[j + 1], vf[j]);
            assert_eq!(rev[n - j - 1], vf[j]);
        }
        assert_eq!(fwd[0], 0.0);
        assert_eq!(rev[0], 0.0);
        assert_eq!(fwd.iter().filter(|c| **c != 0.0).count(), K - 1); // one demo entry is 0
        for (j, m) in demo_mask().iter().enumerate() {
            assert_eq!(msk[j + 1], *m as f64);
        }
        assert_eq!(msk[0], 0.0);
        assert_eq!(msk[MASK_WIDTH + 1], 0.0);
    }

    /// Both roles pass the native check, bind both messages to the Greco
    /// legs, and the ciphertexts decrypt to the declared layout.
    #[test]
    fn submission_passes_native_check_and_binds_both_messages() {
        for role in [Role::A, Role::B] {
            let (sub, sk) = demo_submission(role);
            let preset = matching_preset().unwrap();
            let configs = MatchingConfigs::compute(&preset).unwrap();
            sub.matching_inputs.check(&configs).unwrap();
            assert_eq!(sub.matching_inputs.m_vec, sub.vector.greco_m);
            assert_eq!(sub.matching_inputs.m_mask, sub.mask.greco_m);
            assert_ne!(sub.vector.ciphertext, sub.mask.ciphertext);
            assert_eq!(sub.matching_inputs.index, role.bit());
            let words = public_input_words(&sub.matching_inputs, configs.m_bit);
            assert_eq!(words.len(), MATCHING_PUBLIC_INPUTS);
            assert_eq!(words[WORD_ROLE], field_word_hex(&BigInt::from(role.bit())));
            assert_eq!(words[WORD_INDEX], field_word_hex(&BigInt::from(role.bit())));
            assert_eq!(
                words[WORD_M_VEC],
                field_word_hex(&compute_m_commitment(&sub.vector.greco_m, configs.m_bit))
            );
            assert_eq!(
                words[WORD_M_MASK],
                field_word_hex(&compute_m_commitment(&sub.mask.greco_m, configs.m_bit))
            );
            assert!(sub.matching_toml.contains("role = \""));
            // A negative entry word is p − |V| (entry 1 of A, entry 2 of B).
            let neg = match role {
                Role::A => 1,
                Role::B => 2,
            };
            let json = sub.matching_inputs.to_json();
            let values = json["values"].as_array().unwrap();
            assert!(sub.matching_inputs.values.0[neg] < 0);
            assert_eq!(
                values[neg].as_str().unwrap(),
                (bn254_r() - BigInt::from(sub.matching_inputs.values.0[neg].unsigned_abs()))
                    .to_string()
            );

            // Decrypt and compare against the layout.
            let ct =
                <fhe::ckks::CkksCiphertext as fhe_traits::DeserializeParametrized>::from_bytes(
                    &sub.vector.ciphertext,
                    &preset.params,
                )
                .unwrap();
            let pt = sk.try_decrypt(&ct).unwrap();
            let decoded = CkksEncoder::new(&preset.params)
                .decode_coefficients(&pt, 512)
                .unwrap();
            let (expected, _) = layout_vectors(
                512,
                role,
                &sub.matching_inputs.values,
                &sub.matching_inputs.mask,
            );
            for k in 0..512 {
                assert!(
                    (decoded[k] - expected[k]).abs() < 1e-6,
                    "role {role:?} coefficient {k}: {} vs {}",
                    decoded[k],
                    expected[k]
                );
            }
        }
    }

    #[test]
    fn native_check_attributes_each_tamper() {
        let (sub, _) = demo_submission(Role::A);
        let configs = MatchingConfigs::compute(&matching_preset().unwrap()).unwrap();
        let n = configs.n;

        // Wrong role on the same polynomial (forward read as reversed).
        let mut t = sub.matching_inputs.clone();
        t.role = Role::B;
        t.index = 1;
        assert!(matches!(
            t.check(&configs),
            Err(MatchingCheckError::EncodingMismatch {
                which: "vector",
                ..
            }) | Err(MatchingCheckError::NonZeroCoefficient {
                which: "vector",
                ..
            })
        ));

        // Index / role mismatch.
        let mut t = sub.matching_inputs.clone();
        t.index = 1;
        assert_eq!(
            t.check(&configs),
            Err(MatchingCheckError::IndexRoleMismatch {
                index: 1,
                role: Role::A
            })
        );

        // Wrong declared value.
        let mut t = sub.matching_inputs.clone();
        t.values.0[2] -= 1;
        assert!(matches!(
            t.check(&configs),
            Err(MatchingCheckError::EncodingMismatch {
                which: "vector",
                index: 3,
                ..
            })
        ));

        // Entry above 1.
        let mut t = sub.matching_inputs.clone();
        t.values.0[0] = FRAC_SCALE as i32 + 1;
        assert_eq!(
            t.check(&configs),
            Err(MatchingCheckError::EntryOutOfRange {
                index: 0,
                value: FRAC_SCALE as i32 + 1
            })
        );

        // Hidden coefficient in the dead zone.
        let mut t = sub.matching_inputs.clone();
        let mut coeffs = t.m_vec.coefficients().to_vec();
        coeffs[n - 1 - 100] += BigInt::from(1_000_000u32);
        t.m_vec = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(MatchingCheckError::NonZeroCoefficient {
                which: "vector",
                index: 100,
                ..
            })
        ));

        // Mask value drifted.
        let mut t = sub.matching_inputs.clone();
        t.mask[7] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(MatchingCheckError::EncodingMismatch {
                which: "mask",
                index: 8,
                ..
            })
        ));

        // Mask out of range.
        let mut t = sub.matching_inputs.clone();
        t.mask[3] = 1 << MASK_BITS;
        assert_eq!(
            t.check(&configs),
            Err(MatchingCheckError::MaskOutOfRange {
                index: 3,
                value: 1 << MASK_BITS
            })
        );

        // Mask on coefficient 0.
        let mut t = sub.matching_inputs.clone();
        let mut coeffs = t.m_mask.coefficients().to_vec();
        coeffs[n - 1] = BigInt::from(1u32);
        t.m_mask = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(MatchingCheckError::NonZeroCoefficient {
                which: "mask",
                index: 0,
                ..
            })
        ));

        // Build-time refusals.
        let (_, pk) = keypair();
        let err = build_matching_submission(
            pk.clone(),
            address_to_biguint(ALICE).unwrap(),
            Role::A,
            Vector([FRAC_SCALE as i32 + 1; K]),
            demo_mask(),
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("entry"), "{err}");
        let mut bad_mask = demo_mask();
        bad_mask[0] = 1024;
        let err = build_matching_submission(
            pk,
            address_to_biguint(ALICE).unwrap(),
            Role::A,
            Vector::from_f64(&DEMO_A).unwrap(),
            bad_mask,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("mask"), "{err}");
        assert!(Role::from_index(2).is_err());
    }

    /// `nargo fmt` re-wraps long generated lines (the checked-in files are
    /// formatted), so the drift guard compares the token stream.
    fn assert_checked_in(rel: &str, generated: &str) {
        let path = format!(
            "{}/../../circuits/lib/src/configs/{rel}",
            env!("CARGO_MANIFEST_DIR")
        );
        let checked_in = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{path} missing; write it from codegen output"));
        let tokens = |s: &str| {
            s.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .replace("[ ", "[")
                .replace(", ]", "]")
                .replace(",]", "]")
        };
        assert_eq!(
            tokens(&checked_in),
            tokens(generated),
            "{path} drifted from codegen"
        );
    }

    #[test]
    fn test_checked_in_matching_configs_match_codegen() {
        let preset = matching_preset().unwrap();
        let configs = MatchingConfigs::compute(&preset).unwrap();
        assert_eq!(configs.m_bit, 51);
        assert_checked_in("ckks_matching_ps5.nr", &generate_matching_configs(&configs));
    }
}
