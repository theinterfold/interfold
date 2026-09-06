// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS treasury-risk validity leg: witness builder and codegen for the
//! `ckks_treasury_validity_ps5` circuit (Noir:
//! `lib::core::threshold::ckks_treasury_validity`) and the ParamSet-5
//! Greco legs (`user_data_encryption_ckks_ct{0,1}_ps5`).
//!
//! A treasury submission is THREE COEFFICIENT-encoded encryptions proven
//! in SEVEN legs bound by shared commitments: Greco ct0 + ct1 for each of
//! the FORWARD, REVERSED and MASK ciphertexts, and this ONE validity leg,
//! which takes the three message polynomials privately, recomputes the
//! three `m_commitment`s (same packing width `BIT_M` / domain separator as
//! the ct0 legs) and proves the layout predicate.
//!
//! ## Coefficient layout (the policy's contract —
//! `e3_trckks::policy::coefficient_layout`)
//!
//! DAO `i` (its on-chain slot `index`) encrypts, COEFFICIENT-encoded at
//! scale Δ (`c_k = round(Δ · v_k)`, no cosine table, no slots):
//!
//! - `ct_fwd = forward(x)`: `x_a` on coefficient `a + 1`, `a < ASSETS`;
//! - `ct_rev = reversed(w ∘ x)`: `w_a · x_a` on coefficient `N − a − 1`;
//! - `ct_mask = mask(m)`: the integer `m_j ∈ [0, 1024)` on coefficient
//!   `j + 1`, `j < MASK_WIDTH`.
//!
//! Exposures and the PUBLIC weights are fixed point over `2^FRAC_BITS`:
//! `x_a = X_a / 2^16 ∈ [0, 1]`, `w_a = W_a / 2^16`, `|w_a| ≤ 1`. With
//! Δ = 2^40 both `Δ · X_a / 2^16` and `Δ · W_a · X_a / 2^32` are exact
//! integers; the circuit still keeps the credit leg's slack pattern.
//!
//! The network sums the three ciphertext families across DAOs and opens
//! `relin(F · R) + M`; coefficient 0 is `−Σ_a w_a (Σ_i x_{i,a})²` (the
//! `t^N ≡ −1` wrap — the app negates).

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
pub const TREASURY_PARAM_SET: u8 = 5;
/// Nargo package of the treasury leg.
pub const TREASURY_CIRCUIT_PACKAGE: &str = "ckks_treasury_validity_ps5";
/// Number of public assets per exposure vector (Noir `ASSETS`).
pub const ASSETS: usize = 4;
/// Cross-term mask width (Noir `MASK_WIDTH`): coefficients `1..=128`.
pub const MASK_WIDTH: usize = 128;
/// Mask entries are integers `< 2^MASK_BITS` (Noir `MASK_BITS`).
pub const MASK_BITS: u32 = 10;
/// Fixed-point fractional bits of exposures and weights (Noir `FRAC_BITS`).
pub const FRAC_BITS: u32 = 16;
/// `2^FRAC_BITS`.
pub const FRAC_SCALE: i64 = 1 << FRAC_BITS;
/// Per-coefficient slack of the encoding windows (Noir `SLACK`).
pub const SLACK: u32 = 8;
/// `log2(N)` for the pinned degree.
pub const LOG_N: u32 = 9;
/// Number of public-input words of the treasury leg (6 inputs + 3 outputs):
/// `[w_0..w_3, address, index, m_c_fwd, m_c_rev, m_c_mask]`.
pub const TREASURY_PUBLIC_INPUTS: usize = ASSETS + 2 + 3;
/// Word offsets in the public-input list.
pub const WORD_WEIGHTS: usize = 0;
pub const WORD_ADDRESS: usize = ASSETS;
pub const WORD_INDEX: usize = ASSETS + 1;
pub const WORD_M_FWD: usize = ASSETS + 2;
pub const WORD_M_REV: usize = ASSETS + 3;
pub const WORD_M_MASK: usize = ASSETS + 4;

/// The ParamSet-5 CKKS parameters.
pub fn treasury_ckks_params() -> Result<Arc<CkksParameters>, CircuitsErrors> {
    e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(TREASURY_PARAM_SET)
        .map_err(|e| CircuitsErrors::Other(format!("ParamSet-5 CKKS params: {e}")))
}

/// The Greco preset for ParamSet 5 (`input_bound = 1024`).
pub fn treasury_preset() -> Result<CkksPreset, CircuitsErrors> {
    ckks_preset_for_param_set(TREASURY_PARAM_SET)
}

/// Fixed-point exposures `X_a` (`x_a = X_a / 2^16 ∈ [0, 1]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposures(pub [u32; ASSETS]);

impl Exposures {
    /// Round cap-normalised f64 exposures into the fixed point.
    pub fn from_f64(x: &[f64; ASSETS]) -> Result<Self, CircuitsErrors> {
        let mut out = [0u32; ASSETS];
        for (a, v) in x.iter().enumerate() {
            if !v.is_finite() || *v < 0.0 || *v > 1.0 {
                return Err(CircuitsErrors::Other(format!(
                    "exposure {a} = {v} is outside [0, 1]"
                )));
            }
            out[a] = (v * FRAC_SCALE as f64).round() as u32;
        }
        Ok(Self(out))
    }

    /// The f64 exposures (what the encoder takes).
    pub fn to_f64(&self) -> [f64; ASSETS] {
        std::array::from_fn(|a| self.0[a] as f64 / FRAC_SCALE as f64)
    }

    pub fn in_range(&self) -> bool {
        self.0.iter().all(|x| i64::from(*x) <= FRAC_SCALE)
    }
}

/// Fixed-point PUBLIC risk weights `W_a` (`w_a = W_a / 2^16`, `|w_a| ≤ 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Weights(pub [i32; ASSETS]);

impl Weights {
    pub fn from_f64(w: &[f64; ASSETS]) -> Result<Self, CircuitsErrors> {
        let mut out = [0i32; ASSETS];
        for (a, v) in w.iter().enumerate() {
            if !v.is_finite() || v.abs() > 1.0 {
                return Err(CircuitsErrors::Other(format!(
                    "weight {a} = {v} is outside [-1, 1]"
                )));
            }
            out[a] = (v * FRAC_SCALE as f64).round() as i32;
        }
        Ok(Self(out))
    }

    pub fn to_f64(&self) -> [f64; ASSETS] {
        std::array::from_fn(|a| self.0[a] as f64 / FRAC_SCALE as f64)
    }

    pub fn in_range(&self) -> bool {
        self.0.iter().all(|w| i64::from(*w).abs() <= FRAC_SCALE)
    }

    /// The f64 weighted vector `w ∘ x` the reversed ciphertext encodes.
    pub fn weighted(&self, x: &Exposures) -> [f64; ASSETS] {
        let w = self.to_f64();
        let x = x.to_f64();
        std::array::from_fn(|a| w[a] * x[a])
    }
}

/// Public parameters of the treasury leg (baked into
/// `configs/ckks_treasury_ps5.nr`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreasuryConfigs {
    pub n: usize,
    /// `delta` as an exact integer.
    pub delta: BigUint,
    /// The ct0 leg's `m_bound`.
    pub m_bound: BigUint,
    /// Packing width of `m` (`BIT_M` of the ct0 leg).
    pub m_bit: u32,
}

impl TreasuryConfigs {
    pub fn compute(preset: &CkksPreset) -> Result<Self, CircuitsErrors> {
        let bounds = GrecoBounds::compute(preset.clone(), &())?;
        let bits =
            crate::threshold::user_data_encryption_ckks::Bits::compute(preset.clone(), &bounds)?;
        let scale = preset.params.scale();
        if scale.fract() != 0.0 || scale <= 0.0 || scale >= 2f64.powi(120) {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not an exact integer the treasury leg can pin"
            )));
        }
        let n = preset.params.degree();
        if n != 1usize << LOG_N {
            return Err(CircuitsErrors::Other(format!(
                "treasury leg is pinned to N = 2^{LOG_N}, got {n}"
            )));
        }
        if 2 * MASK_WIDTH >= n || ASSETS + 1 > MASK_WIDTH {
            return Err(CircuitsErrors::Other(
                "mask width must cover the cross-term block and stay below N/2".into(),
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
        // Field soundness: 2^32 · |c| + Δ · 2^32 must stay far below 2^253.
        if bits.m_bit + 2 * FRAC_BITS + 2 >= 250 {
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
pub enum TreasuryCheckError {
    #[error("exposure {index} = {value} is outside [0, 2^{FRAC_BITS}]")]
    ExposureOutOfRange { index: usize, value: u32 },
    #[error("weight {index} = {value} is outside |W| <= 2^{FRAC_BITS}")]
    WeightOutOfRange { index: usize, value: i32 },
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
}

/// Witness of the treasury leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryInputs {
    /// `forward(x)` (circuit layout: reversed, centered) — the SAME `m`
    /// the forward ct0 leg carries.
    pub m_fwd: Polynomial,
    /// `reversed(w ∘ x)` — the SAME `m` the reversed ct0 leg carries.
    pub m_rev: Polynomial,
    /// `mask(m)` — the SAME `m` the mask ct0 leg carries.
    pub m_mask: Polynomial,
    /// The DAO's fixed-point exposures.
    pub x: Exposures,
    /// The DAO's cross-term mask (integers `< 1024`).
    pub mask: Vec<u32>,
    /// The round's PUBLIC weights.
    pub weights: Weights,
    /// The DAO's address as a big-endian 20-byte integer.
    pub address: BigUint,
    /// The DAO's slot index (assigned on-chain).
    pub index: u32,
}

/// Coefficient `k` of a circuit-layout polynomial (`coeffs[n − 1 − k]`).
fn coeff(m: &Polynomial, k: usize) -> &BigInt {
    let n = m.coefficients().len();
    &m.coefficients()[n - 1 - k]
}

impl TreasuryInputs {
    /// Native pre-check of exactly the constraints the Noir leg enforces,
    /// in the circuit's order.
    pub fn check(&self, configs: &TreasuryConfigs) -> Result<(), TreasuryCheckError> {
        let n = configs.n;
        for (index, x) in self.x.0.iter().enumerate() {
            if i64::from(*x) > FRAC_SCALE {
                return Err(TreasuryCheckError::ExposureOutOfRange { index, value: *x });
            }
        }
        for (index, w) in self.weights.0.iter().enumerate() {
            if i64::from(*w).abs() > FRAC_SCALE {
                return Err(TreasuryCheckError::WeightOutOfRange { index, value: *w });
            }
        }
        if self.mask.len() != MASK_WIDTH {
            return Err(TreasuryCheckError::WrongDegree {
                which: "mask vector",
                got: self.mask.len(),
                want: MASK_WIDTH,
            });
        }
        for (index, m) in self.mask.iter().enumerate() {
            if *m >= (1u32 << MASK_BITS) {
                return Err(TreasuryCheckError::MaskOutOfRange { index, value: *m });
            }
        }
        for (which, m) in [
            ("forward", &self.m_fwd),
            ("reversed", &self.m_rev),
            ("mask", &self.m_mask),
        ] {
            if m.coefficients().len() != n {
                return Err(TreasuryCheckError::WrongDegree {
                    which,
                    got: m.coefficients().len(),
                    want: n,
                });
            }
        }
        let bound = BigInt::from(configs.m_bound.clone());
        let delta = BigInt::from(configs.delta.clone());
        let scale = BigInt::from(FRAC_SCALE);
        let scale_sq = &scale * &scale;
        let slack = BigInt::from(SLACK);
        let too_large =
            |which, index: usize, value: &BigInt| TreasuryCheckError::CoefficientTooLarge {
                which,
                index,
                value: value.clone(),
                bound: configs.m_bound.clone(),
            };

        // Forward: c_{a+1} ≈ Δ · X_a / 2^16.
        for a in 0..ASSETS {
            let c = coeff(&self.m_fwd, a + 1);
            if c.abs() > bound {
                return Err(too_large("forward", a + 1, c));
            }
            let residual = &scale * c - &delta * BigInt::from(self.x.0[a]);
            if residual.abs() > BigInt::from(FRAC_SCALE / 2) + &slack {
                return Err(TreasuryCheckError::EncodingMismatch {
                    which: "forward",
                    index: a + 1,
                    residual,
                });
            }
        }
        for k in (0..n).filter(|k| *k == 0 || *k > ASSETS) {
            let c = coeff(&self.m_fwd, k);
            if !c.is_zero() {
                return Err(TreasuryCheckError::NonZeroCoefficient {
                    which: "forward",
                    index: k,
                    value: c.clone(),
                });
            }
        }
        // Reversed: c_{N−a−1} ≈ Δ · W_a · X_a / 2^32.
        for a in 0..ASSETS {
            let k = n - a - 1;
            let c = coeff(&self.m_rev, k);
            if c.abs() > bound {
                return Err(too_large("reversed", k, c));
            }
            let residual = &scale_sq * c
                - &delta * BigInt::from(self.weights.0[a]) * BigInt::from(self.x.0[a]);
            if residual.abs() > BigInt::from((FRAC_SCALE * FRAC_SCALE) / 2) + &slack {
                return Err(TreasuryCheckError::EncodingMismatch {
                    which: "reversed",
                    index: k,
                    residual,
                });
            }
        }
        for k in 0..n - ASSETS {
            let c = coeff(&self.m_rev, k);
            if !c.is_zero() {
                return Err(TreasuryCheckError::NonZeroCoefficient {
                    which: "reversed",
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
                return Err(TreasuryCheckError::EncodingMismatch {
                    which: "mask",
                    index: j + 1,
                    residual,
                });
            }
        }
        for k in (0..n).filter(|k| *k == 0 || *k > MASK_WIDTH) {
            let c = coeff(&self.m_mask, k);
            if !c.is_zero() {
                return Err(TreasuryCheckError::NonZeroCoefficient {
                    which: "mask",
                    index: k,
                    value: c.clone(),
                });
            }
        }
        Ok(())
    }

    /// Prover.toml for the treasury leg.
    pub fn to_toml(&self) -> Result<String, CircuitsErrors> {
        Ok(toml::to_string(&self.to_json())?)
    }

    /// The treasury leg's inputs as JSON (the noir_js `InputMap` shape;
    /// also what `to_toml` serializes). Negative weights are emitted as the
    /// field element `p − |W|` in decimal (what the on-chain word carries).
    pub fn to_json(&self) -> serde_json::Value {
        use crate::polynomial_to_toml_json;
        let x: Vec<String> = self.x.0.iter().map(|v| v.to_string()).collect();
        let mask: Vec<String> = self.mask.iter().map(|v| v.to_string()).collect();
        let weights: Vec<String> = self
            .weights
            .0
            .iter()
            .map(|w| signed_field_decimal(i64::from(*w)))
            .collect();
        serde_json::json!({
            "m_fwd": polynomial_to_toml_json(&self.m_fwd),
            "m_rev": polynomial_to_toml_json(&self.m_rev),
            "m_mask": polynomial_to_toml_json(&self.m_mask),
            "x": x,
            "mask": mask,
            "weights": weights,
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

/// One proven encryption of the submission (forward, reversed or mask).
#[derive(Debug, Clone)]
pub struct TreasuryCiphertextLeg {
    pub ciphertext: Vec<u8>,
    /// Serves BOTH Greco bin packages of this ciphertext.
    pub greco_toml: String,
    /// The Greco message polynomial, for cross-leg assertions.
    pub greco_m: Polynomial,
}

/// The complete client-side submission: three ciphertexts, their Greco
/// witnesses, and the validity leg's witness.
#[derive(Debug, Clone)]
pub struct TreasurySubmission {
    pub forward: TreasuryCiphertextLeg,
    pub reversed: TreasuryCiphertextLeg,
    pub mask: TreasuryCiphertextLeg,
    pub treasury_toml: String,
    pub treasury_inputs: TreasuryInputs,
}

/// The length-N coefficient vectors of one submission, in the policy's
/// layout (`e3_trckks::policy::coefficient_layout`, duplicated here so
/// zk-helpers stays free of the trckks dependency; the policy tests pin
/// the same indices).
pub fn layout_vectors(
    n: usize,
    x: &Exposures,
    weights: &Weights,
    mask: &[u32],
) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let xf = x.to_f64();
    let wx = weights.weighted(x);
    let mut fwd = vec![0.0f64; n];
    let mut rev = vec![0.0f64; n];
    let mut msk = vec![0.0f64; n];
    for a in 0..ASSETS {
        fwd[a + 1] = xf[a];
        rev[n - a - 1] = wx[a];
    }
    for (j, m) in mask.iter().enumerate() {
        msk[j + 1] = *m as f64;
    }
    (fwd, rev, msk)
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
/// caller-supplied RNG. Does NOT run the treasury pre-check.
pub fn treasury_greco_inputs_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: &CkksPublicKey,
    values: &[f64],
    rng: &mut R,
) -> Result<GrecoInputs, CircuitsErrors> {
    let preset = treasury_preset()?;
    let pt = encode_coefficients(&preset.params, values)?;
    GrecoInputs::compute_from_plaintext_with_rng(preset, public_key, &pt, rng)
}

/// Uniform cross-term mask: `MASK_WIDTH` integers in `[0, 2^MASK_BITS)`.
pub fn sample_mask<R: rand::RngCore>(rng: &mut R) -> Vec<u32> {
    (0..MASK_WIDTH)
        .map(|_| rng.next_u32() % (1u32 << MASK_BITS))
        .collect()
}

/// Builds a submission from THREE encryptions (fresh randomness per call).
pub fn build_treasury_submission(
    public_key: CkksPublicKey,
    address: BigUint,
    index: u32,
    x: Exposures,
    weights: Weights,
    mask: Vec<u32>,
) -> Result<TreasurySubmission, CircuitsErrors> {
    build_treasury_submission_with_rng(
        public_key,
        address,
        index,
        x,
        weights,
        mask,
        &mut rand::rng(),
    )
}

/// [`build_treasury_submission`] with a caller-supplied RNG: the forward
/// encryption draws first, then the reversed, then the mask (the order
/// the WASM builder mirrors).
pub fn build_treasury_submission_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: CkksPublicKey,
    address: BigUint,
    index: u32,
    x: Exposures,
    weights: Weights,
    mask: Vec<u32>,
    rng: &mut R,
) -> Result<TreasurySubmission, CircuitsErrors> {
    let preset = treasury_preset()?;
    if !x.in_range() {
        return Err(CircuitsErrors::Other("exposure outside [0, 1]".into()));
    }
    if !weights.in_range() {
        return Err(CircuitsErrors::Other("weight outside [-1, 1]".into()));
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
    let configs = TreasuryConfigs::compute(&preset)?;
    let n = configs.n;
    let (fwd, rev, msk) = layout_vectors(n, &x, &weights, &mask);
    let greco_f = treasury_greco_inputs_with_rng(&public_key, &fwd, rng)?;
    let greco_r = treasury_greco_inputs_with_rng(&public_key, &rev, rng)?;
    let greco_m = treasury_greco_inputs_with_rng(&public_key, &msk, rng)?;
    let treasury_inputs = TreasuryInputs {
        m_fwd: greco_f.m.clone(),
        m_rev: greco_r.m.clone(),
        m_mask: greco_m.m.clone(),
        x,
        mask,
        weights,
        address,
        index,
    };
    treasury_inputs
        .check(&configs)
        .map_err(|e| CircuitsErrors::Other(format!("treasury leg pre-check failed: {e}")))?;
    let treasury_toml = treasury_inputs.to_toml()?;
    let leg = |greco: GrecoInputs| -> Result<TreasuryCiphertextLeg, CircuitsErrors> {
        let ciphertext = greco.ciphertext.clone();
        let greco_m = greco.m.clone();
        let greco_toml = generate_toml(greco)?;
        Ok(TreasuryCiphertextLeg {
            ciphertext,
            greco_toml,
            greco_m,
        })
    };
    Ok(TreasurySubmission {
        forward: leg(greco_f)?,
        reversed: leg(greco_r)?,
        mask: leg(greco_m)?,
        treasury_toml,
        treasury_inputs,
    })
}

/// Recomputes a ct0 leg's `m_commitment` natively (must equal that leg's
/// third public output).
pub fn compute_m_commitment(m: &Polynomial, m_bit: u32) -> BigInt {
    crate::circuits::commitments::compute_user_data_encryption_m_commitment(m, m_bit)
}

/// The on-chain public-input words of the treasury leg, in circuit order:
/// `[w_0..w_3, address, index, m_commitment_fwd, m_commitment_rev, m_commitment_mask]`.
pub fn public_input_words(inputs: &TreasuryInputs, m_bit: u32) -> Vec<String> {
    let mut words = Vec::with_capacity(TREASURY_PUBLIC_INPUTS);
    for w in inputs.weights.0 {
        words.push(field_word_hex(&signed_field_bigint(i64::from(w))));
    }
    words.push(field_word_hex(&BigInt::from(inputs.address.clone())));
    words.push(field_word_hex(&BigInt::from(inputs.index)));
    words.push(field_word_hex(&compute_m_commitment(&inputs.m_fwd, m_bit)));
    words.push(field_word_hex(&compute_m_commitment(&inputs.m_rev, m_bit)));
    words.push(field_word_hex(&compute_m_commitment(&inputs.m_mask, m_bit)));
    debug_assert_eq!(words.len(), TREASURY_PUBLIC_INPUTS);
    words
}

/// The risk the policy opens for a set of books under `weights`:
/// `Σ_a w_a (Σ_i x_{i,a})²` (oracle; the network never sees the books).
pub fn expected_risk(books: &[Exposures], weights: &Weights) -> f64 {
    let w = weights.to_f64();
    let mut agg = [0.0f64; ASSETS];
    for b in books {
        let x = b.to_f64();
        for a in 0..ASSETS {
            agg[a] += x[a];
        }
    }
    (0..ASSETS).map(|a| w[a] * agg[a] * agg[a]).sum()
}

/// Generated Noir configs for the treasury leg (`configs/ckks_treasury_ps5.nr`).
pub fn generate_treasury_configs(configs: &TreasuryConfigs) -> String {
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers ckks_treasury_validity codegen
// (`cargo run -p e3-zk-helpers --example gen_ckks_treasury_prover -- configs`).
// Do not hand-edit; regenerate-and-diff is enforced by
// `test_checked_in_treasury_configs_match_codegen`.
// CKKS treasury-risk validity leg on ParamSet {ps}: N={n}, delta=2^{scale_bits},
// coefficient encoding (forward / reversed / mask layouts).

use crate::core::threshold::ckks_treasury_validity::Configs as CkksTreasuryValidityConfigs;

pub global CKKS_TREASURY_N: u32 = {n};
/// Packing width of `m` — MUST equal the ct0 leg's BIT_M so the
/// recomputed m_commitment matches.
pub global CKKS_TREASURY_BIT_M: u32 = {m_bit};
pub global CKKS_TREASURY_DELTA: Field = {delta};
pub global CKKS_TREASURY_M_BOUND: Field = {m_bound};

pub global CKKS_TREASURY_CONFIGS: CkksTreasuryValidityConfigs =
    CkksTreasuryValidityConfigs::new(CKKS_TREASURY_DELTA, CKKS_TREASURY_M_BOUND);
"#,
        ps = TREASURY_PARAM_SET,
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
    /// x = [0.30, 0.10, 0.45, 0.15], w = [0.5, -0.25, 1.0, 0.125].
    const DEMO_X: Exposures = Exposures([19661, 6554, 29491, 9830]);
    const DEMO_W: Weights = Weights([32768, -16384, 65536, 8192]);
    const DEMO_INDEX: u32 = 1;

    fn demo_mask() -> Vec<u32> {
        (0..MASK_WIDTH as u32)
            .map(|j| (j * 37 + 11) % 1024)
            .collect()
    }

    fn keypair() -> CkksPublicKey {
        let preset = treasury_preset().unwrap();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        CkksPublicKey::new(&sk, &mut rng).unwrap()
    }

    fn demo_submission() -> TreasurySubmission {
        build_treasury_submission(
            keypair(),
            address_to_biguint(ALICE).unwrap(),
            DEMO_INDEX,
            DEMO_X,
            DEMO_W,
            demo_mask(),
        )
        .unwrap()
    }

    #[test]
    fn fixed_point_round_trips() {
        let x = Exposures::from_f64(&[0.30, 0.10, 0.45, 0.15]).unwrap();
        assert_eq!(x, DEMO_X);
        let w = Weights::from_f64(&[0.5, -0.25, 1.0, 0.125]).unwrap();
        assert_eq!(w, DEMO_W);
        assert!(Exposures::from_f64(&[1.5, 0.0, 0.0, 0.0]).is_err());
        assert!(Exposures::from_f64(&[-0.1, 0.0, 0.0, 0.0]).is_err());
        assert!(Weights::from_f64(&[1.5, 0.0, 0.0, 0.0]).is_err());
        assert!(!Exposures([65537, 0, 0, 0]).in_range());
        assert!(!Weights([-65537, 0, 0, 0]).in_range());
        let wx = w.weighted(&x);
        assert!((wx[1] - (-0.25 * (6554.0 / 65536.0))).abs() < 1e-15);
    }

    #[test]
    fn preset_is_the_fhe_params_shape() {
        let preset = treasury_preset().unwrap();
        assert_eq!(preset.params.degree(), 512);
        assert_eq!(preset.params.moduli().len(), 3);
        assert_eq!(preset.params.scale(), 2f64.powi(40));
        assert_eq!(preset.input_bound, 1024.0);
        let configs = TreasuryConfigs::compute(&preset).unwrap();
        assert_eq!(configs.m_bit, 51);
        assert_eq!(configs.delta, BigUint::from(1u128 << 40));
    }

    /// The layout matches `e3_trckks::policy::coefficient_layout` index
    /// for index (forward → j+1, reversed → n−j−1, mask → j+1).
    #[test]
    fn layout_vectors_match_policy_indices() {
        let n = 512;
        let mask = demo_mask();
        let (fwd, rev, msk) = layout_vectors(n, &DEMO_X, &DEMO_W, &mask);
        let x = DEMO_X.to_f64();
        let wx = DEMO_W.weighted(&DEMO_X);
        assert_eq!(fwd[0], 0.0);
        for a in 0..ASSETS {
            assert_eq!(fwd[a + 1], x[a]);
            assert_eq!(rev[n - a - 1], wx[a]);
        }
        assert!(fwd[ASSETS + 1..].iter().all(|v| *v == 0.0));
        assert!(rev[..n - ASSETS].iter().all(|v| *v == 0.0));
        assert_eq!(msk[0], 0.0);
        for (j, m) in mask.iter().enumerate() {
            assert_eq!(msk[j + 1], *m as f64);
        }
        assert!(msk[MASK_WIDTH + 1..].iter().all(|v| *v == 0.0));
    }

    /// The encoder's coefficient plaintext is EXACTLY the integers the
    /// circuit pins (`X · 2^24`, `W · X · 2^8`, `Δ · m`).
    #[test]
    fn encoder_plaintext_matches_layout_contract() {
        let sub = demo_submission();
        let configs = TreasuryConfigs::compute(&treasury_preset().unwrap()).unwrap();
        let n = configs.n;
        let t = &sub.treasury_inputs;
        t.check(&configs).unwrap();
        for a in 0..ASSETS {
            assert_eq!(
                *coeff(&t.m_fwd, a + 1),
                BigInt::from(DEMO_X.0[a]) << 24,
                "forward {a}"
            );
            assert_eq!(
                *coeff(&t.m_rev, n - a - 1),
                (BigInt::from(DEMO_W.0[a]) * BigInt::from(DEMO_X.0[a])) << 8,
                "reversed {a}"
            );
        }
        for (j, m) in demo_mask().iter().enumerate() {
            assert_eq!(*coeff(&t.m_mask, j + 1), BigInt::from(*m) << 40);
        }
        assert_eq!(t.m_fwd, sub.forward.greco_m);
        assert_eq!(t.m_rev, sub.reversed.greco_m);
        assert_eq!(t.m_mask, sub.mask.greco_m);
        assert_ne!(sub.forward.ciphertext, sub.reversed.ciphertext);
        assert!(sub.treasury_toml.contains("weights = ["));
        let words = public_input_words(t, configs.m_bit);
        assert_eq!(words.len(), TREASURY_PUBLIC_INPUTS);
        assert_eq!(
            words[WORD_WEIGHTS + 1],
            field_word_hex(&(bn254_r() - BigInt::from(16384)))
        );
        assert!(words[WORD_ADDRESS].ends_with(&ALICE[2..]));
        assert_eq!(words[WORD_INDEX], field_word_hex(&BigInt::from(DEMO_INDEX)));
        assert_eq!(
            words[WORD_M_FWD],
            field_word_hex(&compute_m_commitment(&sub.forward.greco_m, configs.m_bit))
        );
        assert_eq!(
            words[WORD_M_REV],
            field_word_hex(&compute_m_commitment(&sub.reversed.greco_m, configs.m_bit))
        );
        assert_eq!(
            words[WORD_M_MASK],
            field_word_hex(&compute_m_commitment(&sub.mask.greco_m, configs.m_bit))
        );
        assert_ne!(words[WORD_M_FWD], words[WORD_M_REV]);
    }

    #[test]
    fn native_check_attributes_each_tamper() {
        let sub = demo_submission();
        let configs = TreasuryConfigs::compute(&treasury_preset().unwrap()).unwrap();
        let n = configs.n;

        // Wrong exposure claim.
        let mut t = sub.treasury_inputs.clone();
        t.x.0[2] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(TreasuryCheckError::EncodingMismatch {
                which: "forward",
                index: 3,
                ..
            })
        ));

        // Wrong weights (the reversed ct was encrypted under the real ones).
        let mut t = sub.treasury_inputs.clone();
        t.weights.0[1] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(TreasuryCheckError::EncodingMismatch {
                which: "reversed",
                ..
            })
        ));

        // Wrong mask claim.
        let mut t = sub.treasury_inputs.clone();
        t.mask[7] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(TreasuryCheckError::EncodingMismatch {
                which: "mask",
                index: 8,
                ..
            })
        ));

        // Hidden coefficient in the forward tail.
        let mut t = sub.treasury_inputs.clone();
        let mut coeffs = t.m_fwd.coefficients().to_vec();
        coeffs[n - 1 - 9] = BigInt::from(1);
        t.m_fwd = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(TreasuryCheckError::NonZeroCoefficient {
                which: "forward",
                index: 9,
                ..
            })
        ));

        // Mask on coefficient 0 (the result).
        let mut t = sub.treasury_inputs.clone();
        let mut coeffs = t.m_mask.coefficients().to_vec();
        coeffs[n - 1] = BigInt::from(1u64 << 40);
        t.m_mask = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(TreasuryCheckError::NonZeroCoefficient {
                which: "mask",
                index: 0,
                ..
            })
        ));

        // Range refusals.
        let mut t = sub.treasury_inputs.clone();
        t.x.0[0] = 65537;
        assert_eq!(
            t.check(&configs),
            Err(TreasuryCheckError::ExposureOutOfRange {
                index: 0,
                value: 65537
            })
        );
        let mut t = sub.treasury_inputs.clone();
        t.weights.0[3] = -65537;
        assert_eq!(
            t.check(&configs),
            Err(TreasuryCheckError::WeightOutOfRange {
                index: 3,
                value: -65537
            })
        );
        let mut t = sub.treasury_inputs.clone();
        t.mask[0] = 1024;
        assert_eq!(
            t.check(&configs),
            Err(TreasuryCheckError::MaskOutOfRange {
                index: 0,
                value: 1024
            })
        );

        // Build-time refusals.
        let alice = address_to_biguint(ALICE).unwrap();
        let err = build_treasury_submission(
            keypair(),
            alice.clone(),
            0,
            Exposures([65537, 0, 0, 0]),
            DEMO_W,
            demo_mask(),
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("exposure"), "{err}");
        let err = build_treasury_submission(
            keypair(),
            alice.clone(),
            0,
            DEMO_X,
            Weights([0, 0, 0, 65537]),
            demo_mask(),
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("weight"), "{err}");
        let mut bad_mask = demo_mask();
        bad_mask[3] = 1024;
        let err = build_treasury_submission(keypair(), alice, 0, DEMO_X, DEMO_W, bad_mask)
            .expect_err("must reject");
        assert!(err.to_string().contains("mask"), "{err}");
    }

    #[test]
    fn expected_risk_is_the_weighted_square_of_the_aggregate() {
        let books = [DEMO_X, DEMO_X];
        let w = DEMO_W.to_f64();
        let x = DEMO_X.to_f64();
        let want: f64 = (0..ASSETS).map(|a| w[a] * (2.0 * x[a]).powi(2)).sum();
        assert!((expected_risk(&books, &DEMO_W) - want).abs() < 1e-12);
    }

    #[test]
    fn sample_mask_is_in_range() {
        let m = sample_mask(&mut rand::rng());
        assert_eq!(m.len(), MASK_WIDTH);
        assert!(m.iter().all(|v| *v < 1024));
    }

    /// `nargo fmt` re-wraps long generated lines, so the drift guard
    /// compares the token stream.
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
    fn test_checked_in_treasury_configs_match_codegen() {
        let preset = treasury_preset().unwrap();
        let configs = TreasuryConfigs::compute(&preset).unwrap();
        assert_checked_in("ckks_treasury_ps5.nr", &generate_treasury_configs(&configs));
    }
}
