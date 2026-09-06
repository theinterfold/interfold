// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private federated-averaging validity leg: witness builder and
//! codegen for the `ckks_fedavg_validity_ps5` circuit (Noir:
//! `lib::core::threshold::ckks_fedavg_validity`) on top of the ParamSet-5
//! Greco legs (`user_data_encryption_ckks_ct{0,1}_ps5`).
//!
//! One client update is TWO encryptions proven in FIVE legs bound by
//! shared commitments: Greco ct0 + ct1 for the GRADIENT ciphertext, Greco
//! ct0 + ct1 for the COUNT ciphertext, and this ONE validity leg, which
//! takes both message polynomials privately, recomputes both
//! `m_commitment`s (same packing width `BIT_M` / domain separator as the
//! ct0 legs) and proves the update predicate.
//!
//! ## Coefficient layout (the policy's contract — `federated_average_policy`)
//!
//! Client `index` encrypts, COEFFICIENT-encoded at scale Δ
//! ([`e3_trckks::policy::coefficient_layout`]):
//!
//! - `ct_grad = gradient_block(g)`: `g_j` on coefficient `j + 1` for
//!   `j < D`, `1.0` on coefficient `D + 1`, zero elsewhere. Entries are
//!   fixed point `g_j = G_j / 2^WEIGHT_FRAC_BITS`, `|G_j| ≤ 2^16`.
//! - `ct_count = constant(n)`: the PRIVATE integer sample count `n` on
//!   coefficient 0, `1 ≤ n < 2^COUNT_BITS`, zero elsewhere.
//!
//! The network multiplies each pair (scalar × vector: no cross terms, no
//! masks), sums, rescales once and opens: coefficient `j + 1` =
//! `Σ_i n_i g_{i,j}`, coefficient `D + 1` = `Σ_i n_i`.
//!
//! ## Encoding contract (pinned Rust ↔ Noir ↔ WASM)
//!
//! `CkksEncoder::encode_coefficients` rounds per coefficient:
//! `c_k = round(Δ · v_k)`. At Δ = 2^40 with `v = G / 2^16` that is the
//! exact integer `2^24 · G`, so the circuit's window
//! `|2^16 · c_k − Δ · G_j| ≤ 2^15 + SLACK` is met with residual 0; the
//! marker and the count coefficient are exact equalities and every other
//! coefficient must be 0.

use crate::circuits::computation::Computation;
use crate::threshold::ckks_app_validity::field_word_hex;
use crate::threshold::ckks_credit_validity::signed_field_bigint;
use crate::threshold::user_data_encryption_ckks::{
    generate_toml, Bounds as GrecoBounds, CkksPreset, Inputs as GrecoInputs,
};
use crate::CircuitsErrors;
use e3_polynomial::Polynomial;
use fhe::ckks::{CkksEncoder, CkksParameters, CkksPublicKey};
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, Zero};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// On-chain `ParamSet` value of the coefficient-transport preset.
pub const FEDAVG_PARAM_SET: u8 = 5;
/// Nargo package of the federated-averaging leg.
pub const FEDAVG_CIRCUIT_PACKAGE: &str = "ckks_fedavg_validity_ps5";
/// Model-update dimension compiled into the circuit (Noir `CKKS_FEDAVG_D`).
pub const FEDAVG_D: usize = 8;
/// Fractional bits of an update entry (Noir `WEIGHT_FRAC_BITS`).
pub const WEIGHT_FRAC_BITS: u32 = 16;
/// `|G_j| ≤ WEIGHT_LIMIT` (Noir `WEIGHT_LIMIT`): `|g_j| ≤ 1`.
pub const WEIGHT_LIMIT: i64 = 1 << WEIGHT_FRAC_BITS;
/// Fractional bits of the squared-norm bound (Noir `NORM_FRAC_BITS`).
pub const NORM_FRAC_BITS: u32 = 32;
/// Bit width of `norm_bound` (Noir `NORM_BITS`).
pub const NORM_BITS: u32 = 40;
/// Sample-count width (Noir `COUNT_BITS`): `1 ≤ n < 1024`.
pub const COUNT_BITS: u32 = 10;
/// Per-entry slack of the encoding window (Noir `SLACK`).
pub const SLACK: u32 = 8;
/// Half-ulp of the rounding in `2^16 · c − Δ · G` units (Noir `HALF_ULP`).
pub const HALF_ULP: u64 = 1 << (WEIGHT_FRAC_BITS - 1);
/// Upper bound on the public slot index (Noir `MAX_INDEX`).
pub const MAX_INDEX: u32 = 1 << 16;
/// Greco input bound of the preset: every coefficient value is `< 1024`.
pub const FEDAVG_INPUT_BOUND: f64 = 1024.0;

/// The ParamSet-5 CKKS parameters.
pub fn fedavg_ckks_params() -> Result<Arc<CkksParameters>, CircuitsErrors> {
    e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(FEDAVG_PARAM_SET)
        .map_err(|e| CircuitsErrors::Other(format!("ParamSet-5 CKKS params: {e}")))
}

/// The Greco preset for ParamSet 5.
pub fn fedavg_preset() -> Result<CkksPreset, CircuitsErrors> {
    Ok(CkksPreset {
        params: fedavg_ckks_params()?,
        input_bound: FEDAVG_INPUT_BOUND,
    })
}

/// A model update in the circuit's fixed point: `g_j = entries[j] / 2^16`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedPointUpdate {
    pub entries: Vec<i32>,
}

impl FixedPointUpdate {
    /// Round an f64 update into the fixed point.
    pub fn from_f64(g: &[f64]) -> Self {
        let scale = (1u64 << WEIGHT_FRAC_BITS) as f64;
        Self {
            entries: g.iter().map(|v| (v * scale).round() as i32).collect(),
        }
    }

    /// The f64 entries the encoder takes (exact: `G / 2^16`).
    pub fn to_f64(&self) -> Vec<f64> {
        let scale = (1u64 << WEIGHT_FRAC_BITS) as f64;
        self.entries.iter().map(|g| *g as f64 / scale).collect()
    }

    /// Every entry inside `|G| ≤ 2^16`.
    pub fn in_range(&self) -> bool {
        self.entries
            .iter()
            .all(|g| (*g as i64).abs() <= WEIGHT_LIMIT)
    }

    /// `Σ_j G_j²` — the squared norm in `2^32` fixed point.
    pub fn squared_norm(&self) -> u64 {
        self.entries
            .iter()
            .map(|g| (*g as i64 * *g as i64) as u64)
            .sum()
    }

    /// The f64 squared norm `Σ_j g_j²`.
    pub fn squared_norm_f64(&self) -> f64 {
        self.squared_norm() as f64 / 2f64.powi(NORM_FRAC_BITS as i32)
    }
}

/// The round's public squared-norm bound `B` in the circuit's `2^32`
/// fixed point (rounded down so the bound can only tighten).
pub fn norm_bound_fixed_point(bound: f64) -> u64 {
    (bound * 2f64.powi(NORM_FRAC_BITS as i32)).floor() as u64
}

/// Public parameters of the leg (baked into `configs/ckks_fedavg_ps5.nr`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FedAvgConfigs {
    pub n: usize,
    pub d: usize,
    /// `delta` as an exact integer.
    pub delta: BigUint,
    /// The ct0 leg's `m_bound`.
    pub m_bound: BigUint,
    /// Packing width of `m` (`BIT_M` of the ct0 leg).
    pub m_bit: u32,
}

impl FedAvgConfigs {
    pub fn compute(preset: &CkksPreset) -> Result<Self, CircuitsErrors> {
        let bounds = GrecoBounds::compute(preset.clone(), &())?;
        let bits =
            crate::threshold::user_data_encryption_ckks::Bits::compute(preset.clone(), &bounds)?;
        let scale = preset.params.scale();
        if scale.fract() != 0.0 || scale <= 0.0 || scale >= 2f64.powi(120) {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not an exact integer the fedavg leg can pin"
            )));
        }
        // The window `2^16·c − Δ·G` is exact only when Δ / 2^16 is an integer.
        if (scale / 2f64.powi(WEIGHT_FRAC_BITS as i32)).fract() != 0.0 {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not a multiple of 2^{WEIGHT_FRAC_BITS}"
            )));
        }
        let n = preset.params.degree();
        // `COEFFICIENT_OUTPUT_COUNT` (e3_trckks::program) = 64.
        if FEDAVG_D + 2 > 64 {
            return Err(CircuitsErrors::Other(format!(
                "D = {FEDAVG_D} does not fit the published coefficient window"
            )));
        }
        let delta = BigUint::from(scale as u128);
        // The Greco bound must admit the largest coefficient: Δ · 1023.
        let max_coeff = &delta * BigUint::from((1u64 << COUNT_BITS) - 1);
        if max_coeff > bounds.m_bound {
            return Err(CircuitsErrors::Other(format!(
                "Greco m_bound {} does not cover the largest count coefficient {max_coeff}",
                bounds.m_bound
            )));
        }
        Ok(Self {
            n,
            d: FEDAVG_D,
            delta,
            m_bound: bounds.m_bound,
            m_bit: bits.m_bit,
        })
    }

    /// The circuit-layout coefficient `k` of `m` (`coeffs[n − 1 − k]`).
    fn coeff<'a>(&self, m: &'a Polynomial, k: usize) -> &'a BigInt {
        &m.coefficients()[self.n - 1 - k]
    }

    /// Checks that `m` (circuit layout) is `gradient_block(g)` within
    /// the window; returns the first offending coefficient index.
    pub fn check_gradient_block(
        &self,
        m: &Polynomial,
        g: &FixedPointUpdate,
    ) -> Result<(), (usize, BigInt)> {
        let delta = BigInt::from(self.delta.clone());
        let tol = BigInt::from(HALF_ULP + SLACK as u64);
        let scale = BigInt::from(1u64 << WEIGHT_FRAC_BITS);
        if !self.coeff(m, 0).is_zero() {
            return Err((0, self.coeff(m, 0).clone()));
        }
        for (j, gj) in g.entries.iter().enumerate() {
            let c = self.coeff(m, j + 1);
            let residual = &scale * c - &delta * BigInt::from(*gj);
            if residual.abs() > tol {
                return Err((j + 1, residual));
            }
        }
        let marker = self.coeff(m, self.d + 1);
        if *marker != delta {
            return Err((self.d + 1, marker - &delta));
        }
        for k in self.d + 2..self.n {
            if !self.coeff(m, k).is_zero() {
                return Err((k, self.coeff(m, k).clone()));
            }
        }
        Ok(())
    }

    /// Checks that `m` (circuit layout) is `constant(count)`; returns the
    /// first offending coefficient index.
    pub fn check_constant(&self, m: &Polynomial, count: u32) -> Result<(), (usize, BigInt)> {
        let want = BigInt::from(self.delta.clone()) * BigInt::from(count);
        if *self.coeff(m, 0) != want {
            return Err((0, self.coeff(m, 0) - want));
        }
        for k in 1..self.n {
            if !self.coeff(m, k).is_zero() {
                return Err((k, self.coeff(m, k).clone()));
            }
        }
        Ok(())
    }
}

/// Errors from the native constraint pre-check, attributable to a field.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FedAvgCheckError {
    #[error("update has {got} entries, the circuit takes {want}")]
    WrongDimension { got: usize, want: usize },
    #[error("entry {index} is outside |G| <= 2^{WEIGHT_FRAC_BITS} (1.0 in real units)")]
    EntryOutOfRange { index: usize },
    #[error("squared norm {norm} exceeds the round bound {bound} (x 2^32)")]
    NormOverBound { norm: u64, bound: u64 },
    #[error("norm bound {bound} does not fit {NORM_BITS} bits")]
    NormBoundTooLarge { bound: u64 },
    #[error("sample count {count} is not in [1, 2^{COUNT_BITS})")]
    CountOutOfRange { count: u32 },
    #[error("slot index {index} is not below {MAX_INDEX}")]
    IndexOutOfRange { index: u32 },
    #[error("{which} message polynomial has {got} coefficients, expected {want}")]
    WrongDegree {
        which: &'static str,
        got: usize,
        want: usize,
    },
    #[error("|m_{index}| = {value} of the {which} message exceeds m_bound {bound}")]
    CoefficientTooLarge {
        which: &'static str,
        index: usize,
        value: BigInt,
        bound: BigUint,
    },
    #[error("coefficient {index} of the {which} message is not the declared layout (residual {residual})")]
    LayoutMismatch {
        which: &'static str,
        index: usize,
        residual: BigInt,
    },
}

/// Witness of the federated-averaging leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedAvgInputs {
    /// The GRADIENT message polynomial (circuit layout: reversed,
    /// centered) — the SAME `m` the gradient ct0 leg carries.
    pub m_grad: Polynomial,
    /// The COUNT message polynomial — the SAME `m` the count ct0 leg carries.
    pub m_count: Polynomial,
    /// The client's update in fixed point.
    pub update: FixedPointUpdate,
    /// The client's PRIVATE sample count.
    pub count: u32,
    /// The round's public squared-norm bound (`× 2^32`).
    pub norm_bound: u64,
    /// The client's address as a big-endian 20-byte integer.
    pub address: BigUint,
    /// The client's slot index (assigned on-chain).
    pub index: u32,
}

impl FedAvgInputs {
    /// Native pre-check of exactly the constraints the Noir leg enforces,
    /// in the circuit's order.
    pub fn check(&self, configs: &FedAvgConfigs) -> Result<(), FedAvgCheckError> {
        if self.update.entries.len() != configs.d {
            return Err(FedAvgCheckError::WrongDimension {
                got: self.update.entries.len(),
                want: configs.d,
            });
        }
        if self.index >= MAX_INDEX {
            return Err(FedAvgCheckError::IndexOutOfRange { index: self.index });
        }
        if self.norm_bound >= (1u64 << NORM_BITS) {
            return Err(FedAvgCheckError::NormBoundTooLarge {
                bound: self.norm_bound,
            });
        }
        for (index, g) in self.update.entries.iter().enumerate() {
            if (*g as i64).abs() > WEIGHT_LIMIT {
                return Err(FedAvgCheckError::EntryOutOfRange { index });
            }
        }
        let norm = self.update.squared_norm();
        if norm > self.norm_bound {
            return Err(FedAvgCheckError::NormOverBound {
                norm,
                bound: self.norm_bound,
            });
        }
        if self.count == 0 || self.count >= (1u32 << COUNT_BITS) {
            return Err(FedAvgCheckError::CountOutOfRange { count: self.count });
        }
        let n = configs.n;
        let bound = BigInt::from(configs.m_bound.clone());
        for (which, m) in [("gradient", &self.m_grad), ("count", &self.m_count)] {
            let coeffs = m.coefficients();
            if coeffs.len() != n {
                return Err(FedAvgCheckError::WrongDegree {
                    which,
                    got: coeffs.len(),
                    want: n,
                });
            }
            for (index, c) in coeffs.iter().enumerate() {
                if c.abs() > bound {
                    return Err(FedAvgCheckError::CoefficientTooLarge {
                        which,
                        index: n - 1 - index,
                        value: c.clone(),
                        bound: configs.m_bound.clone(),
                    });
                }
            }
        }
        configs
            .check_gradient_block(&self.m_grad, &self.update)
            .map_err(|(index, residual)| FedAvgCheckError::LayoutMismatch {
                which: "gradient",
                index,
                residual,
            })?;
        configs
            .check_constant(&self.m_count, self.count)
            .map_err(|(index, residual)| FedAvgCheckError::LayoutMismatch {
                which: "count",
                index,
                residual,
            })?;
        Ok(())
    }

    /// Prover.toml for the leg.
    pub fn to_toml(&self) -> Result<String, CircuitsErrors> {
        Ok(toml::to_string(&self.to_json())?)
    }

    /// The leg's inputs as JSON (the noir_js `InputMap` shape; also what
    /// `to_toml` serializes). Negative entries are emitted as the field
    /// element `p − |G|` in decimal.
    pub fn to_json(&self) -> serde_json::Value {
        use crate::polynomial_to_toml_json;
        let g: Vec<String> = self
            .update
            .entries
            .iter()
            .map(|v| signed_field_bigint(*v as i64).to_string())
            .collect();
        serde_json::json!({
            "m_grad": polynomial_to_toml_json(&self.m_grad),
            "m_count": polynomial_to_toml_json(&self.m_count),
            "g": g,
            "count": self.count.to_string(),
            "norm_bound": self.norm_bound.to_string(),
            "address": self.address.to_string(),
            "index": self.index.to_string(),
        })
    }
}

/// One proven encryption of the update (gradient or count).
#[derive(Debug, Clone)]
pub struct FedAvgCiphertextLeg {
    pub ciphertext: Vec<u8>,
    /// Serves BOTH Greco bin packages of this ciphertext.
    pub greco_toml: String,
    /// The Greco message polynomial, for cross-leg assertions.
    pub greco_m: Polynomial,
}

/// The complete client-side submission: two ciphertexts, their Greco
/// witnesses, and the validity leg's witness.
#[derive(Debug, Clone)]
pub struct FedAvgSubmission {
    pub gradient: FedAvgCiphertextLeg,
    pub count: FedAvgCiphertextLeg,
    pub fedavg_toml: String,
    pub fedavg_inputs: FedAvgInputs,
}

/// Coefficient-encodes a full length-`N` value vector at level 0 / scale
/// Δ — the plaintext both the Greco legs and the validity leg are proven
/// over.
pub fn encode_coefficients(
    params: &Arc<CkksParameters>,
    values: &[f64],
) -> Result<fhe::ckks::CkksPlaintext, CircuitsErrors> {
    CkksEncoder::new(params)
        .encode_coefficients(values, 0, params.scale())
        .map_err(|e| CircuitsErrors::Other(format!("coefficient encoding: {e}")))
}

/// Greco inputs for ONE coefficient-encoded encryption. Does NOT run the
/// validity pre-check — `build_fedavg_submission` does; this is the escape
/// hatch for deliberately-invalid fixtures.
pub fn fedavg_greco_inputs_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: &CkksPublicKey,
    values: &[f64],
    rng: &mut R,
) -> Result<GrecoInputs, CircuitsErrors> {
    let preset = fedavg_preset()?;
    let pt = encode_coefficients(&preset.params, values)?;
    GrecoInputs::compute_from_plaintext_with_rng(preset, public_key, &pt, rng)
}

/// Client-side layouts, duplicated from
/// `e3_trckks::policy::coefficient_layout` (index for index — pinned by
/// `layouts_match_policy_indices`) so this crate does not pull the
/// runtime crate in.
pub mod layout {
    /// `gradient_block(g)`: `g_j` on coefficient `j + 1`, `1.0` on `d + 1`.
    pub fn gradient_block(g: &[f64], n: usize) -> Vec<f64> {
        assert!(
            g.len() + 2 <= 64,
            "gradient block does not fit the output window"
        );
        let mut c = vec![0.0; n];
        for (j, v) in g.iter().enumerate() {
            c[j + 1] = *v;
        }
        c[g.len() + 1] = 1.0;
        c
    }

    /// `constant(v)`: `v` on coefficient 0 only.
    pub fn constant(v: f64, n: usize) -> Vec<f64> {
        let mut c = vec![0.0; n];
        c[0] = v;
        c
    }
}

/// The two coefficient vectors a client encrypts (length `N` each).
pub fn fedavg_layouts(update: &FixedPointUpdate, count: u32, n: usize) -> (Vec<f64>, Vec<f64>) {
    (
        layout::gradient_block(&update.to_f64(), n),
        layout::constant(count as f64, n),
    )
}

/// Builds a submission from TWO encryptions (fresh randomness per call —
/// never call twice for one submission).
pub fn build_fedavg_submission(
    public_key: CkksPublicKey,
    update: FixedPointUpdate,
    count: u32,
    norm_bound: u64,
    address: BigUint,
    index: u32,
) -> Result<FedAvgSubmission, CircuitsErrors> {
    build_fedavg_submission_with_rng(
        public_key,
        update,
        count,
        norm_bound,
        address,
        index,
        &mut rand::rng(),
    )
}

/// [`build_fedavg_submission`] with a caller-supplied RNG: the gradient
/// encryption draws first, then the count encryption (the order the WASM
/// builder mirrors byte for byte).
pub fn build_fedavg_submission_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: CkksPublicKey,
    update: FixedPointUpdate,
    count: u32,
    norm_bound: u64,
    address: BigUint,
    index: u32,
    rng: &mut R,
) -> Result<FedAvgSubmission, CircuitsErrors> {
    let preset = fedavg_preset()?;
    let configs = FedAvgConfigs::compute(&preset)?;
    if update.entries.len() != configs.d {
        return Err(CircuitsErrors::Other(format!(
            "update has {} entries, the circuit takes {}",
            update.entries.len(),
            configs.d
        )));
    }
    if !update.in_range() {
        return Err(CircuitsErrors::Other(
            "update entry outside |g| <= 1".into(),
        ));
    }
    if update.squared_norm() > norm_bound {
        return Err(CircuitsErrors::Other(format!(
            "squared norm {} exceeds the round bound {norm_bound}",
            update.squared_norm()
        )));
    }
    if count == 0 || count >= (1u32 << COUNT_BITS) {
        return Err(CircuitsErrors::Other(format!(
            "sample count {count} is not in [1, 2^{COUNT_BITS})"
        )));
    }
    let (grad_values, count_values) = fedavg_layouts(&update, count, configs.n);
    let greco_g = fedavg_greco_inputs_with_rng(&public_key, &grad_values, rng)?;
    let greco_c = fedavg_greco_inputs_with_rng(&public_key, &count_values, rng)?;
    let fedavg_inputs = FedAvgInputs {
        m_grad: greco_g.m.clone(),
        m_count: greco_c.m.clone(),
        update,
        count,
        norm_bound,
        address,
        index,
    };
    fedavg_inputs
        .check(&configs)
        .map_err(|e| CircuitsErrors::Other(format!("fedavg leg pre-check failed: {e}")))?;
    let fedavg_toml = fedavg_inputs.to_toml()?;
    let leg = |greco: GrecoInputs| -> Result<FedAvgCiphertextLeg, CircuitsErrors> {
        let ciphertext = greco.ciphertext.clone();
        let greco_m = greco.m.clone();
        let greco_toml = generate_toml(greco)?;
        Ok(FedAvgCiphertextLeg {
            ciphertext,
            greco_toml,
            greco_m,
        })
    };
    Ok(FedAvgSubmission {
        gradient: leg(greco_g)?,
        count: leg(greco_c)?,
        fedavg_toml,
        fedavg_inputs,
    })
}

/// Recomputes a ct0 leg's `m_commitment` natively (must equal that leg's
/// third public output).
pub fn compute_m_commitment(m: &Polynomial, m_bit: u32) -> BigInt {
    crate::circuits::commitments::compute_user_data_encryption_m_commitment(m, m_bit)
}

/// Number of public-input words of the leg (3 inputs + 2 outputs).
pub const FEDAVG_PUBLIC_INPUTS: usize = 5;

/// The on-chain public-input words of the leg, in circuit order:
/// `[norm_bound, address, index, m_commitment_grad, m_commitment_count]`.
pub fn public_input_words(inputs: &FedAvgInputs, m_bit: u32) -> Vec<String> {
    let words = vec![
        field_word_hex(&BigInt::from(inputs.norm_bound)),
        field_word_hex(&BigInt::from(inputs.address.clone())),
        field_word_hex(&BigInt::from(inputs.index)),
        field_word_hex(&compute_m_commitment(&inputs.m_grad, m_bit)),
        field_word_hex(&compute_m_commitment(&inputs.m_count, m_bit)),
    ];
    debug_assert_eq!(words.len(), FEDAVG_PUBLIC_INPUTS);
    words
}

/// Generated Noir configs for the leg (`configs/ckks_fedavg_ps5.nr`).
pub fn generate_fedavg_configs(configs: &FedAvgConfigs) -> String {
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers ckks_fedavg_validity codegen
// (`cargo run -p e3-zk-helpers --example gen_ckks_fedavg_prover -- configs`).
// Do not hand-edit; regenerate-and-diff is enforced by
// `test_checked_in_fedavg_configs_match_codegen`.
// CKKS federated-averaging validity leg on ParamSet {ps}: N={n}, delta=2^{scale_bits},
// coefficient encoding (gradient block of D={d} entries + count constant).

use crate::core::threshold::ckks_fedavg_validity::Configs as CkksFedAvgValidityConfigs;

pub global CKKS_FEDAVG_N: u32 = {n};
/// Model-update dimension the leg is compiled for (`d + 2 <= 64`).
pub global CKKS_FEDAVG_D: u32 = {d};
/// Packing width of `m` — MUST equal the ct0 leg's BIT_M so the
/// recomputed m_commitment matches.
pub global CKKS_FEDAVG_BIT_M: u32 = {m_bit};
pub global CKKS_FEDAVG_DELTA: Field = {delta};
pub global CKKS_FEDAVG_M_BOUND: Field = {m_bound};

pub global CKKS_FEDAVG_CONFIGS: CkksFedAvgValidityConfigs =
    CkksFedAvgValidityConfigs::new(CKKS_FEDAVG_DELTA, CKKS_FEDAVG_M_BOUND);
"#,
        ps = FEDAVG_PARAM_SET,
        n = configs.n,
        d = configs.d,
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
    use crate::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
    use fhe::ckks::CkksSecretKey;
    use fhe_traits::DeserializeParametrized;

    const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const DEMO_G: [f64; FEDAVG_D] = [0.5, -0.25, 0.75, -1.0, 0.125, 0.0, -0.5, 0.3];
    const DEMO_COUNT: u32 = 137;
    /// `B = 2.5` (the demo squared norm is ≈ 2.09).
    const DEMO_BOUND: f64 = 2.5;
    const DEMO_INDEX: u32 = 2;

    fn keypair() -> (CkksSecretKey, CkksPublicKey) {
        let preset = fedavg_preset().unwrap();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();
        (sk, pk)
    }

    fn demo_submission() -> (FedAvgSubmission, CkksSecretKey) {
        let (sk, pk) = keypair();
        let sub = build_fedavg_submission(
            pk,
            FixedPointUpdate::from_f64(&DEMO_G),
            DEMO_COUNT,
            norm_bound_fixed_point(DEMO_BOUND),
            address_to_biguint(ALICE).unwrap(),
            DEMO_INDEX,
        )
        .unwrap();
        (sub, sk)
    }

    #[test]
    fn fixed_point_update_round_trips() {
        let u = FixedPointUpdate::from_f64(&DEMO_G);
        assert_eq!(
            u.entries,
            [32768, -16384, 49152, -65536, 8192, 0, -32768, 19661]
        );
        assert!(u.in_range());
        assert_eq!(u.to_f64()[0], 0.5);
        let want: f64 = DEMO_G.iter().map(|g| g * g).sum();
        // 0.3 rounds to 19661 / 2^16 (2^-17 away), so the norm is within 2^-15.
        assert!((u.squared_norm_f64() - want).abs() < 1e-4);
        assert!(!FixedPointUpdate::from_f64(&[1.5; FEDAVG_D]).in_range());
        assert_eq!(norm_bound_fixed_point(2.0), 1u64 << 33);
    }

    /// The N=32 / D=4 vectors the Noir unit tests pin (`ckks_fedavg_validity.nr`).
    #[test]
    fn small_vectors_match_noir_test_vectors() {
        let u = FixedPointUpdate::from_f64(&[0.5, -0.25, 0.75, -1.0]);
        assert_eq!(u.entries, [32768, -16384, 49152, -65536]);
        assert_eq!(u.squared_norm(), 8_053_063_680);
        assert_eq!(norm_bound_fixed_point(2.0), 8_589_934_592);
        // c = round(2^40 · G / 2^16) = 2^24 · G exactly.
        let params = fedavg_ckks_params().unwrap();
        let pt = encode_coefficients(&params, &layout::gradient_block(&u.to_f64(), 512)).unwrap();
        let dec = CkksEncoder::new(&params)
            .decode_coefficients(&pt, 8)
            .unwrap();
        assert_eq!(dec[1], 0.5);
        assert_eq!(dec[5], 1.0);
        assert_eq!(dec[0], 0.0);
    }

    /// Index-for-index the policy's `coefficient_layout` (the layouts are
    /// duplicated here; `e3_trckks` is not a dependency of this crate).
    #[test]
    fn layouts_match_policy_indices() {
        let g = [0.5, -0.25, 0.75];
        let block = layout::gradient_block(&g, 16);
        assert_eq!(block[0], 0.0);
        assert_eq!(&block[1..4], &g);
        assert_eq!(block[4], 1.0);
        assert!(block[5..].iter().all(|v| *v == 0.0));
        let c = layout::constant(137.0, 16);
        assert_eq!(c[0], 137.0);
        assert!(c[1..].iter().all(|v| *v == 0.0));
    }

    #[test]
    fn preset_is_the_fhe_params_shape() {
        let preset = ckks_preset_for_param_set(FEDAVG_PARAM_SET).unwrap();
        assert_eq!(preset.params.degree(), 512);
        assert_eq!(preset.params.moduli().len(), 3);
        assert_eq!(preset.params.scale(), 2f64.powi(40));
        assert_eq!(preset.input_bound, 1024.0);
    }

    #[test]
    fn submission_passes_native_check_and_binds_both_messages() {
        let (sub, sk) = demo_submission();
        let preset = fedavg_preset().unwrap();
        let configs = FedAvgConfigs::compute(&preset).unwrap();
        sub.fedavg_inputs.check(&configs).unwrap();
        assert_eq!(sub.fedavg_inputs.m_grad, sub.gradient.greco_m);
        assert_eq!(sub.fedavg_inputs.m_count, sub.count.greco_m);
        assert_ne!(sub.gradient.ciphertext, sub.count.ciphertext);
        assert!(sub.fedavg_toml.contains("g = ["));
        let words = public_input_words(&sub.fedavg_inputs, configs.m_bit);
        assert_eq!(words.len(), FEDAVG_PUBLIC_INPUTS);
        assert_eq!(
            words[0],
            field_word_hex(&BigInt::from(norm_bound_fixed_point(DEMO_BOUND)))
        );
        assert!(words[1].ends_with(&ALICE[2..]));
        assert_eq!(words[2], field_word_hex(&BigInt::from(DEMO_INDEX)));
        assert_eq!(
            words[3],
            field_word_hex(&compute_m_commitment(&sub.gradient.greco_m, configs.m_bit))
        );
        // The ciphertexts decrypt to the layouts the policy expects.
        let params = &preset.params;
        let enc = CkksEncoder::new(params);
        let ct = fhe::ckks::CkksCiphertext::from_bytes(&sub.gradient.ciphertext, params).unwrap();
        let g = enc
            .decode_coefficients(&sk.try_decrypt(&ct).unwrap(), FEDAVG_D + 2)
            .unwrap();
        let want = sub.fedavg_inputs.update.to_f64();
        for j in 0..FEDAVG_D {
            assert!((g[j + 1] - want[j]).abs() < 1e-6, "g_{j}: {}", g[j + 1]);
        }
        assert!((g[FEDAVG_D + 1] - 1.0).abs() < 1e-6);
        assert!(g[0].abs() < 1e-6);
        let ct = fhe::ckks::CkksCiphertext::from_bytes(&sub.count.ciphertext, params).unwrap();
        let c = enc
            .decode_coefficients(&sk.try_decrypt(&ct).unwrap(), 2)
            .unwrap();
        assert!((c[0] - DEMO_COUNT as f64).abs() < 1e-6);
        assert!(c[1].abs() < 1e-6);
    }

    #[test]
    fn native_check_attributes_each_tamper() {
        let (sub, _) = demo_submission();
        let configs = FedAvgConfigs::compute(&fedavg_preset().unwrap()).unwrap();
        let n = configs.n;

        // Wrong entry claim.
        let mut t = sub.fedavg_inputs.clone();
        t.update.entries[1] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(FedAvgCheckError::LayoutMismatch {
                which: "gradient",
                index: 2,
                ..
            })
        ));

        // Wrong count claim.
        let mut t = sub.fedavg_inputs.clone();
        t.count += 1;
        assert!(matches!(
            t.check(&configs),
            Err(FedAvgCheckError::LayoutMismatch {
                which: "count",
                index: 0,
                ..
            })
        ));

        // Missing marker.
        let mut t = sub.fedavg_inputs.clone();
        let mut coeffs = t.m_grad.coefficients().to_vec();
        coeffs[n - 1 - (FEDAVG_D + 1)] = BigInt::zero();
        t.m_grad = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(FedAvgCheckError::LayoutMismatch {
                which: "gradient",
                index: 9,
                ..
            })
        ));

        // Extra coefficient in the tail.
        let mut t = sub.fedavg_inputs.clone();
        let mut coeffs = t.m_grad.coefficients().to_vec();
        coeffs[0] = BigInt::from(1);
        t.m_grad = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(FedAvgCheckError::LayoutMismatch {
                which: "gradient",
                index: 511,
                ..
            })
        ));

        // Norm bound too tight.
        let mut t = sub.fedavg_inputs.clone();
        t.norm_bound = t.update.squared_norm() - 1;
        assert!(matches!(
            t.check(&configs),
            Err(FedAvgCheckError::NormOverBound { .. })
        ));

        // Entry out of range.
        let mut t = sub.fedavg_inputs.clone();
        t.update.entries[3] = -(WEIGHT_LIMIT as i32) - 1;
        assert_eq!(
            t.check(&configs),
            Err(FedAvgCheckError::EntryOutOfRange { index: 3 })
        );

        // Count out of range.
        let mut t = sub.fedavg_inputs.clone();
        t.count = 1024;
        assert_eq!(
            t.check(&configs),
            Err(FedAvgCheckError::CountOutOfRange { count: 1024 })
        );
        let mut t = sub.fedavg_inputs.clone();
        t.count = 0;
        assert_eq!(
            t.check(&configs),
            Err(FedAvgCheckError::CountOutOfRange { count: 0 })
        );

        // Build-time refusals.
        let (_, pk) = keypair();
        let alice = address_to_biguint(ALICE).unwrap();
        let err = build_fedavg_submission(
            pk.clone(),
            FixedPointUpdate::from_f64(&DEMO_G),
            DEMO_COUNT,
            norm_bound_fixed_point(1.0),
            alice.clone(),
            DEMO_INDEX,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("squared norm"), "{err}");
        let err = build_fedavg_submission(
            pk.clone(),
            FixedPointUpdate::from_f64(&[1.5; FEDAVG_D]),
            DEMO_COUNT,
            norm_bound_fixed_point(100.0),
            alice.clone(),
            DEMO_INDEX,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("|g| <= 1"), "{err}");
        let err = build_fedavg_submission(
            pk,
            FixedPointUpdate::from_f64(&DEMO_G),
            0,
            norm_bound_fixed_point(DEMO_BOUND),
            alice,
            DEMO_INDEX,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("sample count"), "{err}");
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
    fn test_checked_in_fedavg_configs_match_codegen() {
        let preset = fedavg_preset().unwrap();
        let configs = FedAvgConfigs::compute(&preset).unwrap();
        assert_eq!(configs.m_bit, 51);
        assert_eq!(configs.d, 8);
        assert_checked_in("ckks_fedavg_ps5.nr", &generate_fedavg_configs(&configs));
    }
}
