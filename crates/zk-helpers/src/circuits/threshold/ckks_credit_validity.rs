// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private-credit-scoring (v2) validity leg: witness builder and
//! codegen for the `ckks_credit_validity_ps4` circuit (Noir:
//! `lib::core::threshold::ckks_credit_validity`) and the ParamSet-4 Greco
//! legs (`user_data_encryption_ckks_ct{0,1}_ps4`).
//!
//! A credit-v2 application is TWO encryptions proven in FIVE legs bound
//! by shared commitments: Greco ct0 + ct1 for the LOGIT ciphertext, Greco
//! ct0 + ct1 for the MASK ciphertext, and this ONE validity leg, which
//! takes both message polynomials privately, recomputes both
//! `m_commitment`s (same packing width `BIT_M` / domain separator as the
//! ct0 legs) and proves the application predicate.
//!
//! ## Slot layout (the policy's contract — `credit_sigmoid_policy`)
//!
//! Applicant `i` (its on-chain slot `index`) encrypts, SLOT-encoded at
//! scale Δ:
//!
//! - `ct_z`: slot `index` = `z = ⟨w, x⟩/cap + b` — the PUBLIC model's
//!   logit over the applicant's Merkle-attested features; every other
//!   slot 0. Weights and bias are fixed point: `w_j = W_j / 2^WEIGHT_FRAC_BITS`,
//!   `|W_j| ≤ 2^(WEIGHT_FRAC_BITS + 3)` (`|w_j| ≤ 8`), likewise `b`.
//! - `ct_m`: slot `index` = `m = M / 2^MASK_FRAC_BITS ∈ [0, 1024)`, the
//!   applicant's OUTPUT mask; every other slot 0.
//!
//! ## Encoding contract (pinned Rust ↔ Noir ↔ WASM)
//!
//! For a single non-zero slot the canonical-embedding encoder
//! (`fhe.rs ckks/encoder.rs::encode_with_scale`) gives, for every `k < N`,
//! `m_k = round(Δ · (2/N) · v · cos(π · e · k / N))`, `e = 5^index mod 2N`.
//! With `v = V / D` (integer numerator / denominator) and the fixed-point
//! cosine table `C_t = round(2^COS_FRAC_BITS · cos(π t / N))`
//! ([`credit_cos_table`]), the circuit checks, over the integers,
//!
//! `|Q · m_k − 2 · Δ · V · C_{(e·k) mod 2N}| ≤ SLACK · Q`,  `Q = N · D · 2^COS_FRAC_BITS`
//!
//! for EVERY coefficient (`SLACK = 8`: ½ from rounding, ≤ 3 from the
//! table quantisation at `|v| < 1024`, margin for a 1-ulp platform `cos`
//! difference). Pinning all `N` coefficients against ONE declared slot
//! value forces every other slot to 0 (a residual of ≤ 8 per coefficient
//! decodes to `< N·8/Δ ≈ 2^-28` in any slot).
//!
//! ## ParamSet 4 (v2)
//!
//! `N = 512`, FIVE 36-bit NTT-friendly moduli, `Δ = 2^40`
//! (`e3_fhe_params::ckks_presets`). The Greco input bound is
//! `CREDIT_INPUT_BOUND = 1024` (the mask range; `|z| ≤ 72` sits inside),
//! so `m_bound = Δ·1024 + 1 ≈ 2^50` — wider than one limb's centered
//! range, sound because the Greco legs lift `m` mod the full `Q ≈ 2^180`.

use crate::circuits::computation::Computation;
use crate::threshold::ckks_app_validity::{
    field_word_hex, poseidon2_bn254, AUCTION_MERKLE_MAX_DEPTH,
};
use crate::threshold::user_data_encryption_ckks::{
    generate_toml, Bounds as GrecoBounds, CkksPreset, Inputs as GrecoInputs,
};
use crate::CircuitsErrors;
use ark_bn254_04::Fr as Fr04;
use ark_ff_04::{BigInteger as BigInteger04, PrimeField as PrimeField04};
use e3_polynomial::Polynomial;
use fhe::ckks::{CkksEncoder, CkksParameters, CkksPublicKey};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// On-chain `ParamSet` value of the credit-scoring preset.
pub const CREDIT_PARAM_SET: u8 = 4;
/// Nargo package of the credit leg.
pub const CREDIT_CIRCUIT_PACKAGE: &str = "ckks_credit_validity_ps4";
/// Number of issuer-attested features (Noir `FEATURES`).
pub const FEATURES: usize = 8;
/// Fractional bits of the OUTPUT mask (Noir `MASK_FRAC_BITS`): `m = M / 2^10`.
pub const MASK_FRAC_BITS: u32 = 10;
/// Total mask width (Noir `MASK_BITS`): `M < 2^20`, i.e. `m ∈ [0, 1024)`.
pub const MASK_BITS: u32 = 20;
/// Fractional bits of a weight / the bias (Noir `WEIGHT_FRAC_BITS`).
pub const WEIGHT_FRAC_BITS: u32 = 16;
/// `|W_j| ≤ 2^WEIGHT_MAG_BITS` (Noir `WEIGHT_MAG_BITS`): `|w_j| ≤ 8`.
pub const WEIGHT_MAG_BITS: u32 = WEIGHT_FRAC_BITS + 3;
/// Bit width of `cap` and every feature numerator (Noir `CAP_BITS`).
pub const CAP_BITS: u32 = 32;
/// Fixed-point bits of the cosine table (Noir `COS_FRAC_BITS`).
pub const COS_FRAC_BITS: u32 = 40;
/// Per-coefficient slack of the encoding check, in units of `Q` (Noir `SLACK`).
pub const SLACK: u32 = 8;
/// Maximum Merkle depth compiled into the credit circuit.
pub const CREDIT_MERKLE_MAX_DEPTH: usize = AUCTION_MERKLE_MAX_DEPTH;
/// ParamSet-4 ciphertext moduli (mirror of `e3_fhe_params`).
pub const CREDIT_CKKS_MODULI: [u64; 5] = e3_fhe_params::ckks_presets::CREDIT_CKKS_MODULI;
/// Greco input bound: every slot value is `< 1024` in magnitude.
pub const CREDIT_INPUT_BOUND: f64 = 1024.0;
/// `log2(N)` for the pinned degree (Noir `LOG_N`).
pub const LOG_N: u32 = 9;
/// Window bits of the logit encoding check (Noir `LOGIT_WIN_BITS`):
/// `2·SLACK·Q ≤ 2^(LOG_N + WEIGHT_FRAC_BITS + CAP_BITS + COS_FRAC_BITS + 4)`
/// with `Q = N · 2^WEIGHT_FRAC_BITS · cap · 2^COS_FRAC_BITS`.
pub const LOGIT_WIN_BITS: u32 = LOG_N + WEIGHT_FRAC_BITS + CAP_BITS + COS_FRAC_BITS + 5;
/// Window bits of the mask encoding check (Noir `MASK_WIN_BITS`):
/// `2·SLACK·Q = 2^(LOG_N + MASK_FRAC_BITS + COS_FRAC_BITS + 4)`.
pub const MASK_WIN_BITS: u32 = LOG_N + MASK_FRAC_BITS + COS_FRAC_BITS + 5;

/// The ParamSet-4 CKKS parameters.
pub fn credit_ckks_params() -> Result<Arc<CkksParameters>, CircuitsErrors> {
    e3_fhe_params::ckks_presets::ckks_params_for_on_chain_param_set(CREDIT_PARAM_SET)
        .map_err(|e| CircuitsErrors::Other(format!("ParamSet-4 CKKS params: {e}")))
}

/// The Greco preset for ParamSet 4.
pub fn credit_preset() -> Result<CkksPreset, CircuitsErrors> {
    Ok(CkksPreset {
        params: credit_ckks_params()?,
        input_bound: CREDIT_INPUT_BOUND,
    })
}

/// The public scoring model in the circuit's fixed point:
/// `w_j = weights[j] / 2^WEIGHT_FRAC_BITS`, `b = bias / 2^WEIGHT_FRAC_BITS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditModel {
    pub weights: [i32; FEATURES],
    pub bias: i32,
}

impl CreditModel {
    /// Round an f64 model into the fixed point.
    pub fn from_f64(weights: &[f64; FEATURES], bias: f64) -> Self {
        let scale = (1u64 << WEIGHT_FRAC_BITS) as f64;
        Self {
            weights: std::array::from_fn(|j| (weights[j] * scale).round() as i32),
            bias: (bias * scale).round() as i32,
        }
    }

    /// The f64 weights the policy oracle uses.
    pub fn weights_f64(&self) -> [f64; FEATURES] {
        let scale = (1u64 << WEIGHT_FRAC_BITS) as f64;
        std::array::from_fn(|j| self.weights[j] as f64 / scale)
    }

    /// The f64 bias.
    pub fn bias_f64(&self) -> f64 {
        self.bias as f64 / (1u64 << WEIGHT_FRAC_BITS) as f64
    }

    /// Every coefficient inside `|W| ≤ 2^WEIGHT_MAG_BITS`.
    pub fn in_range(&self) -> bool {
        let lim = 1i64 << WEIGHT_MAG_BITS;
        self.weights.iter().all(|w| (*w as i64).abs() <= lim) && (self.bias as i64).abs() <= lim
    }

    /// The logit NUMERATOR `Σ_j W_j x_j + B · cap` (the logit is this over
    /// `2^WEIGHT_FRAC_BITS · cap`).
    pub fn logit_numerator(&self, features: &[u32; FEATURES], cap: u32) -> i128 {
        let mut acc: i128 = 0;
        for (w, x) in self.weights.iter().zip(features.iter()) {
            acc += *w as i128 * *x as i128;
        }
        acc + self.bias as i128 * cap as i128
    }

    /// The f64 logit `⟨w, x/cap⟩ + b` the applicant encrypts (numerator
    /// over `2^WEIGHT_FRAC_BITS · cap`, exact in f64 up to 2^-53).
    pub fn logit(&self, features: &[u32; FEATURES], cap: u32) -> f64 {
        self.logit_numerator(features, cap) as f64
            / ((1u64 << WEIGHT_FRAC_BITS) as f64 * cap as f64)
    }
}

/// Fixed-point cosine table: `C_t = round(2^COS_FRAC_BITS · cos(π t / N))`
/// for `t ∈ [0, 2N)` — the Noir `Configs::cos` table for degree `n`.
pub fn credit_cos_table(n: usize) -> Vec<i64> {
    let scale = 2f64.powi(COS_FRAC_BITS as i32);
    (0..2 * n)
        .map(|t| (scale * (std::f64::consts::PI * t as f64 / n as f64).cos()).round() as i64)
        .collect()
}

/// Slot exponents `5^i mod 2N` for `i < N/2` — the Noir `Configs::exp5`
/// table (mirrors `CkksEncoder::new`'s `root_exponents`).
pub fn credit_exp5_table(n: usize) -> Vec<u32> {
    let m = 2 * n;
    let mut out = Vec::with_capacity(n / 2);
    let mut e = 1usize;
    for _ in 0..n / 2 {
        out.push(e as u32);
        e = (e * 5) % m;
    }
    out
}

/// Slot-encoding residual check for one coefficient: returns
/// `Q · m_k − 2·Δ·V·C_t` (the circuit's pre-slack difference).
fn slot_residual(q: &BigInt, m_k: &BigInt, two_delta_v: &BigInt, cos: i64) -> BigInt {
    q * m_k - two_delta_v * BigInt::from(cos)
}

/// Public parameters of the credit leg (baked into
/// `configs/ckks_credit_ps4.nr`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditConfigs {
    pub n: usize,
    /// `delta` as an exact integer.
    pub delta: BigUint,
    /// The ct0 leg's `m_bound`.
    pub m_bound: BigUint,
    /// Packing width of `m` (`BIT_M` of the ct0 leg).
    pub m_bit: u32,
    /// [`credit_cos_table`] for `n`.
    pub cos: Vec<i64>,
    /// [`credit_exp5_table`] for `n`.
    pub exp5: Vec<u32>,
}

impl CreditConfigs {
    pub fn compute(preset: &CkksPreset) -> Result<Self, CircuitsErrors> {
        let bounds = GrecoBounds::compute(preset.clone(), &())?;
        let bits =
            crate::threshold::user_data_encryption_ckks::Bits::compute(preset.clone(), &bounds)?;
        let scale = preset.params.scale();
        if scale.fract() != 0.0 || scale <= 0.0 || scale >= 2f64.powi(120) {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not an exact integer the credit leg can pin"
            )));
        }
        let n = preset.params.degree();
        if n != 1usize << LOG_N {
            return Err(CircuitsErrors::Other(format!(
                "credit leg is pinned to N = 2^{LOG_N}, got {n}"
            )));
        }
        // Field soundness: |Q·m| + |2ΔV·C| must stay far below 2^253.
        let q_bits = LOG_N + WEIGHT_FRAC_BITS + CAP_BITS + COS_FRAC_BITS;
        if bits.m_bit + q_bits + 2 >= 250 {
            return Err(CircuitsErrors::Other(format!(
                "m_bit {} + window {q_bits} too wide for an exact integer check",
                bits.m_bit
            )));
        }
        let delta = BigUint::from(scale as u128);
        // The Greco bound must admit the largest single-slot coefficient
        // (|m_k| ≤ Δ·(2/N)·1024·1 < Δ·1024).
        let max_coeff =
            &delta * BigUint::from(1u64 << MASK_FRAC_BITS) * BigUint::from(2u32) / BigUint::from(n);
        if max_coeff > bounds.m_bound {
            return Err(CircuitsErrors::Other(format!(
                "Greco m_bound {} does not cover the largest slot coefficient {max_coeff}",
                bounds.m_bound
            )));
        }
        Ok(Self {
            n,
            delta,
            m_bound: bounds.m_bound,
            m_bit: bits.m_bit,
            cos: credit_cos_table(n),
            exp5: credit_exp5_table(n),
        })
    }

    /// Checks that `m` (circuit layout: `m_k = coeffs[n-1-k]`) is the
    /// slot-`index` encoding of `v = numerator / denominator` within
    /// `SLACK`; returns the first offending coefficient.
    pub fn check_slot_encoding(
        &self,
        m: &Polynomial,
        numerator: &BigInt,
        denominator: &BigUint,
        index: usize,
    ) -> Result<(), (usize, BigInt)> {
        let n = self.n;
        let coeffs = m.coefficients();
        let e = self.exp5[index] as usize;
        let q =
            BigInt::from(BigUint::from(n) * denominator * BigUint::from(1u128 << COS_FRAC_BITS));
        let two_delta_v = BigInt::from(2u32) * BigInt::from(self.delta.clone()) * numerator;
        let slack = &q * BigInt::from(SLACK);
        let mut t = 0usize;
        for k in 0..n {
            let residual = slot_residual(&q, &coeffs[n - 1 - k], &two_delta_v, self.cos[t]);
            if residual.abs() > slack {
                return Err((k, residual));
            }
            t = (t + e) % (2 * n);
        }
        Ok(())
    }
}

/// Circom-compatible Poseidon over nine BN254 field elements — matches
/// the Noir `poseidon::poseidon::bn254::hash_9` the circuit uses for the
/// feature leaf.
pub fn poseidon9_bn254(inputs: &[BigUint; 9]) -> BigUint {
    let to_fr = |x: &BigUint| Fr04::from_le_bytes_mod_order(&x.to_bytes_le());
    let mut hasher = Poseidon::<Fr04>::new_circom(9).expect("poseidon t=10 params");
    let frs: Vec<Fr04> = inputs.iter().map(to_fr).collect();
    let out = hasher.hash(&frs).expect("poseidon hash");
    BigUint::from_bytes_le(&out.into_bigint().to_bytes_le())
}

/// Feature leaf: `poseidon([address, x_0, .., x_7])` (issuer snapshot).
pub fn feature_leaf(address: &BigUint, features: &[u32; FEATURES]) -> BigUint {
    let mut inputs: [BigUint; 9] = std::array::from_fn(|_| BigUint::from(0u32));
    inputs[0] = address.clone();
    for (i, x) in features.iter().enumerate() {
        inputs[i + 1] = BigUint::from(*x);
    }
    poseidon9_bn254(&inputs)
}

/// Opening of `(address, features)` under the issuer root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureProof {
    /// The applicant's address as a big-endian 20-byte integer.
    pub address: BigUint,
    /// The attested feature numerators (`x_j in [0, cap]`).
    pub features: [u32; FEATURES],
    /// Published root the proof opens to.
    pub merkle_root: BigUint,
    /// Effective tree depth (`<= CREDIT_MERKLE_MAX_DEPTH`).
    pub depth: u32,
    /// Path direction bits, leaf to root (`false` = node is left).
    pub indices: Vec<bool>,
    /// Sibling hashes, leaf to root.
    pub siblings: Vec<BigUint>,
}

/// Recomputes the Merkle root the circuit derives.
pub fn feature_root_from_proof(proof: &FeatureProof) -> BigUint {
    let mut node = feature_leaf(&proof.address, &proof.features);
    for (is_right, sibling) in proof.indices.iter().zip(&proof.siblings) {
        node = if *is_right {
            poseidon2_bn254(sibling, &node)
        } else {
            poseidon2_bn254(&node, sibling)
        };
    }
    node
}

/// Binary Merkle tree over feature leaves with zero padding (the issuer
/// snapshot). Same walk as `ckks_app_validity::BalanceTree`.
#[derive(Debug, Clone)]
pub struct FeatureTree {
    depth: u32,
    levels: Vec<Vec<BigUint>>,
}

impl FeatureTree {
    /// Builds a tree over `(address, features)` leaves. Depth is
    /// `max(1, ceil(log2(len)))`, capped at [`CREDIT_MERKLE_MAX_DEPTH`].
    pub fn new(leaves: &[(BigUint, [u32; FEATURES])]) -> Result<Self, CircuitsErrors> {
        if leaves.is_empty() {
            return Err(CircuitsErrors::Other("feature tree needs a leaf".into()));
        }
        let depth = ((leaves.len() as f64).log2().ceil() as u32).max(1);
        if depth as usize > CREDIT_MERKLE_MAX_DEPTH {
            return Err(CircuitsErrors::Other(format!(
                "feature tree depth {depth} exceeds circuit max {CREDIT_MERKLE_MAX_DEPTH}"
            )));
        }
        let mut level: Vec<BigUint> = leaves.iter().map(|(a, f)| feature_leaf(a, f)).collect();
        level.resize(1usize << depth, BigUint::from(0u32));
        let mut levels = vec![level];
        for _ in 0..depth {
            let prev = levels.last().expect("level");
            let next: Vec<BigUint> = prev
                .chunks(2)
                .map(|pair| poseidon2_bn254(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        Ok(Self { depth, levels })
    }

    /// The published root.
    pub fn root(&self) -> BigUint {
        self.levels[self.depth as usize][0].clone()
    }

    /// Opening for leaf `index` (the position in the constructor slice).
    pub fn proof(
        &self,
        index: usize,
        address: &BigUint,
        features: [u32; FEATURES],
    ) -> FeatureProof {
        let mut indices = Vec::with_capacity(self.depth as usize);
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut pos = index;
        for level in 0..self.depth as usize {
            let is_right = pos % 2 == 1;
            let sibling = if is_right { pos - 1 } else { pos + 1 };
            indices.push(is_right);
            siblings.push(self.levels[level][sibling].clone());
            pos /= 2;
        }
        FeatureProof {
            address: address.clone(),
            features,
            merkle_root: self.root(),
            depth: self.depth,
            indices,
            siblings,
        }
    }
}

/// Errors from the native constraint pre-check, attributable to a field.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CreditCheckError {
    #[error("cap must be nonzero and < 2^{CAP_BITS}")]
    BadCap,
    #[error("feature {index} = {value} exceeds cap {cap}")]
    FeatureOverCap { index: usize, value: u32, cap: u32 },
    #[error("weight/bias {index} is outside |W| <= 2^{WEIGHT_MAG_BITS} (8 in real units)")]
    WeightOutOfRange { index: usize },
    #[error("mask {mask} is not in [0, 2^{MASK_BITS})")]
    MaskOutOfRange { mask: u32 },
    #[error("slot index {index} is outside the {slots} slots")]
    IndexOutOfRange { index: usize, slots: usize },
    #[error("|m_{index}| = {value} of the {which} message exceeds m_bound {bound}")]
    CoefficientTooLarge {
        which: &'static str,
        index: usize,
        value: BigInt,
        bound: BigUint,
    },
    #[error("coefficient {index} of the {which} message is not the slot encoding of the declared value (residual {residual})")]
    EncodingMismatch {
        which: &'static str,
        index: usize,
        residual: BigInt,
    },
    #[error("feature proof depth {depth} exceeds max {max}")]
    DepthTooLarge { depth: u32, max: usize },
    #[error(
        "feature proof path length mismatch: {indices} indices, {siblings} siblings, depth {depth}"
    )]
    PathLengthMismatch {
        indices: usize,
        siblings: usize,
        depth: u32,
    },
    #[error("feature leaf does not open to the published root")]
    RootMismatch,
    #[error("{which} message polynomial has {got} coefficients, expected {want}")]
    WrongDegree {
        which: &'static str,
        got: usize,
        want: usize,
    },
}

/// Witness of the credit leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditInputs {
    /// The LOGIT message polynomial (circuit layout: reversed, centered)
    /// — the SAME `m` the logit ct0 leg carries.
    pub m_z: Polynomial,
    /// The MASK message polynomial — the SAME `m` the mask ct0 leg carries.
    pub m_m: Polynomial,
    /// Public normalization cap (`x_j / cap` is the feature value).
    pub cap: u32,
    /// The applicant's slot index (assigned on-chain).
    pub index: u32,
    /// The round's public model (registered on-chain).
    pub model: CreditModel,
    /// The applicant's output-mask numerator (`m = mask / 2^10`).
    pub mask: u32,
    pub feature_proof: FeatureProof,
}

impl CreditInputs {
    /// Native pre-check of exactly the constraints the Noir leg enforces,
    /// in the circuit's order.
    pub fn check(&self, configs: &CreditConfigs) -> Result<(), CreditCheckError> {
        if self.cap == 0 {
            return Err(CreditCheckError::BadCap);
        }
        let proof = &self.feature_proof;
        for (index, x) in proof.features.iter().enumerate() {
            if *x > self.cap {
                return Err(CreditCheckError::FeatureOverCap {
                    index,
                    value: *x,
                    cap: self.cap,
                });
            }
        }
        let lim = 1i64 << WEIGHT_MAG_BITS;
        for (index, w) in self.model.weights.iter().enumerate() {
            if (*w as i64).abs() > lim {
                return Err(CreditCheckError::WeightOutOfRange { index });
            }
        }
        if (self.model.bias as i64).abs() > lim {
            return Err(CreditCheckError::WeightOutOfRange { index: FEATURES });
        }
        if self.mask >= (1u32 << MASK_BITS) {
            return Err(CreditCheckError::MaskOutOfRange { mask: self.mask });
        }
        let n = configs.n;
        if self.index as usize >= n / 2 {
            return Err(CreditCheckError::IndexOutOfRange {
                index: self.index as usize,
                slots: n / 2,
            });
        }
        let bound = BigInt::from(configs.m_bound.clone());
        for (which, m) in [("logit", &self.m_z), ("mask", &self.m_m)] {
            let coeffs = m.coefficients();
            if coeffs.len() != n {
                return Err(CreditCheckError::WrongDegree {
                    which,
                    got: coeffs.len(),
                    want: n,
                });
            }
            for (index, c) in coeffs.iter().enumerate() {
                if c.abs() > bound {
                    return Err(CreditCheckError::CoefficientTooLarge {
                        which,
                        index: n - 1 - index,
                        value: c.clone(),
                        bound: configs.m_bound.clone(),
                    });
                }
            }
        }

        // Logit: slot `index` = (Σ W_j x_j + B·cap) / (2^16 · cap).
        let z_num = BigInt::from(self.model.logit_numerator(&proof.features, self.cap));
        let z_den = BigUint::from(self.cap) * BigUint::from(1u64 << WEIGHT_FRAC_BITS);
        configs
            .check_slot_encoding(&self.m_z, &z_num, &z_den, self.index as usize)
            .map_err(|(index, residual)| CreditCheckError::EncodingMismatch {
                which: "logit",
                index,
                residual,
            })?;
        // Mask: slot `index` = M / 2^10.
        configs
            .check_slot_encoding(
                &self.m_m,
                &BigInt::from(self.mask),
                &BigUint::from(1u64 << MASK_FRAC_BITS),
                self.index as usize,
            )
            .map_err(|(index, residual)| CreditCheckError::EncodingMismatch {
                which: "mask",
                index,
                residual,
            })?;

        if proof.depth as usize > CREDIT_MERKLE_MAX_DEPTH {
            return Err(CreditCheckError::DepthTooLarge {
                depth: proof.depth,
                max: CREDIT_MERKLE_MAX_DEPTH,
            });
        }
        if proof.indices.len() != proof.depth as usize
            || proof.siblings.len() != proof.depth as usize
        {
            return Err(CreditCheckError::PathLengthMismatch {
                indices: proof.indices.len(),
                siblings: proof.siblings.len(),
                depth: proof.depth,
            });
        }
        if feature_root_from_proof(proof) != proof.merkle_root {
            return Err(CreditCheckError::RootMismatch);
        }
        Ok(())
    }

    /// Prover.toml for the credit leg.
    pub fn to_toml(&self) -> Result<String, CircuitsErrors> {
        Ok(toml::to_string(&self.to_json())?)
    }

    /// The credit leg's inputs as JSON (the noir_js `InputMap` shape; also
    /// what `to_toml` serializes). Negative weights are emitted as the
    /// field element `p − |W|` in decimal (what the on-chain word carries).
    pub fn to_json(&self) -> serde_json::Value {
        use crate::polynomial_to_toml_json;
        let proof = &self.feature_proof;
        let mut indices = vec![false; CREDIT_MERKLE_MAX_DEPTH];
        let mut siblings = vec!["0".to_string(); CREDIT_MERKLE_MAX_DEPTH];
        for (i, (b, s)) in proof.indices.iter().zip(&proof.siblings).enumerate() {
            indices[i] = *b;
            siblings[i] = s.to_string();
        }
        let features: Vec<String> = proof.features.iter().map(|x| x.to_string()).collect();
        let weights: Vec<String> = self
            .model
            .weights
            .iter()
            .map(|w| signed_field_decimal(*w as i64))
            .collect();
        serde_json::json!({
            "m_z": polynomial_to_toml_json(&self.m_z),
            "m_m": polynomial_to_toml_json(&self.m_m),
            "features": features,
            "depth": proof.depth.to_string(),
            "indices": indices,
            "siblings": siblings,
            "mask": self.mask.to_string(),
            "cap": self.cap.to_string(),
            "address": proof.address.to_string(),
            "merkle_root": proof.merkle_root.to_string(),
            "index": self.index.to_string(),
            "weights": weights,
            "bias": signed_field_decimal(self.model.bias as i64),
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

/// One proven encryption of the application (logit or mask).
#[derive(Debug, Clone)]
pub struct CreditCiphertextLeg {
    pub ciphertext: Vec<u8>,
    /// Serves BOTH Greco bin packages of this ciphertext.
    pub greco_toml: String,
    /// The Greco message polynomial, for cross-leg assertions.
    pub greco_m: Polynomial,
}

/// The complete client-side submission: two ciphertexts, their Greco
/// witnesses, and the validity leg's witness.
#[derive(Debug, Clone)]
pub struct CreditSubmission {
    pub logit: CreditCiphertextLeg,
    pub mask: CreditCiphertextLeg,
    pub credit_toml: String,
    pub credit_inputs: CreditInputs,
}

/// Encodes ONE slot value (`value` in slot `index`, all other slots 0)
/// at level 0 / scale Δ — the plaintext both the Greco legs and the
/// credit leg are proven over.
pub fn encode_credit_slot(
    params: &Arc<CkksParameters>,
    value: f64,
    index: usize,
) -> Result<fhe::ckks::CkksPlaintext, CircuitsErrors> {
    let slots = params.slots();
    if index >= slots {
        return Err(CircuitsErrors::Other(format!(
            "slot index {index} is outside the {slots} slots"
        )));
    }
    let mut v = vec![0.0f64; index + 1];
    v[index] = value;
    CkksEncoder::new(params)
        .encode(&v, 0)
        .map_err(|e| CircuitsErrors::Other(format!("slot encoding: {e}")))
}

/// Greco inputs for ONE slot encryption. Does NOT run the credit
/// pre-check — `build_credit_submission` does; this is the escape hatch
/// for deliberately-invalid fixtures.
pub fn credit_greco_inputs(
    public_key: &CkksPublicKey,
    value: f64,
    index: usize,
) -> Result<GrecoInputs, CircuitsErrors> {
    credit_greco_inputs_with_rng(public_key, value, index, &mut rand::rng())
}

/// [`credit_greco_inputs`] with a caller-supplied RNG.
pub fn credit_greco_inputs_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: &CkksPublicKey,
    value: f64,
    index: usize,
    rng: &mut R,
) -> Result<GrecoInputs, CircuitsErrors> {
    let preset = credit_preset()?;
    let pt = encode_credit_slot(&preset.params, value, index)?;
    GrecoInputs::compute_from_plaintext_with_rng(preset, public_key, &pt, rng)
}

/// The mask value `mask / 2^MASK_FRAC_BITS`.
pub fn mask_value(mask: u32) -> f64 {
    mask as f64 / (1u64 << MASK_FRAC_BITS) as f64
}

/// Builds a submission from TWO encryptions (fresh randomness per call —
/// never call twice for one submission).
pub fn build_credit_submission(
    public_key: CkksPublicKey,
    feature_proof: FeatureProof,
    cap: u32,
    model: CreditModel,
    index: u32,
    mask: u32,
) -> Result<CreditSubmission, CircuitsErrors> {
    build_credit_submission_with_rng(
        public_key,
        feature_proof,
        cap,
        model,
        index,
        mask,
        &mut rand::rng(),
    )
}

/// [`build_credit_submission`] with a caller-supplied RNG: the logit
/// encryption draws first, then the mask encryption (the order the WASM
/// builder mirrors byte for byte).
pub fn build_credit_submission_with_rng<R: rand::RngCore + rand::CryptoRng>(
    public_key: CkksPublicKey,
    feature_proof: FeatureProof,
    cap: u32,
    model: CreditModel,
    index: u32,
    mask: u32,
    rng: &mut R,
) -> Result<CreditSubmission, CircuitsErrors> {
    let preset = credit_preset()?;
    if cap == 0 {
        return Err(CircuitsErrors::Other("cap must be nonzero".into()));
    }
    if mask >= (1u32 << MASK_BITS) {
        return Err(CircuitsErrors::Other(format!(
            "mask {mask} is not in [0, 2^{MASK_BITS})"
        )));
    }
    if !model.in_range() {
        return Err(CircuitsErrors::Other(
            "model weights/bias outside |w| <= 8".into(),
        ));
    }
    if let Some((j, x)) = feature_proof
        .features
        .iter()
        .enumerate()
        .find(|(_, x)| **x > cap)
    {
        return Err(CircuitsErrors::Other(format!(
            "feature {j} = {x} exceeds cap {cap}"
        )));
    }
    let configs = CreditConfigs::compute(&preset)?;
    let z = model.logit(&feature_proof.features, cap);
    let greco_z = credit_greco_inputs_with_rng(&public_key, z, index as usize, rng)?;
    let greco_m = credit_greco_inputs_with_rng(&public_key, mask_value(mask), index as usize, rng)?;
    let credit_inputs = CreditInputs {
        m_z: greco_z.m.clone(),
        m_m: greco_m.m.clone(),
        cap,
        index,
        model,
        mask,
        feature_proof,
    };
    credit_inputs
        .check(&configs)
        .map_err(|e| CircuitsErrors::Other(format!("credit leg pre-check failed: {e}")))?;
    let credit_toml = credit_inputs.to_toml()?;
    let leg = |greco: GrecoInputs| -> Result<CreditCiphertextLeg, CircuitsErrors> {
        let ciphertext = greco.ciphertext.clone();
        let greco_m = greco.m.clone();
        let greco_toml = generate_toml(greco)?;
        Ok(CreditCiphertextLeg {
            ciphertext,
            greco_toml,
            greco_m,
        })
    };
    Ok(CreditSubmission {
        logit: leg(greco_z)?,
        mask: leg(greco_m)?,
        credit_toml,
        credit_inputs,
    })
}

/// Recomputes a ct0 leg's `m_commitment` natively (must equal that leg's
/// third public output).
pub fn compute_m_commitment(m: &Polynomial, m_bit: u32) -> BigInt {
    crate::circuits::commitments::compute_user_data_encryption_m_commitment(m, m_bit)
}

/// Number of public-input words of the credit leg (13 inputs + 2 outputs).
pub const CREDIT_PUBLIC_INPUTS: usize = 4 + FEATURES + 1 + 2;

/// The on-chain public-input words of the credit leg, in circuit order:
/// `[cap, address, merkle_root, index, w_0..w_7, b, m_commitment_z, m_commitment_m]`.
pub fn public_input_words(inputs: &CreditInputs, m_bit: u32) -> Vec<String> {
    let mut words = vec![
        field_word_hex(&BigInt::from(inputs.cap)),
        field_word_hex(&BigInt::from(inputs.feature_proof.address.clone())),
        field_word_hex(&BigInt::from(inputs.feature_proof.merkle_root.clone())),
        field_word_hex(&BigInt::from(inputs.index)),
    ];
    for w in inputs.model.weights {
        words.push(field_word_hex(&signed_field_bigint(w as i64)));
    }
    words.push(field_word_hex(&signed_field_bigint(
        inputs.model.bias as i64,
    )));
    words.push(field_word_hex(&compute_m_commitment(&inputs.m_z, m_bit)));
    words.push(field_word_hex(&compute_m_commitment(&inputs.m_m, m_bit)));
    debug_assert_eq!(words.len(), CREDIT_PUBLIC_INPUTS);
    words
}

fn field_array_literal(values: &[i64]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Generated Noir configs for the credit leg (`configs/ckks_credit_ps4.nr`).
pub fn generate_credit_configs(configs: &CreditConfigs) -> String {
    let exp5: Vec<i64> = configs.exp5.iter().map(|e| *e as i64).collect();
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers ckks_credit_validity codegen
// (`cargo run -p e3-zk-helpers --example gen_ckks_credit_prover -- configs`).
// Do not hand-edit; regenerate-and-diff is enforced by
// `test_checked_in_credit_configs_match_codegen`.
// CKKS credit-scoring v2 validity leg on ParamSet {ps}: N={n}, delta=2^{scale_bits},
// slot encoding (one slot per applicant) of the logit and the output mask.

use crate::core::threshold::ckks_credit_validity::Configs as CkksCreditValidityConfigs;

pub global CKKS_CREDIT_N: u32 = {n};
/// Packing width of `m` — MUST equal the ct0 leg's BIT_M so the
/// recomputed m_commitment matches.
pub global CKKS_CREDIT_BIT_M: u32 = {m_bit};
pub global CKKS_CREDIT_MERKLE_MAX_DEPTH: u32 = {depth};
pub global CKKS_CREDIT_DELTA: Field = {delta};
pub global CKKS_CREDIT_M_BOUND: Field = {m_bound};
/// `round(2^{cos_bits} * cos(pi * t / N))` for `t in 0..2N`.
pub global CKKS_CREDIT_COS: [Field; 2 * CKKS_CREDIT_N] = [{cos}];
/// `5^i mod 2N` for `i in 0..N/2` (the slot exponents).
pub global CKKS_CREDIT_EXP5: [u32; CKKS_CREDIT_N / 2] = [{exp5}];

pub global CKKS_CREDIT_CONFIGS: CkksCreditValidityConfigs<CKKS_CREDIT_N> =
    CkksCreditValidityConfigs::new(
        CKKS_CREDIT_DELTA,
        CKKS_CREDIT_M_BOUND,
        CKKS_CREDIT_COS,
        CKKS_CREDIT_EXP5,
    );
"#,
        ps = CREDIT_PARAM_SET,
        n = configs.n,
        scale_bits = configs.delta.bits() - 1,
        m_bit = configs.m_bit,
        depth = CREDIT_MERKLE_MAX_DEPTH,
        delta = configs.delta,
        m_bound = configs.m_bound,
        cos_bits = COS_FRAC_BITS,
        cos = field_array_literal(&configs.cos),
        exp5 = field_array_literal(&exp5),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::ckks_app_validity::address_to_biguint;
    use crate::threshold::user_data_encryption_ckks::{
        ckks_preset_for_param_set, generate_configs as generate_greco_configs,
        Configs as GrecoConfigs,
    };
    use fhe::ckks::CkksSecretKey;

    const ALICE: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const BOB: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const DEMO_FEATURES: [u32; FEATURES] = [520, 130, 350, 999, 0, 1, 777, 42];
    const DEMO_CAP: u32 = 1000;
    /// The demo model in fixed point (×2^16): weights
    /// [1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2], bias -0.8.
    const DEMO_MODEL: CreditModel = CreditModel {
        weights: [111411, -150733, 58982, 26214, -72090, 170394, -32768, 78643],
        bias: -52429,
    };
    const DEMO_MASK: u32 = 529_664; // 517.25
    const DEMO_INDEX: u32 = 2;

    fn keypair() -> CkksPublicKey {
        let preset = credit_preset().unwrap();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        CkksPublicKey::new(&sk, &mut rng).unwrap()
    }

    fn demo_tree() -> (FeatureTree, BigUint, BigUint) {
        let alice = address_to_biguint(ALICE).unwrap();
        let bob = address_to_biguint(BOB).unwrap();
        let tree = FeatureTree::new(&[
            (alice.clone(), DEMO_FEATURES),
            (bob.clone(), [1, 2, 3, 4, 5, 6, 7, 8]),
        ])
        .unwrap();
        (tree, alice, bob)
    }

    fn demo_submission() -> (CreditSubmission, FeatureTree, BigUint, BigUint) {
        let (tree, alice, bob) = demo_tree();
        let proof = tree.proof(0, &alice, DEMO_FEATURES);
        let sub = build_credit_submission(
            keypair(),
            proof,
            DEMO_CAP,
            DEMO_MODEL,
            DEMO_INDEX,
            DEMO_MASK,
        )
        .unwrap();
        (sub, tree, alice, bob)
    }

    #[test]
    fn model_fixed_point_round_trips() {
        let m = CreditModel::from_f64(&[1.7, -2.3, 0.9, 0.4, -1.1, 2.6, -0.5, 1.2], -0.8);
        assert_eq!(m, DEMO_MODEL);
        assert!(m.in_range());
        let z = m.logit(&DEMO_FEATURES, DEMO_CAP);
        let w = m.weights_f64();
        let want: f64 = w
            .iter()
            .zip(DEMO_FEATURES)
            .map(|(w, x)| w * x as f64 / DEMO_CAP as f64)
            .sum::<f64>()
            + m.bias_f64();
        assert!((z - want).abs() < 1e-12);
        assert!(!CreditModel::from_f64(&[8.5; 8], 0.0).in_range());
    }

    /// The N=32 tables the Noir unit tests pin (`ckks_credit_validity.nr`).
    #[test]
    fn small_tables_match_noir_test_vectors() {
        let cos = credit_cos_table(32);
        assert_eq!(cos[0], 1 << 40);
        assert_eq!(cos[16], 0);
        assert_eq!(cos[32], -(1 << 40));
        assert_eq!(cos[1], 1_094_217_178_761); // round(2^40 cos(pi/32))
        assert_eq!(cos[8], 777_472_127_994); // round(2^40 cos(pi/4))
        assert_eq!(
            credit_exp5_table(32),
            vec![1, 5, 25, 61, 49, 53, 9, 45, 33, 37, 57, 29, 17, 21, 41, 13]
        );
        let n512 = credit_exp5_table(512);
        assert_eq!(n512.len(), 256);
        let enc = CkksEncoder::new(&credit_ckks_params().unwrap());
        let _ = enc; // the encoder's root exponents are 5^j mod 2N by construction
    }

    /// The encoder's plaintext for one non-zero slot passes the integer
    /// slot-encoding window for BOTH the logit and the mask, and a wrong
    /// index / wrong value fails it.
    #[test]
    fn encoder_plaintext_matches_slot_contract() {
        let preset = credit_preset().unwrap();
        let params = &preset.params;
        let configs = CreditConfigs::compute(&preset).unwrap();
        let z = DEMO_MODEL.logit(&DEMO_FEATURES, DEMO_CAP);
        let pt = encode_credit_slot(params, z, DEMO_INDEX as usize).unwrap();
        // Circuit layout: reversed + centered (what the Greco witness carries).
        let raw = Vec::<BigUint>::from(&pt.poly().clone().into_power_basis());
        let q: BigUint = params.moduli().iter().map(|q| BigUint::from(*q)).product();
        let half = &q / 2u32;
        let mut coeffs: Vec<BigInt> = raw
            .iter()
            .map(|c| {
                if c > &half {
                    BigInt::from(c.clone()) - BigInt::from(q.clone())
                } else {
                    BigInt::from(c.clone())
                }
            })
            .collect();
        coeffs.reverse();
        let m = Polynomial::new(coeffs);
        let num = BigInt::from(DEMO_MODEL.logit_numerator(&DEMO_FEATURES, DEMO_CAP));
        let den = BigUint::from(DEMO_CAP) * BigUint::from(1u64 << WEIGHT_FRAC_BITS);
        configs
            .check_slot_encoding(&m, &num, &den, DEMO_INDEX as usize)
            .unwrap();
        assert!(configs
            .check_slot_encoding(&m, &num, &den, DEMO_INDEX as usize + 1)
            .is_err());
        assert!(configs
            .check_slot_encoding(&m, &(num + 1), &den, DEMO_INDEX as usize)
            .is_err());
        // Largest mask value at the highest slot.
        let pt = encode_credit_slot(params, mask_value((1 << MASK_BITS) - 1), 255).unwrap();
        let raw = Vec::<BigUint>::from(&pt.poly().clone().into_power_basis());
        let mut coeffs: Vec<BigInt> = raw
            .iter()
            .map(|c| {
                if c > &half {
                    BigInt::from(c.clone()) - BigInt::from(q.clone())
                } else {
                    BigInt::from(c.clone())
                }
            })
            .collect();
        coeffs.reverse();
        configs
            .check_slot_encoding(
                &Polynomial::new(coeffs),
                &BigInt::from((1u32 << MASK_BITS) - 1),
                &BigUint::from(1u64 << MASK_FRAC_BITS),
                255,
            )
            .unwrap();
    }

    #[test]
    fn preset_is_the_fhe_params_shape() {
        let preset = ckks_preset_for_param_set(CREDIT_PARAM_SET).unwrap();
        assert_eq!(preset.params.degree(), 512);
        assert_eq!(preset.params.moduli(), &CREDIT_CKKS_MODULI);
        assert_eq!(preset.params.moduli().len(), 5);
        assert_eq!(preset.params.scale(), 2f64.powi(40));
        assert_eq!(preset.input_bound, 1024.0);
    }

    /// The Rust Poseidon-9 reproduces the Noir `hash_9` vector pinned in
    /// `ckks_credit_validity.nr` (`test_feature_leaf_vector`).
    #[test]
    fn poseidon9_matches_noir_vector() {
        let alice = address_to_biguint(ALICE).unwrap();
        let leaf = feature_leaf(&alice, &DEMO_FEATURES);
        assert_eq!(leaf.to_str_radix(16), NOIR_LEAF_HEX);
    }

    /// `hash_9([ALICE, 520, 130, 350, 999, 0, 1, 777, 42])` as Noir prints it.
    const NOIR_LEAF_HEX: &str = "2e70bfe6109556e0a2a8885470e8fdb18abb76d03a135766b644ab2bd2ad0c0e";

    #[test]
    fn submission_passes_native_check_and_binds_both_messages() {
        let (sub, _, _, _) = demo_submission();
        let configs = CreditConfigs::compute(&credit_preset().unwrap()).unwrap();
        sub.credit_inputs.check(&configs).unwrap();
        assert_eq!(sub.credit_inputs.m_z, sub.logit.greco_m);
        assert_eq!(sub.credit_inputs.m_m, sub.mask.greco_m);
        assert_ne!(sub.logit.ciphertext, sub.mask.ciphertext);
        assert!(sub.credit_toml.contains("weights = ["));
        let words = public_input_words(&sub.credit_inputs, configs.m_bit);
        assert_eq!(words.len(), CREDIT_PUBLIC_INPUTS);
        assert_eq!(words[0], field_word_hex(&BigInt::from(DEMO_CAP)));
        assert!(words[1].ends_with(&ALICE[2..]));
        assert_eq!(words[3], field_word_hex(&BigInt::from(DEMO_INDEX)));
        assert_eq!(
            words[13],
            field_word_hex(&compute_m_commitment(&sub.logit.greco_m, configs.m_bit))
        );
        assert_eq!(
            words[14],
            field_word_hex(&compute_m_commitment(&sub.mask.greco_m, configs.m_bit))
        );
        // Negative weight word is p − |W|.
        assert_eq!(
            words[5],
            field_word_hex(&(bn254_r() - BigInt::from(150733)))
        );
    }

    #[test]
    fn native_check_attributes_each_tamper() {
        let (sub, tree, alice, bob) = demo_submission();
        let configs = CreditConfigs::compute(&credit_preset().unwrap()).unwrap();
        let n = configs.n;

        // Wrong logit claim: features that hash to a different leaf.
        let mut t = sub.credit_inputs.clone();
        let mut features = DEMO_FEATURES;
        features[0] = 521;
        let tree2 = FeatureTree::new(&[(alice.clone(), features)]).unwrap();
        t.feature_proof = tree2.proof(0, &alice, features);
        assert!(matches!(
            t.check(&configs),
            Err(CreditCheckError::EncodingMismatch { which: "logit", .. })
        ));

        // Wrong weights (the logit was encrypted under the real model).
        let mut t = sub.credit_inputs.clone();
        t.model.weights[1] += 1;
        assert!(matches!(
            t.check(&configs),
            Err(CreditCheckError::EncodingMismatch { which: "logit", .. })
        ));

        // Wrong mask claim.
        let mut t = sub.credit_inputs.clone();
        t.mask += 1;
        assert!(matches!(
            t.check(&configs),
            Err(CreditCheckError::EncodingMismatch { which: "mask", .. })
        ));

        // Wrong index (the same plaintexts read at another slot).
        let mut t = sub.credit_inputs.clone();
        t.index += 1;
        assert!(matches!(
            t.check(&configs),
            Err(CreditCheckError::EncodingMismatch { which: "logit", .. })
        ));

        // Extra slot: perturb a coefficient beyond the slack.
        let mut t = sub.credit_inputs.clone();
        let mut coeffs = t.m_z.coefficients().to_vec();
        coeffs[n - 1] += BigInt::from(1_000_000u32);
        t.m_z = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(CreditCheckError::EncodingMismatch {
                which: "logit",
                index: 0,
                ..
            })
        ));

        // Over cap.
        let mut t = sub.credit_inputs.clone();
        t.feature_proof.features[3] = 1001;
        assert_eq!(
            t.check(&configs),
            Err(CreditCheckError::FeatureOverCap {
                index: 3,
                value: 1001,
                cap: DEMO_CAP
            })
        );

        // Weight out of range.
        let mut t = sub.credit_inputs.clone();
        t.model.weights[4] = (1 << WEIGHT_MAG_BITS) + 1;
        assert_eq!(
            t.check(&configs),
            Err(CreditCheckError::WeightOutOfRange { index: 4 })
        );

        // Mask out of range.
        let mut t = sub.credit_inputs.clone();
        t.mask = 1 << MASK_BITS;
        assert_eq!(
            t.check(&configs),
            Err(CreditCheckError::MaskOutOfRange {
                mask: 1 << MASK_BITS
            })
        );

        // Bob's leaf under Alice's address does not open.
        let mut t = sub.credit_inputs.clone();
        let mut p = tree.proof(1, &bob, [1, 2, 3, 4, 5, 6, 7, 8]);
        p.address = alice.clone();
        p.features = DEMO_FEATURES;
        t.feature_proof = p;
        assert_eq!(t.check(&configs), Err(CreditCheckError::RootMismatch));

        // Build-time refusals.
        let err = build_credit_submission(
            keypair(),
            tree.proof(0, &alice, DEMO_FEATURES),
            DEMO_CAP,
            DEMO_MODEL,
            DEMO_INDEX,
            1 << MASK_BITS,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("mask"), "{err}");
        let mut over = tree.proof(0, &alice, DEMO_FEATURES);
        over.features[0] = DEMO_CAP + 1;
        let err =
            build_credit_submission(keypair(), over, DEMO_CAP, DEMO_MODEL, DEMO_INDEX, DEMO_MASK)
                .expect_err("must reject");
        assert!(err.to_string().contains("exceeds cap"), "{err}");
        let err = build_credit_submission(
            keypair(),
            tree.proof(0, &alice, DEMO_FEATURES),
            DEMO_CAP,
            DEMO_MODEL,
            256,
            DEMO_MASK,
        )
        .expect_err("must reject");
        assert!(err.to_string().contains("slot index"), "{err}");
    }

    /// `nargo fmt` re-wraps long generated lines (the checked-in files are
    /// formatted), so the drift guard compares the token stream: every
    /// constant, name and order must match, whitespace may not.
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
    fn test_checked_in_credit_configs_match_codegen() {
        let preset = credit_preset().unwrap();
        let configs = CreditConfigs::compute(&preset).unwrap();
        assert_eq!(configs.m_bit, 51);
        assert_checked_in("ckks_credit_ps4.nr", &generate_credit_configs(&configs));
    }

    #[test]
    fn test_checked_in_greco_ps4_configs_match_codegen() {
        let preset = ckks_preset_for_param_set(CREDIT_PARAM_SET).unwrap();
        let configs = GrecoConfigs::compute(preset.clone(), &()).unwrap();
        assert_eq!(configs.l, 5);
        assert_eq!(configs.bits.m_bit, 51);
        assert_checked_in("ckks_ps4.nr", &generate_greco_configs(&preset, &configs));
    }
}
