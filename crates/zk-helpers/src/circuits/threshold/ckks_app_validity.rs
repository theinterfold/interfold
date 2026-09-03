// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS application-validity legs: witness builders for the
//! `ckks_salary_validity_ps3` and `ckks_auction_validity_ps2` circuits
//! (Noir: `lib::core::threshold::ckks_app_validity`).
//!
//! A submission is ONE encryption (one `Inputs::compute` of the Greco
//! builder) proven in three legs bound by shared commitments:
//!
//! - Greco ct0 leg → `(pk0_c, ct0_c, m_commitment, u_commitment)`
//! - Greco ct1 leg → `(pk1_c, ct1_c, u_commitment)`
//! - app leg       → `m_commitment` (+ the app's public inputs)
//!
//! The app leg takes the SAME message polynomial `m` as the ct0 leg,
//! recomputes `m_commitment` with the same packing width, and proves the
//! application predicate on the value `m` encodes. The on-chain program
//! contract equates `m_commitment` across the ct0 and app legs and
//! `u_commitment` across the ct0 and ct1 legs.
//!
//! Encoding fact (verified against fhe.rs
//! `crates/fhe/src/ckks/encoder.rs::encode_with_scale`): a slot-replicated
//! constant `c` encodes to `m_0 = round(delta * c)` with every other
//! coefficient at most a few tens in magnitude (float noise of the
//! O(N^2) transform). The circuit pins `m_0` to `delta * v_raw / cap`
//! within `+-2` and every tail coefficient to `|m_k| <= tail_bound`.
//!
//! This module is free of I/O: [`build_app_submission`] returns the
//! ciphertext bytes plus one Prover.toml per leg so the participant CLI
//! (or a future WASM crate) can drive nargo/bb however it likes.

use crate::circuits::computation::Computation;
use crate::threshold::user_data_encryption_ckks::{
    ckks_preset_for_param_set, generate_toml, Bounds as GrecoBounds, CkksPreset,
    Inputs as GrecoInputs, UserDataEncryptionCkksCircuitData,
};
use crate::CircuitsErrors;
use ark_bn254_04::Fr as Fr04;
use ark_ff_04::{BigInteger as BigInteger04, PrimeField as PrimeField04};
use e3_polynomial::Polynomial;
use fhe::ckks::CkksPublicKey;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::{BigInt, BigUint};
use num_traits::Signed;
use serde::{Deserialize, Serialize};

/// Maximum Merkle depth compiled into the auction circuit (CRISP's
/// token-holder tree uses the same fixed maximum).
pub const AUCTION_MERKLE_MAX_DEPTH: usize = 20;

/// Symmetric bound on the non-constant message coefficients of a
/// slot-replicated encoding. Measured worst case at delta = 2^40 over
/// B = 1000 is 35 (N = 512); 64 leaves headroom while still rejecting
/// any non-replicated message (a second distinct slot value moves tail
/// coefficients by `~delta * |z_j - z_k| / N >> 64`).
pub const REPLICATED_TAIL_BOUND: u64 = 64;

/// Which application leg to build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CkksApp {
    /// Private salary survey: `0 <= salary_raw <= cap` (ParamSet 3).
    SalarySurvey,
    /// Sealed-bid auction: `0 <= bid_raw <= balance`, balance leaf under
    /// the published Merkle root, address bound to `msg.sender` on-chain
    /// (ParamSet 2).
    Auction,
}

impl CkksApp {
    /// On-chain ParamSet this app runs on.
    pub fn param_set(self) -> u8 {
        match self {
            CkksApp::SalarySurvey => 3,
            CkksApp::Auction => 2,
        }
    }

    /// Nargo package name of the app leg.
    pub fn circuit_package(self) -> &'static str {
        match self {
            CkksApp::SalarySurvey => "ckks_salary_validity_ps3",
            CkksApp::Auction => "ckks_auction_validity_ps2",
        }
    }
}

/// Proof that `(address, balance)` is a leaf of the balance tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceProof {
    /// The bidder's address as a big-endian 20-byte integer.
    pub address: BigUint,
    /// The attested token balance (raw units, `< 2^64`).
    pub balance: u64,
    /// Published root the proof opens to.
    pub merkle_root: BigUint,
    /// Effective tree depth (`<= AUCTION_MERKLE_MAX_DEPTH`).
    pub depth: u32,
    /// Path direction bits, leaf to root (`false` = node is left).
    pub indices: Vec<bool>,
    /// Sibling hashes, leaf to root.
    pub siblings: Vec<BigUint>,
}

/// Circom-compatible Poseidon over two BN254 field elements — matches the
/// Noir `poseidon::poseidon::bn254::hash_2` the circuit uses.
pub fn poseidon2_bn254(a: &BigUint, b: &BigUint) -> BigUint {
    let to_fr = |x: &BigUint| Fr04::from_le_bytes_mod_order(&x.to_bytes_le());
    let mut hasher = Poseidon::<Fr04>::new_circom(2).expect("poseidon t=3 params");
    let out = hasher.hash(&[to_fr(a), to_fr(b)]).expect("poseidon hash");
    BigUint::from_bytes_le(&out.into_bigint().to_bytes_le())
}

/// Balance leaf: `poseidon([address, balance])` (CRISP token-holder model).
pub fn balance_leaf(address: &BigUint, balance: u64) -> BigUint {
    poseidon2_bn254(address, &BigUint::from(balance))
}

/// Minimal binary Merkle tree over `poseidon([left, right])` with zero
/// padding, mirroring the circuit's `binary_merkle_root` walk. Test and
/// demo helper: the auction round-opener publishes the root; bidders get
/// their path.
#[derive(Debug, Clone)]
pub struct BalanceTree {
    depth: u32,
    levels: Vec<Vec<BigUint>>,
}

impl BalanceTree {
    /// Builds a tree over `(address, balance)` leaves. Depth is
    /// `max(1, ceil(log2(len)))`, capped at [`AUCTION_MERKLE_MAX_DEPTH`].
    pub fn new(leaves: &[(BigUint, u64)]) -> Result<Self, CircuitsErrors> {
        if leaves.is_empty() {
            return Err(CircuitsErrors::Other("balance tree needs a leaf".into()));
        }
        let depth = ((leaves.len() as f64).log2().ceil() as u32).max(1);
        if depth as usize > AUCTION_MERKLE_MAX_DEPTH {
            return Err(CircuitsErrors::Other(format!(
                "balance tree depth {depth} exceeds circuit max {AUCTION_MERKLE_MAX_DEPTH}"
            )));
        }
        let mut level: Vec<BigUint> = leaves.iter().map(|(a, b)| balance_leaf(a, *b)).collect();
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
    pub fn proof(&self, index: usize, address: &BigUint, balance: u64) -> BalanceProof {
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
        BalanceProof {
            address: address.clone(),
            balance,
            merkle_root: self.root(),
            depth: self.depth,
            indices,
            siblings,
        }
    }
}

/// Public parameters of an app leg, derived from the preset (they are
/// baked into the generated Noir configs; see `generate_configs`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppConfigs {
    pub n: usize,
    /// `delta` as an exact integer.
    pub delta: BigUint,
    /// The ct0 leg's `m_bound` (so both legs pin `m_0` identically).
    pub m_bound: BigUint,
    /// Packing width of `m` (`BIT_M` of the ct0 leg).
    pub m_bit: u32,
    pub tail_bound: u64,
    pub tail_bit: u32,
}

impl AppConfigs {
    pub fn compute(preset: &CkksPreset) -> Result<Self, CircuitsErrors> {
        let bounds = GrecoBounds::compute(preset.clone(), &())?;
        let bits =
            crate::threshold::user_data_encryption_ckks::Bits::compute(preset.clone(), &bounds)?;
        let scale = preset.params.scale();
        if scale.fract() != 0.0 || scale <= 0.0 || scale >= 2f64.powi(120) {
            return Err(CircuitsErrors::Other(format!(
                "CKKS scale {scale} is not an exact integer the app leg can pin"
            )));
        }
        let delta = BigUint::from(scale as u128);
        // BIT_M + 64 < 254 keeps `m_0 * cap` and the head window exact.
        if bits.m_bit + 64 >= 254 {
            return Err(CircuitsErrors::Other(format!(
                "m_bit {} too wide for the app leg's integer head check",
                bits.m_bit
            )));
        }
        Ok(Self {
            n: preset.params.degree(),
            delta,
            m_bound: bounds.m_bound,
            m_bit: bits.m_bit,
            tail_bound: REPLICATED_TAIL_BOUND,
            tail_bit: crate::calculate_bit_width(BigInt::from(REPLICATED_TAIL_BOUND)),
        })
    }
}

/// Witness for one app leg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInputs {
    pub app: CkksApp,
    /// The message polynomial (circuit layout: reversed, centered) — the
    /// SAME `m` the ct0 leg carries.
    pub m: Polynomial,
    /// Raw integer value (salary or bid).
    pub value_raw: u64,
    /// Public normalization cap.
    pub cap: u64,
    /// Auction only.
    pub balance_proof: Option<BalanceProof>,
}

/// Errors from the native constraint pre-check, attributable to a field.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppCheckError {
    #[error("value_raw {value} exceeds cap {cap}")]
    ValueOverCap { value: u64, cap: u64 },
    #[error("bid {value} exceeds attested balance {balance}")]
    BidOverBalance { value: u64, balance: u64 },
    #[error("cap must be nonzero")]
    ZeroCap,
    #[error("message constant term {m0} is not round(delta*value/cap) = {expected} (+-2)")]
    HeadMismatch { m0: BigInt, expected: BigInt },
    #[error("message coefficient {index} = {value} exceeds the replicated tail bound {bound}")]
    TailTooLarge {
        index: usize,
        value: BigInt,
        bound: u64,
    },
    #[error("|m_0| = {m0} exceeds m_bound {bound}")]
    HeadTooLarge { m0: BigInt, bound: BigUint },
    #[error("balance proof missing for the auction leg")]
    MissingBalanceProof,
    #[error("balance proof depth {depth} exceeds max {max}")]
    DepthTooLarge { depth: u32, max: usize },
    #[error(
        "balance proof path length mismatch: {indices} indices, {siblings} siblings, depth {depth}"
    )]
    PathLengthMismatch {
        indices: usize,
        siblings: usize,
        depth: u32,
    },
    #[error("balance leaf does not open to the published root")]
    RootMismatch,
    #[error("message polynomial has {got} coefficients, expected {want}")]
    WrongDegree { got: usize, want: usize },
}

/// Recomputes the Merkle root the circuit derives.
pub fn balance_root_from_proof(proof: &BalanceProof) -> BigUint {
    let mut node = balance_leaf(&proof.address, proof.balance);
    for (is_right, sibling) in proof.indices.iter().zip(&proof.siblings) {
        node = if *is_right {
            poseidon2_bn254(sibling, &node)
        } else {
            poseidon2_bn254(&node, sibling)
        };
    }
    node
}

impl AppInputs {
    /// Native pre-check of exactly the constraints the Noir leg enforces.
    pub fn check(&self, configs: &AppConfigs) -> Result<(), AppCheckError> {
        if self.cap == 0 {
            return Err(AppCheckError::ZeroCap);
        }
        let coeffs = self.m.coefficients();
        if coeffs.len() != configs.n {
            return Err(AppCheckError::WrongDegree {
                got: coeffs.len(),
                want: configs.n,
            });
        }
        // Circuit layout: constant term LAST.
        let m0 = coeffs[configs.n - 1].clone();
        if m0.magnitude() > &configs.m_bound {
            return Err(AppCheckError::HeadTooLarge {
                m0,
                bound: configs.m_bound.clone(),
            });
        }
        let cap = BigInt::from(self.cap);
        let delta_v = BigInt::from(configs.delta.clone()) * BigInt::from(self.value_raw);
        let head = &m0 * &cap - &delta_v;
        if head.abs() > BigInt::from(2u32) * &cap {
            let expected = (&delta_v + &cap / 2) / &cap;
            return Err(AppCheckError::HeadMismatch { m0, expected });
        }
        let bound = BigInt::from(configs.tail_bound);
        for (index, c) in coeffs[..configs.n - 1].iter().enumerate() {
            if c.abs() > bound {
                return Err(AppCheckError::TailTooLarge {
                    index,
                    value: c.clone(),
                    bound: configs.tail_bound,
                });
            }
        }
        match self.app {
            CkksApp::SalarySurvey => {
                if self.value_raw > self.cap {
                    return Err(AppCheckError::ValueOverCap {
                        value: self.value_raw,
                        cap: self.cap,
                    });
                }
            }
            CkksApp::Auction => {
                let proof = self
                    .balance_proof
                    .as_ref()
                    .ok_or(AppCheckError::MissingBalanceProof)?;
                if self.value_raw > proof.balance {
                    return Err(AppCheckError::BidOverBalance {
                        value: self.value_raw,
                        balance: proof.balance,
                    });
                }
                if proof.depth as usize > AUCTION_MERKLE_MAX_DEPTH {
                    return Err(AppCheckError::DepthTooLarge {
                        depth: proof.depth,
                        max: AUCTION_MERKLE_MAX_DEPTH,
                    });
                }
                if proof.indices.len() != proof.depth as usize
                    || proof.siblings.len() != proof.depth as usize
                {
                    return Err(AppCheckError::PathLengthMismatch {
                        indices: proof.indices.len(),
                        siblings: proof.siblings.len(),
                        depth: proof.depth,
                    });
                }
                if balance_root_from_proof(proof) != proof.merkle_root {
                    return Err(AppCheckError::RootMismatch);
                }
            }
        }
        Ok(())
    }

    /// Prover.toml for the app leg.
    pub fn to_toml(&self) -> Result<String, CircuitsErrors> {
        use crate::polynomial_to_toml_json;
        let mut json = serde_json::json!({
            "m": polynomial_to_toml_json(&self.m),
            "value_raw": self.value_raw.to_string(),
            "cap": self.cap.to_string(),
        });
        if let CkksApp::Auction = self.app {
            let proof = self
                .balance_proof
                .as_ref()
                .ok_or_else(|| CircuitsErrors::Other("auction leg needs a balance proof".into()))?;
            let mut indices = vec![false; AUCTION_MERKLE_MAX_DEPTH];
            let mut siblings = vec!["0".to_string(); AUCTION_MERKLE_MAX_DEPTH];
            for (i, (b, s)) in proof.indices.iter().zip(&proof.siblings).enumerate() {
                indices[i] = *b;
                siblings[i] = s.to_string();
            }
            let obj = json.as_object_mut().expect("object");
            obj.insert("balance".into(), proof.balance.to_string().into());
            obj.insert("address".into(), proof.address.to_string().into());
            obj.insert("merkle_root".into(), proof.merkle_root.to_string().into());
            obj.insert("depth".into(), proof.depth.to_string().into());
            obj.insert("indices".into(), indices.into());
            obj.insert("siblings".into(), siblings.into());
        }
        Ok(toml::to_string(&json)?)
    }
}

/// The complete client-side submission: ciphertext bytes plus one
/// Prover.toml per leg (`ct0`, `ct1`, `app`).
#[derive(Debug, Clone)]
pub struct AppSubmission {
    pub app: CkksApp,
    pub param_set: u8,
    pub ciphertext: Vec<u8>,
    /// Serves BOTH Greco bin packages (nargo ignores undeclared keys).
    pub greco_toml: String,
    pub app_toml: String,
    /// Kept so callers can print/inspect the public inputs they expect.
    pub app_inputs: AppInputs,
    /// The Greco message polynomial, for cross-leg assertions.
    pub greco_m: Polynomial,
}

/// Builds a submission from ONE encryption: the ciphertext, the Greco
/// legs' toml and the app leg's toml all derive from the same
/// `Inputs::compute` (fresh randomness per call — never call twice).
///
/// `value` is the raw integer (salary or bid), `cap` the public
/// normalization cap; the encrypted slot value is `value / cap`,
/// replicated across all `N/2` slots. `balance_proof` is required for
/// [`CkksApp::Auction`] and ignored otherwise.
pub fn build_app_submission(
    app: CkksApp,
    public_key: CkksPublicKey,
    value: u64,
    cap: u64,
    balance_proof: Option<BalanceProof>,
) -> Result<AppSubmission, CircuitsErrors> {
    let param_set = app.param_set();
    let preset = ckks_preset_for_param_set(param_set)?;
    if cap == 0 {
        return Err(CircuitsErrors::Other("cap must be nonzero".into()));
    }
    let normalized = value as f64 / cap as f64;
    if normalized.abs() > preset.input_bound {
        return Err(CircuitsErrors::Other(format!(
            "normalized value {normalized} exceeds the ParamSet {param_set} input bound {}",
            preset.input_bound
        )));
    }
    let configs = AppConfigs::compute(&preset)?;
    let slots = preset.params.degree() / 2;
    let data = UserDataEncryptionCkksCircuitData {
        public_key,
        values: vec![normalized; slots],
    };
    let greco = GrecoInputs::compute(preset, &data)?;
    let app_inputs = AppInputs {
        app,
        m: greco.m.clone(),
        value_raw: value,
        cap,
        balance_proof: if app == CkksApp::Auction {
            Some(
                balance_proof
                    .ok_or_else(|| CircuitsErrors::Other("auction needs a balance proof".into()))?,
            )
        } else {
            None
        },
    };
    app_inputs
        .check(&configs)
        .map_err(|e| CircuitsErrors::Other(format!("app leg pre-check failed: {e}")))?;
    let app_toml = app_inputs.to_toml()?;
    let ciphertext = greco.ciphertext.clone();
    let greco_m = greco.m.clone();
    let greco_toml = generate_toml(greco)?;
    Ok(AppSubmission {
        app,
        param_set,
        ciphertext,
        greco_toml,
        app_toml,
        app_inputs,
        greco_m,
    })
}

/// Recomputes the app leg's `m_commitment` natively (must equal the ct0
/// leg's third public output).
pub fn compute_m_commitment(m: &Polynomial, m_bit: u32) -> BigInt {
    crate::circuits::commitments::compute_user_data_encryption_m_commitment(m, m_bit)
}

/// Generated Noir configs for an app leg (`configs/ckks_app_ps<N>.nr`).
pub fn generate_configs(app: CkksApp, configs: &AppConfigs) -> String {
    let (label, prefix) = match app {
        CkksApp::SalarySurvey => ("salary survey", "CKKS_SALARY"),
        CkksApp::Auction => ("auction", "CKKS_AUCTION"),
    };
    let depth_line = match app {
        CkksApp::Auction => {
            format!("pub global {prefix}_MERKLE_MAX_DEPTH: u32 = {AUCTION_MERKLE_MAX_DEPTH};\n")
        }
        CkksApp::SalarySurvey => String::new(),
    };
    format!(
        r#"// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
//
// Auto-generated by e3-zk-helpers ckks_app_validity codegen
// (`cargo run -p e3-zk-helpers --example gen_ckks_app_configs`).
// Do not hand-edit; regenerate-and-diff is enforced by
// `test_checked_in_app_configs_match_codegen`.
// CKKS {label} app leg on ParamSet {ps}: N={n}, delta=2^{scale_bits}.

use crate::core::threshold::ckks_app_validity::Configs as CkksAppValidityConfigs;

pub global {prefix}_N: u32 = {n};
/// Packing width of `m` — MUST equal the ct0 leg's BIT_M so the
/// recomputed m_commitment matches.
pub global {prefix}_BIT_M: u32 = {m_bit};
pub global {prefix}_BIT_TAIL: u32 = {tail_bit};
{depth_line}pub global {prefix}_DELTA: Field = {delta};
pub global {prefix}_M_BOUND: Field = {m_bound};
pub global {prefix}_TAIL_BOUND: Field = {tail_bound};

pub global {prefix}_CONFIGS: CkksAppValidityConfigs = CkksAppValidityConfigs::new(
    {prefix}_DELTA,
    {prefix}_M_BOUND,
    {prefix}_TAIL_BOUND,
);
"#,
        ps = app.param_set(),
        n = configs.n,
        scale_bits = configs.delta.bits() - 1,
        m_bit = configs.m_bit,
        tail_bit = configs.tail_bit,
        delta = configs.delta,
        m_bound = configs.m_bound,
        tail_bound = configs.tail_bound,
    )
}

/// Big-endian bytes of a `BigInt` field element as a 32-byte `0x` hex
/// word (the on-chain public-input form).
pub fn field_word_hex(v: &BigInt) -> String {
    let (_, bytes) = v.to_bytes_be();
    let mut word = [0u8; 32];
    word[32 - bytes.len()..].copy_from_slice(&bytes);
    format!("0x{}", hex::encode(word))
}

/// Convenience: parse a 20-byte hex address into the field integer the
/// circuit uses.
pub fn address_to_biguint(address_hex: &str) -> Result<BigUint, CircuitsErrors> {
    let bytes = hex::decode(address_hex.trim_start_matches("0x"))
        .map_err(|e| CircuitsErrors::Other(format!("bad address hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(CircuitsErrors::Other(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(BigUint::from_bytes_be(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::ckks::CkksSecretKey;

    fn keypair(param_set: u8) -> CkksPublicKey {
        let preset = ckks_preset_for_param_set(param_set).unwrap();
        let mut rng = rand::rng();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        CkksPublicKey::new(&sk, &mut rng).unwrap()
    }

    /// The Rust Poseidon must reproduce the Noir `hash_2` used by the
    /// circuit: CRISP's `merkle_tree.nr` pins this depth-2 vector.
    #[test]
    fn poseidon_matches_noir_vector() {
        let address = address_to_biguint("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let balance = 1_000_000_000_000_000_000u64;
        // CRISP `test_get_merkle_root`: depth 2, leaf at index 0, zero siblings.
        let expected = BigUint::parse_bytes(
            b"11c1a161d2d84845a176670f3501200b4a0df1048073c0caea6ead2e71b7edaf",
            16,
        )
        .unwrap();
        let proof = BalanceProof {
            address: address.clone(),
            balance,
            merkle_root: expected.clone(),
            depth: 2,
            indices: vec![false, false],
            siblings: vec![BigUint::from(0u32), BigUint::from(0u32)],
        };
        assert_eq!(balance_root_from_proof(&proof), expected);
        // A four-leaf tree (depth 2) with the leaf first reproduces it too.
        let zero = BigUint::from(0u32);
        let tree = BalanceTree::new(&[
            (address.clone(), balance),
            (zero.clone(), 0),
            (zero.clone(), 0),
            (zero, 0),
        ])
        .unwrap();
        // Padded leaves are poseidon([0,0]) not 0, so only the opening
        // walk is compared here, not the root.
        let opening = tree.proof(0, &address, balance);
        assert_eq!(balance_root_from_proof(&opening), tree.root());
    }

    #[test]
    fn salary_submission_passes_native_check_and_binds_m() {
        let pk = keypair(3);
        let sub = build_app_submission(CkksApp::SalarySurvey, pk, 52_000, 100_000, None).unwrap();
        let preset = ckks_preset_for_param_set(3).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();
        sub.app_inputs.check(&configs).unwrap();
        assert_eq!(sub.app_inputs.m, sub.greco_m);
        assert!(sub.app_toml.contains("value_raw = \"52000\""));
        assert!(!sub.ciphertext.is_empty());
        // Head is round(delta * 0.52) up to the float rounding of the
        // O(N^2) encoder sum (the circuit's window is +-2).
        let m0 = sub.app_inputs.m.coefficients()[configs.n - 1].clone();
        let expected = BigInt::from(571_746_046_443u64);
        assert!((m0.clone() - &expected).abs() <= BigInt::from(2u32), "{m0}");
    }

    #[test]
    fn salary_over_cap_is_rejected() {
        let pk = keypair(3);
        // 1.2 is within the Greco input bound? B = 1 for ps3 -> rejected
        // already at the bound check; use the native check directly.
        let err = build_app_submission(CkksApp::SalarySurvey, pk, 120_000, 100_000, None)
            .expect_err("must reject");
        assert!(err.to_string().contains("input bound"), "{err}");
    }

    #[test]
    fn native_check_attributes_each_tamper() {
        let pk = keypair(3);
        let sub = build_app_submission(CkksApp::SalarySurvey, pk, 52_000, 100_000, None).unwrap();
        let preset = ckks_preset_for_param_set(3).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();

        // Claim a different value.
        let mut t = sub.app_inputs.clone();
        t.value_raw = 10_000;
        assert!(matches!(
            t.check(&configs),
            Err(AppCheckError::HeadMismatch { .. })
        ));

        // Over cap: for the ps3 preset (B = 1) the ct0 message bound
        // `m_bound = delta + 1` already rules out any head encoding a
        // value above the cap, so the head check fires FIRST (same order
        // as the circuit: range check, then the cap assert). The explicit
        // `value <= cap` rule remains for presets with B > 1.
        let mut t = sub.app_inputs.clone();
        t.value_raw = 100_001;
        let mut coeffs = t.m.coefficients().to_vec();
        coeffs[configs.n - 1] = (BigInt::from(configs.delta.clone()) * 100_001u32
            + BigInt::from(50_000u32))
            / 100_000u32;
        t.m = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(AppCheckError::HeadTooLarge { .. })
        ));
        // With a widened bound (B = 2 style configs) the cap rule is the
        // one that fires.
        let mut wide = configs.clone();
        wide.m_bound = &configs.m_bound * BigUint::from(2u32);
        assert_eq!(
            t.check(&wide),
            Err(AppCheckError::ValueOverCap {
                value: 100_001,
                cap: 100_000
            })
        );

        // Non-replicated tail.
        let mut t = sub.app_inputs.clone();
        let mut coeffs = t.m.coefficients().to_vec();
        coeffs[7] = BigInt::from(1_000_000u32);
        t.m = Polynomial::new(coeffs);
        assert!(matches!(
            t.check(&configs),
            Err(AppCheckError::TailTooLarge { index: 7, .. })
        ));
    }

    #[test]
    fn auction_submission_with_balance_proof() {
        let pk = keypair(2);
        let alice = address_to_biguint("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        let bob = address_to_biguint("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();
        let tree = BalanceTree::new(&[(alice.clone(), 800), (bob.clone(), 300)]).unwrap();
        let proof = tree.proof(0, &alice, 800);
        let sub = build_app_submission(CkksApp::Auction, pk, 700, 1, Some(proof.clone())).unwrap();
        let preset = ckks_preset_for_param_set(2).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();
        sub.app_inputs.check(&configs).unwrap();
        assert!(sub.app_toml.contains("merkle_root"));

        // Over balance.
        let mut t = sub.app_inputs.clone();
        t.value_raw = 801;
        let mut coeffs = t.m.coefficients().to_vec();
        coeffs[configs.n - 1] = BigInt::from(configs.delta.clone()) * 801u32;
        t.m = Polynomial::new(coeffs);
        assert_eq!(
            t.check(&configs),
            Err(AppCheckError::BidOverBalance {
                value: 801,
                balance: 800
            })
        );

        // Bob's balance under Alice's address: the bid (700) exceeds Bob's
        // 300 first; with a bid that fits, the leaf no longer opens.
        let mut t = sub.app_inputs.clone();
        let mut p = tree.proof(1, &bob, 300);
        p.address = alice.clone();
        t.balance_proof = Some(p.clone());
        assert_eq!(
            t.check(&configs),
            Err(AppCheckError::BidOverBalance {
                value: 700,
                balance: 300
            })
        );
        t.value_raw = 200;
        let mut coeffs = t.m.coefficients().to_vec();
        coeffs[configs.n - 1] = BigInt::from(configs.delta.clone()) * 200u32;
        t.m = Polynomial::new(coeffs);
        assert_eq!(t.check(&configs), Err(AppCheckError::RootMismatch));

        // Over-balance at build time is refused.
        let pk = keypair(2);
        let err = build_app_submission(CkksApp::Auction, pk, 900, 1, Some(proof))
            .expect_err("must reject");
        assert!(
            err.to_string().contains("exceeds attested balance"),
            "{err}"
        );
    }

    #[test]
    fn m_commitment_matches_greco_leg() {
        // Both legs pack `m` with the same BIT_M; the native commitment
        // helper is shared, so equality here is the layout contract.
        let pk = keypair(3);
        let sub = build_app_submission(CkksApp::SalarySurvey, pk, 1, 1, None).unwrap();
        let preset = ckks_preset_for_param_set(3).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();
        let a = compute_m_commitment(&sub.app_inputs.m, configs.m_bit);
        let b = compute_m_commitment(&sub.greco_m, configs.m_bit);
        assert_eq!(a, b);
        assert!(field_word_hex(&a).starts_with("0x"));
    }

    fn checked_in_matches(app: CkksApp) {
        let preset = ckks_preset_for_param_set(app.param_set()).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();
        let generated = generate_configs(app, &configs);
        let path = format!(
            "{}/../../circuits/lib/src/configs/ckks_app_ps{}.nr",
            env!("CARGO_MANIFEST_DIR"),
            app.param_set()
        );
        let checked_in = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{path} missing; write it from codegen output"));
        assert_eq!(checked_in, generated, "{path} drifted from codegen");
    }

    #[test]
    fn test_checked_in_app_configs_match_codegen() {
        checked_in_matches(CkksApp::SalarySurvey);
        checked_in_matches(CkksApp::Auction);
    }
}
