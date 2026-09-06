// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS private-matching program (the E3 "policy").
//!
//! The computation the committee's ciphertext output carries is
//! [`e3_trckks::policy::matching_score_policy`]: exactly TWO parties per
//! round. Party A (slot 0) submits `forward(a)` — its private length-[`K`]
//! profile vector, cap-normalised to `[-1, 1]`, on coefficients `1..=K` —
//! and a cross-term `mask(m_a)`; party B (slot 1) submits `reversed(b)`
//! (`b_j` on coefficient `N − j − 1`) and `mask(m_b)`. The network does
//! ONE ciphertext × ciphertext product `forward(a) · reversed(b)`
//! relinearised under the committee's level-0 key (`rlk_level_0.bin`, the
//! ParamSet-5 ceremony plan `PerLevel([0])`), rescales once and adds both
//! masks. Coefficient 0 of the opened output is `−⟨a, b⟩` (the `t^N ≡ −1`
//! wrap — this crate negates); coefficients `1..` are the cross terms
//! `a_i b_j`, hidden by the two masks, and carry no usable signal. Neither
//! vector is ever opened: only the one similarity number.
//!
//! The committee runs NO app logic: this crate is the plain-Rust wrapper
//! the coordination server calls (CRISP's `program/` is a RISC Zero
//! guest; the CKKS demos run the policy natively — the ciphertext output
//! is published with a mock proof, see the Readme's honest-scope section).

use anyhow::{bail, Context, Result};
use e3_fhe_params::ckks_presets::{
    ckks_opening_level_for_param_set, ckks_params_for_on_chain_param_set,
    relin_ceremony_plan_for_param_set, RelinCeremonyPlan,
};
use e3_trckks::policy::{
    matching_score_policy, RelinKeys, COEFFICIENT_MASK_BOUND, COEFFICIENT_MASK_WIDTH,
};
use e3_trckks::program::{
    decode_fixed_point_output, COEFFICIENT_OUTPUT_COUNT, COEFFICIENT_OUTPUT_DECIMALS,
};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::{CkksParameters, CkksRelinearizationKey};
use fhe_traits::Serialize as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// On-chain ParamSet of the coefficient-encoded preset (N=512, 3 limbs, Δ=2^40).
pub const PARAM_SET: u8 = 5;
/// Length of each party's profile vector (Noir `K` of `ckks_matching_validity_ps5`).
pub const K: usize = 16;
/// Exactly two parties per round: A (slot 0, forward) and B (slot 1, reversed).
pub const PARTIES: usize = 2;
/// Cross-term mask: `MASK_WIDTH` integers uniform in `[0, MASK_BOUND)`.
pub const MASK_WIDTH: usize = COEFFICIENT_MASK_WIDTH;
pub const MASK_BOUND: f64 = COEFFICIENT_MASK_BOUND;
/// Fixed-point bits of vector entries the circuit takes (`×2^16`).
pub const FRAC_BITS: u32 = 16;
/// `|v_j| ≤ ENTRY_BOUND` (cap-normalised in the browser).
pub const ENTRY_BOUND: f64 = 1.0;
/// The published output: the first 64 coefficients at 4 decimals.
pub const OUTPUT_COUNT: usize = COEFFICIENT_OUTPUT_COUNT;
pub const OUTPUT_DECIMALS: u32 = COEFFICIENT_OUTPUT_DECIMALS;
/// The level the policy relinearises at (the ceremony's key file).
pub const RELIN_LEVELS: [usize; 1] = [0];

/// Which of the two layouts a party submits (its slot index IS its role).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Slot 0: `forward(a)`.
    A = 0,
    /// Slot 1: `reversed(b)`.
    B = 1,
}

impl Role {
    pub fn from_index(index: u64) -> Result<Self> {
        match index {
            0 => Ok(Role::A),
            1 => Ok(Role::B),
            other => bail!("matching has exactly two slots (0 = A, 1 = B); got {other}"),
        }
    }

    pub fn index(self) -> u64 {
        self as u64
    }

    pub fn layout(self) -> &'static str {
        match self {
            Role::A => "forward",
            Role::B => "reversed",
        }
    }
}

/// Canonical serialized ParamSet-5 parameters (byte-identical to every node's).
pub fn params() -> Result<Arc<CkksParameters>> {
    ckks_params_for_on_chain_param_set(PARAM_SET).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn params_bytes() -> Result<Vec<u8>> {
    Ok(params()?.to_bytes())
}

/// Level the output is opened at (1: one rescale).
pub fn opening_level() -> usize {
    ckks_opening_level_for_param_set(PARAM_SET).unwrap_or(0)
}

/// Ceremony keys a complete DKG writes for this set: ONE (`rlk_level_0.bin`).
pub fn expected_ceremony_keys() -> usize {
    relin_ceremony_plan_for_param_set(PARAM_SET)
        .map(|p| p.key_count())
        .unwrap_or(0)
}

/// The ceremony's key file names the evaluator waits for.
pub fn ceremony_key_files() -> Vec<String> {
    match relin_ceremony_plan_for_param_set(PARAM_SET) {
        Ok(RelinCeremonyPlan::PerLevel(levels)) => levels
            .iter()
            .map(|l| RelinKeys::level_key_file(*l))
            .collect(),
        Ok(RelinCeremonyPlan::Hybrid) => vec![RelinKeys::HYBRID_KEY_FILE.to_string()],
        _ => vec![],
    }
}

/// Loads the joint level-0 key from a ceremony key directory
/// (`<node data dir>/<node>/ckks/relin-keys/<chain>:<e3_id>/`).
pub fn load_ceremony_keys(dir: &Path, params: &Arc<CkksParameters>) -> Result<RelinKeys> {
    RelinKeys::load_from_dir(dir, params, &RELIN_LEVELS)
        .with_context(|| format!("loading ceremony keys from {}", dir.display()))
}

/// The level-0 relinearization key the policy multiplies under
/// (`matching_score_policy` takes the ONE per-level key, not the bundle).
pub fn level_0_key(keys: &RelinKeys) -> Result<&CkksRelinearizationKey> {
    match keys {
        RelinKeys::PerLevel(levels) => levels
            .iter()
            .find(|k| k.level() == 0)
            .context("ceremony bundle has no level-0 relin key (rlk_level_0.bin)"),
        RelinKeys::Hybrid(_) => bail!(
            "ParamSet {PARAM_SET} uses the PerLevel([0]) ceremony plan; got a hybrid key bundle"
        ),
    }
}

/// One party's two accepted ciphertexts: `(vector, mask)`.
pub type PartyInputs = (Vec<u8>, Vec<u8>);

/// The round's inputs in the policy's order: `[f_a, r_b, m_a, m_b]`.
#[derive(Debug, Clone)]
pub struct RoundInputs {
    /// Party A: `(forward(a), mask(m_a))`.
    pub a: PartyInputs,
    /// Party B: `(reversed(b), mask(m_b))`.
    pub b: PartyInputs,
}

impl RoundInputs {
    /// Assembles the round from `(slot, vector ct, mask ct)` submissions
    /// in any order; both slots must be present exactly once.
    pub fn from_submissions(subs: &[(u64, Vec<u8>, Vec<u8>)]) -> Result<Self> {
        let mut a: Option<PartyInputs> = None;
        let mut b: Option<PartyInputs> = None;
        for (slot, v, m) in subs {
            let target = match Role::from_index(*slot)? {
                Role::A => &mut a,
                Role::B => &mut b,
            };
            if target.is_some() {
                bail!("slot {slot} submitted twice");
            }
            *target = Some((v.clone(), m.clone()));
        }
        Ok(Self {
            a: a.context("party A (slot 0, forward layout) has not submitted")?,
            b: b.context("party B (slot 1, reversed layout) has not submitted")?,
        })
    }
}

/// Evaluate the round: returns the ciphertext output bytes to publish
/// on-chain. Needs BOTH parties (`inputs.a`, `inputs.b`).
pub fn evaluate(inputs: &RoundInputs, rlk_dir: &Path) -> Result<Vec<u8>> {
    let params = params()?;
    let keys = load_ceremony_keys(rlk_dir, &params)?;
    let rlk = level_0_key(&keys)?;
    let flat: Vec<ArcBytes> = vec![
        ArcBytes::from_bytes(&inputs.a.0),
        ArcBytes::from_bytes(&inputs.b.0),
        ArcBytes::from_bytes(&inputs.a.1),
        ArcBytes::from_bytes(&inputs.b.1),
    ];
    let config = TrCkksConfig::new(ArcBytes::from_bytes(&params.to_bytes()), 1, 1);
    let out = matching_score_policy(&config, &flat, rlk).context("matching score policy")?;
    Ok(out.to_vec())
}

/// The opened coefficients of an on-chain plaintext (64 values at 4 decimals).
pub fn decode_opened(plaintext: &[u8]) -> Result<Vec<f64>> {
    let values = decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)?;
    if values.len() != OUTPUT_COUNT {
        bail!(
            "plaintext has {} coefficients, expected {OUTPUT_COUNT}",
            values.len()
        );
    }
    Ok(values)
}

/// The compatibility score `⟨a, b⟩ = −opened[0]` (the `t^N ≡ −1` wrap of
/// `forward · reversed`).
pub fn score_from_opened(opened: &[f64]) -> Result<f64> {
    opened
        .first()
        .map(|c0| -c0)
        .context("opened output has no coefficient 0")
}

/// The fixed-point rounding the circuit applies to an entry (`×2^16`).
pub fn fixed_point(v: f64) -> f64 {
    let scale = (1u64 << FRAC_BITS) as f64;
    (v * scale).round() / scale
}

/// The value the network computes for the given vectors (oracle; test/e2e
/// use — needs both plaintext vectors).
pub fn expected_score(a: &[f64; K], b: &[f64; K]) -> f64 {
    (0..K).map(|j| fixed_point(a[j]) * fixed_point(b[j])).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decodes_opened_coefficients_and_negates_the_score() {
        let mut values = vec![0.0f64; OUTPUT_COUNT];
        values[0] = 2.4275;
        values[1] = 517.75;
        let bytes = encode_fixed_point_output(&values, OUTPUT_DECIMALS).unwrap();
        let opened = decode_opened(&bytes).unwrap();
        assert_eq!(opened.len(), OUTPUT_COUNT);
        assert!((opened[0] - 2.4275).abs() < 1e-9);
        assert!((score_from_opened(&opened).unwrap() + 2.4275).abs() < 1e-9);
        let short = encode_fixed_point_output(&[1.0, 2.0], OUTPUT_DECIMALS).unwrap();
        assert!(decode_opened(&short).is_err());
    }

    #[test]
    fn roles_ceremony_shape_and_params() {
        assert_eq!(Role::from_index(0).unwrap(), Role::A);
        assert_eq!(Role::from_index(1).unwrap(), Role::B);
        assert!(Role::from_index(2).is_err());
        assert_eq!(Role::A.layout(), "forward");
        assert_eq!(Role::B.layout(), "reversed");
        assert_eq!(expected_ceremony_keys(), 1);
        assert_eq!(ceremony_key_files(), vec!["rlk_level_0.bin".to_string()]);
        assert_eq!(opening_level(), 1);
        assert_eq!(params().unwrap().degree(), 512);
        assert_eq!(params().unwrap().moduli().len(), 3);
        assert_eq!(MASK_WIDTH, 128);
        assert_eq!(MASK_BOUND, 1024.0);
    }

    #[test]
    fn expected_score_is_the_fixed_point_dot_product() {
        // The fixture vectors of `gen_ckks_matching_prover` (score −2.4275…).
        let a = [
            0.5, -0.25, 1.0, -1.0, 0.125, 0.0, 0.75, -0.5, 0.3, -0.7, 0.9, -0.1, 0.6, 0.2, -0.4,
            0.05,
        ];
        let b = [
            0.4, 0.3, -0.2, 0.9, -1.0, 1.0, 0.1, 0.5, -0.6, 0.8, 0.25, 0.75, -0.35, 0.15, 0.95,
            -0.05,
        ];
        let plain: f64 = (0..K).map(|j| a[j] * b[j]).sum();
        let got = expected_score(&a, &b);
        assert!((got - plain).abs() < 1e-4, "{got} vs {plain}");
        assert!((got + 2.4275).abs() < 1e-3, "{got}");
    }

    #[test]
    fn assembles_both_slots_in_any_order_and_refuses_gaps() {
        let subs = vec![(1u64, vec![1u8], vec![2u8]), (0u64, vec![3u8], vec![4u8])];
        let r = RoundInputs::from_submissions(&subs).unwrap();
        assert_eq!(r.a, (vec![3u8], vec![4u8]));
        assert_eq!(r.b, (vec![1u8], vec![2u8]));
        let err = RoundInputs::from_submissions(&subs[..1]).unwrap_err();
        assert!(err.to_string().contains("party A"), "{err}");
        assert!(RoundInputs::from_submissions(&[(2, vec![], vec![])]).is_err());
        let dup = vec![(0u64, vec![], vec![]), (0u64, vec![], vec![])];
        assert!(RoundInputs::from_submissions(&dup).is_err());
        // No ceremony key dir → evaluate fails before touching the policy.
        let dir = std::env::temp_dir().join("ckks-matching-no-such-keys");
        assert!(evaluate(&r, &dir).is_err());
    }
}
