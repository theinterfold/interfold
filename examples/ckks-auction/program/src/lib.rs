// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CKKS sealed-bid auction program (the E3 "policy").
//!
//! The computation the committee's ciphertext output carries is
//! [`e3_trckks::policy::sign_extraction_policy`] over ALL `i<j` bidder
//! pairs: each pair's difference is normalised by `1/bound`, packed into
//! its own slot, and driven through 12 iterations of `f(y)=(1.5-0.5y²)y`
//! so that every opened slot is EXACTLY `±1`. The threshold decryption
//! therefore reveals the comparison bits (who outbid whom) and nothing
//! about the bids or their gaps. Every relinearization of the 24
//! multiplications uses the committee's ONE hybrid relinearization key
//! (`rlk_hybrid.bin`, ParamSet 2 carries special primes) — a single
//! two-round ceremony after the DKG instead of one per level.
//!
//! This crate is the plain-Rust wrapper the coordination server calls
//! (CRISP's `program/` is a RISC Zero guest; the CKKS demos run the
//! policy natively — the ciphertext output is published with a mock
//! proof, see the Readme's honest-scope section).

use anyhow::{bail, Context, Result};
use e3_fhe_params::ckks_presets::{
    ckks_params_for_on_chain_param_set, relin_ceremony_plan_for_param_set,
    sign_extraction_mult_levels, RelinCeremonyPlan, SIGN_EXTRACTION_ITERATIONS,
};
use e3_trckks::policy::{sign_extraction_policy, RelinKeys};
use e3_trckks::program::{decode_fixed_point_output, AuctionRound};
use e3_trckks::TrCkksConfig;
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksParameters;
use fhe_traits::Serialize as _;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// On-chain ParamSet of the sign-extraction ladder.
pub const PARAM_SET: u8 = 2;
/// Sign-map iterations (binarises gaps down to ~2% of the bound).
pub const ITERATIONS: usize = SIGN_EXTRACTION_ITERATIONS;
/// Decimals of the canonical on-chain fixed-point output.
pub const OUTPUT_DECIMALS: u32 = 2;
/// A slot counts as a saturated sign when `| |v| - 1 | <= SATURATION_TOLERANCE`.
pub const SATURATION_TOLERANCE: f64 = 0.05;

/// The multiplication levels the policy relinearizes at (all served by
/// the one hybrid key).
pub fn relin_levels(iterations: usize) -> Vec<usize> {
    sign_extraction_mult_levels(iterations)
}

/// Number of joint ceremony key files a complete DKG writes (ONE:
/// `rlk_hybrid.bin`).
pub fn expected_ceremony_keys() -> usize {
    relin_ceremony_plan_for_param_set(PARAM_SET)
        .map(|p| p.key_count())
        .unwrap_or(0)
}

/// The ceremony's key file name(s) the evaluator waits for.
pub fn ceremony_key_files() -> Vec<String> {
    match relin_ceremony_plan_for_param_set(PARAM_SET) {
        Ok(RelinCeremonyPlan::Hybrid) => vec![RelinKeys::HYBRID_KEY_FILE.to_string()],
        Ok(RelinCeremonyPlan::PerLevel(levels)) => levels
            .iter()
            .map(|l| RelinKeys::level_key_file(*l))
            .collect(),
        _ => vec![],
    }
}

/// Canonical serialized ParamSet-2 parameters (byte-identical to every node's).
pub fn params() -> Result<Arc<CkksParameters>> {
    ckks_params_for_on_chain_param_set(PARAM_SET).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn params_bytes() -> Result<Vec<u8>> {
    Ok(params()?.to_bytes())
}

/// All `i<j` pairs in slot order.
pub fn pairs(bidders: usize) -> Vec<(usize, usize)> {
    AuctionRound::all_pairs(bidders).pairs
}

/// Loads the ceremony key(s) from a ceremony key directory
/// (`<node data dir>/<node>/ckks/relin-keys/<chain>:<e3_id>/`): the ONE `rlk_hybrid.bin`.
pub fn load_ceremony_keys(dir: &Path, params: &Arc<CkksParameters>) -> Result<RelinKeys> {
    RelinKeys::load_from_dir(dir, params, &relin_levels(ITERATIONS))
        .with_context(|| format!("loading ceremony keys from {}", dir.display()))
}

/// Evaluate the auction: returns the ciphertext output bytes to publish on-chain.
pub fn evaluate(bids: &[Vec<u8>], bound: f64, ceremony_dir: &Path) -> Result<Vec<u8>> {
    if bids.len() < 2 {
        bail!("need at least two bids");
    }
    let params = params()?;
    let config = TrCkksConfig::new(
        ArcBytes::from_bytes(&params.to_bytes()),
        bids.len() as u64,
        1,
    );
    let rlks = load_ceremony_keys(ceremony_dir, &params)?;
    let inputs: Vec<ArcBytes> = bids.iter().map(|b| ArcBytes::from_bytes(b)).collect();
    let out = sign_extraction_policy(
        &config,
        &inputs,
        &pairs(bids.len()),
        bound,
        ITERATIONS,
        &rlks,
    )?;
    Ok(out.to_vec())
}

/// Decoded outcome of an opened round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub pairs: Vec<(usize, usize)>,
    pub values: Vec<f64>,
    pub signs: Vec<i8>,
    pub binarized: bool,
    pub wins: Vec<usize>,
    pub winner: usize,
}

/// Interpret the on-chain plaintext (canonical fixed point) for `bidders` bids.
pub fn decode_outcome(plaintext: &[u8], bidders: usize) -> Result<Outcome> {
    let pairs = pairs(bidders);
    let values = decode_fixed_point_output(plaintext, OUTPUT_DECIMALS)?;
    if values.len() < pairs.len() {
        bail!(
            "plaintext has {} slots but {} pairs were evaluated",
            values.len(),
            pairs.len()
        );
    }
    let values: Vec<f64> = values[..pairs.len()].to_vec();
    let signs: Vec<i8> = values
        .iter()
        .map(|v| if *v > 0.0 { 1 } else { -1 })
        .collect();
    let binarized = values
        .iter()
        .all(|v| (v.abs() - 1.0).abs() <= SATURATION_TOLERANCE);
    let mut wins = vec![0usize; bidders];
    for (p, &(a, b)) in pairs.iter().enumerate() {
        if signs[p] > 0 {
            wins[a] += 1;
        } else {
            wins[b] += 1;
        }
    }
    let winner = (0..bidders)
        .max_by_key(|&i| (wins[i], usize::MAX - i))
        .context("no bidders")?;
    Ok(Outcome {
        pairs,
        values,
        signs,
        binarized,
        wins,
        winner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_trckks::program::encode_fixed_point_output;

    #[test]
    fn decodes_winner_from_sign_matrix() {
        // 4 bidders: 220, 815, 402, 382 → bidder 1 wins; pairs (0,1)(0,2)(0,3)(1,2)(1,3)(2,3)
        let bytes =
            encode_fixed_point_output(&[-1.0, -1.0, -1.0, 1.0, 1.0, 1.0], OUTPUT_DECIMALS).unwrap();
        let o = decode_outcome(&bytes, 4).unwrap();
        assert_eq!(o.winner, 1);
        assert_eq!(o.wins, vec![0, 3, 2, 1]);
        assert!(o.binarized);
    }

    #[test]
    fn unsaturated_slot_is_flagged() {
        let bytes =
            encode_fixed_point_output(&[-1.0, 0.33, -1.0, 1.0, 1.0, 1.0], OUTPUT_DECIMALS).unwrap();
        assert!(!decode_outcome(&bytes, 4).unwrap().binarized);
    }

    #[test]
    fn relin_levels_match_the_ladder() {
        assert_eq!(relin_levels(2), vec![1, 3, 4, 6]);
        // ONE hybrid key serves all 24 levels.
        assert_eq!(expected_ceremony_keys(), 1);
        assert_eq!(ceremony_key_files(), vec!["rlk_hybrid.bin".to_string()]);
        assert!(params().unwrap().hybrid_enabled());
    }
}
