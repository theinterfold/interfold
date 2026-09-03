// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

//! C8-CKKS (hybrid, per-digit): `relin_round1_hybrid_ckks_digit`.
//!
//! One proof per gadget digit of a party's round-1 share. The zk-helpers
//! witness builder takes `(share data, digit)`; this adapter packs the pair
//! into one `Provable::Input` so the generic prove path applies.

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks::CkksHybridRelinRound1Data;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks_digit::{
    compute_digit_inputs, CkksHybridRelinRound1DigitCircuit, DigitInputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::CkksPreset;
use e3_zk_helpers::{CircuitsErrors, Computation};
use std::sync::Arc;

/// `(whole-share witness data, digit index)` for one digit proof.
pub struct CkksHybridRelinRound1DigitData {
    pub share: Arc<CkksHybridRelinRound1Data>,
    pub digit: usize,
}

/// Newtype so `Computation` can be implemented here (both the trait and
/// `DigitInputs` live in zk-helpers; the sibling's builder is a free fn).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DigitInputsAdapter(pub DigitInputs);

impl Computation for DigitInputsAdapter {
    type Preset = CkksPreset;
    type Data = CkksHybridRelinRound1DigitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        compute_digit_inputs(&preset, &data.share, data.digit).map(DigitInputsAdapter)
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(self.0.to_json())
    }
}

impl Provable for CkksHybridRelinRound1DigitCircuit {
    type Params = CkksPreset;
    type Input = CkksHybridRelinRound1DigitData;
    type Inputs = DigitInputsAdapter;

    fn circuit(&self) -> CircuitName {
        CircuitName::RelinRound1HybridCkksDigit
    }
}
