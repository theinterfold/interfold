// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Witnesses for chunked share decryption (C4): the limb chain of
//! `circuits/lib/src/core/dkg/share_decryption_chain.nr`.
//!
//! Limb `l` opens every honest party's limb-`l` share commitment and continues the aggregate
//! commitment's sponge. Replaying the sponge natively gives each limb's carried state and input
//! hash, and the aggregate commitment the last limb returns.

use super::share_computation_chain::field_to_string;
use super::share_decryption::Inputs;
use crate::commitments::{
    compute_commitments, DS_AGGREGATED_SHARES, DS_SHARE_DECRYPTION_CHAIN_STATE,
};
use crate::encoding::poly_coefficients_to_toml_json;
use crate::packing::packer;
use crate::WitnessError;
use ark_bn254::Fr as Field;
use e3_polynomial::Polynomial;
use e3_safe::{absorb_from, initial_state, squeeze_one_after_absorb, ABSORB_FLAG, STATE_SIZE};
use e3_zk_config::dkg::share_decryption::Configs;
use num_bigint::BigInt;
use num_traits::Signed;

/// One limb's witness.
#[derive(Debug, Clone)]
pub struct LimbChunk {
    /// `expected_commitments[party][limb]` for this limb.
    pub expected_commitments: Vec<BigInt>,
    /// `decrypted_shares[party][limb]` for this limb.
    pub decrypted_shares: Vec<Vec<BigInt>>,
    pub h_in: Field,
    pub state_in: [Field; STATE_SIZE],
}

impl LimbChunk {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "expected_commitments": self
                .expected_commitments
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>(),
            "h_in": field_to_string(&self.h_in),
            "decrypted_shares": self
                .decrypted_shares
                .iter()
                .map(|share| poly_coefficients_to_toml_json(share))
                .collect::<Vec<_>>(),
            "state_in": self.state_in.iter().map(field_to_string).collect::<Vec<_>>(),
        })
    }
}

/// The limb chain and the aggregate commitment it ends on.
#[derive(Debug, Clone)]
pub struct LimbChain {
    pub limbs: Vec<LimbChunk>,
    /// Hash of the fresh aggregate sponge: limb 0's `h_in`.
    pub start_hash: Field,
    /// The commitment the last limb returns (the unchunked C4 output).
    pub aggregate: Field,
}

impl LimbChain {
    pub fn compute(config: &Configs, inputs: &Inputs) -> Result<Self, WitnessError> {
        let moduli = config.threshold_params.moduli();
        let num_moduli = moduli.len();
        let degree = config.threshold_params.degree();
        let agg_bit = config.bits.agg_bit;
        let nibble_bits = agg_bit.div_ceil(4) * 4;
        let group = (254 / (nibble_bits + 4)) as usize;
        let io_pattern = [
            ABSORB_FLAG | (num_moduli * degree.div_ceil(group)) as u32,
            1,
        ];

        let mut state = initial_state(io_pattern, DS_AGGREGATED_SHARES);
        let mut pos = 0;
        let start_hash = limb_state_hash(&state);
        let mut limbs = Vec::with_capacity(num_moduli);
        for (limb, &q) in moduli.iter().enumerate() {
            let shares: Vec<Vec<BigInt>> = inputs
                .decrypted_shares
                .iter()
                .map(|party| party[limb].clone())
                .collect();
            if shares.iter().any(|share| share.len() != degree) {
                return Err(WitnessError::Other(format!(
                    "C4 limb {limb} expects {degree} coefficients per share"
                )));
            }
            limbs.push(LimbChunk {
                expected_commitments: inputs
                    .expected_commitments
                    .iter()
                    .map(|party| party[limb].clone())
                    .collect(),
                decrypted_shares: shares.clone(),
                h_in: limb_state_hash(&state),
                state_in: state,
            });

            // C4's normalization: sum the shares, center mod q, highest degree first.
            let q = BigInt::from(q);
            let half = (&q - 1) / 2;
            let mut normalized: Vec<BigInt> = (0..degree)
                .map(|i| {
                    let sum: BigInt = shares.iter().map(|share| &share[i]).sum();
                    let mut r = sum % &q;
                    if r.is_negative() {
                        r += &q;
                    }
                    if r > half {
                        r - &q
                    } else {
                        r
                    }
                })
                .collect();
            normalized.reverse();
            let carriers = packer(&Polynomial::new(normalized), agg_bit);
            (state, pos) = absorb_from(state, pos, &carriers);
        }

        Ok(LimbChain {
            limbs,
            start_hash,
            aggregate: squeeze_one_after_absorb(io_pattern, state, pos),
        })
    }
}

/// Matches Noir `limb_state_hash`.
pub fn limb_state_hash(state: &[Field; STATE_SIZE]) -> Field {
    compute_commitments(
        state.to_vec(),
        DS_SHARE_DECRYPTION_CHAIN_STATE,
        [ABSORB_FLAG | STATE_SIZE as u32, 1],
    )[0]
}
