// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Witnesses for chunked share computation (C2): the chunk chain of
//! `circuits/lib/src/core/dkg/share_computation_chain.nr`.
//!
//! A chunk holds `y` rows in the commitments' absorb order (highest degree first) and the state of
//! every commitment sponge before it. Replaying the sponges natively gives each chunk's carried
//! state, its input hash and, after the last chunk, the outputs the final C2 circuit exposes.

use super::share_computation::Inputs;
use crate::commitments::{
    compute_commitments, packer, DS_SHARE_COMPUTATION_CHAIN_OUTPUT,
    DS_SHARE_COMPUTATION_CHAIN_SECRET, DS_SHARE_COMPUTATION_CHAIN_STATE, DS_SHARE_ENCRYPTION,
};
use crate::WitnessError;
use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};
use e3_polynomial::Polynomial;
use e3_safe::{absorb_from, initial_state, squeeze_one_after_absorb, ABSORB_FLAG, STATE_SIZE};
use e3_zk_config::dkg::share_computation::Configs;
use e3_zk_config::DkgInputType;
use num_bigint::{BigInt, BigUint};

/// One chunk's witness.
#[derive(Debug, Clone)]
pub struct ChainChunk {
    /// Hash of `states_in` and `positions_in`: the chunk's public input.
    pub h_in: Field,
    /// Every sponge's state before the chunk: the `N_PARTIES * L` share sponges, then the secret's.
    pub states_in: Vec<[Field; STATE_SIZE]>,
    pub positions_in: Vec<usize>,
    /// `y_chunk[i] = y[N - 1 - (start + i)]`.
    pub y_chunk: Vec<Vec<Vec<BigInt>>>,
    /// The chain's last chunk, proven by the `_last` circuit.
    pub is_last: bool,
}

impl ChainChunk {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "h_in": field_to_string(&self.h_in),
            "states_in": self
                .states_in
                .iter()
                .map(|state| state.iter().map(field_to_string).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            "positions_in": self.positions_in,
            "y_chunk": self
                .y_chunk
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|limb| limb.iter().map(|v| v.to_string()).collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        })
    }
}

/// The whole chain: its chunks and what the last one hands the final circuit.
#[derive(Debug, Clone)]
pub struct Chain {
    pub chunks: Vec<ChainChunk>,
    /// The secret chain digest, then the share commitments in `[party][limb]` order.
    pub outputs: Vec<Field>,
    /// Hash of every sponge fresh: the first chunk's `h_in`.
    pub start_hash: Field,
}

impl Chain {
    /// The chain for `inputs` as `config.chunks` splits it.
    pub fn compute(config: &Configs, inputs: &Inputs) -> Result<Self, WitnessError> {
        let degree = config.params.degree();
        let num_moduli = config.params.moduli().len();
        let n_parties = config.committee.values().n;
        let layout = &config.chunks;
        let bit_share = config.bits.bit_share;
        let secret_limbs = match inputs.dkg_input_type {
            DkgInputType::SecretKey => 1,
            DkgInputType::SmudgingNoise => num_moduli,
        };
        if inputs.y.len() != degree {
            return Err(WitnessError::Other(format!(
                "C2 chain expects {degree} share rows, got {}",
                inputs.y.len()
            )));
        }

        let share_io = share_io_pattern(degree, bit_share);
        let secret_io = [ABSORB_FLAG | (degree * secret_limbs) as u32, 1];
        let shares = n_parties * num_moduli;
        let mut states = vec![initial_state(share_io, DS_SHARE_ENCRYPTION); shares + 1];
        states[shares] = initial_state(secret_io, DS_SHARE_COMPUTATION_CHAIN_SECRET);
        let mut positions = vec![0usize; shares + 1];
        let start_hash = chain_state_hash(&states, &positions);

        let mut chunks = Vec::with_capacity(layout.n_chunks);
        for c in 0..layout.n_chunks {
            let is_last = c + 1 == layout.n_chunks;
            let size = if is_last {
                layout.last_chunk_size
            } else {
                layout.chunk_size
            };
            let start = c * layout.chunk_size;
            let y_chunk: Vec<Vec<Vec<BigInt>>> = (0..size)
                .map(|i| inputs.y[degree - 1 - (start + i)].clone())
                .collect();
            chunks.push(ChainChunk {
                h_in: chain_state_hash(&states, &positions),
                states_in: states.clone(),
                positions_in: positions.clone(),
                y_chunk: y_chunk.clone(),
                is_last,
            });

            for party_idx in 0..n_parties {
                for mod_idx in 0..num_moduli {
                    let values: Vec<BigInt> = y_chunk
                        .iter()
                        .map(|row| row[mod_idx][party_idx + 1].clone())
                        .collect();
                    let s = party_idx * num_moduli + mod_idx;
                    let carriers = packer(&Polynomial::new(values), bit_share);
                    (states[s], positions[s]) = absorb_from(states[s], positions[s], &carriers);
                }
            }
            let secret: Vec<Field> = y_chunk
                .iter()
                .flat_map(|row| (0..secret_limbs).map(move |mod_idx| to_field(&row[mod_idx][0])))
                .collect();
            (states[shares], positions[shares]) =
                absorb_from(states[shares], positions[shares], &secret);
        }

        let mut outputs = Vec::with_capacity(shares + 1);
        outputs.push(squeeze_one_after_absorb(
            secret_io,
            states[shares],
            positions[shares],
        ));
        for s in 0..shares {
            outputs.push(squeeze_one_after_absorb(share_io, states[s], positions[s]));
        }

        Ok(Chain {
            chunks,
            outputs,
            start_hash,
        })
    }

    /// The last chunk's public output.
    pub fn output_hash(&self) -> Field {
        chain_output_hash(&self.outputs)
    }

    pub fn outputs_json(&self) -> Vec<String> {
        self.outputs.iter().map(field_to_string).collect()
    }
}

/// SAFE IO pattern of one share commitment over `degree` coefficients.
fn share_io_pattern(degree: usize, bit_share: u32) -> [u32; 2] {
    let nibble_bits = bit_share.div_ceil(4) * 4;
    let group = (254 / (nibble_bits + 4)) as usize;
    [ABSORB_FLAG | degree.div_ceil(group) as u32, 1]
}

/// Matches Noir `chain_state_hash`.
pub fn chain_state_hash(states: &[[Field; STATE_SIZE]], positions: &[usize]) -> Field {
    let mut inputs = Vec::with_capacity(states.len() * (STATE_SIZE + 1));
    for (state, position) in states.iter().zip(positions) {
        inputs.extend_from_slice(state);
        inputs.push(Field::from(*position as u64));
    }
    let io_pattern = [ABSORB_FLAG | inputs.len() as u32, 1];
    compute_commitments(inputs, DS_SHARE_COMPUTATION_CHAIN_STATE, io_pattern)[0]
}

/// Matches Noir `chain_output_hash`.
pub fn chain_output_hash(outputs: &[Field]) -> Field {
    let io_pattern = [ABSORB_FLAG | outputs.len() as u32, 1];
    compute_commitments(
        outputs.to_vec(),
        DS_SHARE_COMPUTATION_CHAIN_OUTPUT,
        io_pattern,
    )[0]
}

/// `value` as a field element; a negative value (the `sk` column holds `-1`) wraps mod p, as the
/// circuit's input parser reads it.
fn to_field(value: &BigInt) -> Field {
    let (sign, bytes) = value.to_bytes_le();
    let magnitude = Field::from_le_bytes_mod_order(&bytes);
    if sign == num_bigint::Sign::Minus {
        -magnitude
    } else {
        magnitude
    }
}

pub fn field_to_string(value: &Field) -> String {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le()).to_string()
}
