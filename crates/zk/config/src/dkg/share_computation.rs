// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static parameters, bounds, widths, and Noir declarations.

use crate::{CircuitMetadata, ConfigError};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::utils::*;
use e3_fhe_params::{BfvPreset, ParameterType};
use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
pub mod parity;
use parity::parity_matrix_constant_string;

pub const METADATA: CircuitMetadata = CircuitMetadata {
    name: "share-computation",
    prefix: "SHARE_COMPUTATION",
    parameter: ParameterType::THRESHOLD,
};
#[derive(Debug, Clone)]
pub struct Configs {
    pub params: Arc<BfvParameters>,
    pub committee: CiphernodesCommitteeSize,
    preset: BfvPreset,
    pub bits: Bits,
    pub chunks: ChunkLayout,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub bit_sk_secret: u32,
    pub bit_e_sm_secret: u32,
    pub bit_share: u32,
}
impl Configs {
    pub fn new(
        preset: BfvPreset,
        threshold_params: &Arc<BfvParameters>,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        crate::parameters::require_threshold_preset(preset, threshold_params)?;
        let bits = Bits::new(threshold_params);
        let chunks = ChunkLayout::new(threshold_params.degree(), bits.bit_share)?;

        Ok(Configs {
            params: threshold_params.clone(),
            committee,
            preset,

            bits,
            chunks,
        })
    }
}
/// How chunked C2 splits the degree: `n_chunks - 1` chunks of `chunk_size` coefficients, then
/// one of `last_chunk_size`, verified `chunks_per_batch` at a time.
///
/// A chunk other than the last holds whole share carriers and whole sponge blocks (rate 3), so
/// `chunk_size` is a multiple of three packing groups and every chunk starts each sponge on a block
/// boundary. The target of 16 chunks keeps a chunk near 2^21 gates at 39 parties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChunkLayout {
    pub chunk_size: usize,
    pub last_chunk_size: usize,
    pub n_chunks: usize,
    pub chunks_per_batch: usize,
    pub n_batches: usize,
}

impl ChunkLayout {
    const TARGET_CHUNKS: usize = 16;
    const MIN_CHUNKS: usize = 4;
    const CHUNKS_PER_BATCH: usize = 4;

    pub fn new(degree: usize, bit_share: u32) -> Result<Self, ConfigError> {
        let nibble_bits = bit_share.div_ceil(4) * 4;
        let group = (254 / (nibble_bits + 4)) as usize;
        let target = (degree / 16).clamp(Self::MIN_CHUNKS, Self::TARGET_CHUNKS);
        let block = 3 * group;
        let chunk_size = degree.div_ceil(target).div_ceil(block) * block;
        let n_chunks = degree.div_ceil(chunk_size);
        let last_chunk_size = degree - (n_chunks - 1) * chunk_size;
        if n_chunks % Self::CHUNKS_PER_BATCH != 0 {
            return Err(ConfigError::Other(format!(
                "degree {degree} splits into {n_chunks} C2 chunks, not a multiple of {}",
                Self::CHUNKS_PER_BATCH
            )));
        }
        Ok(ChunkLayout {
            chunk_size,
            last_chunk_size,
            n_chunks,
            chunks_per_batch: Self::CHUNKS_PER_BATCH,
            n_batches: n_chunks / Self::CHUNKS_PER_BATCH,
        })
    }
}

impl Bits {
    fn new(threshold_params: &Arc<BfvParameters>) -> Self {
        let bit_share = compute_native_crt_coeff_bit(threshold_params.moduli());

        Bits {
            bit_sk_secret: calculate_bit_width(&BigUint::from(SecretKey::sk_bound() as u128)),
            // The e_sm secret is held as centered CRT residues, so it shares the modulus width
            // with C1's committed limbs. C1 range-checks the smudging bound on its lifted
            // witness; that bound exceeds every q_i and is not the width of what is hashed here.
            bit_e_sm_secret: compute_modulus_bit(threshold_params),
            bit_share,
        }
    }
}
impl Configs {
    pub fn render(&self) -> Result<String, ConfigError> {
        let configs = self;
        let preset = self.preset;
        let committee = self.committee;
        let threshold_params = &self.params;
        let config_name = preset.metadata().security.as_config_str();
        let bits = &configs.bits;
        let committee = committee.values();
        let parity_matrix_str =
            parity_matrix_constant_string(threshold_params, committee.n, committee.threshold)?;
        let prefix = METADATA.prefix;
        let configs = format!(
            r#"
pub use crate::configs::{}::threshold::{{L as L_THRESHOLD, QIS as QIS_THRESHOLD}};

pub global N: u32 = {};

{}
/************************************
-------------------------------------
share_computation_sk (CIRCUIT 2a)
-------------------------------------
************************************/

// share_computation_sk - bit parameters
pub global {}_BIT_SHARE: u32 = {};
pub global {}_SK_BIT_SECRET: u32 = {};

// share_computation_sk - configs
pub global {}_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation_e_sm (CIRCUIT 2b)
-------------------------------------
************************************/

// share_computation_e_sm - bit parameters
pub global {}_E_SM_BIT_SECRET: u32 = {};

// verify_shares - configs
pub global {}_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);

/************************************
-------------------------------------
share_computation chunks (chunked C2a and C2b)
-------------------------------------
************************************/

pub global {}_CHUNK_SIZE: u32 = {};
pub global {}_LAST_CHUNK_SIZE: u32 = {};
pub global {}_N_CHUNKS: u32 = {};
pub global {}_CHUNKS_PER_BATCH: u32 = {};
pub global {}_N_BATCHES: u32 = {};
"#,
            config_name,
            configs.params.degree(),
            parity_matrix_str,
            prefix,
            bits.bit_share,
            prefix,
            bits.bit_sk_secret,
            prefix,
            prefix,
            bits.bit_e_sm_secret,
            prefix,
            prefix,
            self.chunks.chunk_size,
            prefix,
            self.chunks.last_chunk_size,
            prefix,
            self.chunks.n_chunks,
            prefix,
            self.chunks.chunks_per_batch,
            prefix,
            self.chunks.n_batches,
        );

        Ok(configs)
    }
}

impl Configs {
    pub fn for_preset(
        preset: BfvPreset,
        committee: CiphernodesCommitteeSize,
    ) -> Result<Self, ConfigError> {
        let (threshold_params, _) = preset
            .build_pair()
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Self::new(preset, &threshold_params, committee)
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkLayout;

    #[test]
    fn chunk_layouts_cover_the_degree_with_whole_carriers() {
        // 60-bit shares pack three per carrier.
        for (degree, chunk_size, last_chunk_size, n_chunks) in
            [(8192, 513, 497, 16), (64, 18, 10, 4)]
        {
            let layout = ChunkLayout::new(degree, 60).unwrap();
            assert_eq!(
                (layout.chunk_size, layout.last_chunk_size, layout.n_chunks),
                (chunk_size, last_chunk_size, n_chunks)
            );
            assert_eq!(layout.chunk_size % 9, 0);
            assert_eq!(
                (layout.n_chunks - 1) * layout.chunk_size + layout.last_chunk_size,
                degree
            );
            assert_eq!(layout.n_batches * layout.chunks_per_batch, layout.n_chunks);
        }
    }
}
