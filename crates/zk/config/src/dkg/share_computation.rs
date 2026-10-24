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
    /// C2a's chunks.
    pub sk_chunks: ChunkLayout,
    /// C2b's chunks.
    pub e_sm_chunks: ChunkLayout,
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
        let degree = threshold_params.degree();
        let sk_chunks = ChunkLayout::new(degree, bits.bit_share, ChunkLayout::SK_TARGET_CHUNKS)?;
        let e_sm_chunks =
            ChunkLayout::new(degree, bits.bit_share, ChunkLayout::E_SM_TARGET_CHUNKS)?;

        Ok(Configs {
            params: threshold_params.clone(),
            committee,
            preset,

            bits,
            sk_chunks,
            e_sm_chunks,
        })
    }
}
/// How chunked C2 splits the degree: `n_chunks - 1` chunks of `chunk_size` coefficients, then
/// one of `last_chunk_size`. The final C2 circuit verifies every chunk.
///
/// A chunk other than the last holds whole share carriers and whole sponge blocks (rate 3), so
/// `chunk_size` is a multiple of three packing groups and every chunk starts each sponge on a block
/// boundary.
///
/// The targets keep every chunk inside 2^22 at 39 parties with as few chunks as possible, which
/// costs less proving than more, smaller chunks. At degree 8192, C2a takes five chunks of 1647
/// (4.14M gates). C2b also hashes every secret limb, so five chunks would cross 2^22; it takes six
/// of 1368 (about 3.5M). Eleven chunks for C2a and C2b fit within one Chonk stack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChunkLayout {
    pub chunk_size: usize,
    pub last_chunk_size: usize,
    pub n_chunks: usize,
}

impl ChunkLayout {
    pub const SK_TARGET_CHUNKS: usize = 5;
    pub const E_SM_TARGET_CHUNKS: usize = 6;
    const MIN_CHUNKS: usize = 2;

    pub fn new(degree: usize, bit_share: u32, target_chunks: usize) -> Result<Self, ConfigError> {
        let nibble_bits = bit_share.div_ceil(4) * 4;
        let group = (254 / (nibble_bits + 4)) as usize;
        let target = (degree / 16).clamp(Self::MIN_CHUNKS, target_chunks);
        let block = 3 * group;
        let chunk_size = degree.div_ceil(target).div_ceil(block) * block;
        let n_chunks = degree.div_ceil(chunk_size);
        let last_chunk_size = degree - (n_chunks - 1) * chunk_size;
        if n_chunks < 2 {
            return Err(ConfigError::Other(format!(
                "degree {degree} gives one C2 chunk; the chain needs a last chunk after full ones"
            )));
        }
        Ok(ChunkLayout {
            chunk_size,
            last_chunk_size,
            n_chunks,
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

pub global {}_SK_CHUNK_SIZE: u32 = {};
pub global {}_SK_LAST_CHUNK_SIZE: u32 = {};
pub global {}_SK_N_CHUNKS: u32 = {};
pub global {}_E_SM_CHUNK_SIZE: u32 = {};
pub global {}_E_SM_LAST_CHUNK_SIZE: u32 = {};
pub global {}_E_SM_N_CHUNKS: u32 = {};
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
            self.sk_chunks.chunk_size,
            prefix,
            self.sk_chunks.last_chunk_size,
            prefix,
            self.sk_chunks.n_chunks,
            prefix,
            self.e_sm_chunks.chunk_size,
            prefix,
            self.e_sm_chunks.last_chunk_size,
            prefix,
            self.e_sm_chunks.n_chunks,
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
        for (degree, target, chunk_size, last_chunk_size, n_chunks) in [
            (8192, ChunkLayout::SK_TARGET_CHUNKS, 1647, 1604, 5),
            (8192, ChunkLayout::E_SM_TARGET_CHUNKS, 1368, 1352, 6),
            (64, ChunkLayout::E_SM_TARGET_CHUNKS, 18, 10, 4),
        ] {
            let layout = ChunkLayout::new(degree, 60, target).unwrap();
            assert_eq!(
                (layout.chunk_size, layout.last_chunk_size, layout.n_chunks),
                (chunk_size, last_chunk_size, n_chunks)
            );
            assert_eq!(layout.chunk_size % 9, 0);
            assert_eq!(
                (layout.n_chunks - 1) * layout.chunk_size + layout.last_chunk_size,
                degree
            );
        }
    }
}
