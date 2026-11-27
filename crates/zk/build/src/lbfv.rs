// SPDX-License-Identifier: LGPL-3.0-only

//! Deterministic l-BFV public randomness and shared configuration; no artificial samples.

use anyhow::Result;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::CrtPolynomial;
use e3_polynomial_fhe::FromFhePolynomial;
use e3_zk_config::threshold;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

fn rows(params: &Arc<BfvParameters>, seed: [u8; 32]) -> Result<Vec<CrtPolynomial>> {
    CommonRandomPolyVec::from_seed(params, seed)?
        .to_polys()
        .into_iter()
        .map(|poly| {
            let mut row = CrtPolynomial::from_fhe_polynomial(&poly);
            row.reverse();
            row.center(params.moduli())?;
            Ok(row)
        })
        .collect()
}

/// `lbfv/mod.nr` for `preset`: the committed row commitments of the CRS and URS, which the
/// circuits open instead of embedding the rows. The rows are derived in memory from the pinned
/// seeds and never written to disk. A preset without l-BFV seeds has no such file.
pub fn public_randomness(
    root: &Path,
    preset: BfvPreset,
    params: &Arc<BfvParameters>,
) -> Result<Vec<(PathBuf, String)>> {
    let preset = if preset == BfvPreset::InsecureThreshold {
        BfvPreset::InsecureThresholdLbfv
    } else {
        preset
    };
    let (Some(crs_seed), Some(urs_seed)) = (lbfv_crs_seed(preset), lbfv_urs_seed(preset)) else {
        return Ok(Vec::new());
    };
    let bit = e3_fhe_params::utils::compute_modulus_bit(params);
    let commitments = |seed: [u8; 32]| -> Result<String> {
        Ok(rows(params, seed)?
            .iter()
            .map(|row| {
                format!(
                    "    {},",
                    e3_zk_witness::commitments::compute_pk_aggregation_component_commitment(
                        row, bit
                    )
                )
            })
            .collect::<Vec<_>>()
            .join("\n"))
    };
    let (crs, urs) = (commitments(crs_seed)?, commitments(urs_seed)?);
    let header = "// SPDX-License-Identifier: LGPL-3.0-only\n//\n// This file is provided WITHOUT ANY WARRANTY;\n// without even the implied warranty of MERCHANTABILITY\n// or FITNESS FOR A PARTICULAR PURPOSE.\n";
    let module = format!("{header}\nuse super::threshold::GADGET_DIM;\n\n/// `commit(row)` under `DS_PK_AGGREGATION` for each CRS row, the `pk1` half of C5's output.\n/// The rows derive from a pinned seed (`crates/zk/build`) and are not committed.\npub global LBFV_CRS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [\n{crs}\n];\n\n/// `commit(row)` under the same hash for each URS row, which `rlk_generation` opens.\n/// The rows derive from a pinned seed (`crates/zk/build`) and are not committed.\npub global LBFV_URS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [\n{urs}\n];\n");
    let path = root
        .join("circuits/lib/src/configs")
        .join(preset.noir_config_module())
        .join("lbfv/mod.nr");
    Ok(vec![(path, module)])
}

pub fn threshold_constants(
    preset: BfvPreset,
    params: &Arc<BfvParameters>,
    committee: CiphernodesCommitteeSize,
) -> Result<String> {
    let preset = if preset == BfvPreset::InsecureThreshold {
        BfvPreset::InsecureThresholdLbfv
    } else {
        preset
    };
    let pk = threshold::pk_generation::Configs::new(preset, params, committee)?;
    let mut out = format!(
        "pub global LBFV_PK_GENERATION_BIT_R: u32 = {};\n",
        pk.bits.r_bit
    );
    if lbfv_crs_seed(preset).is_some() && lbfv_urs_seed(preset).is_some() {
        out.push_str(
            &threshold::rlk_generation::RlkGenerationConfigs::new(preset, params, committee)?
                .render()?,
        );
        out.push_str(
            &threshold::rlk_aggregation::RlkAggregationConfigs::new(preset, params, committee)?
                .render()?,
        );
    }
    Ok(out)
}

pub fn chunk_grid(degree: usize) -> String {
    // The active committee selects the compiled grid at degree 16384.
    let chunk = e3_zk_config::chunks::c2_chunk_size_noir(degree);
    format!("pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = {chunk};\npub global SHARE_COMPUTATION_N_CHUNKS: u32 = N / SHARE_COMPUTATION_CHUNK_SIZE;\npub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = if SHARE_COMPUTATION_N_CHUNKS < 4 {{\n    SHARE_COMPUTATION_N_CHUNKS\n}} else {{\n    4\n}};\npub global SHARE_COMPUTATION_N_BATCHES: u32 = SHARE_COMPUTATION_N_CHUNKS / SHARE_COMPUTATION_CHUNKS_PER_BATCH;\n")
}
