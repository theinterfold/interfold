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

fn rows_literal(rows: &[CrtPolynomial]) -> String {
    let rows = rows
        .iter()
        .map(|row| {
            let limbs = row
                .limbs
                .iter()
                .map(|limb| {
                    let coefficients = limb
                        .coefficients()
                        .iter()
                        .map(|coefficient| {
                            format!(
                                "        {},",
                                e3_zk_config::field::bigint_to_field(coefficient)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("    Polynomial::new([\n{coefficients}\n    ]),")
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("[\n{limbs}\n]")
        })
        .collect::<Vec<_>>()
        .join(",\n");
    format!("[\n{rows}\n]")
}

pub fn public_randomness(
    root: &Path,
    preset: BfvPreset,
    params: &Arc<BfvParameters>,
) -> Result<Vec<(PathBuf, String)>> {
    let (Some(crs_seed), Some(urs_seed)) = (lbfv_crs_seed(preset), lbfv_urs_seed(preset)) else {
        return Ok(Vec::new());
    };
    let crs = rows(params, crs_seed)?;
    let urs = rows(params, urs_seed)?;
    let bit = e3_fhe_params::utils::compute_modulus_bit(params);
    let commitments = |rows: &[CrtPolynomial]| {
        rows.iter()
            .map(|row| {
                e3_zk_witness::commitments::compute_pk_aggregation_pk1_commitment(row, bit)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let slug = preset.noir_config_module();
    let header = "// SPDX-License-Identifier: LGPL-3.0-only\n//\n// This file is provided WITHOUT ANY WARRANTY;\n// without even the implied warranty of MERCHANTABILITY\n// or FITNESS FOR A PARTICULAR PURPOSE.\n";
    let module = format!("{header}\nuse super::threshold::GADGET_DIM;\n\npub mod crs;\npub mod urs;\n\npub use crate::configs::{slug}::lbfv::crs::LBFV_CRS_GADGET_ROWS;\npub use crate::configs::{slug}::lbfv::urs::LBFV_URS_GADGET_ROWS;\n\n/// `commit(LBFV_CRS_GADGET_ROWS[row])` under `DS_PK_AGGREGATION`, the `pk1` half of C5's output.\npub global LBFV_CRS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [{}];\n\n/// `commit(LBFV_URS_GADGET_ROWS[row])` under the same hash, which `rlk_generation` opens.\npub global LBFV_URS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [{}];\n", commitments(&crs), commitments(&urs));
    let directory = root
        .join("circuits/lib/src/configs")
        .join(slug)
        .join("lbfv");
    let mut updates = vec![(directory.join("mod.nr"), module)];
    for (name, rows) in [("crs", crs), ("urs", urs)] {
        updates.push((directory.join(format!("{name}.nr")), format!("{header}\nuse crate::math::polynomial::Polynomial;\nuse super::super::threshold::{{GADGET_DIM, L, N}};\n\npub global LBFV_{}_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = {};\n", name.to_uppercase(), rows_literal(&rows))));
    }
    Ok(updates)
}

pub fn threshold_constants(
    preset: BfvPreset,
    params: &Arc<BfvParameters>,
    committee: CiphernodesCommitteeSize,
) -> Result<String> {
    let pk = threshold::pk_generation::Configs::new(preset, params, committee)?;
    // The l-BFV row and C1 use the same reduced per-limb relation and quotient bounds.
    let bounds = pk
        .bounds
        .r_bounds
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!("pub global LBFV_PK_GENERATION_BIT_R: u32 = {};\npub global LBFV_PK_GENERATION_R_BOUNDS: [Field; L] = [{bounds}];\n", pk.bits.r_bit);
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
    // Keep the degree-16384 committee expression; the active committee selects the compiled grid.
    let chunk = if degree >= 16384 {
        "if crate::configs::committee::active::N_PARTIES <= 4 {\n    8192\n} else {\n    2048\n}"
            .to_string()
    } else {
        degree.min(512).to_string()
    };
    format!("pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = {chunk};\npub global SHARE_COMPUTATION_N_CHUNKS: u32 = N / SHARE_COMPUTATION_CHUNK_SIZE;\npub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = if SHARE_COMPUTATION_N_CHUNKS < 4 {{\n    SHARE_COMPUTATION_N_CHUNKS\n}} else {{\n    4\n}};\npub global SHARE_COMPUTATION_N_BATCHES: u32 = SHARE_COMPUTATION_N_CHUNKS / SHARE_COMPUTATION_CHUNKS_PER_BATCH;\n")
}
