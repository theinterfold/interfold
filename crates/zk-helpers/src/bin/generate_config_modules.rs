// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Regenerates the global BFV/CRT config modules in `circuits/lib/src/configs/<preset-module>`
//! (`mod.nr`, `threshold.nr`, `dkg.nr`) for the given preset.
//!
//! These were historically hand-maintained (with the 24k-line `threshold.nr` dominated
//! by the deterministic `CRP` literal). This binary derives every value from the same
//! Rust parameter / bound computation the per-circuit `zk_cli` codegen uses, so the
//! on-disk modules can never silently desync from the prover.
//!
//! Usage:
//!     cargo run --release --bin generate_config_modules -- \
//!         --preset INSECURE_THRESHOLD \
//!         [--output-root <path-to-circuits/lib/src/configs>]
//!
//! A preset maps to a distinct Noir module (`insecure`, `secure_8192`, or `secure_16384`); the
//! generator writes into `<output-root>/<preset-module>/`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use e3_fhe_params::{
    build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset, ParameterType,
};
use e3_polynomial::CrtPolynomial;
use e3_zk_helpers::ciphernodes_committee::CiphernodesCommitteeSize;
use e3_zk_helpers::circuits::commitments::compute_pk_aggregation_pk1_commitment;
use e3_zk_helpers::circuits::dkg::pk::computation::{Bits as DkgPkBits, Configs as DkgPkConfigs};
use e3_zk_helpers::circuits::dkg::share_encryption::circuit::ShareEncryptionCircuitData;
use e3_zk_helpers::circuits::dkg::share_encryption::Configs as ShareEncryptionConfigs;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::computation::Configs as DsaConfigs;
use e3_zk_helpers::circuits::threshold::pk_aggregation::Configs as PkAggregationConfigs;
use e3_zk_helpers::circuits::threshold::pk_generation::computation::Configs as PkGenerationConfigs;
use e3_zk_helpers::circuits::threshold::pk_generation::utils::deterministic_crp_crt_polynomial;
use e3_zk_helpers::circuits::threshold::rlk_generation::RlkGenerationConfigs;
use e3_zk_helpers::circuits::threshold::share_decryption::Configs as ThresholdShareDecryptionConfigs;
use e3_zk_helpers::circuits::threshold::user_data_encryption::Configs as UserDataEncryptionConfigs;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::utils::{bigint_to_field, error_sampler_bound, join_display};
use e3_zk_helpers::Computation;
use num_bigint::{BigInt, BigUint};

const LICENSE: &str = "// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
";

/// Default coefficient count per C2 chunk. Mirrors
/// `crates/zk-prover/src/circuits/aggregation/c2_chunk_config.rs`.
const DEFAULT_C2_CHUNK_SIZE: u32 = 512;
/// Default chunk count per C2 batch. Mirrors the same source.
const DEFAULT_C2_CHUNKS_PER_BATCH: u32 = 4;

/// The section banner used across the committed config modules: a `/**`...`*/`
/// box with the circuit title centered between two dash lines.
fn banner(title: &str) -> String {
    format!(
        "/************************************\n\
         -------------------------------------\n\
         {title}\n\
         -------------------------------------\n\
         ************************************/"
    )
}

/// Prepend the section banner to a body, separating them with a blank line.
fn section(title: &str, body: &str) -> String {
    format!("{}\n\n{}", banner(title), body.trim_end())
}

/// The `use` lines and `pub global {prefix}_*` declarations of one circuit's generated configs.
///
/// Each trBFV circuit's own codegen writes a standalone `configs.nr`: the shared preset globals
/// (`N`, `L`, `QIS`, the CRP) followed by that circuit's constants. The module generator renders
/// the shared globals once and takes only each circuit's prefixed declarations, so a circuit's
/// constants have one definition, in its codegen. Declarations may span lines and contain `;`
/// inside array types (`[Field; L]`), so a declaration ends at the first `;` outside brackets.
struct CircuitGlobals {
    uses: Vec<String>,
    declarations: Vec<(String, String)>,
}

fn circuit_globals(src: &str, prefix: &str, skip: &[&str]) -> CircuitGlobals {
    let mut uses = Vec::new();
    let mut declarations = Vec::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("use ") {
            uses.push(trimmed.trim_end().to_string());
            continue;
        }
        if !trimmed.starts_with("pub global ") {
            continue;
        }
        let mut declaration = String::from(line);
        let mut done = false;
        loop {
            let mut depth = 0i32;
            for c in declaration.chars() {
                match c {
                    '[' | '(' | '{' => depth += 1,
                    ']' | ')' | '}' => depth -= 1,
                    ';' if depth == 0 => {
                        done = true;
                        break;
                    }
                    _ => {}
                }
            }
            if done {
                break;
            }
            match lines.next() {
                Some(next) => {
                    declaration.push('\n');
                    declaration.push_str(next);
                }
                None => break,
            }
        }
        let name = trimmed["pub global ".len()..]
            .split(|c: char| c == ':' || c.is_whitespace())
            .next()
            .unwrap_or_default()
            .to_string();
        if name.starts_with(&format!("{prefix}_")) && !skip.contains(&name.as_str()) {
            declarations.push((name, declaration.trim_end().to_string()));
        }
    }
    CircuitGlobals { uses, declarations }
}

/// Joins circuits' declarations in order, keeping the first definition of a repeated name.
fn render_globals(sources: &[&CircuitGlobals]) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for source in sources {
        for (name, declaration) in &source.declarations {
            if seen.insert(name.clone()) {
                out.push(declaration.clone());
            }
        }
    }
    out.join("\n")
}

fn render_uses(base: &[&str], sources: &[&CircuitGlobals]) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in base
        .iter()
        .map(|l| l.to_string())
        .chain(sources.iter().flat_map(|s| s.uses.clone()))
    {
        if seen.insert(line.clone()) {
            out.push(line);
        }
    }
    out.join("\n")
}

fn join_biguint(vals: &[BigUint]) -> String {
    join_display(vals, ", ")
}

fn centered_str(v: &BigInt) -> String {
    if *v < BigInt::from(0u32) {
        format!("-{}", -v)
    } else {
        v.to_string()
    }
}

fn moduli_str(moduli: &[u64]) -> String {
    join_display(moduli, ", ")
}

fn b_enc_value(preset: BfvPreset) -> Result<BigUint> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    Ok(error_sampler_bound(threshold_params.get_error1_variance()))
}

/// Computes the encryption bound used by the upstream error sampler and smudging calculator.
fn smudging_b_enc_value(preset: BfvPreset) -> Result<BigUint> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    Ok(error_sampler_bound(threshold_params.get_error1_variance()))
}

/// The C2 chunk grid as Noir global expressions, matching `c2_chunk_layout::C2ChunkLayout::compiled`
/// and `c2_chunk_config::c2_chunk_size`.
///
/// At degree 16384 the chunk size depends on the committee (the leaf cost grows with
/// `chunk_size * n_parties`), so it is written as an expression over the active committee's
/// `N_PARTIES`; the committee is chosen when the circuits are built. Other degrees use fixed values.
fn c2_chunking(degree: u32) -> (String, String, String, String) {
    let chunk_size = if degree >= 16384 {
        "if crate::configs::committee::active::N_PARTIES <= 4 {\n    4096\n} else if crate::configs::committee::active::N_PARTIES <= 12 {\n    1024\n} else {\n    512\n}".to_string()
    } else {
        DEFAULT_C2_CHUNK_SIZE.min(degree).to_string()
    };
    (
        chunk_size,
        "N / SHARE_COMPUTATION_CHUNK_SIZE".to_string(),
        format!(
            "if SHARE_COMPUTATION_N_CHUNKS < {DEFAULT_C2_CHUNKS_PER_BATCH} {{\n    SHARE_COMPUTATION_N_CHUNKS\n}} else {{\n    {DEFAULT_C2_CHUNKS_PER_BATCH}\n}}"
        ),
        "SHARE_COMPUTATION_N_CHUNKS / SHARE_COMPUTATION_CHUNKS_PER_BATCH".to_string(),
    )
}

/// Serializes the deterministic CRP the same way `crp_matrix_constant_string` does, but
/// one coefficient per line to match the committed 24k-line `threshold.nr` layout:
///
/// ```text
/// pub global CRP: [Polynomial<N>; L] = [
///     Polynomial::new([
///         <coeff>,
///         <coeff>,
///     ]),
///     ...
/// ];
/// ```
fn crp_block(threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>) -> Result<String> {
    let a = deterministic_crp_crt_polynomial(threshold_params)
        .context("deterministic_crp_crt_polynomial failed")?;

    let limb_strings: Vec<String> = a
        .limbs
        .iter()
        .map(|limb| {
            let coeffs: Vec<String> = limb
                .coefficients()
                .iter()
                .map(|c| format!("        {},", bigint_to_field(c)))
                .collect();
            format!("    Polynomial::new([\n{}\n    ]),", coeffs.join("\n"))
        })
        .collect();

    Ok(format!(
        "pub global CRP: [Polynomial<N>; L] = [\n{}\n];",
        limb_strings.join("\n")
    ))
}

/// Serialize one fixed l-BFV public-randomness vector as circuit rows.
///
/// The outer vector is the l-BFV key-switching slot. Each row contains the CRT limbs of one
/// concrete polynomial. The values must remain identical to the `CommonRandomPolyVec` used by the
/// runtime l-BFV key path.
fn lbfv_crt_rows(
    threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    seed: [u8; 32],
) -> Result<Vec<CrtPolynomial>> {
    fhe::bfv::CommonRandomPolyVec::from_seed(threshold_params, seed)?
        .to_polys()
        .into_iter()
        .map(|poly| {
            let mut row = CrtPolynomial::from_fhe_polynomial(&poly);
            row.reverse();
            row.center(threshold_params.moduli())?;
            Ok(row)
        })
        .collect()
}

fn lbfv_rows_block(
    threshold_params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    seed: [u8; 32],
) -> Result<String> {
    let rows = lbfv_crt_rows(threshold_params, seed)?
        .into_iter()
        .map(|row| {
            let limbs = row
                .limbs
                .iter()
                .map(|limb| {
                    let coefficients = limb
                        .coefficients()
                        .iter()
                        .map(|coefficient| format!("        {},", bigint_to_field(coefficient)))
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("    Polynomial::new([\n{}\n    ]),", coefficients)
                })
                .collect::<Vec<_>>()
                .join("\n");

            Ok(format!("[\n{}\n]", limbs))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(format!("[\n{}\n]", rows.join(",\n")))
}

fn render_lbfv(preset: BfvPreset) -> Result<Option<(String, String, String)>> {
    let (Some(crs_seed), Some(urs_seed)) = (lbfv_crs_seed(preset), lbfv_urs_seed(preset)) else {
        return Ok(None);
    };

    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    let crs_rows = lbfv_rows_block(&threshold_params, crs_seed)?;
    let urs_rows = lbfv_rows_block(&threshold_params, urs_seed)?;
    // `lbfv_pk_aggregation` uses these instead of hashing the fixed CRS row in-circuit.
    let pk_bit = PkAggregationConfigs::compute(preset, &())
        .with_context(|| format!("PkAggregationConfigs::compute({preset:?}) failed"))?
        .bits
        .pk_bit;
    let crs_row_commitments = lbfv_crt_rows(&threshold_params, crs_seed)?
        .iter()
        .map(|row| compute_pk_aggregation_pk1_commitment(row, pk_bit).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let slug = preset.noir_config_module();
    let header = format!(
        "{LICENSE}\nuse crate::math::polynomial::Polynomial;\nuse super::super::threshold::{{GADGET_DIM, L, N}};\n"
    );
    let crs = format!(
        "{header}\npub global LBFV_CRS_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = {crs_rows};\n"
    );
    let urs = format!(
        "{header}\npub global LBFV_URS_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = {urs_rows};\n"
    );
    let module = format!(
        "{LICENSE}\nuse super::threshold::GADGET_DIM;\n\npub mod crs;\npub mod urs;\n\npub use crate::configs::{slug}::lbfv::crs::LBFV_CRS_GADGET_ROWS;\npub use crate::configs::{slug}::lbfv::urs::LBFV_URS_GADGET_ROWS;\n\n/// `commit(LBFV_CRS_GADGET_ROWS[row])` under `DS_PK_AGGREGATION`, the `pk1` half of C5's output.\npub global LBFV_CRS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [{crs_row_commitments}];\n"
    );

    Ok(Some((module, crs, urs)))
}

fn render_threshold(preset: BfvPreset) -> Result<String> {
    let committee = CiphernodesCommitteeSize::Minimum.values();

    let pkgen = PkGenerationConfigs::compute(preset, &committee)
        .context("PkGenerationConfigs::compute failed")?;
    let lbfv_enabled = lbfv_crs_seed(preset).is_some() && lbfv_urs_seed(preset).is_some();
    let rlkgen = lbfv_enabled
        .then(|| RlkGenerationConfigs::compute(preset, &committee))
        .transpose()
        .context("RlkGenerationConfigs::compute failed")?;
    let dsa = DsaConfigs::compute(preset, &()).context("DsaConfigs::compute failed")?;
    let udec = UserDataEncryptionConfigs::compute(preset, &())
        .context("UserDataEncryptionConfigs::compute failed")?;
    let pkagg = PkAggregationConfigs::compute(preset, &())
        .context("PkAggregationConfigs::compute failed")?;
    let tsd = ThresholdShareDecryptionConfigs::compute(preset, &())
        .context("ThresholdShareDecryptionConfigs::compute failed")?;
    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    let crp = crp_block(&threshold_params)?;
    let _ = b_enc_value(preset)?;

    // trBFV circuits: each circuit's constants come from its own codegen.
    use e3_zk_helpers::circuits::threshold as th;
    let pkgen_globals = circuit_globals(
        &th::pk_generation::generate_configs(preset, &pkgen)
            .context("pk_generation codegen failed")?,
        "PK_GENERATION",
        &[],
    );
    let pkagg_globals = circuit_globals(
        &th::pk_aggregation::generate_configs(preset, &pkagg),
        "PK_AGGREGATION",
        &[],
    );
    let udec_globals = circuit_globals(
        &th::user_data_encryption::generate_configs(preset, &udec),
        "USER_DATA_ENCRYPTION",
        &[],
    );
    let tsd_globals = circuit_globals(
        &th::share_decryption::generate_configs(preset, &tsd),
        "THRESHOLD_SHARE_DECRYPTION",
        &[],
    );
    let dsa_globals = circuit_globals(
        &th::decrypted_shares_aggregation::generate_configs(preset, &dsa),
        "DECRYPTED_SHARES_AGGREGATION",
        &[],
    );
    // l-BFV path variants with their own prefixes: the chunked ct0/ct1 pipeline and the wide C7.
    let udec_chunked = th::user_data_encryption_chunked::Configs::compute(preset, &())
        .context("chunked user_data_encryption Configs::compute failed")?;
    let udec_chunked_globals = circuit_globals(
        &th::user_data_encryption_chunked::generate_configs(preset, &udec_chunked),
        "USER_DATA_ENCRYPTION_CHUNKED",
        // The pre-merge whole-witness ct0/ct1 config types; only the chunk configs are used.
        &[
            "USER_DATA_ENCRYPTION_CHUNKED_CT0_CONFIGS",
            "USER_DATA_ENCRYPTION_CHUNKED_CT1_CONFIGS",
        ],
    );
    let lbfv_r_bounds = th::pk_generation::lbfv_limb_quotient_bounds(
        preset,
        &pkgen.bounds.sk_bound,
        &pkgen.bounds.eek_bound,
    )
    .context("lbfv_limb_quotient_bounds failed")?;
    let bit_of = |bounds: &[BigUint]| {
        bounds
            .iter()
            .map(|b| b.bits() as u32 + 1)
            .max()
            .unwrap_or(1)
    };

    let slug = preset.noir_config_module();

    let uses = render_uses(
        &[
            "use crate::core::threshold::rlk_aggregation::Configs as RlkAggregationConfigs;",
            "use crate::core::threshold::rlk_generation::Configs as RlkGenerationConfigs;",
            "use crate::math::polynomial::Polynomial;",
        ],
        &[
            &pkgen_globals,
            &pkagg_globals,
            &udec_globals,
            &udec_chunked_globals,
            &tsd_globals,
            &dsa_globals,
        ],
    );
    let header = format!(
        "{LICENSE}
{uses}

// Global configs for threshold {slug} preset
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};
pub global Q_INVERSE_MOD_T: Field = {};
pub global PARAMS_SEARCH_N: Field = {};
pub global PARAMS_SEARCH_Z: Field = {};
pub global PARAMS_LAMBDA: u32 = {};
pub global PARAMS_TWO_POW_LAMBDA_PLUS_ONE: Field = {};
pub global PARAMS_MULT_DEPTH: u32 = {};
pub global PARAMS_SMUDGING_B_ENC: Field = {};

{crp}
\n",
        pkgen.n,
        pkgen.l,
        moduli_str(&pkgen.moduli),
        dsa.plaintext_modulus,
        dsa.q_mod_t,
        centered_str(&dsa.q_mod_t_centered),
        dsa.q_inverse_mod_t,
        preset
            .search_defaults()
            .context("search_defaults() missing for threshold preset")?
            .n,
        preset
            .search_defaults()
            .context("search_defaults() missing for threshold preset")?
            .z,
        preset
            .lambda()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?,
        1u128
            << (preset
                .lambda()
                .map_err(|e| anyhow::anyhow!(e.to_string()))?
                + 1),
        preset
            .search_defaults()
            .context("search_defaults() missing for threshold preset")?
            .mult_depth,
        smudging_b_enc_value(preset)?,
    );

    let pkgen_section = section(
        "pk_generation (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)",
        &render_globals(&[&pkgen_globals]),
    );
    // The l-BFV public-key limb checks the reduced relation for one limb, so its quotient `r`
    // has `N` coefficients and its own per-limb bound.
    let lbfv_pk_section = section(
        "lbfv_pk_generation_limb (l-BFV PUBLIC KEY LIMB)",
        &format!(
            "pub global LBFV_PK_GENERATION_BIT_R: u32 = {};
pub global LBFV_PK_GENERATION_R_BOUNDS: [Field; L] = [{}];",
            bit_of(&lbfv_r_bounds),
            join_biguint(&lbfv_r_bounds),
        ),
    );

    let gadget_rows = std::iter::repeat("CRP")
        .take(pkgen.l as usize)
        .collect::<Vec<_>>()
        .join(", ");
    let lbfv_rows = if lbfv_enabled {
        "pub use super::lbfv::{\n    LBFV_CRS_GADGET_ROWS, LBFV_CRS_ROW_COMMITMENTS, LBFV_URS_GADGET_ROWS,\n};"
            .to_string()
    } else {
        let rows = std::iter::repeat("CRP")
            .take(pkgen.l as usize)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "pub global LBFV_CRS_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = [{rows}];\npub global LBFV_URS_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = [{rows}];\n// No l-BFV rows on this preset; `lbfv_pk_aggregation` is never built for it.\npub global LBFV_CRS_ROW_COMMITMENTS: [Field; GADGET_DIM] = [{}];",
            std::iter::repeat("0")
                .take(pkgen.l as usize)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let c1_rows_comment = if lbfv_enabled {
        "// C1 uses the repeated CRP path. The dedicated l-BFV public-key circuit selects rows below."
    } else {
        "// C1 uses the repeated CRP path because this preset does not enable l-BFV."
    };
    let rlk_generation_constants = if let Some(rlkgen) = rlkgen {
        format!(
            "pub global RLK_GENERATION_BIT_R: u32 = {};
pub global RLK_GENERATION_BIT_SK: u32 = {};
pub global RLK_GENERATION_BIT_E0: u32 = {};
pub global RLK_GENERATION_BIT_E2: u32 = {};
pub global RLK_GENERATION_BIT_RD0: u32 = {};
pub global RLK_GENERATION_BIT_RD2: u32 = {};
pub global RLK_GENERATION_BIT_D: u32 = {};

pub global RLK_GENERATION_R_BOUND: Field = {};
pub global RLK_GENERATION_SK_BOUND: Field = {};
pub global RLK_GENERATION_E0_BOUND: Field = {};
pub global RLK_GENERATION_E2_BOUND: Field = {};
pub global RLK_GENERATION_RD0_BOUNDS: [Field; L] = [{}];
pub global RLK_GENERATION_RD2_BOUNDS: [Field; L] = [{}];",
            rlkgen.bits.r_bit,
            rlkgen.bits.sk_bit,
            rlkgen.bits.e0_bit,
            rlkgen.bits.e2_bit,
            rlkgen.bits.rd0_bit,
            rlkgen.bits.rd2_bit,
            rlkgen.bits.d_bit,
            rlkgen.bounds.r_bound,
            rlkgen.bounds.sk_bound,
            rlkgen.bounds.e0_bound,
            rlkgen.bounds.e2_bound,
            join_biguint(&rlkgen.bounds.rd0_bounds),
            join_biguint(&rlkgen.bounds.rd2_bounds),
        )
    } else {
        "pub global RLK_GENERATION_BIT_R: u32 = PK_GENERATION_BIT_SK;
pub global RLK_GENERATION_BIT_SK: u32 = PK_GENERATION_BIT_SK;
pub global RLK_GENERATION_BIT_E0: u32 = PK_GENERATION_BIT_EEK;
pub global RLK_GENERATION_BIT_E2: u32 = PK_GENERATION_BIT_EEK;
pub global RLK_GENERATION_BIT_RD0: u32 = LBFV_PK_GENERATION_BIT_R;
pub global RLK_GENERATION_BIT_RD2: u32 = LBFV_PK_GENERATION_BIT_R;
pub global RLK_GENERATION_BIT_D: u32 = PK_GENERATION_BIT_PK;

pub global RLK_GENERATION_R_BOUND: Field = PK_GENERATION_SK_BOUND;
pub global RLK_GENERATION_SK_BOUND: Field = PK_GENERATION_SK_BOUND;
pub global RLK_GENERATION_E0_BOUND: Field = PK_GENERATION_EEK_BOUND;
pub global RLK_GENERATION_E2_BOUND: Field = PK_GENERATION_EEK_BOUND;
pub global RLK_GENERATION_RD0_BOUNDS: [Field; L] = LBFV_PK_GENERATION_R_BOUNDS;
pub global RLK_GENERATION_RD2_BOUNDS: [Field; L] = LBFV_PK_GENERATION_R_BOUNDS;"
            .to_string()
    };
    let rlk_section = section(
        "l-BFV relinearization key circuits",
        &format!(
            "pub global GADGET_DIM: u32 = L;
{c1_rows_comment}
pub global CRP_GADGET_ROWS: [[Polynomial<N>; L]; GADGET_DIM] = [{}];
// l-BFV rows are fixed public randomness for the supported preset. Unsupported presets retain
// placeholder declarations because their RLK path is disabled.
{lbfv_rows}

{rlk_generation_constants}

pub global RLK_GENERATION_CONFIGS: RlkGenerationConfigs<N, L> = RlkGenerationConfigs::new(
    QIS,
    RLK_GENERATION_R_BOUND,
    RLK_GENERATION_SK_BOUND,
    RLK_GENERATION_E0_BOUND,
    RLK_GENERATION_E2_BOUND,
    RLK_GENERATION_RD0_BOUNDS,
    RLK_GENERATION_RD2_BOUNDS,
);

pub global RLK_AGGREGATION_BIT_D: u32 = PK_GENERATION_BIT_PK;
pub global RLK_AGGREGATION_CONFIGS: RlkAggregationConfigs<L> = RlkAggregationConfigs::new(QIS);",
            gadget_rows,
        ),
    );

    let pkagg_section = section(
        "pk_aggregation (CIRCUIT 5)",
        &render_globals(&[&pkagg_globals]),
    );
    let udec_section = section(
        "user_data_encryption, user_data_encryption_ct0, user_data_encryption_ct1 (trBFV)",
        &render_globals(&[&udec_globals]),
    );
    // Chunk grid of the l-BFV ct0/ct1 pipeline: not a cryptographic parameter, just how the
    // range-check and evaluation work is split across browser-sized circuits.
    let udec_chunked_section = section(
        "user_data_encryption chunked pipeline (l-BFV)",
        &render_globals(&[&udec_chunked_globals]),
    );
    let tsd_section = section(
        "share_decryption (CIRCUIT 6 - THRESHOLD BFV SHARE DECRYPTION)",
        &render_globals(&[&tsd_globals]),
    );
    let dsa_section = section(
        "decrypted_shares_aggregation (CIRCUIT 7)",
        &render_globals(&[&dsa_globals]),
    );

    Ok(format!(
        "{header}{pkgen_section}\n\n{lbfv_pk_section}\n\n{rlk_section}\n\n{pkagg_section}\n\n{udec_section}\n\n{udec_chunked_section}\n\n{tsd_section}\n\n{dsa_section}\n"
    ))
}

fn render_dkg(preset: BfvPreset) -> Result<String> {
    let committee = CiphernodesCommitteeSize::Minimum.values();

    let dkg_pk = DkgPkConfigs::compute(preset, &()).context("DkgPkConfigs::compute failed")?;
    let dkg_pk_bits = DkgPkBits::compute(preset, &()).context("DkgPkBits::compute failed")?;
    let sd = preset
        .search_defaults()
        .context("search_defaults() failed")?;
    let se_sample = ShareEncryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
        sd.z,
    )
    .context("ShareEncryptionCircuitData::generate_sample failed")?;
    let sh_enc = ShareEncryptionConfigs::compute(preset, &se_sample)
        .context("ShareEncryptionConfigs::compute failed")?;
    let (_, dkg_params) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;

    let cfg_dir = preset.config_dir();
    let slug = preset.noir_config_module();
    let dkg_plaintext = dkg_params.plaintext();
    let (chunk_size, n_chunks, chunks_per_batch, n_batches) = c2_chunking(dkg_pk.n as u32);
    let parity_flag = slug.to_uppercase();

    // trBFV DKG circuits: each circuit's constants come from its own codegen.
    use e3_zk_helpers::circuits::dkg as dk;
    let pk_globals = circuit_globals(&dk::pk::generate_configs(&dkg_pk, &dkg_pk_bits), "PK", &[]);
    let sc_sample = dk::share_computation::ShareComputationCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .context("ShareComputationCircuitData::generate_sample failed")?;
    let sc_bounds = dk::share_computation::Bounds::compute(preset, &sc_sample)
        .context("share_computation Bounds::compute failed")?;
    let sc_bits = dk::share_computation::Bits::compute(preset, &sc_bounds)
        .context("share_computation Bits::compute failed")?;
    let sc_globals = circuit_globals(
        &dk::share_computation::codegen::generate_configs(
            preset,
            &sc_bits,
            committee.n,
            committee.threshold,
            // Only feeds the two chunk globals excluded below; the chunk-grid section owns them.
            e3_zk_helpers::circuits::dkg::share_computation::c2_chunk_size(dkg_pk.n, committee.n),
        )
        .context("share_computation codegen failed")?,
        "SHARE_COMPUTATION",
        // Owned by the chunk-grid section below.
        &["SHARE_COMPUTATION_CHUNK_SIZE", "SHARE_COMPUTATION_N_CHUNKS"],
    );
    let sh_enc_globals = circuit_globals(
        &dk::share_encryption::codegen::generate_configs(preset, &sh_enc),
        "SHARE_ENCRYPTION",
        &[],
    );
    let sd_sample = dk::share_decryption::ShareDecryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )
    .context("ShareDecryptionCircuitData::generate_sample failed")?;
    let sh_dec = dk::share_decryption::Configs::compute(preset, &sd_sample)
        .context("share_decryption Configs::compute failed")?;
    let sh_dec_globals = circuit_globals(
        &dk::share_decryption::codegen::generate_configs(preset, &sh_dec),
        "SHARE_DECRYPTION",
        &[],
    );
    let uses = render_uses(
        &["use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;"],
        &[&pk_globals, &sc_globals, &sh_enc_globals, &sh_dec_globals],
    );

    let header = format!(
        "{LICENSE}
pub use crate::configs::{slug}::threshold::{{L as L_THRESHOLD, QIS as QIS_THRESHOLD}};
{uses}

// Global configs for DKG {slug} preset
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};
pub global DKG_ERROR_BOUND: Field = {};

// Parity matrix is sized for the active committee and the {cfg_dir} threshold QIS;
// see `committee/{{name}}/parity_{slug}.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_{parity_flag} as PARITY_MATRIX;
\n",
        dkg_pk.n,
        dkg_pk.l,
        moduli_str(&sh_enc.moduli),
        dkg_plaintext,
        sh_enc.q_mod_t,
        centered_str(&sh_enc.q_mod_t_centered),
        dkg_params.variance() * 2,
    );

    let pk_section = section("pk (CIRCUIT 0)", &render_globals(&[&pk_globals]));
    // C2 chunk grid for the l-BFV path's chunked C2; the trBFV C2 is one proof.
    let chunking_section = section(
        "share_computation chunk grid (l-BFV)",
        &format!(
            "pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = {chunk_size};
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = {n_chunks};
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = {chunks_per_batch};
pub global SHARE_COMPUTATION_N_BATCHES: u32 = {n_batches};"
        ),
    );
    let sc_section = section(
        "share_computation_sk (CIRCUIT 2a)\nshare_computation_e_sm (CIRCUIT 2b)",
        &render_globals(&[&sc_globals]),
    );
    let sh_enc_section = section(
        "share_encryption_sk (CIRCUIT 3a)\nshare_encryption_e_sm (CIRCUIT 3b)",
        &render_globals(&[&sh_enc_globals]),
    );
    let sh_dec_section = section(
        "share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)\nshare_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)",
        &render_globals(&[&sh_dec_globals]),
    );

    Ok(format!(
        "{header}{pk_section}\n\n{chunking_section}\n\n{sc_section}\n\n{sh_enc_section}\n\n{sh_dec_section}\n"
    ))
}

fn render_mod(preset: BfvPreset) -> String {
    let lbfv = if lbfv_crs_seed(preset).is_some() && lbfv_urs_seed(preset).is_some() {
        "pub mod lbfv;\n"
    } else {
        ""
    };
    format!("{LICENSE}\npub mod dkg;\n{lbfv}pub mod threshold;\n")
}

fn main() -> Result<()> {
    let args = Args::parse();
    let preset = BfvPreset::from_name(&args.preset)
        .with_context(|| format!("unknown preset: {:?}", args.preset))?;
    if preset.metadata().parameter_type != ParameterType::THRESHOLD {
        anyhow::bail!(
            "preset {:?} is a DKG-only preset; pass the threshold variant (for example, INSECURE_THRESHOLD)",
            preset
        );
    }

    let root = output_root(&args)?;
    let dir = root.join(preset.noir_config_module());
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let threshold = render_threshold(preset)?;
    let dkg = render_dkg(preset)?;
    let lbfv = render_lbfv(preset)?;

    let tp = dir.join("threshold.nr");
    let dp = dir.join("dkg.nr");
    let mp = dir.join("mod.nr");

    std::fs::write(&tp, threshold).with_context(|| format!("writing {}", tp.display()))?;
    std::fs::write(&dp, dkg).with_context(|| format!("writing {}", dp.display()))?;
    std::fs::write(&mp, render_mod(preset)).with_context(|| format!("writing {}", mp.display()))?;

    if let Some((module, crs, urs)) = lbfv {
        let lbfv_dir = dir.join("lbfv");
        std::fs::create_dir_all(&lbfv_dir)
            .with_context(|| format!("creating {}", lbfv_dir.display()))?;
        let lmp = lbfv_dir.join("mod.nr");
        let lcp = lbfv_dir.join("crs.nr");
        let lup = lbfv_dir.join("urs.nr");
        std::fs::write(&lmp, module).with_context(|| format!("writing {}", lmp.display()))?;
        std::fs::write(&lcp, crs).with_context(|| format!("writing {}", lcp.display()))?;
        std::fs::write(&lup, urs).with_context(|| format!("writing {}", lup.display()))?;
    }

    println!("{}", tp.display());
    println!("{}", dp.display());
    println!("{}", mp.display());

    Ok(())
}

#[derive(Debug, Parser)]
#[command(
    name = "generate_config_modules",
    about = "Regenerate a preset's BFV/CRT config module (threshold.nr / dkg.nr / mod.nr)."
)]
struct Args {
    /// Preset name (for example, `INSECURE_THRESHOLD`, `SECURE_THRESHOLD_8192`, or `SECURE_THRESHOLD_16384`).
    #[arg(long)]
    preset: String,

    /// Root directory containing the per-preset modules. Defaults to
    /// `<repo>/circuits/lib/src/configs` relative to the workspace.
    #[arg(long)]
    output_root: Option<PathBuf>,
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .context("could not locate workspace root from CARGO_MANIFEST_DIR")
}

fn output_root(args: &Args) -> Result<PathBuf> {
    if let Some(p) = &args.output_root {
        return Ok(p.clone());
    }
    Ok(workspace_root()?
        .join("circuits")
        .join("lib")
        .join("src")
        .join("configs"))
}
