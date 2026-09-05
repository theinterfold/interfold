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
//!         --preset INSECURE_THRESHOLD_512 \
//!         [--output-root <path-to-circuits/lib/src/configs>]
//!
//! A preset maps to a distinct Noir module (`insecure`, `secure_8192`, or `secure_16384`); the
//! generator writes into `<output-root>/<preset-module>/`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use e3_fhe_params::{build_pair_for_preset, BfvPreset, ParameterType};
use e3_zk_helpers::ciphernodes_committee::CiphernodesCommitteeSize;
use e3_zk_helpers::circuits::dkg::pk::computation::{Bits as DkgPkBits, Configs as DkgPkConfigs};
use e3_zk_helpers::circuits::dkg::share_encryption::circuit::ShareEncryptionCircuitData;
use e3_zk_helpers::circuits::dkg::share_encryption::Configs as ShareEncryptionConfigs;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::computation::Configs as DsaConfigs;
use e3_zk_helpers::circuits::threshold::pk_aggregation::Configs as PkAggregationConfigs;
use e3_zk_helpers::circuits::threshold::pk_generation::computation::Configs as PkGenerationConfigs;
use e3_zk_helpers::circuits::threshold::pk_generation::utils::deterministic_crp_crt_polynomial;
use e3_zk_helpers::circuits::threshold::share_decryption::Configs as ThresholdShareDecryptionConfigs;
use e3_zk_helpers::circuits::threshold::user_data_encryption::Configs as UserDataEncryptionConfigs;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::utils::{bigint_to_field, ceil_sqrt, compute_msg_bit, join_display};
use e3_zk_helpers::Computation;
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;

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

/// Computes the deterministic error bound `B_enc = ceil(sqrt(3 * error1_variance))`
/// for the threshold parameter set, matching `pk_generation` codegen.
fn b_enc_value(preset: BfvPreset) -> Result<BigUint> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    Ok(ceil_sqrt(
        &(BigUint::from(3u32) * threshold_params.get_error1_variance()),
    ))
}

/// Computes the sampler-aligned encryption bound used by the smudging calculator.
fn smudging_b_enc_value(preset: BfvPreset) -> Result<BigUint> {
    let (threshold_params, _) = build_pair_for_preset(preset)
        .with_context(|| format!("build_pair_for_preset({preset:?}) failed"))?;
    let variance = threshold_params.get_error1_variance();
    if variance < &BigUint::from(16u32) {
        Ok(BigUint::from(2u64 * variance.to_u64().unwrap()))
    } else {
        Ok((BigUint::from(3u32) * variance).sqrt())
    }
}

/// The C2 chunking for a polynomial degree, matching `c2_chunk_layout::C2ChunkLayout::compiled`.
fn c2_chunking(degree: u32) -> (u32, u32, u32, u32) {
    let chunk_size = DEFAULT_C2_CHUNK_SIZE.min(degree);
    let n_chunks = degree / chunk_size;
    let chunks_per_batch = if degree <= DEFAULT_C2_CHUNK_SIZE {
        1
    } else {
        DEFAULT_C2_CHUNKS_PER_BATCH
    };
    let n_batches = n_chunks / chunks_per_batch;
    (chunk_size, n_chunks, chunks_per_batch, n_batches)
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

fn render_threshold(preset: BfvPreset) -> Result<String> {
    let committee = CiphernodesCommitteeSize::Minimum.values();

    let pkgen = PkGenerationConfigs::compute(preset, &committee)
        .context("PkGenerationConfigs::compute failed")?;
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
    let b_enc = b_enc_value(preset)?;

    let slug = preset.noir_config_module();
    let esm_prefix = match preset {
        BfvPreset::InsecureThreshold512 => "INSECURE",
        BfvPreset::SecureThreshold8192 => "SECURE_8192",
        BfvPreset::SecureThreshold16384 => "SECURE_16384",
        _ => unreachable!("config generation requires a threshold preset"),
    };

    let header = format!(
        "{LICENSE}
use crate::core::threshold::decrypted_shares_aggregation::Configs as DecryptedSharesAggregationConfigs;
use crate::core::threshold::pk_aggregation::Configs as PkAggregationConfigs;
use crate::core::threshold::pk_generation::Configs as PkGenerationConfigs;
use crate::core::threshold::share_decryption::Configs as ShareDecryptionConfigs;
use crate::core::threshold::user_data_encryption_ct0::Configs as UserDataEncryptionCt0Configs;
use crate::core::threshold::user_data_encryption_ct1::Configs as UserDataEncryptionCt1Configs;
use crate::math::polynomial::Polynomial;

pub use crate::configs::committee::active::{{
    {esm_prefix}_E_SM_BIT as PK_GENERATION_BIT_E_SM, {esm_prefix}_E_SM_BOUND as PK_GENERATION_E_SM_BOUND,
}};

// Global configs for threshold {slug} preset
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_MOD_T: Field = {};
pub global Q_MOD_T_CENTERED: Field = {};
pub global Q_INVERSE_MOD_T: Field = {};
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
            .z,
        preset
            .lambda()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .value(),
        1u128 << (preset
            .lambda()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .value()
            + 1),
        preset
            .search_defaults()
            .context("search_defaults() missing for threshold preset")?
            .mult_depth,
        smudging_b_enc_value(preset)?,
    );

    let pkgen_section = section(
        "pk_generation (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)",
        &format!(
            "pub global PK_GENERATION_BIT_EEK: u32 = {};
pub global PK_GENERATION_BIT_SK: u32 = {};
pub global PK_GENERATION_BIT_R1: u32 = {};
pub global PK_GENERATION_BIT_R2: u32 = {};
pub global PK_GENERATION_BIT_PK: u32 = {};

pub global PK_GENERATION_EEK_BOUND: Field = {};
pub global PK_GENERATION_SK_BOUND: Field = {};
pub global PK_GENERATION_R1_BOUNDS: [Field; L] = [{}];
pub global PK_GENERATION_R2_BOUNDS: [Field; L] = [{}];

pub global PK_GENERATION_B_ENC: Field = {};

pub global PK_GENERATION_CONFIGS: PkGenerationConfigs<N, L> = PkGenerationConfigs::new(
    QIS,
    PK_GENERATION_EEK_BOUND,
    PK_GENERATION_SK_BOUND,
    PK_GENERATION_E_SM_BOUND,
    PK_GENERATION_R1_BOUNDS,
    PK_GENERATION_R2_BOUNDS,
);",
            pkgen.bits.eek_bit,
            pkgen.bits.sk_bit,
            pkgen.bits.r1_bit,
            pkgen.bits.r2_bit,
            pkgen.bits.pk_bit,
            pkgen.bounds.eek_bound,
            pkgen.bounds.sk_bound,
            join_biguint(&pkgen.bounds.r1_bounds),
            join_biguint(&pkgen.bounds.r2_bounds),
            b_enc,
        ),
    );

    let pkagg_section = section(
        "pk_aggregation (CIRCUIT 5)",
        &format!(
            "pub global PK_AGGREGATION_BIT_PK: u32 = {};
\npub global PK_AGGREGATION_CONFIGS: PkAggregationConfigs<L> = PkAggregationConfigs::new(QIS);",
            pkagg.bits.pk_bit,
        ),
    );

    let udec_section = section(
        "user_data_encryption (USED FOR DATA ENCRYPTION)",
        &format!(
            "pub global USER_DATA_ENCRYPTION_BIT_PK: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_CT: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_U: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_E0: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_E1: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_K: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_R1: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_R2: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_P1: u32 = {};
pub global USER_DATA_ENCRYPTION_BIT_P2: u32 = {};

pub global USER_DATA_ENCRYPTION_K0IS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_PK_BOUNDS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_E0_BOUND: Field = {};
pub global USER_DATA_ENCRYPTION_E1_BOUND: Field = {};
pub global USER_DATA_ENCRYPTION_U_BOUND: Field = {};
pub global USER_DATA_ENCRYPTION_K1_LOW_BOUND: Field = {};
pub global USER_DATA_ENCRYPTION_K1_UP_BOUND: Field = {};
pub global USER_DATA_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_R2_BOUNDS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_P1_BOUNDS: [Field; L] = [{}];
pub global USER_DATA_ENCRYPTION_P2_BOUNDS: [Field; L] = [{}];",
            udec.bits.pk_bit,
            udec.bits.ct_bit,
            udec.bits.u_bit,
            udec.bits.e0_bit,
            udec.bits.e1_bit,
            udec.bits.k_bit,
            udec.bits.r1_bit,
            udec.bits.r2_bit,
            udec.bits.p1_bit,
            udec.bits.p2_bit,
            join_display(&udec.k0is, ", "),
            join_biguint(&udec.bounds.pk_bounds),
            udec.bounds.e0_bound,
            udec.bounds.e1_bound,
            udec.bounds.u_bound,
            udec.bounds.k1_low_bound,
            udec.bounds.k1_up_bound,
            join_biguint(&udec.bounds.r1_low_bounds),
            join_biguint(&udec.bounds.r1_up_bounds),
            join_biguint(&udec.bounds.r2_bounds),
            join_biguint(&udec.bounds.p1_bounds),
            join_biguint(&udec.bounds.p2_bounds),
        ),
    );

    let udec_ct0_section = section(
        "user_data_encryption_ct0 (CIRCUIT A - CT0 ENCRYPTION)",
        "pub global USER_DATA_ENCRYPTION_CT0_CONFIGS: UserDataEncryptionCt0Configs<N, L> = UserDataEncryptionCt0Configs::new(
    QIS,
    USER_DATA_ENCRYPTION_K0IS,
    USER_DATA_ENCRYPTION_E0_BOUND,
    USER_DATA_ENCRYPTION_U_BOUND,
    USER_DATA_ENCRYPTION_R1_LOW_BOUNDS,
    USER_DATA_ENCRYPTION_R1_UP_BOUNDS,
    USER_DATA_ENCRYPTION_R2_BOUNDS,
    USER_DATA_ENCRYPTION_K1_LOW_BOUND,
    USER_DATA_ENCRYPTION_K1_UP_BOUND,
);",
    );

    let udec_ct1_section = section(
        "user_data_encryption_ct1 (CIRCUIT B - CT1 ENCRYPTION)",
        "pub global USER_DATA_ENCRYPTION_CT1_CONFIGS: UserDataEncryptionCt1Configs<N, L> = UserDataEncryptionCt1Configs::new(
    QIS,
    USER_DATA_ENCRYPTION_E1_BOUND,
    USER_DATA_ENCRYPTION_U_BOUND,
    USER_DATA_ENCRYPTION_P1_BOUNDS,
    USER_DATA_ENCRYPTION_P2_BOUNDS,
);",
    );

    let tsd_section = section(
        "share_decryption (CIRCUIT 6 - THRESHOLD BFV SHARE DECRYPTION)",
        &format!(
            "pub global THRESHOLD_SHARE_DECRYPTION_BIT_CT: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_SK: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_E_SM: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_R1: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_R2: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_D: u32 = {};
pub global THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE: u32 = {};

pub global THRESHOLD_SHARE_DECRYPTION_R1_BOUNDS: [Field; L] = [{}];
pub global THRESHOLD_SHARE_DECRYPTION_R2_BOUNDS: [Field; L] = [{}];

pub global THRESHOLD_SHARE_DECRYPTION_CONFIGS: ShareDecryptionConfigs<L> = ShareDecryptionConfigs::new(
    QIS,
    THRESHOLD_SHARE_DECRYPTION_R1_BOUNDS,
    THRESHOLD_SHARE_DECRYPTION_R2_BOUNDS,
);",
            tsd.bits.ct_bit,
            tsd.bits.sk_bit,
            tsd.bits.e_sm_bit,
            tsd.bits.r1_bit,
            tsd.bits.r2_bit,
            tsd.bits.d_bit,
            tsd.bits.d_native_bit,
            join_biguint(&tsd.bounds.r1_bounds),
            join_biguint(&tsd.bounds.r2_bounds),
        ),
    );

    let dsa_section = section(
        "decrypted_shares_aggregation (CIRCUIT 7)",
        &format!(
            "pub global DECRYPTED_SHARES_AGGREGATION_BIT_NOISE: u32 = {};
pub global DECRYPTED_SHARES_AGGREGATION_BIT_D_NATIVE: u32 = {};

pub global DECRYPTED_SHARES_AGGREGATION_CONFIGS: DecryptedSharesAggregationConfigs<L> =
    DecryptedSharesAggregationConfigs::new(QIS, PLAINTEXT_MODULUS, Q_INVERSE_MOD_T);",
            dsa.bits.noise_bit, dsa.bits.d_native_bit,
        ),
    );

    Ok(format!(
        "{header}{pkgen_section}\n\n{pkagg_section}\n\n{udec_section}\n\n{udec_ct0_section}\n\n{udec_ct1_section}\n\n{tsd_section}\n\n{dsa_section}\n"
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
    let msg_bit = compute_msg_bit(&dkg_params);
    let (chunk_size, n_chunks, chunks_per_batch, n_batches) = c2_chunking(dkg_pk.n as u32);
    let parity_flag = slug.to_uppercase();

    let header = format!(
        "{LICENSE}
pub use crate::configs::{slug}::threshold::{{
    L as L_THRESHOLD, PK_GENERATION_BIT_E_SM as SHARE_COMPUTATION_E_SM_BIT_SECRET,
    QIS as QIS_THRESHOLD, THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
}};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

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

    let pk_section = section(
        "pk (CIRCUIT 0)",
        &format!(
            "// pk - bit parameters
pub global PK_BIT_PK: u32 = {};",
            dkg_pk_bits.pk_bit,
        ),
    );

    let sc_sk_section = section(
        "share_computation_sk (CIRCUIT 2a)",
        &format!(
            "pub global SHARE_COMPUTATION_BIT_SHARE: u32 = {};
pub global SHARE_COMPUTATION_SK_BIT_SECRET: u32 = {};
pub global SHARE_COMPUTATION_CHUNK_SIZE: u32 = {};
pub global SHARE_COMPUTATION_N_CHUNKS: u32 = {};
pub global SHARE_COMPUTATION_CHUNKS_PER_BATCH: u32 = {};
pub global SHARE_COMPUTATION_N_BATCHES: u32 = {};

pub global SHARE_COMPUTATION_SK_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);",
            msg_bit, 1u32, chunk_size, n_chunks, chunks_per_batch, n_batches,
        ),
    );

    let sc_esm_section = section(
        "share_computation_e_sm (CIRCUIT 2b)",
        "pub global SHARE_COMPUTATION_E_SM_CONFIGS: ShareComputationConfigs<L_THRESHOLD> =
    ShareComputationConfigs::new(QIS_THRESHOLD);",
    );

    let sh_enc_section = section(
        "share_encryption_sk (CIRCUIT 3a)\nshare_encryption_e_sm (CIRCUIT 3b)",
        &format!(
            "pub global SHARE_ENCRYPTION_BIT_PK: u32 = {};
pub global SHARE_ENCRYPTION_BIT_CT: u32 = {};
pub global SHARE_ENCRYPTION_BIT_U: u32 = {};
pub global SHARE_ENCRYPTION_BIT_E0: u32 = {};
pub global SHARE_ENCRYPTION_BIT_E1: u32 = {};
pub global SHARE_ENCRYPTION_BIT_MSG: u32 = {};
pub global SHARE_ENCRYPTION_BIT_R1: u32 = {};
pub global SHARE_ENCRYPTION_BIT_R2: u32 = {};
pub global SHARE_ENCRYPTION_BIT_P1: u32 = {};
pub global SHARE_ENCRYPTION_BIT_P2: u32 = {};

pub global SHARE_ENCRYPTION_K0IS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_PK_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_E0_BOUND: Field = {};
pub global SHARE_ENCRYPTION_E1_BOUND: Field = {};
pub global SHARE_ENCRYPTION_U_BOUND: Field = {};
pub global SHARE_ENCRYPTION_R1_LOW_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_R1_UP_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_R2_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_P1_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_P2_BOUNDS: [Field; L] = [{}];
pub global SHARE_ENCRYPTION_MSG_BOUND: Field = {};

pub global SHARE_ENCRYPTION_CONFIGS: ShareEncryptionConfigs<L> = ShareEncryptionConfigs::new(
    PLAINTEXT_MODULUS,
    Q_MOD_T,
    QIS,
    SHARE_ENCRYPTION_K0IS,
    SHARE_ENCRYPTION_PK_BOUNDS,
    SHARE_ENCRYPTION_E0_BOUND,
    SHARE_ENCRYPTION_E1_BOUND,
    SHARE_ENCRYPTION_U_BOUND,
    SHARE_ENCRYPTION_R1_LOW_BOUNDS,
    SHARE_ENCRYPTION_R1_UP_BOUNDS,
    SHARE_ENCRYPTION_R2_BOUNDS,
    SHARE_ENCRYPTION_P1_BOUNDS,
    SHARE_ENCRYPTION_P2_BOUNDS,
    SHARE_ENCRYPTION_MSG_BOUND,
);",
            sh_enc.bits.pk_bit,
            sh_enc.bits.ct_bit,
            sh_enc.bits.u_bit,
            sh_enc.bits.e0_bit,
            sh_enc.bits.e1_bit,
            sh_enc.bits.msg_bit,
            sh_enc.bits.r1_bit,
            sh_enc.bits.r2_bit,
            sh_enc.bits.p1_bit,
            sh_enc.bits.p2_bit,
            join_display(&sh_enc.k0is, ", "),
            join_biguint(&sh_enc.bounds.pk_bounds),
            sh_enc.bounds.e0_bound,
            sh_enc.bounds.e1_bound,
            sh_enc.bounds.u_bound,
            join_biguint(&sh_enc.bounds.r1_low_bounds),
            join_biguint(&sh_enc.bounds.r1_up_bounds),
            join_biguint(&sh_enc.bounds.r2_bounds),
            join_biguint(&sh_enc.bounds.p1_bounds),
            join_biguint(&sh_enc.bounds.p2_bounds),
            sh_enc.bounds.msg_bound,
        ),
    );

    let sh_dec_section = section(
        "share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)\nshare_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)",
        &format!(
            "pub global SHARE_DECRYPTION_BIT_MSG: u32 = {};
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).",
            msg_bit,
        ),
    );

    Ok(format!(
        "{header}{pk_section}\n\n{sc_sk_section}\n\n{sc_esm_section}\n\n{sh_enc_section}\n\n{sh_dec_section}\n"
    ))
}

fn render_mod() -> String {
    format!("{LICENSE}\npub mod dkg;\npub mod threshold;\n")
}

fn main() -> Result<()> {
    let args = Args::parse();
    let preset = BfvPreset::from_name(&args.preset)
        .with_context(|| format!("unknown preset: {:?}", args.preset))?;
    if preset.metadata().parameter_type != ParameterType::THRESHOLD {
        anyhow::bail!(
            "preset {:?} is a DKG-only preset; pass the threshold variant (e.g. INSECURE_THRESHOLD_512)",
            preset
        );
    }

    let root = output_root(&args)?;
    let dir = root.join(preset.noir_config_module());
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let threshold = render_threshold(preset)?;
    let dkg = render_dkg(preset)?;

    let tp = dir.join("threshold.nr");
    let dp = dir.join("dkg.nr");
    let mp = dir.join("mod.nr");

    std::fs::write(&tp, threshold).with_context(|| format!("writing {}", tp.display()))?;
    std::fs::write(&dp, dkg).with_context(|| format!("writing {}", dp.display()))?;
    std::fs::write(&mp, render_mod()).with_context(|| format!("writing {}", mp.display()))?;

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
    /// Preset name (e.g. `INSECURE_THRESHOLD_512`, `SECURE_THRESHOLD_8192`, `SECURE_THRESHOLD_16384`).
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
