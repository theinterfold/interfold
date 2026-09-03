// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the Noir config tier for the WIDE DKG transport preset
//! (`BfvPreset::InsecureDkgWide512`): `circuits/lib/src/configs/insecure_wide/{mod,dkg}.nr`.
//!
//! The wide preset shares the insecure-512 THRESHOLD side (its `threshold`
//! module is a re-export of `configs::insecure::threshold`, so C1/C5/C6/C7
//! and the C2a/C2b parity constants are byte-identical) and differs only
//! on the DKG side: `Q = 2 × 52-bit`, `t = 0x3fffffff6401` — the shape the
//! C0 (`pk`), C3 (`share_encryption`) and C4 (`share_decryption`) circuits
//! compile against. `pnpm build:circuits --preset insecure-dkg-wide-512`
//! points `configs::default` at this tier.
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_wide_dkg_configs`

use e3_fhe_params::BfvPreset;
use e3_zk_helpers::ciphernodes_committee::CiphernodesCommitteeSize;
use e3_zk_helpers::circuits::computation::{CircuitComputation, Computation};
use e3_zk_helpers::circuits::dkg::pk::{generate_configs as pk_configs, Bits as PkBits, PkCircuit};
use e3_zk_helpers::circuits::dkg::share_computation::{
    codegen::generate_configs as share_computation_configs, ShareComputationCircuit,
    ShareComputationCircuitData, ShareComputationOutput,
};
use e3_zk_helpers::circuits::dkg::share_decryption::{
    codegen::generate_configs as share_decryption_configs, Configs as ShareDecryptionConfigs,
    ShareDecryptionCircuitData as DkgShareDecryptionCircuitData,
};
use e3_zk_helpers::circuits::dkg::share_encryption::{
    codegen::generate_configs as share_encryption_configs, Configs as ShareEncryptionConfigs,
    ShareEncryptionCircuitData,
};
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::Circuit;

const HEADER: &str = "// SPDX-License-Identifier: LGPL-3.0-only\n//\n// This file is provided WITHOUT ANY WARRANTY;\n// without even the implied warranty of MERCHANTABILITY\n// or FITNESS FOR A PARTICULAR PURPOSE.\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let preset = BfvPreset::InsecureDkgWide512;
    let committee = CiphernodesCommitteeSize::Minimum.values();
    let sd = preset
        .search_defaults()
        .expect("wide preset search defaults");

    // C0 (pk): PK_BIT_PK over the wide DKG moduli.
    let pk_bits = PkBits::compute(preset, &())?;
    let pk_fragment = pk_configs(preset, &pk_bits);
    let pk_bit_line = pk_fragment
        .lines()
        .find(|l| l.contains(&format!("{}_BIT_PK", <PkCircuit as Circuit>::PREFIX)))
        .expect("PK_BIT_PK line")
        .to_string();

    // C3 (share_encryption): full DKG-side constants (N, L, QIS, t, k0is, bounds).
    let se_sample = ShareEncryptionCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
        sd.z,
    )?;
    let se_configs = ShareEncryptionConfigs::compute(preset, &se_sample)?;
    let se_fragment = share_encryption_configs(preset, &se_configs);

    // C2a/C2b: threshold-side constants + parity matrix (same as `insecure`,
    // re-exported through committee::active so the committee switch stays one-file).
    let sc_sample = ShareComputationCircuitData::generate_sample(
        preset,
        committee.clone(),
        DkgInputType::SecretKey,
    )?;
    let ShareComputationOutput { bits: sc_bits, .. } =
        ShareComputationCircuit::compute(preset, &sc_sample)?;
    let sc_fragment =
        share_computation_configs(preset, &sc_bits, committee.n, committee.threshold)?;

    // C4 (share_decryption): BIT_MSG over the wide t.
    let sd_sample =
        DkgShareDecryptionCircuitData::generate_sample(preset, committee, DkgInputType::SecretKey)?;
    let sd_configs = ShareDecryptionConfigs::compute(preset, &sd_sample)?;
    let sd_fragment = share_decryption_configs(preset, &sd_configs);
    let sd_bit_msg_line = sd_fragment
        .lines()
        .find(|l| l.contains("SHARE_DECRYPTION_BIT_MSG"))
        .expect("SHARE_DECRYPTION_BIT_MSG line")
        .to_string();

    // Assemble `dkg.nr` in the SAME layout as `configs/insecure/dkg.nr`.
    let se_body: String = se_fragment
        .lines()
        .skip_while(|l| l.starts_with("use ")) // the `use ShareEncryptionConfigs` line is hoisted
        .collect::<Vec<_>>()
        .join("\n");
    let (se_globals, se_rest) = se_body
        .split_once("/************************************")
        .expect("share_encryption fragment layout");
    // C2 section: everything after the parity matrix constant (the fragment
    // starts with the threshold re-export + `N` + PARITY_MATRIX literal,
    // which the tier gets from committee::active instead).
    let sc_section = sc_fragment
        .split("/************************************")
        .skip(1)
        .map(|s| format!("/************************************{s}"))
        .collect::<Vec<_>>()
        .join("");

    let dkg_nr = format!(
        "{HEADER}
pub use crate::configs::insecure::threshold::{{
    L as L_THRESHOLD, QIS as QIS_THRESHOLD,
    THRESHOLD_SHARE_DECRYPTION_BIT_SK as SHARE_DECRYPTION_BIT_AGG,
}};
use crate::core::dkg::share_computation::Configs as ShareComputationConfigs;
use crate::core::dkg::share_encryption::Configs as ShareEncryptionConfigs;

// Global configs for the WIDE DKG transport preset (INSECURE_DKG_WIDE_512).
// Auto-generated by `cargo run -p e3-zk-helpers --example gen_wide_dkg_configs`;
// do not hand-edit. Threshold-side constants are `configs::insecure::threshold`.
{se_globals}
// Parity matrix is sized for the active committee and the insecure-512 threshold QIS;
// see `committee/{{name}}/parity_insecure.nr`. Re-exported via `committee::active`.
pub use crate::configs::committee::active::PARITY_MATRIX_INSECURE as PARITY_MATRIX;

/************************************
-------------------------------------
pk (CIRCUIT 0)
-------------------------------------
************************************/

// pk - bit parameters
{pk_bit_line}

{sc_section}
/************************************{se_rest}
/************************************
-------------------------------------
share_decryption_sk (CIRCUIT 4a - BFV DECRYPTION SK)
share_decryption_e_sm (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

{sd_bit_msg_line}
// SHARE_DECRYPTION_BIT_AGG: see `pub use` of `THRESHOLD_SHARE_DECRYPTION_BIT_SK` (C6 `BIT_SK`).
"
    );

    let mod_nr = format!(
        "{HEADER}
// Config tier for the WIDE DKG transport preset (`BfvPreset::InsecureDkgWide512`,
// `pnpm build:circuits --preset insecure-dkg-wide-512`). The threshold side IS the
// insecure-512 threshold tier (same BFV encoding on-chain); only the DKG side is wide.
// Auto-generated by `cargo run -p e3-zk-helpers --example gen_wide_dkg_configs`.

pub mod dkg;
pub use crate::configs::insecure::threshold;
"
    );

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let dir = format!("{root}/circuits/lib/src/configs/insecure_wide");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/mod.nr"), mod_nr)?;
    std::fs::write(format!("{dir}/dkg.nr"), dkg_nr)?;
    println!("written {dir}/{{mod,dkg}}.nr");
    Ok(())
}
