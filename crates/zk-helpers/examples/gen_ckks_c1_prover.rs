// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the C1-CKKS (pk_generation_ckks) Noir config file for one
//! on-chain CKKS ParamSet and a Prover.toml witness from a real CKKS
//! public-key share (`pk0 = -a*sk + e` over the E3-seed CRP).
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_c1_prover -- --param-set 0|2|3`
//! Writes `circuits/lib/src/configs/ckks_pk_generation_ps<N>.nr` and
//! `circuits/bin/threshold/pk_generation_ckks_ps<N>/Prover.toml`.

use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::circuits::threshold::pk_generation_ckks::{
    compute_pk_share, generate_configs_nr, sample_pk_share_error, CkksPkGenerationData, Configs,
    Inputs, CKKS_PK_GENERATION_SMUDGING_BITS,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
use fhe::ckks::CkksSecretKey;
use fhe::trckks::{CkksCrp, TRCKKS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let param_set: u8 = args
        .iter()
        .position(|a| a == "--param-set")
        .and_then(|i| args.get(i + 1))
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(0);
    let mut rng = rand::rng();
    let preset = ckks_preset_for_param_set(param_set)?;
    let params = preset.params.clone();

    // Real share: seed-derived CRP, fresh secret, explicit error (the
    // public math of `CkksPublicKeyShare::new`), dealt smudging noise.
    let crp = CkksCrp::from_seed(&params, [42u8; 32])?;
    let sk = CkksSecretKey::random(&params, &mut rng);
    let e = sample_pk_share_error(&params, &mut rng);
    let pk_share = compute_pk_share(&params, &crp, sk.coeffs.as_ref(), &e)?;
    let trckks = TRCKKS::new(3, 1, params.clone())?;
    let e_sm: Vec<i64> = trckks
        .generate_smudging_error(CKKS_PK_GENERATION_SMUDGING_BITS, &mut rng)?
        .iter()
        .map(i64::try_from)
        .collect::<Result<_, _>>()?;

    let data = CkksPkGenerationData {
        crp,
        pk_share,
        sk_coeffs: sk.coeffs.to_vec(),
        e_coeffs: e,
        e_sm_coeffs: e_sm,
    };

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let configs = Configs::compute(preset.clone(), &())?;
    std::fs::write(
        format!("{root}/circuits/lib/src/configs/ckks_pk_generation_ps{param_set}.nr"),
        generate_configs_nr(param_set, &configs),
    )?;

    let inputs = Inputs::compute(preset, &data)?;
    let toml_str = toml::to_string(&inputs.to_json()?)?;
    let dir = format!("{root}/circuits/bin/threshold/pk_generation_ckks_ps{param_set}");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/Prover.toml"), &toml_str)?;
    println!(
        "ParamSet {param_set}: Prover.toml ({} bytes) + ckks_pk_generation_ps{param_set}.nr written; \
         sk_commitment={} pk_commitment={} e_sm_commitment={}",
        toml_str.len(),
        inputs.sk_commitment,
        inputs.pk_commitment,
        inputs.e_sm_commitment
    );
    Ok(())
}
