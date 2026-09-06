// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the C6-CKKS (share_decryption_ckks) Noir config file and a
//! Prover.toml witness fixture from a REAL threshold pipeline (T=1 to match
//! the active `minimum` committee): DKG share dealing → aggregated party
//! shares → ciphertext at the OPENING level → decryption share → circuit
//! witnesses.
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_c6_prover [-- --param-set 0|2|3|4 [--level L]]`
//! ParamSet 0 (default) writes the canonical `ckks_share_decryption.nr` +
//! `share_decryption_ckks/Prover.toml`; other sets write
//! `ckks_share_decryption_ps<N>.nr` + `share_decryption_ckks_ps<N>/Prover.toml`.
//!
//! The configs and the witness are generated at `--level` (default: the
//! set's OPENING level, `ckks_opening_level_for_param_set` — the level the
//! E3 output is decrypted at, so `L` is the number of moduli that REMAIN
//! there). The fresh ciphertext is mod-switched down to that level and the
//! party shares are projected to it, exactly what the node does
//! (`multithread::handle_threshold_share_decryption_proof_ckks`).

use e3_fhe_params::ckks_presets::ckks_opening_level_for_param_set;
use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::circuits::threshold::share_decryption_ckks::{
    bin_package_for_param_set, config_module_for_param_set, generate_configs_nr_for_param_set,
    CkksShareDecryptionData, Configs, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
use fhe::trckks::TRCKKS;

fn arg<T: std::str::FromStr>(args: &[String], name: &str) -> Result<Option<T>, String>
where
    T::Err: std::fmt::Display,
{
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|v| v.parse::<T>().map_err(|e| format!("{name} {v}: {e}")))
        .transpose()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let param_set: u8 = arg(&args, "--param-set")?.unwrap_or(0);
    let level: usize = match arg(&args, "--level")? {
        Some(l) => l,
        None => ckks_opening_level_for_param_set(param_set)?,
    };
    let mut rng = rand::rng();
    let preset = ckks_preset_for_param_set(param_set)?;
    let params = preset.params.clone();

    // Committee shape must match the active Noir committee: minimum = (3, 1).
    let (n_parties, threshold) = (3usize, 1usize);
    let trckks = TRCKKS::new(n_parties, threshold, params.clone())?;

    // Single-dealer pipeline (matches gen_ckks_agg_prover): secret + smudging
    // dealt via Shamir, party 1 takes row 0 of each matrix.
    let sk = fhe::ckks::CkksSecretKey::random(&params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng)?;

    let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
    let sk_mats = trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
    let es = trckks.generate_smudging_error(20, &mut rng)?;
    let es_poly_dealer = trckks.smudging_to_poly(&es)?;
    let es_mats = trckks.generate_secret_shares_from_poly(es_poly_dealer, &mut rng)?;

    let encoder = fhe::ckks::CkksEncoder::new(&params);
    let pt = encoder.encode(&[42.5, -17.25], 0)?;
    let mut ct = pk.try_encrypt(&pt, &mut rng)?;
    // The ciphertext the E3 opens sits at the opening level.
    ct.mod_switch_to_level(level)?;

    // Party 1 (x=1): row 0 shares projected to the ciphertext's level,
    // then its real decryption share.
    let sk_share = trckks.project_share_to_level(&trckks.share_row_to_poly(&sk_mats, 0)?, level)?;
    let es_share = trckks.project_share_to_level(&trckks.share_row_to_poly(&es_mats, 0)?, level)?;
    let d_share = trckks.decryption_share(&ct, sk_share.clone().into_ntt(), es_share.clone())?;

    let data = CkksShareDecryptionData {
        ciphertext: ct,
        sk_poly: sk_share,
        es_poly: es_share,
        d_share,
        domain_hi: 7,
        domain_lo: 13,
    };

    // Configs fragment (stable) + witness TOML (fresh-random each run).
    let configs = Configs::compute_at_level(&preset, level)?;
    let nr = generate_configs_nr_for_param_set(param_set, &configs);
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let module = config_module_for_param_set(param_set);
    std::fs::write(format!("{root}/circuits/lib/src/configs/{module}.nr"), nr)?;

    let inputs = Inputs::compute(preset, &data)?;
    let json = inputs.to_json()?;
    let toml_str = toml::to_string(&json)?;
    let package = bin_package_for_param_set(param_set);
    let dir = format!("{root}/circuits/bin/threshold/{package}");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/Prover.toml"), &toml_str)?;
    println!(
        "ParamSet {param_set} level {level} (L={}): {package}/Prover.toml ({} bytes) + {module}.nr written",
        configs.l,
        toml_str.len()
    );
    Ok(())
}
