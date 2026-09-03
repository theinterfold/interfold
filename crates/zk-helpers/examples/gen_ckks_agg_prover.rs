// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// Generate configs + Prover.toml for the CKKS decrypted shares aggregation
// (C7-CKKS) bin circuit from a real threshold pipeline (T=1 to match the
// active `minimum` committee).
//
// Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_agg_prover [-- --param-set 0|2|3]`
// ParamSet 0 (default) writes the canonical `ckks_aggregation.nr` +
// `decrypted_shares_aggregation_ckks/Prover.toml`; other sets write
// `ckks_aggregation_ps<N>.nr` + `decrypted_shares_aggregation_ckks_ps<N>/Prover.toml`.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use e3_zk_helpers::circuits::codegen::CircuitCodegen;
    use e3_zk_helpers::circuits::computation::Computation;
    use e3_zk_helpers::threshold::decrypted_shares_aggregation_ckks::{
        bin_package_for_param_set, config_module_for_param_set, generate_configs_nr_for_param_set,
        Configs, DecryptedSharesAggregationCkksCircuit, DecryptedSharesAggregationCkksCircuitData,
    };
    use e3_zk_helpers::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
    use fhe::trckks::TRCKKS;

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

    // Committee shape must match the active Noir committee: minimum = (3, 1).
    let (n_parties, threshold) = (3usize, 1usize);
    let trckks = TRCKKS::new(n_parties, threshold, params.clone())?;

    let sk = fhe::ckks::CkksSecretKey::random(&params, &mut rng);
    let pk = fhe::ckks::CkksPublicKey::new(&sk, &mut rng)?;

    let sk_poly = trckks.coeffs_to_poly(sk.coeffs.as_ref())?;
    let sk_mats = trckks.generate_secret_shares_from_poly(sk_poly, &mut rng)?;
    let es = trckks.generate_smudging_error(20, &mut rng)?;
    let es_poly = trckks.smudging_to_poly(&es)?;
    let es_mats = trckks.generate_secret_shares_from_poly(es_poly, &mut rng)?;

    let encoder = fhe::ckks::CkksEncoder::new(&params);
    let pt = encoder.encode(&[42.5, -17.25], 0)?;
    let ct = pk.try_encrypt(&pt, &mut rng)?;

    let parties: Vec<usize> = vec![1, 3];
    let mut d_share_polys = Vec::new();
    for &j in &parties {
        let sk_share = trckks.share_row_to_poly(&sk_mats, j - 1)?;
        let es_share = trckks.share_row_to_poly(&es_mats, j - 1)?;
        d_share_polys.push(trckks.decryption_share(&ct, sk_share.into_ntt(), es_share)?);
    }

    let data = DecryptedSharesAggregationCkksCircuitData {
        threshold,
        d_share_polys,
        reconstructing_parties: parties,
    };

    let artifacts = DecryptedSharesAggregationCkksCircuit.codegen(preset.clone(), &data)?;
    let configs = Configs::compute(preset, &())?;

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let package = bin_package_for_param_set(param_set);
    let module = config_module_for_param_set(param_set);
    let dir = format!("{root}/circuits/bin/threshold/{package}");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{dir}/Prover.toml"), &artifacts.toml)?;
    std::fs::write(
        format!("{root}/circuits/lib/src/configs/{module}.nr"),
        generate_configs_nr_for_param_set(param_set, &configs),
    )?;
    println!(
        "ParamSet {param_set}: {package}/Prover.toml ({} bytes) + {module}.nr written",
        artifacts.toml.len()
    );
    Ok(())
}
