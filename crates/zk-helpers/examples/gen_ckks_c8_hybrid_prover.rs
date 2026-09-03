// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the C8-CKKS HYBRID (relin_round1_hybrid_ckks) Noir config
//! file and a Prover.toml witness fixture from a round-1 share of the
//! hybrid relinearization ceremony: party secret key -> CRP vector over
//! Q·P -> round-1 share (recomputed from sampled u/e0/e1 with the public
//! gadget math, because fhe.rs's hybrid generator does not expose its
//! sampled secrets) -> circuit witnesses.
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_c8_hybrid_prover [--param-set N]`
//! Default: a small 4-limb + 2-special-prime ladder shape (dnum 2, fast
//! to prove). `--param-set 2` emits the full ParamSet-2 config (38 + 3
//! limbs, dnum 13) — a ~2.7 MiB share, minutes to execute.

use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks::{
    compute_round_1_share, generate_configs_nr, sample_round_1_secrets, CkksHybridRelinRound1Data,
    Configs, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::{
    ckks_preset_for_param_set, CkksPreset,
};
use fhe::ckks::{CkksParametersBuilder, CkksSecretKey};
use fhe::trckks::CkksCrp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    let args: Vec<String> = std::env::args().collect();
    let preset = match args.iter().position(|a| a == "--param-set") {
        Some(i) => ckks_preset_for_param_set(args[i + 1].parse()?)?,
        None => CkksPreset {
            params: CkksParametersBuilder::new()
                .set_degree(512)
                .set_moduli_sizes(&[45, 40, 40, 40])
                .set_special_moduli_sizes(&[60, 60])
                .set_scale(2f64.powi(40))
                .build_arc()?,
            input_bound: 1000.0,
        },
    };
    let params = preset.params.clone();
    println!(
        "hybrid C8: N={} L={} k={} dnum={}",
        params.degree(),
        params.moduli().len(),
        params.special_moduli().len(),
        params.dnum()
    );

    let sk = CkksSecretKey::random(&params, &mut rng);
    let crp = CkksCrp::vec_from_seed_qp(&params, [9u8; 32])?;
    let (u, e0, e1) = sample_round_1_secrets(&params, &mut rng);
    let share = compute_round_1_share(&params, &crp, sk.coeffs.as_ref(), &u, &e0, &e1)?;
    let data = CkksHybridRelinRound1Data {
        crp,
        share,
        sk_coeffs: sk.coeffs.to_vec(),
        u_coeffs: u,
        e0_coeffs: e0,
        e1_coeffs: e1,
    };

    let configs = Configs::compute(preset.clone(), &())?;
    let nr = generate_configs_nr(&configs);
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    std::fs::write(
        format!("{root}/circuits/lib/src/configs/ckks_relin_round1_hybrid.nr"),
        nr,
    )?;

    let inputs = Inputs::compute(preset, &data)?;
    let json = inputs.to_json()?;
    let toml_str = toml::to_string(&json)?;
    let toml_path = format!("{root}/circuits/bin/threshold/relin_round1_hybrid_ckks/Prover.toml");
    std::fs::write(&toml_path, &toml_str)?;
    println!(
        "Prover.toml ({} bytes) + ckks_relin_round1_hybrid.nr written",
        toml_str.len()
    );
    Ok(())
}
