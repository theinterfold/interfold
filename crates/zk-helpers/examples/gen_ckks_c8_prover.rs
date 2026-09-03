// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the C8-CKKS (relin_round1_ckks) Noir config file and a
//! Prover.toml witness fixture from a REAL relinearization ceremony
//! round 1: party secret key -> CRP vector -> round-1 share (+ extracted
//! error/ephemeral secrets) -> circuit witnesses.
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_c8_prover`

use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::circuits::threshold::relin_round1_ckks::{
    generate_configs_nr, CkksRelinRound1Data, Configs, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::insecure_512_ckks;
use fhe::ckks::CkksSecretKey;
use fhe::trckks::{CkksCrp, CkksRelinKeyGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    let preset = insecure_512_ckks()?;
    let params = preset.params.clone();

    // One party's real round-1 share at level 0 (see the module's level
    // note: the garner constants baked into the config are level-0).
    let sk = CkksSecretKey::random(&params, &mut rng);
    let crp = CkksCrp::vec_from_seed_leveled(&params, [9u8; 32], params.moduli().len(), 0)?;
    let generator = CkksRelinKeyGenerator::new(&sk, &crp, &mut rng)?;
    let (share, e0s, e1s) = generator.round_1_extended(&mut rng)?;
    let u = generator.u_poly().clone();
    drop(generator);

    let data = CkksRelinRound1Data {
        crp,
        share,
        sk_coeffs: sk.coeffs.to_vec(),
        u,
        e0s,
        e1s,
    };

    // Configs fragment (stable) + witness TOML (fresh-random each run).
    let configs = Configs::compute(preset.clone(), &())?;
    let nr = generate_configs_nr(&configs);
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    std::fs::write(
        format!("{root}/circuits/lib/src/configs/ckks_relin_round1.nr"),
        nr,
    )?;

    let inputs = Inputs::compute(preset, &data)?;
    let json = inputs.to_json()?;
    let toml_str = toml::to_string(&json)?;
    let toml_path = format!("{root}/circuits/bin/threshold/relin_round1_ckks/Prover.toml");
    std::fs::write(&toml_path, &toml_str)?;
    println!(
        "Prover.toml ({} bytes) + ckks_relin_round1.nr written",
        toml_str.len()
    );
    Ok(())
}
