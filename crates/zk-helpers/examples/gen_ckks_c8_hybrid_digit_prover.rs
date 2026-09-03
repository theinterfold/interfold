// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Generates the PER-DIGIT C8-CKKS (hybrid) config + witnesses for one
//! on-chain ParamSet: one `Prover.toml` per gadget digit, all from ONE
//! recomputed round-1 share (shared `s`/`u` commitments).
//!
//! Run: `cargo run --release -p e3-zk-helpers --example gen_ckks_c8_hybrid_digit_prover -- --param-set 2 [--digits 0,1]`
//! Writes `circuits/lib/src/configs/ckks_relin_round1_hybrid_ps<N>.nr` and
//! `circuits/bin/threshold/relin_round1_hybrid_ckks_digit_ps<N>/{Prover.toml,Prover_digit_<j>.toml}`
//! (`Prover.toml` is digit 0 so `nargo execute` works as-is; use
//! `nargo execute -p Prover_digit_<j>` for the others).

use e3_zk_helpers::circuits::computation::Computation;
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks::{
    compute_round_1_share, sample_round_1_secrets, CkksHybridRelinRound1Data, Configs,
};
use e3_zk_helpers::circuits::threshold::relin_round1_hybrid_ckks_digit::{
    compute_digit_inputs, generate_configs_nr_for_param_set,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
use fhe::ckks::CkksSecretKey;
use fhe::trckks::CkksCrp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let param_set: u8 = arg("--param-set").unwrap_or_else(|| "2".into()).parse()?;
    let mut rng = rand::rng();
    let preset = ckks_preset_for_param_set(param_set)?;
    let params = preset.params.clone();
    let dnum = params.dnum();
    let digits: Vec<usize> = match arg("--digits") {
        Some(list) => list
            .split(',')
            .map(|s| s.trim().parse())
            .collect::<Result<_, _>>()?,
        None => (0..dnum).collect(),
    };
    println!(
        "hybrid C8 per-digit: ParamSet {param_set} N={} L={} k={} dnum={} digits={digits:?}",
        params.degree(),
        params.moduli().len(),
        params.special_moduli().len(),
        dnum
    );

    let t0 = std::time::Instant::now();
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
    println!("share computed in {:.2?}", t0.elapsed());

    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let configs = Configs::compute(preset.clone(), &())?;
    std::fs::write(
        format!("{root}/circuits/lib/src/configs/ckks_relin_round1_hybrid_ps{param_set}.nr"),
        generate_configs_nr_for_param_set(param_set, &configs),
    )?;
    let dir = format!("{root}/circuits/bin/threshold/relin_round1_hybrid_ckks_digit_ps{param_set}");
    std::fs::create_dir_all(&dir)?;

    for &j in &digits {
        let t = std::time::Instant::now();
        let inputs = compute_digit_inputs(&preset, &data, j)?;
        let toml_str = toml::to_string(&inputs.to_json())?;
        std::fs::write(format!("{dir}/Prover_digit_{j}.toml"), &toml_str)?;
        if j == 0 {
            std::fs::write(format!("{dir}/Prover.toml"), &toml_str)?;
        }
        println!(
            "digit {j}: Prover_digit_{j}.toml ({} bytes) in {:.2?}; share_commitment={} s_c={} u_c={}",
            toml_str.len(),
            t.elapsed(),
            inputs.share_commitment,
            inputs.s_commitment,
            inputs.u_commitment
        );
    }
    Ok(())
}
