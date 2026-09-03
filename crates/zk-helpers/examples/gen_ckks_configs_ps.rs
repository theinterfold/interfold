// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: emit circuits/lib/src/configs/ckks_ps<N>.nr from codegen for a
// non-canonical on-chain ParamSet (2 = auction sign-extraction ladder,
// 3 = statistics). Usage: cargo run --example gen_ckks_configs_ps -- 3
fn main() {
    use e3_zk_helpers::circuits::computation::Computation;
    let param_set: u8 = std::env::args()
        .nth(1)
        .expect("pass the on-chain ParamSet value (2 or 3)")
        .parse()
        .expect("param set must be a u8");
    let preset =
        e3_zk_helpers::threshold::user_data_encryption_ckks::ckks_preset_for_param_set(param_set)
            .unwrap();
    let configs =
        e3_zk_helpers::threshold::user_data_encryption_ckks::Configs::compute(preset.clone(), &())
            .unwrap();
    let out =
        e3_zk_helpers::threshold::user_data_encryption_ckks::generate_configs(&preset, &configs);
    let path = format!("circuits/lib/src/configs/ckks_ps{param_set}.nr");
    std::fs::write(&path, out).unwrap();
    println!("written {path}");
}
