// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: emit circuits/lib/src/configs/ckks.nr from codegen.
fn main() {
    use e3_zk_helpers::circuits::computation::Computation;
    let preset = e3_zk_helpers::threshold::user_data_encryption_ckks::insecure_512_ckks().unwrap();
    let configs =
        e3_zk_helpers::threshold::user_data_encryption_ckks::Configs::compute(preset.clone(), &())
            .unwrap();
    let out =
        e3_zk_helpers::threshold::user_data_encryption_ckks::generate_configs(&preset, &configs);
    std::fs::write("circuits/lib/src/configs/ckks.nr", out).unwrap();
    println!("written");
}
