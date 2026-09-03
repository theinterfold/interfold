// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// One-off: emit circuits/lib/src/configs/ckks_app_ps{2,3}.nr for the CKKS
// application-validity legs (auction on ParamSet 2, salary survey on
// ParamSet 3). Usage: cargo run -p e3-zk-helpers --example gen_ckks_app_configs
fn main() {
    use e3_zk_helpers::threshold::ckks_app_validity::{generate_configs, AppConfigs, CkksApp};
    use e3_zk_helpers::threshold::user_data_encryption_ckks::ckks_preset_for_param_set;
    for app in [CkksApp::SalarySurvey, CkksApp::Auction] {
        let preset = ckks_preset_for_param_set(app.param_set()).unwrap();
        let configs = AppConfigs::compute(&preset).unwrap();
        let out = generate_configs(app, &configs);
        let path = format!("circuits/lib/src/configs/ckks_app_ps{}.nr", app.param_set());
        std::fs::write(&path, out).unwrap();
        println!("written {path}");
    }
}
