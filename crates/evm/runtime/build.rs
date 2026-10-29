// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
use std::{fs, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=FORCE_BUILD");

    let output = Command::new("solc")
        .args(["--combined-json", "abi,bin", "tests/fixtures/emit_logs.sol"])
        .output()
        .expect("solc must be installed to compile EVM test fixtures");
    assert!(
        output.status.success(),
        "EVM fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let compiled: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("solc returned invalid JSON");
    let contract = &compiled["contracts"]["tests/fixtures/emit_logs.sol:EmitLogs"];
    assert!(contract["abi"].is_array(), "EVM fixture ABI is missing");
    assert!(
        contract["bin"].is_string(),
        "EVM fixture bytecode is missing"
    );
    let fixture = serde_json::json!({"abi": contract["abi"], "bin": contract["bin"]});
    fs::write(
        "tests/fixtures/emit_logs.json",
        serde_json::to_vec_pretty(&fixture).expect("EVM fixture serialization failed"),
    )
    .expect("EVM fixture write failed");

    println!("cargo:rerun-if-changed=tests/fixtures/emit_logs.sol");
}
