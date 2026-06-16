// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use serde_json::{from_reader, Value};
use std::env;
use std::fs::{self, File};
use std::path::Path;
use std::process::Command;

fn main() -> std::io::Result<()> {
    generate_git_sha();
    generate_contract_deployments()?;
    Ok(())
}

fn generate_git_sha() {
    let git_sha = if let Ok(sha) = std::env::var("GIT_SHA") {
        sha
    } else {
        let output = Command::new("git")
            .args(["rev-parse", "--short=9", "HEAD"])
            .output();
        match output {
            Ok(output) if output.status.success() => String::from_utf8(output.stdout)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string(),
            _ => get_remote_commit_hash().unwrap_or_else(|| "unknown".to_string()),
        }
    };
    println!("cargo:rustc-env=GIT_SHA={}", git_sha);
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    println!("cargo:rerun-if-changed=.git/HEAD");
}

fn get_remote_commit_hash() -> Option<String> {
    let output = Command::new("git")
        .args([
            "ls-remote",
            "https://github.com/gnosisguild/interfold",
            "refs/heads/main",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let commit_hash = stdout
        .split_whitespace()
        .next()?
        .chars()
        .take(9)
        .collect::<String>();

    if commit_hash.is_empty() {
        None
    } else {
        Some(commit_hash)
    }
}

fn generate_contract_deployments() -> std::io::Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let deployments_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("packages")
        .join("interfold-contracts")
        .join("deployed_contracts.json");

    let mut contract_info = String::from(
        "pub struct ContractInfo {\n    pub address: &'static str,\n    pub deploy_block: u64,\n}\n\n"
    );
    contract_info.push_str(
        "pub static CONTRACT_DEPLOYMENTS: phf::Map<&'static str, ContractInfo> = phf::phf_map! {\n",
    );

    let file = File::open(&deployments_path)?;
    let json: Value = from_reader(file)?;

    let mut contract_count = 0u32;
    if let Some(networks) = json.as_object() {
        if let Some(sepolia_data) = networks.get("sepolia") {
            if let Some(contracts) = sepolia_data.as_object() {
                for (contract_name, contract_data) in contracts {
                    if let (Some(address), Some(deploy_block)) = (
                        contract_data["address"].as_str(),
                        contract_data["blockNumber"].as_u64(),
                    ) {
                        contract_info.push_str(&format!(
                            "    \"{}\" => ContractInfo {{\n        address: \"{}\",\n        deploy_block: {},\n    }},\n",
                            contract_name, address, deploy_block
                        ));
                        contract_count += 1;
                    } else {
                        panic!(
                            "Contract '{}' in deployed_contracts.json is missing 'address' or 'blockNumber'",
                            contract_name
                        );
                    }
                }
            }
        }
    }

    if contract_count == 0 {
        panic!(
            "No contracts found in deployed_contracts.json — \
             expected a 'sepolia' key with contract entries containing 'address' and 'blockNumber'"
        );
    }

    contract_info.push_str("};\n");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("contract_deployments.rs");
    fs::write(dest_path, contract_info)?;
    println!("cargo:rerun-if-changed=../../packages/interfold-contracts/deployed_contracts.json");
    Ok(())
}
