// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reads `packages/crisp-contracts/deployed_contracts.json` for deployed CRISP addresses.
//!
//! The file is read on every lookup, so a redeploy is picked up without a restart. A build
//! without the source tree falls back to the copy embedded at compile time.

use eyre::{Result, WrapErr};
use serde_json::Value;
use std::path::Path;

const EMBEDDED_DEPLOYMENTS_JSON: &str =
    include_str!("../../packages/crisp-contracts/deployed_contracts.json");

/// The chain id whose entries come from the latest localhost deploy.
pub const LOCALHOST_CHAIN_ID: u64 = 31_337;

fn read_deployments_from_path(path: &Path) -> Result<Value> {
    if path.exists() {
        let raw =
            std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        return serde_json::from_str(&raw).wrap_err_with(|| format!("parse {}", path.display()));
    }
    serde_json::from_str(EMBEDDED_DEPLOYMENTS_JSON)
        .wrap_err("parse embedded CRISP deployment addresses")
}

fn lookup(file: &Value, chain_id: u64, contract: &str) -> Option<String> {
    let network = match chain_id {
        1 => "mainnet",
        11_155_111 => "sepolia",
        31_337 | 1_337 => "localhost",
        _ => return None,
    };
    file.get(network)?
        .get(contract)?
        .get("address")?
        .as_str()
        .map(str::to_owned)
}

/// The address of `contract` (for example `SelfRegistry` or `MockVotingToken`) deployed on
/// `chain_id`, if recorded.
pub fn deployed_address(chain_id: u64, contract: &str) -> Result<Option<String>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("packages")
        .join("crisp-contracts")
        .join("deployed_contracts.json");
    Ok(lookup(
        &read_deployments_from_path(&path)?,
        chain_id,
        contract,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_deployments_parse_without_the_source_tree() {
        read_deployments_from_path(Path::new("missing-deployed-contracts.json"))
            .expect("embedded deployment data must parse");
    }

    #[test]
    fn chain_lookup_selects_the_requested_network() {
        let file: Value = serde_json::from_str(
            r#"{
                "localhost": {"SelfRegistry": {"address": "local"}},
                "sepolia": {"SelfRegistry": {"address": "sepolia"}},
                "mainnet": {"SelfRegistry": {"address": "mainnet"}}
            }"#,
        )
        .expect("synthetic deployment data must parse");

        let address = |chain_id| lookup(&file, chain_id, "SelfRegistry");

        assert_eq!(address(31_337).as_deref(), Some("local"));
        assert_eq!(address(1_337).as_deref(), Some("local"));
        assert_eq!(address(11_155_111).as_deref(), Some("sepolia"));
        assert_eq!(address(1).as_deref(), Some("mainnet"));
        assert_eq!(address(42), None);
        assert_eq!(lookup(&file, 1, "MockVotingToken"), None);
    }
}
