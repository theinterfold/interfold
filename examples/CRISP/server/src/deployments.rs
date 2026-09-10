// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reads `packages/crisp-contracts/deployed_contracts.json` for deployed CRISP addresses.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const EMBEDDED_DEPLOYMENTS_JSON: &str =
    include_str!("../../packages/crisp-contracts/deployed_contracts.json");

#[derive(Debug, Deserialize)]
struct DeploymentEntry {
    address: String,
}

#[derive(Debug, Deserialize)]
struct ChainDeployments {
    #[serde(rename = "CRISPProgram")]
    crisp_program: Option<DeploymentEntry>,
    #[serde(rename = "MockVotingToken")]
    mock_voting_token: Option<DeploymentEntry>,
    #[serde(rename = "SelfRegistry")]
    self_registry: Option<DeploymentEntry>,
}

#[derive(Debug, Deserialize)]
struct DeployedContractsFile {
    localhost: Option<ChainDeployments>,
    sepolia: Option<ChainDeployments>,
    mainnet: Option<ChainDeployments>,
}

fn deployments_json_path() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .join("..")
        .join("packages")
        .join("crisp-contracts")
        .join("deployed_contracts.json"))
}

fn read_deployments() -> Result<DeployedContractsFile> {
    let path = deployments_json_path()?;
    read_deployments_from_path(&path)
}

fn read_deployments_from_path(path: &Path) -> Result<DeployedContractsFile> {
    if path.exists() {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        return serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()));
    }

    serde_json::from_str(EMBEDDED_DEPLOYMENTS_JSON)
        .context("parse embedded CRISP deployment addresses")
}

fn chain_deployments(file: &DeployedContractsFile, chain_id: u64) -> Option<&ChainDeployments> {
    match chain_id {
        1 => file.mainnet.as_ref(),
        11_155_111 => file.sepolia.as_ref(),
        31_337 | 1_337 => file.localhost.as_ref(),
        _ => None,
    }
}

/// `MockVotingToken` address from the latest localhost deploy, if present.
pub fn localhost_mock_voting_token() -> Result<Option<String>> {
    Ok(read_deployments()?
        .localhost
        .and_then(|c| c.mock_voting_token)
        .map(|e| e.address))
}

/// `SelfRegistry` address from the latest localhost deploy, if present.
///
/// The open census for ONCHAIN rounds: pass it as the round's token to run a round anyone can
/// register into during the input window.
pub fn localhost_self_registry() -> Result<Option<String>> {
    Ok(read_deployments()?
        .localhost
        .and_then(|c| c.self_registry)
        .map(|e| e.address))
}

/// `SelfRegistry` address for a deployed chain, if recorded.
pub fn self_registry_for_chain_id(chain_id: u64) -> Result<Option<String>> {
    let file = read_deployments()?;
    Ok(chain_deployments(&file, chain_id)
        .and_then(|c| c.self_registry.as_ref())
        .map(|e| e.address.clone()))
}

/// `CRISPProgram` address from the latest localhost deploy, if present.
pub fn localhost_crisp_program() -> Result<Option<String>> {
    Ok(read_deployments()?
        .localhost
        .and_then(|c| c.crisp_program)
        .map(|e| e.address))
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
        let file: DeployedContractsFile = serde_json::from_str(
            r#"{
                "localhost": {"SelfRegistry": {"address": "local"}},
                "sepolia": {"SelfRegistry": {"address": "sepolia"}},
                "mainnet": {"SelfRegistry": {"address": "mainnet"}}
            }"#,
        )
        .expect("synthetic deployment data must parse");

        let address = |chain_id| {
            chain_deployments(&file, chain_id)
                .and_then(|chain| chain.self_registry.as_ref())
                .map(|entry| entry.address.as_str())
        };

        assert_eq!(address(31_337), Some("local"));
        assert_eq!(address(1_337), Some("local"));
        assert_eq!(address(11_155_111), Some("sepolia"));
        assert_eq!(address(1), Some("mainnet"));
        assert_eq!(address(42), None);
    }
}
