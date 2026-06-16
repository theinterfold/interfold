// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reads `packages/crisp-contracts/deployed_contracts.json` for localhost dev addresses.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

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
}

#[derive(Debug, Deserialize)]
struct DeployedContractsFile {
    localhost: Option<ChainDeployments>,
}

fn deployments_json_path() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .join("..")
        .join("packages")
        .join("crisp-contracts")
        .join("deployed_contracts.json"))
}

/// `MockVotingToken` address from the latest localhost deploy, if present.
pub fn localhost_mock_voting_token() -> Result<Option<String>> {
    let path = deployments_json_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let file: DeployedContractsFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    Ok(file
        .localhost
        .and_then(|c| c.mock_voting_token)
        .map(|e| e.address))
}

/// `CRISPProgram` address from the latest localhost deploy, if present.
pub fn localhost_crisp_program() -> Result<Option<String>> {
    let path = deployments_json_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let file: DeployedContractsFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    Ok(file
        .localhost
        .and_then(|c| c.crisp_program)
        .map(|e| e.address))
}
