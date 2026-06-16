// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_config::AppConfig;
use e3_console::{log, Console};

pub fn extract_env_vars_vite(config: &AppConfig, chain: &str) -> String {
    let mut env_vars = Vec::new();

    // Extract from first enabled chain (or first chain if none specified)
    if let Some(chain) = config.chains().iter().find(|c| c.name == chain) {
        let interfold_addr = &chain.contracts.interfold;
        let registry_addr = &chain.contracts.ciphernode_registry;
        let bonding_registry_addr = &chain.contracts.bonding_registry;
        env_vars.push(format!(
            "VITE_INTERFOLD_ADDRESS={}",
            interfold_addr.address_str()
        ));
        env_vars.push(format!(
            "VITE_REGISTRY_ADDRESS={}",
            registry_addr.address_str()
        ));
        env_vars.push(format!("VITE_RPC_URL={}", chain.rpc_url));
        env_vars.push(format!(
            "VITE_BONDING_REGISTRY_ADDRESS={}",
            bonding_registry_addr.address_str()
        ));
        if let Some(e3_program) = &chain.contracts.e3_program {
            env_vars.push(format!(
                "VITE_E3_PROGRAM_ADDRESS={}",
                e3_program.address_str()
            ));
        }
        if let Some(fee_token) = &chain.contracts.fee_token {
            env_vars.push(format!(
                "VITE_FEE_TOKEN_ADDRESS={}",
                fee_token.address_str()
            ));
        }
    }

    env_vars.join(" ")
}

pub fn extract_env_vars(config: &AppConfig, chain: &str) -> String {
    let mut env_vars = Vec::new();

    // Extract from first enabled chain (or first chain if none specified)
    if let Some(chain) = config.chains().iter().find(|c| c.name == chain) {
        let interfold_addr = &chain.contracts.interfold;
        let registry_addr = &chain.contracts.ciphernode_registry;
        let bonding_registry_addr = &chain.contracts.bonding_registry;
        env_vars.push(format!(
            "INTERFOLD_ADDRESS={}",
            interfold_addr.address_str()
        ));
        env_vars.push(format!("RPC_URL={}", chain.rpc_url));
        env_vars.push(format!("REGISTRY_ADDRESS={}", registry_addr.address_str()));
        env_vars.push(format!(
            "BONDING_REGISTRY_ADDRESS={}",
            bonding_registry_addr.address_str()
        ));
        if let Some(e3_program) = &chain.contracts.e3_program {
            env_vars.push(format!("E3_PROGRAM_ADDRESS={}", e3_program.address_str()));
        }
        if let Some(fee_token) = &chain.contracts.fee_token {
            env_vars.push(format!("FEE_TOKEN_ADDRESS={}", fee_token.address_str()));
        }
    }

    env_vars.join(" ")
}
pub async fn execute(out: Console, config: &AppConfig, chain: &str, as_vite: bool) -> Result<()> {
    if as_vite {
        log!(out, "{}", extract_env_vars_vite(config, chain));
    } else {
        log!(out, "{}", extract_env_vars(config, chain));
    }
    Ok(())
}
