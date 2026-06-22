// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read-only, operator-facing on-chain status query.

use crate::{
    contracts::{IBondingRegistry, ICiphernodeRegistry},
    ProviderConfig,
};
use alloy::primitives::Address;
use e3_config::chain_config::ChainConfig;
use serde::Serialize;
use std::str::FromStr;

#[derive(Clone, Debug, Serialize)]
pub struct OperatorChainStatus {
    pub chain_id: u64,
    pub chain_name: String,
    pub registered_nodes: String,
    pub active_nodes: String,
    pub operator_registered: bool,
    pub operator_active: bool,
    pub exit_in_progress: bool,
    pub ticket_balance: String,
    pub available_tickets: String,
    pub license_bond: String,
}

pub async fn fetch_operator_status(
    chain: &ChainConfig,
    operator: Address,
) -> anyhow::Result<OperatorChainStatus> {
    let provider = ProviderConfig::new(chain.rpc_url()?, chain.rpc_auth.clone())
        .create_readonly_provider()
        .await?;
    let client = provider.provider().clone();
    let bonding_address = Address::from_str(chain.contracts.bonding_registry.address_str())?;
    let registry_address = Address::from_str(chain.contracts.ciphernode_registry.address_str())?;
    let bonding = IBondingRegistry::new(bonding_address, client.clone());
    let registry = ICiphernodeRegistry::new(registry_address, client);

    let (
        ticket_balance,
        license_bond,
        available_tickets,
        operator_registered,
        operator_active,
        active_nodes,
        registered_nodes,
        exit_in_progress,
    ) = tokio::try_join!(
        async { bonding.getTicketBalance(operator).call().await },
        async { bonding.getLicenseBond(operator).call().await },
        async { bonding.availableTickets(operator).call().await },
        async { bonding.isRegistered(operator).call().await },
        async { bonding.isActive(operator).call().await },
        async { bonding.numActiveOperators().call().await },
        async { registry.numCiphernodes().call().await },
        async { bonding.hasExitInProgress(operator).call().await },
    )?;

    Ok(OperatorChainStatus {
        chain_id: provider.chain_id(),
        chain_name: chain.name.clone(),
        registered_nodes: registered_nodes.to_string(),
        active_nodes: active_nodes.to_string(),
        operator_registered,
        operator_active,
        exit_in_progress,
        ticket_balance: ticket_balance.to_string(),
        available_tickets: available_tickets.to_string(),
        license_bond: license_bond.to_string(),
    })
}
