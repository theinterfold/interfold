// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read-only, operator-facing on-chain status query.

use crate::{
    contracts::{IBondingRegistry, ICiphernodeRegistry},
    helpers::get_current_timestamp_from_provider,
    ProviderConfig,
};
use alloy::primitives::{Address, U256};
use e3_config::chain_config::ChainConfig;
use serde::Serialize;
use std::str::FromStr;
use tracing::debug;

#[derive(Clone, Debug, Serialize)]
pub struct OperatorChainStatus {
    pub chain_id: u64,
    pub chain_name: String,
    pub registered_nodes: String,
    pub active_nodes: String,
    pub operator_registered: bool,
    pub operator_active: bool,
    /// `BondingRegistry.eligibilityAt(operator, latest block timestamp)`. Unlike
    /// `operator_active`, it also applies the admission cooldown and the admission policy, which
    /// decide whether sortition for a new committee can select the operator. `None` when the
    /// read fails.
    pub operator_eligible: Option<bool>,
    pub exit_in_progress: bool,
    pub ticket_balance: String,
    pub available_tickets: String,
    pub ciphernode_bond: String,
    pub bond_owner: String,
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

    // A failed eligibility read makes only `operator_eligible` unknown.
    let eligibility = async {
        let timestamp = get_current_timestamp_from_provider(provider.clone()).await?;
        let eligibility = bonding
            .eligibilityAt(operator, U256::from(timestamp))
            .call()
            .await?;
        anyhow::Ok(eligibility.active)
    };
    let (reads, operator_eligible) = tokio::join!(
        async {
            tokio::try_join!(
                async { bonding.getTicketBalance(operator).call().await },
                async { bonding.getCiphernodeBond(operator).call().await },
                async { bonding.availableTickets(operator).call().await },
                async { bonding.isRegistered(operator).call().await },
                async { bonding.isActive(operator).call().await },
                async { bonding.numActiveOperators().call().await },
                async { registry.numCiphernodes().call().await },
                async { bonding.hasExitInProgress(operator).call().await },
                async { bonding.bondOwnerOf(operator).call().await },
            )
        },
        eligibility,
    );
    let (
        ticket_balance,
        ciphernode_bond,
        available_tickets,
        operator_registered,
        operator_active,
        active_nodes,
        registered_nodes,
        exit_in_progress,
        bond_owner,
    ) = reads?;
    let operator_eligible = operator_eligible
        .inspect_err(|error| {
            debug!(chain = %chain.name, %error, "Could not read operator eligibility");
        })
        .ok();

    Ok(OperatorChainStatus {
        chain_id: provider.chain_id(),
        chain_name: chain.name.clone(),
        registered_nodes: registered_nodes.to_string(),
        active_nodes: active_nodes.to_string(),
        operator_registered,
        operator_active,
        operator_eligible,
        exit_in_progress,
        ticket_balance: ticket_balance.to_string(),
        available_tickets: available_tickets.to_string(),
        ciphernode_bond: ciphernode_bond.to_string(),
        bond_owner: bond_owner.to_string(),
    })
}
