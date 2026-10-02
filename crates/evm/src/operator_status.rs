// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read-only, operator-facing on-chain status queries.

use crate::{
    adapters::log_fetcher::fetch_logs_adapting,
    contracts::{IBondingRegistry, ICiphernodeRegistry, IInterfold},
    helpers::get_current_timestamp_from_provider,
    ProviderConfig,
};
use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use anyhow::Context as _;
use e3_config::{chain_config::ChainConfig, ContractAddresses};
use e3_events::E3Stage;
use serde::Serialize;
use std::{collections::BTreeMap, str::FromStr};
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

/// Membership of an operator in a committee that holds its collateral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeMembership {
    /// Holds a provisional seat while sortition for the E3 is open.
    Candidate,
    /// Active member of the finalized committee.
    Member,
    /// Expelled from the finalized committee.
    Expelled,
}

/// A committee that holds the operator's collateral until `releaseCommittee(e3Id)` runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorCommittee {
    pub e3_id: U256,
    pub membership: CommitteeMembership,
    pub e3_stage: E3Stage,
}

/// Lists the committees that hold `operator`'s collateral, in E3 ID order.
///
/// `BondingRegistry` has no view of the obligations of one operator. It emits
/// `CommitteeObligationUpdated`, with the operator as an indexed topic, each time a registry opens
/// or releases an obligation, so the last event for an E3 tells whether the obligation is open. An
/// open obligation makes an exit claim revert with `OperatorInActiveCommittee`.
pub async fn fetch_operator_committees<P: Provider + Clone>(
    provider: &P,
    contracts: &ContractAddresses,
    operator: Address,
) -> anyhow::Result<Vec<OperatorCommittee>> {
    let interfold = contracts
        .interfold
        .address()
        .context("invalid interfold address")?;
    let interfold = IInterfold::new(interfold, provider.clone());
    let bonding_registry = contracts
        .bonding_registry
        .address()
        .context("invalid bonding_registry address")?;
    let filter = Filter::new()
        .address(bonding_registry)
        .event_signature(IBondingRegistry::CommitteeObligationUpdated::SIGNATURE_HASH)
        .topic3(operator.into_word());
    let from_block = contracts.bonding_registry.deploy_block().unwrap_or(0);
    let chain_id = provider.get_chain_id().await?;
    let head = provider.get_block_number().await?;
    let logs = fetch_logs_adapting(provider, &filter, from_block, head, chain_id).await?;

    let mut committees = Vec::new();
    for (e3_id, registry) in open_obligations(logs)? {
        // The registry that opened the obligation owns the committee of that E3.
        let registry = ICiphernodeRegistry::new(registry, provider.clone());
        let (active, member, stage) = tokio::try_join!(
            async {
                registry
                    .isCommitteeMemberActive(e3_id, operator)
                    .call()
                    .await
            },
            async { registry.isCommitteeMember(e3_id, operator).call().await },
            async { interfold.getE3Stage(e3_id).call().await },
        )?;
        // Sortition opens the obligation when it ranks the operator. Only finalization makes the
        // operator a member.
        let membership = match (active, member) {
            (true, _) => CommitteeMembership::Member,
            (false, true) => CommitteeMembership::Expelled,
            (false, false) => CommitteeMembership::Candidate,
        };
        committees.push(OperatorCommittee {
            e3_id,
            membership,
            e3_stage: E3Stage::try_from(stage)
                .with_context(|| format!("E3 {e3_id} reports a stage this node does not know"))?,
        });
    }
    Ok(committees)
}

/// Returns each E3 whose last `CommitteeObligationUpdated` log left the obligation open, with the
/// registry that sent the update.
fn open_obligations(mut logs: Vec<Log>) -> anyhow::Result<BTreeMap<U256, Address>> {
    // `eth_getLogs` does not guarantee the log order, and the last update of an E3 decides whether
    // its obligation is open.
    logs.sort_by_key(|log| (log.block_number, log.log_index));
    let mut open = BTreeMap::new();
    for log in logs {
        let event = IBondingRegistry::CommitteeObligationUpdated::decode_log_data(log.data())
            .context("invalid CommitteeObligationUpdated event")?;
        if event.active {
            open.insert(event.e3Id, event.registry);
        } else {
            open.remove(&event.e3Id);
        }
    }
    Ok(open)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obligation_log(block: u64, index: u64, e3_id: u64, registry: Address, active: bool) -> Log {
        let event = IBondingRegistry::CommitteeObligationUpdated {
            e3Id: U256::from(e3_id),
            registry,
            operator: Address::repeat_byte(0xaa),
            active,
        };
        Log {
            inner: alloy::primitives::Log {
                address: Address::repeat_byte(0xbb),
                data: event.encode_log_data(),
            },
            block_number: Some(block),
            log_index: Some(index),
            ..Default::default()
        }
    }

    #[test]
    fn open_obligations_follow_the_last_update_in_chain_order() {
        let registry = Address::repeat_byte(0x01);
        let replacement = Address::repeat_byte(0x02);
        // Provider order, not chain order.
        let logs = vec![
            // E3 1: released after the E3 ended.
            obligation_log(20, 0, 1, registry, false),
            obligation_log(10, 3, 1, registry, true),
            // E3 2: a better ticket displaced the operator in the same block.
            obligation_log(12, 1, 2, registry, false),
            obligation_log(12, 0, 2, registry, true),
            // E3 3: still open, under another registry.
            obligation_log(15, 0, 3, replacement, true),
        ];

        let open = open_obligations(logs).unwrap();

        assert_eq!(
            open.into_iter().collect::<Vec<_>>(),
            vec![(U256::from(3), replacement)]
        );
    }
}
