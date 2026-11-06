// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Account, Call, Contracts, Estimate, RpcError};
use alloy::{
    eips::BlockId,
    network::TransactionBuilder,
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use e3_evm_contracts::{IBondingRegistry, IInterfold, INodeReleaseRegistry};
use e3_evm_transactions::nonce::{broadcast_refused, next_free_nonce};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a send waits for its receipt before the writer checks the chain again.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(300);

/// The operator's account on one chain over JSON-RPC. Calls run concurrently; only choosing a
/// nonce and broadcasting take turns. Its view of the chain is the reader's: a call is checked
/// against the confirmed head and counts as landed once its block is confirmed, so no reorg the
/// reader would survive undoes a call the writer finished.
pub struct Wallet<P> {
    provider: P,
    chain_id: u64,
    /// Blocks closer to the head than this may still be replaced.
    confirmations: u64,
    /// The nonces this process sent, with their send times.
    sent: Mutex<BTreeMap<u64, Instant>>,
}

impl<P: Provider + WalletProvider> Wallet<P> {
    pub fn new(provider: P, chain_id: u64, confirmations: u64) -> Self {
        Self {
            provider,
            chain_id,
            confirmations,
            sent: Mutex::new(BTreeMap::new()),
        }
    }

    fn request(&self, call: &Call) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(self.provider.default_signer_address())
            .with_to(call.to)
            .with_input(call.data.clone())
    }
}

impl<P: Provider + WalletProvider + Send + Sync> Account for Wallet<P> {
    async fn estimate(&self, call: &Call) -> Result<Estimate, RpcError> {
        let head = self
            .provider
            .get_block_number()
            .await
            .map_err(RpcError::new)?;
        let confirmed = BlockId::number(head.saturating_sub(self.confirmations));
        match self
            .provider
            .estimate_gas(self.request(call))
            .block(confirmed)
            .await
        {
            Ok(gas) => Ok(Estimate::Gas(gas)),
            Err(error) => match error
                .as_error_resp()
                .and_then(|reply| reply.as_revert_data())
            {
                Some(revert) => Ok(Estimate::Reverts(revert)),
                None => Err(RpcError::new(error)),
            },
        }
    }

    /// Fees are estimated before the nonce is chosen, so the turn only signs and broadcasts. An
    /// RPC node's pending count can miss a transaction that another node behind the same endpoint
    /// accepted a moment ago, so the nonce also skips the ones this process sent recently. The
    /// turn ends before the receipt, so a slow confirmation holds up no other call.
    async fn send(&self, call: &Call, gas: u64) -> Result<bool, RpcError> {
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(RpcError::new)?;
        let request = self
            .request(call)
            .with_gas_limit(gas)
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_chain_id(self.chain_id);
        let pending = {
            let mut sent = self.sent.lock().await;
            let count = self
                .provider
                .get_transaction_count(self.provider.default_signer_address())
                .pending()
                .await
                .map_err(RpcError::new)?;
            let nonce = next_free_nonce(&mut sent, count, Instant::now());
            sent.insert(nonce, Instant::now());
            match self
                .provider
                .send_transaction(request.with_nonce(nonce))
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    let error = alloy::contract::Error::TransportError(error);
                    if broadcast_refused(&error) {
                        sent.remove(&nonce);
                    }
                    return Err(RpcError::new(error));
                }
            }
        };
        let receipt = pending
            .with_required_confirmations(self.confirmations + 1)
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(RpcError::new)?;
        Ok(receipt.status())
    }
}

/// The node release this build is. The registries count an operator active only once it
/// acknowledged a release the chain accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    pub id: B256,
    pub protocol_version: u32,
    pub node_generation: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error(
        "the chain requires protocol {protocol} and node generation {generation} or later; \
         this node is protocol {ours_protocol}, generation {ours_generation}"
    )]
    Unsupported {
        protocol: u32,
        generation: u32,
        ours_protocol: u32,
        ours_generation: u32,
    },
    #[error("acknowledging the release reverted")]
    Reverted,
    #[error(transparent)]
    Rpc(#[from] RpcError),
}

impl<P: Provider + WalletProvider + Send + Sync> Wallet<P> {
    /// Acknowledges `release` for the operator, unless the release registry has it already and the
    /// operator is active or not registered. A chain that requires another protocol, or a later
    /// node generation, cannot run this node.
    pub async fn acknowledge_release(
        &self,
        contracts: &Contracts,
        release: Release,
    ) -> Result<(), ReleaseError> {
        let operator = self.provider.default_signer_address();
        let address = IInterfold::new(contracts.interfold, &self.provider)
            .nodeReleaseRegistry()
            .call()
            .await
            .map_err(RpcError::new)?;
        let registry = INodeReleaseRegistry::new(address, &self.provider);
        let protocol = registry
            .requiredProtocolVersion()
            .call()
            .await
            .map_err(RpcError::new)?;
        let generation = registry
            .requiredNodeGeneration()
            .call()
            .await
            .map_err(RpcError::new)?;
        if protocol != release.protocol_version || release.node_generation < generation {
            return Err(ReleaseError::Unsupported {
                protocol,
                generation,
                ours_protocol: release.protocol_version,
                ours_generation: release.node_generation,
            });
        }
        let acknowledged = registry
            .operatorNodeRelease(operator)
            .call()
            .await
            .map_err(RpcError::new)?;
        let bonding = IBondingRegistry::new(contracts.bonding, &self.provider);
        let registered = bonding
            .isRegistered(operator)
            .call()
            .await
            .map_err(RpcError::new)?;
        let active = bonding
            .isActive(operator)
            .call()
            .await
            .map_err(RpcError::new)?;
        let current = acknowledged.releaseId == release.id
            && acknowledged.protocolVersion == release.protocol_version
            && acknowledged.nodeGeneration == release.node_generation;
        if current && (!registered || active) {
            return Ok(());
        }
        let call = Call {
            label: "acknowledgeNodeRelease",
            to: address,
            data: INodeReleaseRegistry::acknowledgeNodeReleaseCall {
                releaseId: release.id,
                protocolVersion: release.protocol_version,
                nodeGeneration: release.node_generation,
            }
            .abi_encode()
            .into(),
            gas_multiplier: 2,
            not_yet: &[],
        };
        let Estimate::Gas(gas) = self.estimate(&call).await? else {
            return Err(ReleaseError::Reverted);
        };
        match self
            .send(&call, gas.saturating_mul(call.gas_multiplier))
            .await?
        {
            true => Ok(()),
            false => Err(ReleaseError::Reverted),
        }
    }
}
