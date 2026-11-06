// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Account, Call, Contracts, Estimate, RpcError};
use alloy::{
    eips::{eip1559::Eip1559Estimation, BlockId},
    network::TransactionBuilder,
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolCall;
use e3_evm_contracts::{IBondingRegistry, IInterfold, INodeReleaseRegistry};
use e3_evm_transactions::nonce::{broadcast_refused, next_free_nonce};
use std::{
    collections::{BTreeMap, HashMap},
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
    nonces: Mutex<Nonces>,
}

#[derive(Default)]
struct Nonces {
    /// The nonces this process sent, with their send times.
    sent: BTreeMap<u64, Instant>,
    /// The last send of each call whose nonce the chain has not used yet.
    unmined: HashMap<(Address, Bytes), Sent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sent {
    nonce: u64,
    fees: Eip1559Estimation,
}

/// A call sent again while its last send waits replaces that transaction at higher fees, so it
/// does not queue behind a transaction stuck on low fees. Nodes take a replacement only for at
/// least a tenth more on both fees.
fn replacement(earlier: Sent, fees: Eip1559Estimation) -> Sent {
    let raise = |fee: u128| fee + fee / 4 + 1;
    let max_fee_per_gas = fees
        .max_fee_per_gas
        .max(raise(earlier.fees.max_fee_per_gas));
    let max_priority_fee_per_gas = fees
        .max_priority_fee_per_gas
        .max(raise(earlier.fees.max_priority_fee_per_gas))
        .min(max_fee_per_gas);
    Sent {
        nonce: earlier.nonce,
        fees: Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
    }
}

impl<P: Provider + WalletProvider> Wallet<P> {
    pub fn new(provider: P, chain_id: u64, confirmations: u64) -> Self {
        Self {
            provider,
            chain_id,
            confirmations,
            nonces: Mutex::default(),
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
    /// accepted a moment ago, so a new nonce also skips the ones this process sent recently. The
    /// turn ends before the receipt, so a slow confirmation holds up no other call.
    async fn send(&self, call: &Call, gas: u64) -> Result<bool, RpcError> {
        let fees = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(RpcError::new)?;
        let account = self.provider.default_signer_address();
        let key = (call.to, call.data.clone());
        let pending = {
            let mut nonces = self.nonces.lock().await;
            let mined = self
                .provider
                .get_transaction_count(account)
                .latest()
                .await
                .map_err(RpcError::new)?;
            nonces.unmined.retain(|_, sent| sent.nonce >= mined);
            let replaced = nonces.unmined.get(&key).copied();
            let send = match replaced {
                Some(earlier) => replacement(earlier, fees),
                None => {
                    let count = self
                        .provider
                        .get_transaction_count(account)
                        .pending()
                        .await
                        .map_err(RpcError::new)?;
                    let nonce = next_free_nonce(&mut nonces.sent, count, Instant::now());
                    Sent { nonce, fees }
                }
            };
            nonces.sent.insert(send.nonce, Instant::now());
            let request = self
                .request(call)
                .with_gas_limit(gas)
                .with_max_fee_per_gas(send.fees.max_fee_per_gas)
                .with_max_priority_fee_per_gas(send.fees.max_priority_fee_per_gas)
                .with_chain_id(self.chain_id)
                .with_nonce(send.nonce);
            match self.provider.send_transaction(request).await {
                Ok(pending) => {
                    nonces.unmined.insert(key.clone(), send);
                    pending
                }
                Err(error) => {
                    let error = alloy::contract::Error::TransportError(error);
                    if replaced.is_none() && broadcast_refused(&error) {
                        nonces.sent.remove(&send.nonce);
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
        self.nonces.lock().await.unmined.remove(&key);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fees(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Eip1559Estimation {
        Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }

    /// Nodes refuse a replacement that raises either fee by less than a tenth.
    #[test]
    fn a_retry_replaces_the_stuck_transaction_at_fees_nodes_take() {
        let earlier = Sent {
            nonce: 7,
            fees: fees(100, 10),
        };
        let again = replacement(earlier, fees(90, 9));
        assert_eq!(again.nonce, 7);
        assert!(again.fees.max_fee_per_gas * 10 >= 100 * 11);
        assert!(again.fees.max_priority_fee_per_gas * 10 >= 10 * 11);
        assert_eq!(replacement(earlier, fees(500, 50)).fees, fees(500, 50));
    }
}
