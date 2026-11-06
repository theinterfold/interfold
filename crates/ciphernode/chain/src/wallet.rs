// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{Account, Call, Estimate, RpcError};
use alloy::{
    network::TransactionBuilder,
    providers::{Provider, WalletProvider},
    rpc::types::TransactionRequest,
};
use e3_evm_transactions::nonce::{broadcast_refused, next_free_nonce};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a send waits for its receipt before the writer checks the chain again.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(300);

/// The operator's account on one chain over JSON-RPC. Calls run concurrently; only choosing a
/// nonce and broadcasting take turns.
pub struct Wallet<P> {
    provider: P,
    chain_id: u64,
    /// The nonces this process sent, with their send times.
    sent: Mutex<BTreeMap<u64, Instant>>,
}

impl<P: Provider + WalletProvider> Wallet<P> {
    pub fn new(provider: P, chain_id: u64) -> Self {
        Self {
            provider,
            chain_id,
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
        match self.provider.estimate_gas(self.request(call)).await {
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
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(RpcError::new)?;
        Ok(receipt.status())
    }
}
