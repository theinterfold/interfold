// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One nonce sequence for each account that sends transactions from this process.

use alloy::{
    contract::{CallBuilder, CallDecoder},
    network::Ethereum,
    primitives::Address,
    providers::{PendingTransactionBuilder, Provider},
};
use e3_utils::nonce::{broadcast_refused, next_free_nonce};
use eyre::Result;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// The limit for the work under the nonce lock: the nonce choice and the broadcast. If an RPC
/// request stops without an answer, this limit releases the lock for the other senders.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

type Reservations = BTreeMap<(u64, Address), BTreeMap<u64, Instant>>;

/// The nonces that this process sent, with their send times, by chain and account.
static SENT_NONCES: Mutex<Reservations> = Mutex::const_new(BTreeMap::new());

/// The reservations of one account on one chain. A signer that sends on two chains has an
/// independent nonce sequence on each, so one chain's reservations must not move the other's.
fn account_reservations(
    sent: &mut Reservations,
    chain_id: u64,
    from: Address,
) -> &mut BTreeMap<u64, Instant> {
    sent.entry((chain_id, from)).or_default()
}

/// Send `call` from `from` with the next free nonce of that account.
///
/// Every transaction that the helpers of this crate send takes its nonce here. A caller in another
/// crate that sends from the same key must use this function too. Then concurrent sends from one
/// account in this process take different nonces, although each send builds its own provider. A
/// transaction from another process is visible only in the pending count of the chain.
///
/// The lock covers the nonce choice and the broadcast only. The caller waits for the receipt after
/// the lock is released, so several transactions of one account can wait for inclusion at the same
/// time.
///
/// It sets the gas limit, the EIP-1559 fees, and the chain ID of `call` from the node before it
/// reserves the nonce, so values that the caller set on `call` are replaced.
pub async fn send_with_next_nonce<P, D>(
    call: CallBuilder<P, D>,
    from: Address,
) -> Result<PendingTransactionBuilder<Ethereum>>
where
    P: Provider<Ethereum>,
    D: CallDecoder,
{
    let mut sent = SENT_NONCES.lock().await;
    let send = async {
        // Fill the transaction before its nonce is reserved, so that the send below only signs
        // and broadcasts it. A failure before the broadcast sends nothing and reserves nothing.
        let call = call.from(from);
        let gas = call.estimate_gas().await?;
        let fees = call.provider.estimate_eip1559_fees().await?;
        let chain_id = call.provider.get_chain_id().await?;
        let pending = call.provider.get_transaction_count(from).pending().await?;
        let account = account_reservations(&mut sent, chain_id, from);
        let nonce = next_free_nonce(account, pending, Instant::now());
        // Reserve the nonce before the broadcast. If the send stops during the broadcast, the node
        // can hold the transaction, and the reservation keeps later sends off its nonce.
        account.insert(nonce, Instant::now());
        let call = call
            .gas(gas)
            .max_fee_per_gas(fees.max_fee_per_gas)
            .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .chain_id(chain_id)
            .nonce(nonce);
        match call.send().await {
            Ok(transaction) => Ok(transaction),
            Err(error) => {
                // The nonce is free only when the send left no transaction with the node. Otherwise
                // the reservation stays until the chain counts the nonce or it expires.
                if broadcast_refused(&error) {
                    account.remove(&nonce);
                }
                Err(eyre::Report::new(error))
            }
        }
    };
    tokio::time::timeout(SEND_TIMEOUT, send)
        .await
        .map_err(|_| eyre::eyre!("timed out while sending a transaction from {from}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One signer on two chains: a reservation on one chain does not move the other chain's nonce.
    #[test]
    fn keeps_the_reservations_of_each_chain_apart() {
        let now = Instant::now();
        let signer = Address::repeat_byte(7);
        let mut sent = Reservations::new();
        let mainnet = account_reservations(&mut sent, 1, signer);
        let nonce = next_free_nonce(mainnet, 0, now);
        mainnet.insert(nonce, now);
        assert_eq!(nonce, 0);
        let sepolia = account_reservations(&mut sent, 11_155_111, signer);
        assert_eq!(next_free_nonce(sepolia, 0, now), 0);
        let mainnet = account_reservations(&mut sent, 1, signer);
        assert_eq!(next_free_nonce(mainnet, 0, now), 1);
    }
}
