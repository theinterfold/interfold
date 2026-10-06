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
    transports::RpcError,
};
use eyre::Result;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a reservation protects the lowest nonce that the chain does not count.
///
/// A reservation covers an RPC node that does not count the transaction yet, for example one node
/// behind a load balancer. The lowest nonce that the chain does not count holds every later
/// transaction of the account. If its reservation is older than this, the network dropped its
/// transaction, and the next send uses the nonce again.
const NONCE_RESERVATION: Duration = Duration::from_secs(120);

/// The limit for the work under the nonce lock: the nonce choice and the broadcast. If an RPC
/// request stops without an answer, this limit releases the lock for the other senders.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// The nonces that this process sent, with their send times, by account.
static SENT_NONCES: Mutex<BTreeMap<Address, BTreeMap<u64, Instant>>> =
    Mutex::const_new(BTreeMap::new());

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
        let account = sent.entry(from).or_default();
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
                // A node that answered with an error refused the transaction, and a local error,
                // such as a wallet that cannot sign, stops the send before the broadcast. Then no
                // transaction holds the nonce. After any other broadcast error the node can hold
                // the transaction, so the reservation stays until the chain counts the nonce or the
                // reservation expires.
                if matches!(
                    &error,
                    alloy::contract::Error::TransportError(
                        RpcError::ErrorResp(_) | RpcError::LocalUsageError(_)
                    )
                ) {
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

/// Choose the next nonce of one account: the lowest nonce, at or above the pending count of the
/// chain, that no reservation holds.
///
/// This also removes the reservations that do not apply any more. The chain counts every nonce
/// below its pending count. The reservation of the first nonce that the chain does not count
/// expires after `NONCE_RESERVATION`. A later reservation stays, because its transaction can wait in
/// the queue behind that nonce.
fn next_free_nonce(sent: &mut BTreeMap<u64, Instant>, pending: u64, now: Instant) -> u64 {
    sent.retain(|&nonce, _| nonce >= pending);
    if sent
        .get(&pending)
        .is_some_and(|&sent_at| now.duration_since(sent_at) >= NONCE_RESERVATION)
    {
        sent.remove(&pending);
    }
    let mut nonce = pending;
    while sent.contains_key(&nonce) {
        nonce += 1;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reservation keeps a nonce that the RPC does not count yet out of the next send.
    #[test]
    fn skips_nonces_that_the_rpc_does_not_count_yet() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // The RPC has not seen nonces 5 and 6 yet, so its pending count is still 5.
        assert_eq!(next_free_nonce(&mut sent, 5, now), 7);
    }

    /// The pending count of the chain wins when it is ahead, and it clears what it counts.
    #[test]
    fn follows_the_chain_past_nonces_that_it_counts() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // Another process also sent from this account, so the chain is ahead of this process.
        assert_eq!(next_free_nonce(&mut sent, 9, now), 9);
        assert!(sent.is_empty());
    }

    /// The lowest nonce that the chain does not count is used again when its reservation expires.
    #[test]
    fn uses_a_dropped_nonce_again_after_its_reservation_expires() {
        let dropped_at = Instant::now();
        let queued_at = dropped_at + Duration::from_secs(100);
        let mut sent = BTreeMap::from([(5, dropped_at), (6, queued_at)]);
        // The network dropped nonce 5, so the pending count stays at 5 and nonce 6 waits behind
        // the gap. Only the reservation keeps nonce 5 in use.
        assert_eq!(next_free_nonce(&mut sent, 5, queued_at), 7);
        assert_eq!(
            next_free_nonce(&mut sent, 5, dropped_at + NONCE_RESERVATION),
            5
        );
    }

    /// An old reservation above a dropped nonce stays, because its transaction waits in the queue.
    #[test]
    fn keeps_the_nonces_queued_behind_a_dropped_one() {
        let sent_at = Instant::now();
        let later = sent_at + 2 * NONCE_RESERVATION;
        let mut sent = BTreeMap::from([(5, sent_at), (6, sent_at), (7, sent_at)]);
        // The network dropped nonce 5. Nonces 6 and 7 wait in the queue behind it, so their old
        // reservations must not free their nonces.
        assert_eq!(next_free_nonce(&mut sent, 5, later), 5);
        sent.insert(5, later);
        // The RPC does not count the new transaction at nonce 5 yet.
        assert_eq!(next_free_nonce(&mut sent, 5, later), 8);
    }
}
