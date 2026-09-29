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
use eyre::Result;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a sent nonce stays reserved for its transaction.
///
/// A reservation covers an RPC node that does not count the transaction yet, for example one node
/// behind a load balancer. After the reservation expires, the pending count of the chain decides
/// alone. That count includes a transaction that is still in the mempool. It does not include a
/// transaction that the network dropped, so the next send uses the dropped nonce again, and the
/// later transactions of the account can execute.
const NONCE_RESERVATION: Duration = Duration::from_secs(120);

/// The limit for one send: the wait for the nonce lock, the nonce choice, and the broadcast. If an
/// RPC request stops without an answer, this limit releases the lock for the other senders.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// The nonces that this process sent, with their send times, by account.
static SENT_NONCES: Mutex<BTreeMap<Address, BTreeMap<u64, Instant>>> =
    Mutex::const_new(BTreeMap::new());

/// Send `call` from `from` with the next free nonce of that account.
///
/// Every transaction that the helpers of this crate send takes its nonce here. A caller in another
/// crate that sends from the same key must use this function too. Then concurrent sends from one
/// account never take the same nonce, although each send builds its own provider.
///
/// The lock covers the nonce choice and the broadcast only. The caller waits for the receipt after
/// the lock is released, so several transactions of one account can wait for inclusion at the same
/// time.
pub async fn send_with_next_nonce<P, D>(
    call: CallBuilder<P, D>,
    from: Address,
) -> Result<PendingTransactionBuilder<Ethereum>>
where
    P: Provider<Ethereum>,
    D: CallDecoder,
{
    tokio::time::timeout(SEND_TIMEOUT, async move {
        let mut sent = SENT_NONCES.lock().await;
        let pending = call.provider.get_transaction_count(from).pending().await?;
        let account = sent.entry(from).or_default();
        let nonce = next_free_nonce(account, pending, Instant::now());
        let transaction = call.nonce(nonce).send().await?;
        account.insert(nonce, Instant::now());
        Ok(transaction)
    })
    .await
    .map_err(|_| eyre::eyre!("timed out while sending a transaction from {from}"))?
}

/// Choose the next nonce of one account: the lowest nonce, at or above the pending count of the
/// chain, that no reservation holds.
///
/// This also removes the reservations that do not apply any more. The chain already counts a nonce
/// below its pending count, and a reservation expires after `NONCE_RESERVATION`.
fn next_free_nonce(sent: &mut BTreeMap<u64, Instant>, pending: u64, now: Instant) -> u64 {
    sent.retain(|&nonce, &mut sent_at| {
        nonce >= pending && now.duration_since(sent_at) < NONCE_RESERVATION
    });
    let mut nonce = pending;
    while sent.contains_key(&nonce) {
        nonce += 1;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_nonces_that_the_rpc_does_not_count_yet() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // The RPC has not seen nonces 5 and 6 yet, so its pending count is still 5.
        assert_eq!(next_free_nonce(&mut sent, 5, now), 7);
    }

    #[test]
    fn follows_the_chain_past_nonces_that_it_counts() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // Another process also sent from this account, so the chain is ahead of this process.
        assert_eq!(next_free_nonce(&mut sent, 9, now), 9);
        assert!(sent.is_empty());
    }

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
}
