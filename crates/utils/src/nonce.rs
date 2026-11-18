// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The nonce choice for one account that sends transactions from this process.

use alloy::{contract::Error, transports::RpcError};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

/// How long a reservation protects the lowest nonce that the chain does not count.
///
/// A reservation covers an RPC node that does not count the transaction yet, for example one node
/// behind a load balancer. The lowest nonce that the chain does not count holds every later
/// transaction of the account. If its reservation is older than this, the network dropped its
/// transaction, and the next send uses the nonce again.
pub const NONCE_RESERVATION: Duration = Duration::from_secs(120);

/// Choose the next nonce of one account: the lowest nonce, at or above the pending count of the
/// chain, that no reservation holds.
///
/// `sent` holds the nonces that this process sent from the account, with their send times. This
/// also removes the reservations that do not apply any more. A reservation below the pending count
/// stays until it expires: the node that answered counts the nonce, but another node behind the
/// same endpoint can lag and answer a lower count. The reservation of the first nonce that the
/// chain does not count expires after `NONCE_RESERVATION`. A later reservation stays, because its
/// transaction can wait in the queue behind that nonce.
pub fn next_free_nonce(sent: &mut BTreeMap<u64, Instant>, pending: u64, now: Instant) -> u64 {
    sent.retain(|&nonce, &mut sent_at| {
        nonce >= pending || now.duration_since(sent_at) < NONCE_RESERVATION
    });
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

/// Whether a failed send left no transaction with the node, so that its nonce is free again.
///
/// A node that answered with an error refused the transaction, and a local error stops the send
/// before the broadcast. An answer that the node already knows the transaction is the exception: it
/// holds the transaction, for example from a retried request. After any other error the node can
/// hold the transaction.
pub fn broadcast_refused(error: &Error) -> bool {
    match error {
        Error::TransportError(RpcError::LocalUsageError(_)) => true,
        Error::TransportError(RpcError::ErrorResp(payload)) => {
            let message: String = payload
                .message
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .map(|c| c.to_ascii_lowercase())
                .collect();
            !["alreadyknown", "knowntransaction", "alreadyimported"]
                .iter()
                .any(|known| message.contains(known))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::rpc::json_rpc::ErrorPayload;
    use alloy::transports::TransportErrorKind;

    /// A node behind the same endpoint that lags answers a lower pending count. A nonce that
    /// another node already counts stays reserved for it.
    #[test]
    fn keeps_a_counted_nonce_reserved_for_a_lagging_node() {
        let now = Instant::now();
        let mut sent = BTreeMap::new();
        for pending in [5, 6, 5] {
            let nonce = next_free_nonce(&mut sent, pending, now);
            sent.insert(nonce, now);
        }
        assert_eq!(sent.keys().copied().collect::<Vec<_>>(), vec![5, 6, 7]);
    }

    /// Only an error answer that refuses the transaction, or a local error, frees its nonce.
    #[test]
    fn a_node_that_knows_the_transaction_holds_its_nonce() {
        let answer = |message: &'static str| {
            Error::TransportError(RpcError::ErrorResp(ErrorPayload::internal_error_message(
                message.into(),
            )))
        };
        assert!(broadcast_refused(&answer("nonce too low")));
        assert!(broadcast_refused(&answer(
            "insufficient funds for gas * price + value"
        )));
        assert!(!broadcast_refused(&answer("already known")));
        assert!(!broadcast_refused(&answer("AlreadyKnown")));
        assert!(!broadcast_refused(&answer(
            "Transaction with the same hash was already imported."
        )));
        assert!(!broadcast_refused(&Error::TransportError(
            TransportErrorKind::custom_str("connection reset")
        )));
    }

    /// A reservation keeps a nonce that the RPC does not count yet out of the next send.
    #[test]
    fn skips_nonces_that_the_rpc_does_not_count_yet() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // The RPC has not seen nonces 5 and 6 yet, so its pending count is still 5.
        assert_eq!(next_free_nonce(&mut sent, 5, now), 7);
    }

    /// The pending count of the chain wins when it is ahead. The nonces that it counts stay
    /// reserved until their reservations expire.
    #[test]
    fn follows_the_chain_past_nonces_that_it_counts() {
        let now = Instant::now();
        let mut sent = BTreeMap::from([(5, now), (6, now)]);
        // Another process also sent from this account, so the chain is ahead of this process.
        assert_eq!(next_free_nonce(&mut sent, 9, now), 9);
        assert_eq!(next_free_nonce(&mut sent, 9, now + NONCE_RESERVATION), 9);
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
