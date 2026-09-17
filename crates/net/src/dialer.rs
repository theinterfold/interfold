// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use futures::future::join_all;
use libp2p::{
    swarm::{dial_opts::DialOpts, ConnectionId, DialError},
    Multiaddr,
};
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, Duration};
use tracing::debug;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::{
    events::{NetCommand, NetEvent, PeerRejectionKind},
    NetEventSender,
};
use e3_utils::{to_retry, OnceTake, RetryError};

const INITIAL_DIAL_ATTEMPTS: u32 = 3;
const INITIAL_DIAL_DELAY: Duration = Duration::from_secs(3);
const BOOTSTRAP_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum time to wait for a swarm result from one connection attempt.
const DIAL_EVENT_TIMEOUT: Duration = Duration::from_secs(20);

enum InitialDialError {
    Retryable(anyhow::Error),
    Permanent(anyhow::Error),
}

/// Dial one address during the bounded startup phase.
async fn dial_multiaddr(
    cmd_tx: &mpsc::Sender<NetCommand>,
    event_tx: &NetEventSender,
    multiaddr_str: &str,
) -> std::result::Result<(), InitialDialError> {
    let multiaddr: Multiaddr = multiaddr_str
        .parse()
        .map_err(|error: libp2p::multiaddr::Error| InitialDialError::Permanent(error.into()))?;
    info!(%multiaddr, "Dialing a configured bootstrap peer");
    let mut delay = INITIAL_DIAL_DELAY;

    for attempt in 1..=INITIAL_DIAL_ATTEMPTS {
        match attempt_connection(cmd_tx, event_tx, &multiaddr).await {
            Ok(peer_id) => {
                cmd_tx
                    .send(NetCommand::ConfiguredPeerAdmitted {
                        address: multiaddr,
                        peer_id,
                    })
                    .await
                    .map_err(|error| InitialDialError::Retryable(error.into()))?;
                return Ok(());
            }
            Err(RetryError::Failure(error)) => {
                return Err(InitialDialError::Permanent(error));
            }
            Err(RetryError::Retry(error)) if attempt == INITIAL_DIAL_ATTEMPTS => {
                return Err(InitialDialError::Retryable(anyhow::anyhow!(
                    "bootstrap dial failed after {INITIAL_DIAL_ATTEMPTS} attempts: {error}"
                )));
            }
            Err(RetryError::Retry(error)) => {
                debug!(
                    %multiaddr,
                    attempt,
                    max_attempts = INITIAL_DIAL_ATTEMPTS,
                    retry_delay_ms = delay.as_millis(),
                    %error,
                    "Bootstrap dial failed; the startup retry will continue"
                );
                sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
        }
    }

    unreachable!("the startup dial loop always returns")
}

async fn retry_multiaddr_in_background(
    cmd_tx: mpsc::Sender<NetCommand>,
    event_tx: NetEventSender,
    multiaddr_str: String,
) {
    let Ok(multiaddr) = multiaddr_str.parse() else {
        debug!(address = %multiaddr_str, "Bootstrap address is invalid; background retry stopped");
        return;
    };

    loop {
        sleep(BOOTSTRAP_RETRY_INTERVAL).await;
        match attempt_connection(&cmd_tx, &event_tx, &multiaddr).await {
            Ok(peer_id) => {
                if cmd_tx
                    .send(NetCommand::ConfiguredPeerAdmitted {
                        address: multiaddr.clone(),
                        peer_id,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                info!(%multiaddr, "Connected to a bootstrap peer after a background retry");
                return;
            }
            Err(RetryError::Failure(error)) => {
                debug!(%multiaddr, %error, "Bootstrap dial cannot be retried");
                return;
            }
            Err(RetryError::Retry(error)) => {
                debug!(
                    %multiaddr,
                    retry_interval_secs = BOOTSTRAP_RETRY_INTERVAL.as_secs(),
                    %error,
                    "Background bootstrap dial failed"
                );
            }
        }
    }
}

/// Initiates connections to multiple network peers
///
/// # Arguments
/// * `cmd_tx` - Sender for network peer commands
/// * `event_tx` - Broadcast sender for peer events
/// * `peers` - List of peer addresses to connect to
///
/// # Returns
/// The number of peers that were successfully connected to.
pub async fn dial_peers(
    cmd_tx: &mpsc::Sender<NetCommand>,
    event_tx: &NetEventSender,
    peers: &[String],
) -> Result<usize> {
    let futures: Vec<_> = peers
        .iter()
        .map(|addr| dial_multiaddr(cmd_tx, event_tx, addr))
        .collect();
    let results = join_all(futures).await;
    let connected = results.iter().filter(|r| r.is_ok()).count();
    let unavailable: Vec<_> = peers
        .iter()
        .zip(results)
        .filter_map(|(address, result)| result.err().map(|error| (address.clone(), error)))
        .collect();
    let retryable = unavailable
        .iter()
        .filter(|(_, error)| matches!(error, InitialDialError::Retryable(_)))
        .count();

    if retryable > 0 {
        warn!(
            unavailable = retryable,
            total = peers.len(),
            retry_interval_secs = BOOTSTRAP_RETRY_INTERVAL.as_secs(),
            "Some bootstrap peers are unavailable; background retries will continue"
        );
    }
    for (address, error) in unavailable {
        match error {
            InitialDialError::Retryable(error) => {
                debug!(%address, %error, "Initial bootstrap dial did not connect");
                tokio::spawn(retry_multiaddr_in_background(
                    cmd_tx.clone(),
                    event_tx.clone(),
                    address,
                ));
            }
            InitialDialError::Permanent(error) => {
                debug!(%address, %error, "Configured bootstrap dial cannot be retried");
            }
        }
    }
    Ok(connected)
}

/// Attempt a connection with retries to a multiaddr.
async fn attempt_connection(
    cmd_tx: &mpsc::Sender<NetCommand>,
    event_tx: &NetEventSender,
    multiaddr: &Multiaddr,
) -> Result<libp2p::PeerId, RetryError> {
    let mut event_rx = event_tx.subscribe();
    let opts: DialOpts = multiaddr.clone().into();
    let dial_connection = opts.connection_id();
    trace!(
        "Dialing: '{}' with connection '{}'",
        multiaddr,
        dial_connection
    );
    cmd_tx
        .send(NetCommand::Dial(OnceTake::new(opts)))
        .await
        .map_err(|error| RetryError::Failure(error.into()))?;
    wait_for_connection(&mut event_rx, dial_connection).await
}

/// Wait for results of a retry based on a given correlation id and return the correct variant of
/// RetryError depending on the result from the downstream event
async fn wait_for_connection(
    event_rx: &mut broadcast::Receiver<NetEvent>,
    dial_connection: ConnectionId,
) -> Result<libp2p::PeerId, RetryError> {
    loop {
        // Create a timeout future that can be reset
        select! {
            result = event_rx.recv() => {
                match result.map_err(to_retry)? {
                    NetEvent::ConfiguredDialAdmitted { connection_id, peer_id } => {
                        if connection_id == dial_connection {
                            trace!("Connection Established");
                            return Ok(peer_id);
                        }
                    }
                    NetEvent::PeerRejected {
                        connection_id,
                        kind,
                        reason,
                    } => {
                        if connection_id == dial_connection {
                            let error = std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                reason,
                            );
                            return match kind {
                                PeerRejectionKind::Transient => {
                                    Err(RetryError::Retry(error.into()))
                                }
                                PeerRejectionKind::Permanent => {
                                    Err(RetryError::Failure(error.into()))
                                }
                            };
                        }
                    }
                    NetEvent::DialError { error } => {
                        return match error.as_ref() {
                            DialError::NoAddresses => {
                                Err(RetryError::Failure(error.clone().into()))
                            }
                            _ => Err(RetryError::Retry(error.clone().into())),
                        };
                    }
                    NetEvent::OutgoingConnectionError {
                        connection_id,
                        error,
                    } => {
                        trace!("OutgoingConnectionError!");
                        if connection_id == dial_connection {
                            return match error.as_ref() {
                                DialError::NoAddresses => {
                                    Err(RetryError::Failure(error.clone().into()))
                                }
                                // The peer at this address has a different identity than
                                // the /p2p/ component in the multiaddr pins — retrying the
                                // same address can never succeed. The swarm event handler
                                // has already re-keyed the routing entry to the new peer.
                                DialError::WrongPeerId { .. } => {
                                    debug!(
                                        "Connection {} failed: {}. Not retrying stale address.",
                                        connection_id, error
                                    );
                                    Err(RetryError::Failure(error.clone().into()))
                                }
                                _ => Err(RetryError::Retry(error.clone().into())),
                            };
                        }
                    }
                    _ => (),
                }
            }
            _ = sleep(DIAL_EVENT_TIMEOUT) => {
                return Err(RetryError::Retry(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connection attempt timed out after {DIAL_EVENT_TIMEOUT:?}"),
                ).into()));
            }
        }
    }
}
