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
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::events::{NetCommand, NetEvent};
use e3_utils::{retry_with_backoff, to_retry, OnceTake, RetryError};

const DIAL_DELAY: u64 = 3000;
const DIAL_RETRIES: u32 = 10;

/// Per-connection timeout: if no swarm events arrive within this window during
/// a single dial attempt, we treat it as timed out and retry.
const DIAL_EVENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Dial a single Multiaddr with retries and return an error should those retries not work
async fn dial_multiaddr(
    cmd_tx: &mpsc::Sender<NetCommand>,
    event_tx: &broadcast::Sender<NetEvent>,
    multiaddr_str: &str,
) -> Result<()> {
    let multiaddr = &multiaddr_str.parse()?;
    info!("Now dialing in to {}", multiaddr);
    retry_with_backoff(
        || attempt_connection(cmd_tx, event_tx, multiaddr),
        DIAL_RETRIES,
        DIAL_DELAY,
    )
    .await?;
    Ok(())
}

fn trace_error(r: Result<()>) {
    if let Err(err) = r {
        error!("{}", err);
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
    event_tx: &broadcast::Sender<NetEvent>,
    peers: &[String],
) -> Result<usize> {
    let futures: Vec<_> = peers
        .iter()
        .map(|addr| dial_multiaddr(cmd_tx, event_tx, addr))
        .collect();
    let results = join_all(futures).await;
    let connected = results.iter().filter(|r| r.is_ok()).count();
    results.into_iter().for_each(trace_error);
    Ok(connected)
}

/// Attempt a connection with retries to a multiaddr.
async fn attempt_connection(
    cmd_tx: &mpsc::Sender<NetCommand>,
    event_tx: &broadcast::Sender<NetEvent>,
    multiaddr: &Multiaddr,
) -> Result<(), RetryError> {
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
        .map_err(to_retry)?;
    wait_for_connection(&mut event_rx, dial_connection).await
}

/// Wait for results of a retry based on a given correlation id and return the correct variant of
/// RetryError depending on the result from the downstream event
async fn wait_for_connection(
    event_rx: &mut broadcast::Receiver<NetEvent>,
    dial_connection: ConnectionId,
) -> Result<(), RetryError> {
    loop {
        // Create a timeout future that can be reset
        select! {
            result = event_rx.recv() => {
                match result.map_err(to_retry)? {
                    NetEvent::ConnectionEstablished { connection_id } => {
                        if connection_id == dial_connection {
                            trace!("Connection Established");
                            return Ok(());
                        }
                    }
                    NetEvent::DialError { error } => {
                        warn!("DialError!");
                        return match error.as_ref() {
                            // If we are dialing ourself then we should just fail
                            DialError::NoAddresses => {
                                warn!("DialError received. Returning RetryError::Failure");
                                Err(RetryError::Failure(error.clone().into()))
                            }
                            // Try again otherwise
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
                                // If we are dialing ourself then we should just fail
                                DialError::NoAddresses => {
                                    Err(RetryError::Failure(error.clone().into()))
                                }
                                // The peer at this address has a different identity than
                                // the /p2p/ component in the multiaddr pins — retrying the
                                // same address can never succeed. The swarm event handler
                                // has already re-keyed the routing entry to the new peer.
                                DialError::WrongPeerId { .. } => {
                                    warn!(
                                        "Connection {} failed: {}. Not retrying stale address.",
                                        connection_id, error
                                    );
                                    Err(RetryError::Failure(error.clone().into()))
                                }
                                // Try again otherwise
                                _ => {
                                    warn!(
                                        "Connection {} failed because of error {}. Retrying...",
                                        connection_id, error
                                    );
                                    Err(RetryError::Retry(error.clone().into()))
                                }
                            };
                        }
                    }
                    _ => (),
                }
            }
            _ = sleep(DIAL_EVENT_TIMEOUT) => {
                warn!("Connection attempt timed out after {:?} of no events", DIAL_EVENT_TIMEOUT);
                return Err(RetryError::Retry(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connection attempt timed out",
                ).into()));
            }
        }
    }
}
