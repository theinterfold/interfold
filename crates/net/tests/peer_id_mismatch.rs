// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Integration test for stale peer ID handling.
//!
//! Reproduces the scenario where a node restarts with new keys: other nodes
//! still hold a multiaddr pinning the old `/p2p/<peer-id>`, so dialing it
//! fails with `DialError::WrongPeerId`. The expected behaviour is that the
//! stale routing entry is replaced exactly once (no retry storm, no
//! bootstrap-fueled redial loop) and the dialer then connects to the node
//! under its new identity via the re-keyed routing entry.

use std::time::Duration;

use anyhow::Result;
use e3_net::events::{NetCommand, NetEvent};
use e3_net::{Libp2pKeypair, Libp2pNetInterface, NetInterface};
use libp2p::swarm::DialError;
use tokio::time::{sleep, timeout};

/// Grab a free UDP port by binding to port 0 and dropping the socket.
fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    socket.local_addr().expect("local addr").port()
}

fn is_wrong_peer_id(event: &NetEvent) -> bool {
    matches!(
        event,
        NetEvent::OutgoingConnectionError { error, .. }
            if matches!(error.as_ref(), DialError::WrongPeerId { .. })
    )
}

#[tokio::test]
async fn stale_peer_id_is_replaced_once_and_connection_recovers() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    // Node B: the "restarted" node, listening with its real (new) identity.
    let port_b = free_udp_port();
    let mut node_b =
        Libp2pNetInterface::new(Libp2pKeypair::generate(), vec![], Some(port_b), "test")?;
    let handle_b = node_b.handle();
    tokio::spawn(async move { node_b.start().await });

    // Give B a moment to bind its QUIC listener.
    sleep(Duration::from_millis(500)).await;

    // Node A: dials B's address pinned to a STALE peer ID (B's pre-restart
    // identity), exactly like a stale routing/config entry.
    let stale_id = Libp2pKeypair::generate().peer_id();
    let stale_addr = format!("/ip4/127.0.0.1/udp/{port_b}/quic-v1/p2p/{stale_id}");
    let mut node_a =
        Libp2pNetInterface::new(Libp2pKeypair::generate(), vec![stale_addr], None, "test")?;
    let handle_a = node_a.handle();
    let mut rx_a = handle_a.rx();
    tokio::spawn(async move { node_a.start().await });

    // Phase 1: the dial must fail with WrongPeerId, then A must recover and
    // connect to B under its real identity (via the re-keyed routing entry
    // and the bootstrap triggered by the first mismatch).
    let mut mismatches = 0usize;
    let mut connected = false;
    timeout(Duration::from_secs(30), async {
        loop {
            let event = rx_a.recv().await?;
            if is_wrong_peer_id(&event) {
                mismatches += 1;
            }
            if matches!(event, NetEvent::ConnectionEstablished { .. }) {
                connected = true;
                break;
            }
        }
        anyhow::Ok(())
    })
    .await
    .expect("timed out waiting for A to recover and connect to B")?;

    assert!(connected, "A should connect to B under its new identity");
    assert_eq!(
        mismatches, 1,
        "stale routing entry should be replaced after a single WrongPeerId"
    );

    // Phase 2: quiet window. The old behaviour redialed the stale address
    // (dialer retries every ~3s + bootstrap loop), flooding WrongPeerId
    // errors. After the fix there must be no further mismatches.
    let extra_mismatches = {
        let mut count = 0usize;
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let event = rx_a.recv().await?;
                if is_wrong_peer_id(&event) {
                    count += 1;
                }
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        })
        .await; // timeout here is the success path
        count
    };
    assert_eq!(
        extra_mismatches, 0,
        "no further WrongPeerId errors should occur after the entry is replaced"
    );

    handle_a.tx().send(NetCommand::Shutdown).await?;
    handle_b.tx().send(NetCommand::Shutdown).await?;
    Ok(())
}
