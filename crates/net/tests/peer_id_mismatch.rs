// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Integration test for stale peer ID handling.
//!
//! Verify that an explicit `/p2p/<peer-id>` bootstrap address pins the remote
//! identity. A node at that endpoint cannot replace the configured identity.

use std::time::Duration;

use anyhow::Result;
use e3_net::events::{NetCommand, NetEvent};
use e3_net::{Libp2pKeypair, Libp2pNetInterface, NetInterface, NetworkPolicy};
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
async fn configured_peer_id_mismatch_is_rejected() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    // Node B: the "restarted" node, listening with its real (new) identity.
    let port_b = free_udp_port();
    let mut node_b = Libp2pNetInterface::new(
        Libp2pKeypair::generate(),
        vec![],
        Some(port_b),
        NetworkPolicy::local_unrestricted(),
    )?;
    let handle_b = node_b.handle();
    tokio::spawn(async move { node_b.start().await });

    // Give B a moment to bind its QUIC listener.
    sleep(Duration::from_millis(500)).await;

    // Node A: dials B's address pinned to a STALE peer ID (B's pre-restart
    // identity), exactly like a stale routing/config entry.
    let stale_id = Libp2pKeypair::generate().peer_id();
    let stale_addr = format!("/ip4/127.0.0.1/udp/{port_b}/quic-v1/p2p/{stale_id}");
    let mut node_a = Libp2pNetInterface::new(
        Libp2pKeypair::generate(),
        vec![stale_addr],
        None,
        NetworkPolicy::local_unrestricted(),
    )?;
    let handle_a = node_a.handle();
    let mut rx_a = handle_a.rx();
    tokio::spawn(async move { node_a.start().await });

    // The dial must fail with WrongPeerId. A must not connect to B under the
    // unexpected identity.
    let mut mismatches = 0usize;
    let mut connected = false;
    let _ = timeout(Duration::from_secs(10), async {
        loop {
            let event = rx_a.recv().await?;
            if is_wrong_peer_id(&event) {
                mismatches += 1;
            }
            if matches!(event, NetEvent::ConnectionEstablished { .. }) {
                connected = true;
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    })
    .await;

    assert!(!connected, "A must reject B's unexpected identity");
    assert_eq!(
        mismatches, 1,
        "the pinned address should produce one terminal identity mismatch"
    );

    handle_a.tx().send(NetCommand::Shutdown).await?;
    handle_b.tx().send(NetCommand::Shutdown).await?;
    Ok(())
}
