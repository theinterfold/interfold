// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use anyhow::{Context, Result};
use e3_net::events::{NetCommand, NetEvent};
use e3_net::{Libp2pKeypair, Libp2pNetInterface, NetInterface, NetInterfaceHandle, NetworkPolicy};
use tokio::time::{sleep, timeout};

fn free_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    Ok(socket.local_addr()?.port())
}

async fn wait_for_connection(rx: &mut tokio::sync::broadcast::Receiver<NetEvent>) -> Result<()> {
    timeout(Duration::from_secs(45), async {
        loop {
            if matches!(rx.recv().await?, NetEvent::ConnectionEstablished { .. }) {
                return Ok(());
            }
        }
    })
    .await
    .context("configured peer did not connect before the deadline")?
}

async fn wait_for_gossip_subscription(handle: &NetInterfaceHandle) -> Result<()> {
    timeout(Duration::from_secs(15), async {
        loop {
            if handle.status().snapshot().gossip_subscribed_peers == 1 {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("configured peer did not establish its gossip subscription")
}

async fn reconnect_after_restart(pinned: bool) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = identity.public().to_peer_id();
    let port = free_udp_port()?;

    let mut remote = Libp2pNetInterface::new(
        Libp2pKeypair::new(identity.clone()),
        vec![],
        Some(port),
        NetworkPolicy::local_unrestricted(),
    )?;
    let remote_handle = remote.handle();
    let remote_task = tokio::spawn(async move { remote.start().await });
    sleep(Duration::from_millis(500)).await;

    let mut address = format!("/ip4/127.0.0.1/udp/{port}/quic-v1");
    if pinned {
        address.push_str(&format!("/p2p/{peer_id}"));
    }
    let mut local = Libp2pNetInterface::new(
        Libp2pKeypair::generate(),
        vec![address],
        None,
        NetworkPolicy::local_unrestricted(),
    )?;
    let local_handle = local.handle();
    let mut local_events = local_handle.rx();
    let local_task = tokio::spawn(async move { local.start().await });
    wait_for_connection(&mut local_events)
        .await
        .context("initial configured dial")?;
    wait_for_gossip_subscription(&local_handle)
        .await
        .context("initial configured dial")?;

    remote_handle.tx().send(NetCommand::Shutdown).await?;
    remote_task.await??;
    drop(remote_handle);
    timeout(Duration::from_secs(5), async {
        loop {
            if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("old peer did not release its UDP port")?;
    timeout(Duration::from_secs(15), async {
        while !local_handle.status().snapshot().connected_peers.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("configured peer did not disconnect")?;

    let mut restarted = Libp2pNetInterface::new(
        Libp2pKeypair::new(identity),
        vec![],
        Some(port),
        NetworkPolicy::local_unrestricted(),
    )?;
    let restarted_handle = restarted.handle();
    let restarted_task = tokio::spawn(async move { restarted.start().await });
    sleep(Duration::from_millis(500)).await;
    if restarted_task.is_finished() {
        restarted_task.await??;
        anyhow::bail!("restarted peer exited before redial");
    }
    assert!(!restarted_handle
        .status()
        .snapshot()
        .listen_addresses
        .is_empty());
    wait_for_connection(&mut local_events)
        .await
        .context("configured peer redial after restart")?;
    assert_eq!(local_handle.status().snapshot().connected_peers.len(), 1);
    wait_for_gossip_subscription(&local_handle)
        .await
        .context("configured peer redial after restart")?;

    local_handle.tx().send(NetCommand::Shutdown).await?;
    restarted_handle.tx().send(NetCommand::Shutdown).await?;
    local_task.await??;
    restarted_task.await??;
    Ok(())
}

#[tokio::test]
async fn pinned_configured_peer_reconnects_after_remote_restart() -> Result<()> {
    reconnect_after_restart(true).await
}

#[tokio::test]
async fn unpinned_configured_peer_reconnects_after_remote_restart() -> Result<()> {
    reconnect_after_restart(false).await
}
