// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use anyhow::Result;
use e3_ciphernode_config::NetworkProfile;
use e3_net::events::NetEvent;
use e3_net::{Libp2pKeypair, Libp2pNetInterface, NetInterface, NetworkPolicy};
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn rejects_another_network() -> Result<()> {
    assert_rejected(
        NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?,
        NetworkPolicy::new(NetworkProfile::sepolia(), [(11_155_111, [2; 20])])?,
    )
    .await
}

#[tokio::test]
async fn rejects_another_deployment() -> Result<()> {
    assert_rejected(
        NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?,
        NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [2; 20])])?,
    )
    .await
}

async fn assert_rejected(listener: NetworkPolicy, dialer: NetworkPolicy) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    let listener_key = Libp2pKeypair::generate();
    let listener_peer = listener_key.peer_id();
    let mut listener_node = Libp2pNetInterface::new(listener_key, vec![], None, listener)?;
    let listener_handle = listener_node.handle();
    tokio::spawn(async move { listener_node.start().await });
    let address = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(address) = listener_handle
                .status()
                .snapshot()
                .listen_addresses
                .into_iter()
                .find(|address| address.starts_with("/ip4/127.0.0.1/"))
            {
                break address;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for the listener");

    let address = format!("{address}/p2p/{listener_peer}");
    let mut dialer_node =
        Libp2pNetInterface::new(Libp2pKeypair::generate(), vec![address], None, dialer)?;
    let handle = dialer_node.handle();
    let mut events = handle.rx();
    tokio::spawn(async move { dialer_node.start().await });

    timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await? {
                NetEvent::ConnectionEstablished { .. } => {
                    anyhow::bail!("incompatible peer entered the admitted network")
                }
                NetEvent::PeerRejected { reason, .. } => {
                    assert!(reason.contains("network identity"));
                    return anyhow::Ok(());
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for network rejection")?;

    Ok(())
}
