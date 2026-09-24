// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{Context, Result};
use e3_config::NetworkProfile;
use e3_events::{
    AggregateId, CorrelationId, E3id, EventConstructorWithTimestamp, EventSource, InterfoldEvent,
    KeyshareCreated, Unsequenced,
};
use e3_utils::ArcBytes;
use libp2p::{identity::Keypair, multiaddr::Protocol, Multiaddr, PeerId};
use std::time::Duration;
use tokio::{
    sync::broadcast,
    task::JoinSet,
    time::{sleep, timeout},
};

use crate::{
    direct_requester::DirectRequester,
    domain::net_event_batch::{BatchCursor, EventBatch, FetchEventsSince},
    events::{GossipData, NetCommand, NetEvent, PeerTarget},
    Libp2pKeypair, Libp2pNetInterface, NetInterface, NetInterfaceHandle, NetworkPolicy,
};

async fn launch(
    tasks: &mut JoinSet<Result<()>>,
    mut interface: Libp2pNetInterface,
) -> Result<(NetInterfaceHandle, broadcast::Receiver<NetEvent>, String)> {
    let handle = interface.handle();
    let rx = handle.rx();
    tasks.spawn(async move { interface.start().await });
    let address = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(address) = handle.status().snapshot().listen_addresses.first() {
                return address.clone();
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("peer did not start listening")?;
    Ok((handle, rx, address))
}

async fn wait_for(
    rx: &mut broadcast::Receiver<NetEvent>,
    predicate: impl Fn(&NetEvent) -> bool,
) -> Result<()> {
    timeout(Duration::from_secs(40), async {
        loop {
            let event = rx.recv().await?;
            if predicate(&event) {
                return anyhow::Ok(());
            }
        }
    })
    .await
    .context("network event timed out")?
}

#[tokio::test]
async fn bootstrap_supports_existing_peers_gossip_dht_sync_and_restart() -> Result<()> {
    let mut tasks = JoinSet::new();
    let network = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?;
    let identity = Keypair::generate_ed25519();
    let peer_id = PeerId::from(identity.public());
    let bootstrap = Libp2pNetInterface::new_bootstrap(
        Libp2pKeypair::new(identity.clone()),
        vec![],
        None,
        network.clone(),
    )?;
    let (relay, mut relay_rx, address) = launch(&mut tasks, bootstrap).await?;
    let (first, mut first_rx, _) = launch(
        &mut tasks,
        Libp2pNetInterface::new(
            Libp2pKeypair::generate(),
            vec![address.clone()],
            None,
            network.clone(),
        )?,
    )
    .await?;
    let (second, mut second_rx, _) = launch(
        &mut tasks,
        Libp2pNetInterface::new(
            Libp2pKeypair::generate(),
            vec![address.clone()],
            None,
            network.clone(),
        )?,
    )
    .await?;
    wait_for(
        &mut relay_rx,
        |event| matches!(event, NetEvent::GossipSubscribed { count, .. } if *count >= 2),
    )
    .await?;
    wait_for(&mut first_rx, |event| {
        matches!(event, NetEvent::GossipSubscribed { .. })
    })
    .await?;
    wait_for(&mut second_rx, |event| {
        matches!(event, NetEvent::GossipSubscribed { .. })
    })
    .await?;

    let requester = DirectRequester::builder(first.tx(), first.events())
        .request_timeout(Duration::from_secs(5))
        .max_retries(0)
        .build()
        .to(PeerTarget::Specific(peer_id));
    let batch: EventBatch<InterfoldEvent<Unsequenced>> = requester
        .request(FetchEventsSince::new(AggregateId::new(1), 0, 100))
        .await?;
    assert!(batch.events.is_empty());
    assert!(matches!(batch.next, BatchCursor::Done));

    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(b"bootstrap-relay-test"),
            e3_id: E3id::new("1", 1),
            node: "test".into(),
            party_id: 0,
            signed_pk_generation_proof: None,
        }
        .into(),
        None,
        1,
        None,
        EventSource::Local,
    );
    let gossip = GossipData::GossipBytes(event.to_bytes()?);
    // Wait for the normal ten-second gossip heartbeat to build the mesh.
    sleep(Duration::from_secs(11)).await;
    first
        .tx()
        .send(NetCommand::gossip_publish(
            network.protocols().gossip_topic().into(),
            gossip.clone(),
            CorrelationId::new(),
        ))
        .await?;
    wait_for(
        &mut second_rx,
        |event| matches!(event, NetEvent::GossipData(data) if data == &gossip),
    )
    .await?;

    let value = b"bootstrap-cached-document";
    let key = crate::ContentHash::from_content(value);
    first
        .tx()
        .send(NetCommand::DhtPutRecord {
            correlation_id: CorrelationId::new(),
            key: key.clone(),
            value: ArcBytes::from_bytes(value),
            expires: None,
        })
        .await?;
    wait_for(&mut first_rx, |event| {
        matches!(event, NetEvent::DhtPutRecordSucceeded { .. })
    })
    .await?;
    second
        .tx()
        .send(NetCommand::DhtGetRecord {
            correlation_id: CorrelationId::new(),
            key,
        })
        .await?;
    wait_for(&mut second_rx, |event| matches!(event, NetEvent::DhtGetRecordSucceeded { value: found, .. } if found.extract_bytes() == value)).await?;

    relay.tx().send(NetCommand::Shutdown).await?;
    timeout(Duration::from_secs(5), tasks.join_next())
        .await?
        .context("missing relay task")???;
    let port = address
        .parse::<Multiaddr>()?
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Udp(port) => Some(port),
            _ => None,
        })
        .context("bootstrap address has no UDP port")?;
    let replacement = Libp2pNetInterface::new_bootstrap(
        Libp2pKeypair::new(identity),
        vec![],
        Some(port),
        network,
    )?;
    let (_replacement, mut replacement_rx, _) = launch(&mut tasks, replacement).await?;
    wait_for(&mut replacement_rx, |event| {
        matches!(event, NetEvent::ConnectionEstablished { .. })
    })
    .await?;
    timeout(Duration::from_secs(5), async {
        while !first
            .status()
            .snapshot()
            .connected_peers
            .iter()
            .any(|peer| peer.peer_id == peer_id.to_string())
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("peer did not reconnect to the bootstrap identity")?;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[tokio::test]
async fn bootstrap_rejects_another_network() -> Result<()> {
    let mut tasks = JoinSet::new();
    let network = NetworkPolicy::new(NetworkProfile::mainnet(), [(1, [1; 20])])?;
    let (relay, _, address) = launch(
        &mut tasks,
        Libp2pNetInterface::new_bootstrap(Libp2pKeypair::generate(), vec![], None, network)?,
    )
    .await?;
    let foreign = NetworkPolicy::new(NetworkProfile::sepolia(), [(11155111, [2; 20])])?;
    let (peer, mut rx, _) = launch(
        &mut tasks,
        Libp2pNetInterface::new(Libp2pKeypair::generate(), vec![address], None, foreign)?,
    )
    .await?;
    wait_for(&mut rx, |event| {
        matches!(event, NetEvent::PeerRejected { .. })
    })
    .await?;
    assert!(relay.status().snapshot().connected_peers.is_empty());
    assert!(peer.status().snapshot().connected_peers.is_empty());
    Ok(())
}
