// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context, Result};
use e3_events::{
    CorrelationId, E3id, Event, EventConstructorWithTimestamp, EventSource, InterfoldEvent,
    InterfoldEventData, KeyshareCreated, Unsequenced,
};
use e3_net::events::{GossipData, NetCommand, NetEvent};
use e3_net::{ContentHash, Libp2pKeypair, Libp2pNetInterface, NetInterface};
use e3_utils::ArcBytes;
use libp2p::gossipsub::IdentTopic;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use std::{env, process};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{sleep, timeout};
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};

async fn test_dht(peer: &mut TestPeer) -> Result<()> {
    let value = b"I am he as you are he, as you are me and we are all together";
    let key = ContentHash::from_content(value);
    peer.sync_nodes().await?;
    if peer.is_lead() {
        // PUT RECORD
        peer.tx
            .send(NetCommand::DhtPutRecord {
                correlation_id: CorrelationId::new(),
                key: key.clone(),
                value: ArcBytes::from_bytes(value),
                expires: None,
            })
            .await?;
        receive_until_collect(
            &mut peer.rx,
            |e| matches!(e, NetEvent::DhtPutRecordSucceeded { .. }),
            Duration::from_secs(15),
        )
        .await?;
    }
    // GET RECORD
    peer.tx
        .send(NetCommand::DhtGetRecord {
            correlation_id: CorrelationId::new(),
            key,
        })
        .await?;
    let events = receive_until_collect(
        &mut peer.rx,
        |e| matches!(e, NetEvent::DhtGetRecordSucceeded { .. }),
        Duration::from_secs(15),
    )
    .await?;
    let Some(NetEvent::DhtGetRecordSucceeded { value: actual, .. }) = events.last() else {
        return Err(anyhow::anyhow!(
            "Failed to receive success from GET RECORD!"
        ));
    };
    assert_eq!(
        value.to_vec(),
        actual.extract_bytes(),
        "Value does not match!"
    );
    peer.sync_nodes().await?;
    Ok(())
}

async fn receive_until_collect<T, F>(
    rx: &mut broadcast::Receiver<T>,
    predicate: F,
    timeout_duration: Duration,
) -> Result<Vec<T>>
where
    T: Clone,
    F: Fn(&T) -> bool,
{
    let result = timeout(timeout_duration, async {
        let mut results = Vec::new();
        loop {
            let value = rx.recv().await?;
            let matches = predicate(&value);
            results.push(value);
            if matches {
                return Ok::<Vec<T>, broadcast::error::RecvError>(results);
            }
        }
    })
    .await
    .context("Timeout waiting for predicate")?
    .context("Failed to receive from channel")?;
    Ok(result)
}

async fn runner() -> Result<Vec<String>> {
    let mut peer = TestPeer::setup().await?;
    let mut report = vec![];
    // DHT test
    test_dht(&mut peer).await?;
    report.push("DHT Test");
    peer.tx.send(NetCommand::Shutdown).await?;
    sleep(Duration::from_secs(20)).await;

    // Write report
    let report_string = report
        .iter()
        .map(|line| format!("\x1b[32m✓\x1b[0m {}", line))
        .collect::<Vec<String>>();

    Ok(report_string)
}

// Universal counter to keep nodes in sync
static COUNTER: AtomicU8 = AtomicU8::new(0);

fn get_next_id() -> u8 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct TestPeer {
    name: String,
    sync_threshold: usize,
    rx: broadcast::Receiver<NetEvent>,
    tx: mpsc::Sender<NetCommand>,
    topic: IdentTopic,
    test_timeout: Option<Duration>,
}

static START_SYNC: &[u8] = b"START_SYNC";
static SYNC: &[u8] = b"SYNC";
static END_SYNC: &[u8] = b"END_SYNC";

impl TestPeer {
    // This helps:
    // - ensure nodes are connected and in communication for our tests.
    // - prevents nodes from quitting early before a test has completed if they are not the leader.
    // - tests the gossip pubsub in general
    pub async fn sync_nodes(&mut self) -> Result<()> {
        sleep(Duration::from_secs(2)).await;
        let id = get_next_id();
        if self.is_lead() {
            info!("LEAD IS SYNCING id={}", id);
            let threshold = self.sync_threshold - 1;
            self.send_msg(START_SYNC, id).await?;
            for node in 0..threshold {
                info!(
                    "SYNC: Waiting for reply {}/{} for id={} ...",
                    node + 1,
                    threshold,
                    id
                );
                self.wait_for_msg(SYNC, id).await?;
            }
            self.send_msg(END_SYNC, id).await?;
            info!("LEAD SYNCED for id={}!", id);
        } else {
            info!("FOLLOWER IS SYNCING for id={}", id);
            self.wait_for_msg(START_SYNC, id).await?;
            self.send_msg(SYNC, id).await?;
            self.wait_for_msg(END_SYNC, id).await?;
            info!("FOLLOWER SYNCED for id={}!", id);
        }
        sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    pub async fn send_msg(&self, marker: &[u8], id: u8) -> Result<()> {
        let data = network_signal(&self.name, marker, id)?;
        Ok(self
            .tx
            .send(NetCommand::GossipPublish {
                correlation_id: CorrelationId::new(),
                topic: self.topic.to_string(),
                data,
            })
            .await?)
    }

    pub async fn wait_for_msg(&mut self, marker: &[u8], id: u8) -> Result<Vec<NetEvent>> {
        receive_until_collect(
            &mut self.rx,
            |e| match e {
                NetEvent::GossipData(data) => is_network_signal(data, marker, id),
                _ => false,
            },
            self.test_timeout.unwrap_or(Duration::from_secs(120)),
        )
        .await
    }

    pub fn is_lead(&self) -> bool {
        env::var("TEST_CONFIG").unwrap_or_default().contains("lead")
    }

    async fn setup() -> Result<TestPeer> {
        let name = env::args().nth(1).expect("need name");

        let udp_port = env::var("QUIC_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok());

        let dial_to = env::var("DIAL_TO")
            .ok()
            .and_then(|p| p.parse::<String>().ok());

        let sync_threshold = env::var("SYNC_THRESHOLD")
            .ok()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(3);

        let peers: Vec<String> = dial_to.iter().cloned().collect();
        let keypair = Libp2pKeypair::generate();
        let network = e3_net::NetworkPolicy::local_unrestricted();
        let topic = IdentTopic::new(network.protocols().gossip_topic());
        let mut peer = Libp2pNetInterface::new(keypair, peers, udp_port, network)?;
        let handle = peer.handle();
        let tx = handle.tx();
        let mut rx = handle.rx();

        tokio::spawn({
            let name = name.clone();
            async move {
                println!("{} starting router task", name);
                if let Err(e) = peer.start().await {
                    println!("{} router task failed: {}", name, e);
                }
                println!("{} router task finished", name);
            }
        });

        println!("WAIT FOR MESH READY...");
        wait_for_mesh_ready(60, 3, &mut rx, &topic).await?;
        println!("MESH READY!");

        // Give network time to initialize
        sleep(Duration::from_secs(3)).await;

        Ok(TestPeer {
            name,
            tx,
            rx,
            sync_threshold,
            topic,
            test_timeout: None,
        })
    }
}

const TEST_CHAIN_ID: u64 = 31_337;

fn network_signal(name: &str, marker: &[u8], id: u8) -> Result<GossipData> {
    let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&signal_payload(marker, id)),
            e3_id: signal_e3_id(id),
            node: name.to_string(),
            party_id: u64::from(id),
            signed_pk_generation_proof: None,
            roster_hash: [0; 32],
        }
        .into(),
        None,
        u128::from(id),
        None,
        EventSource::Local,
    );
    Ok(GossipData::GossipBytes(event.to_bytes()?))
}

fn is_network_signal(data: &GossipData, marker: &[u8], id: u8) -> bool {
    let GossipData::GossipBytes(bytes) = data else {
        return false;
    };
    let Ok(event) = InterfoldEvent::<Unsequenced>::from_bytes(bytes) else {
        return false;
    };
    matches!(
        event.get_data(),
        InterfoldEventData::KeyshareCreated(signal)
            if signal.e3_id == signal_e3_id(id)
                && signal.pubkey.extract_bytes() == signal_payload(marker, id)
    )
}

fn signal_e3_id(id: u8) -> E3id {
    E3id::new(id.to_string(), TEST_CHAIN_ID)
}

fn signal_payload(marker: &[u8], id: u8) -> Vec<u8> {
    let mut payload = marker.to_vec();
    payload.push(id);
    payload
}

async fn wait_for_mesh_ready(
    seconds: u64,
    min_size: usize,
    rx: &mut broadcast::Receiver<NetEvent>,
    topic: &IdentTopic,
) -> Result<()> {
    let topic_hash = topic.hash();
    loop {
        match timeout(Duration::from_secs(seconds), rx.recv()).await {
            Ok(Ok(NetEvent::GossipSubscribed { count, topic })) => {
                info!(
                    "Received GossipSubscribed with count={}/{} topic={}",
                    count, min_size, topic
                );
                if topic_hash == topic && count >= min_size {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_e) => return Err(anyhow::anyhow!("MESH SYNC FAILED!")),
            _ => (),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match runner().await {
        Ok(report) => {
            print!("\n\n<<< TEST REPORT >>>\n---------------------------\n{}\n\n---------------------------\n\n",report.join("\n"));
            process::exit(0);
        }
        Err(e) => {
            print!("\n\n<<< FAILURE REPORT >>>\n---------------------------\n{}\n\n---------------------------\n\n",e);
            process::exit(1);
        }
    }
}
