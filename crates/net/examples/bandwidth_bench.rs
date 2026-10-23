// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bandwidth benchmark node. It sends the DKG document traffic of one E3 through the production
//! event converter, document publisher and network interface, and writes what it sent and
//! received as JSON. `bandwidth_bench.sh` next to this file runs one node per container and shapes
//! each uplink.
//!
//! Each member publishes one encryption key (C0) document to all members and one threshold-share
//! document to each other member, as a DKG dealer does. The payloads are padded to the configured
//! sizes with incompressible bytes, so the documents have the real wire format and size.
//!
//! `bandwidth_bench` runs a node, configured by the `BENCH_*` variables in [`Config::from_env`].
//! `bandwidth_bench summarize <dir>` prints the results of one run.

use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix::{Actor, Context, Handler};
use anyhow::{bail, Context as _, Result};
use e3_event_system::EventSystem;
use e3_events::{
    prelude::*, AggregateConfig, AggregateId, E3id, EncryptionKey, EncryptionKeyCreated, EventType,
    InterfoldEvent, InterfoldEventData, SyncEnded, ThresholdShare, ThresholdShareCreated,
};
use e3_net::{
    events::NetEvent, setup_net_interface, DocumentPublisher, EventConverter, Libp2pKeypair,
    NetInterface, NetworkPolicy, RecoveredDocumentState,
};
use e3_trbfv::shares::BfvEncryptedShares;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use tokio::{sync::broadcast::error::RecvError, time::sleep};

const CHAIN_ID: u64 = 31_337;
/// Bytes that the variant tag of the network document enum adds to the encoded event.
const DOCUMENT_TAG_BYTES: u64 = 4;
const TRAFFIC_SAMPLE: Duration = Duration::from_secs(1);
const KIND_ENCRYPTION_KEY: u32 = 0;
const KIND_THRESHOLD_SHARE: u32 = 1;

struct Config {
    index: usize,
    committee: usize,
    dial: Vec<String>,
    quic_port: u16,
    start_at_ms: u64,
    deadline: Duration,
    out: PathBuf,
    encryption_key_bytes: usize,
    threshold_share_bytes: usize,
    interface: String,
    uplink_mbit: Option<f64>,
    /// Run to the deadline, also after every member has every document: the publishers keep
    /// refreshing their documents until the DKG ends, as nodes do before the key is published.
    hold: bool,
}

impl Config {
    fn from_env() -> Result<Self> {
        let var = |name: &str| env::var(name).with_context(|| format!("{name} is not set"));
        let bytes = |name: &str, default: usize| {
            env::var(name).map_or(Ok(default), |value| value.parse::<usize>())
        };
        Ok(Self {
            index: var("BENCH_INDEX")?.parse()?,
            committee: var("BENCH_COMMITTEE")?.parse()?,
            dial: env::var("BENCH_DIAL")
                .unwrap_or_default()
                .split(',')
                .filter(|address| !address.is_empty())
                .map(str::to_owned)
                .collect(),
            quic_port: env::var("BENCH_QUIC_PORT").map_or(Ok(9091), |port| port.parse())?,
            start_at_ms: var("BENCH_START_AT_MS")?.parse()?,
            deadline: Duration::from_secs(var("BENCH_DEADLINE_SECS")?.parse()?),
            out: var("BENCH_OUT")?.into(),
            // E3-2 sizes (secure parameters, N = 19).
            encryption_key_bytes: bytes("BENCH_C0_BYTES", 152_633)?,
            threshold_share_bytes: bytes("BENCH_SHARE_BYTES", 1_776_213)?,
            interface: env::var("BENCH_IFACE").unwrap_or_else(|_| "eth0".into()),
            uplink_mbit: env::var("BENCH_UPLINK_MBIT")
                .ok()
                .and_then(|value| value.parse().ok()),
            hold: env::var("BENCH_HOLD").is_ok_and(|value| value == "1"),
        })
    }

    fn party(&self) -> Option<u64> {
        (self.index < self.committee).then_some(self.index as u64)
    }

    /// Documents this member receives: one of each kind from every other member.
    fn expected(&self) -> usize {
        let kinds = usize::from(self.encryption_key_bytes > 0)
            + usize::from(self.threshold_share_bytes > 0);
        self.party().map_or(0, |_| (self.committee - 1) * kinds)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Receipt {
    dealer: u64,
    kind: u32,
    ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NodeReport {
    index: usize,
    party: Option<u64>,
    committee: usize,
    uplink_mbit: Option<f64>,
    connected_at_start: usize,
    gossip_peers_at_start: usize,
    expected: usize,
    received: Vec<Receipt>,
    /// Times of this node's puts that another peer acknowledged and served back.
    put_successes: Vec<u64>,
    /// Times and errors of this node's failed puts.
    put_errors: Vec<(u64, String)>,
    /// Times of this node's document fetches that succeeded and that failed.
    get_successes: Vec<u64>,
    get_errors: Vec<(u64, String)>,
    bus_errors: Vec<String>,
    lagged_events: u64,
    /// Interface counters since the start: (ms, tx bytes, rx bytes).
    traffic: Vec<(u64, u64, u64)>,
    received_all_ms: Option<u64>,
    ended_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Incompressible bytes, the same for the same seed (SplitMix64).
fn noise(bytes: usize, seed: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(bytes + 8);
    let mut state = seed;
    while value.len() < bytes {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    value.truncate(bytes);
    value
}

/// Padding that makes an event encode to `bytes` document bytes.
fn padding<T: Serialize>(bytes: usize, unpadded: &T, seed: u64) -> Result<Vec<u8>> {
    let base = DOCUMENT_TAG_BYTES + bincode::serialized_size(unpadded)?;
    Ok(noise((bytes as u64).saturating_sub(base) as usize, seed))
}

fn threshold_share(
    e3_id: &E3id,
    dealer: u64,
    recipient: u64,
    bytes: usize,
) -> Result<ThresholdShareCreated> {
    let event = |pk_share: &[u8]| ThresholdShareCreated {
        e3_id: e3_id.clone(),
        share: Arc::new(ThresholdShare {
            party_id: dealer,
            pk_share: ArcBytes::from_bytes(pk_share),
            sk_sss: BfvEncryptedShares::default(),
            esi_sss: vec![],
        }),
        target_party_id: recipient,
        external: false,
        signed_c2a_proof: None,
        signed_c2b_proof: None,
        signed_c3a_proofs: vec![],
        signed_c3b_proofs: vec![],
        signature: ArcBytes::from_bytes(&[]),
    };
    let seed = (dealer << 32) | (recipient << 8) | u64::from(KIND_THRESHOLD_SHARE);
    Ok(event(&padding(bytes, &event(&[]), seed)?))
}

fn encryption_key(e3_id: &E3id, dealer: u64, bytes: usize) -> Result<EncryptionKeyCreated> {
    let event = |pk_bfv: &[u8]| EncryptionKeyCreated {
        e3_id: e3_id.clone(),
        key: Arc::new(EncryptionKey::new(dealer, ArcBytes::from_bytes(pk_bfv))),
        external: false,
    };
    let seed = (dealer << 32) | u64::from(KIND_ENCRYPTION_KEY);
    Ok(event(&padding(bytes, &event(&[]), seed)?))
}

fn read_counter(interface: &str, name: &str) -> u64 {
    fs::read_to_string(format!("/sys/class/net/{interface}/statistics/{name}"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Records the documents that the event converter decodes, and the errors on the bus.
struct Recorder {
    start_at_ms: u64,
    report: Arc<Mutex<NodeReport>>,
}

impl Actor for Recorder {
    type Context = Context<Self>;
}

impl Handler<InterfoldEvent> for Recorder {
    type Result = ();

    fn handle(&mut self, event: InterfoldEvent, _: &mut Self::Context) {
        let ms = now_ms().saturating_sub(self.start_at_ms);
        let mut report = self.report.lock().unwrap();
        let receipt = match event.get_data() {
            InterfoldEventData::ThresholdShareCreated(share) if share.external => Some(Receipt {
                dealer: share.share.party_id,
                kind: KIND_THRESHOLD_SHARE,
                ms,
            }),
            InterfoldEventData::EncryptionKeyReceived(received) => Some(Receipt {
                dealer: received.key.party_id,
                kind: KIND_ENCRYPTION_KEY,
                ms,
            }),
            InterfoldEventData::InterfoldError(error) => {
                if report.bus_errors.len() < 200 {
                    report.bus_errors.push(format!("{ms} {error}"));
                }
                None
            }
            _ => None,
        };
        if let Some(receipt) = receipt {
            report.received.push(receipt);
            if report.received.len() == report.expected {
                report.received_all_ms = Some(ms);
            }
        }
    }
}

/// A short name for a fetch error, without the peer list.
fn get_error_kind(error: &libp2p::kad::GetRecordError) -> &'static str {
    match error {
        libp2p::kad::GetRecordError::NotFound { .. } => "NotFound",
        libp2p::kad::GetRecordError::QuorumFailed { .. } => "QuorumFailed",
        libp2p::kad::GetRecordError::Timeout { .. } => "Timeout",
    }
}

async fn run_node(config: Config) -> Result<()> {
    let e3_id = E3id::new("1", CHAIN_ID);
    let party = config.party();
    let report = Arc::new(Mutex::new(NodeReport {
        index: config.index,
        party,
        committee: config.committee,
        uplink_mbit: config.uplink_mbit,
        expected: config.expected(),
        ..Default::default()
    }));

    let system = EventSystem::new()
        .with_fresh_bus()
        .with_aggregate_config(AggregateConfig::new(HashMap::from([(
            AggregateId::from_chain_id(Some(CHAIN_ID)),
            Duration::ZERO,
        )])));
    let bus = system.handle()?.enable(&format!("bench-{}", config.index));
    let recorder = Recorder {
        start_at_ms: config.start_at_ms,
        report: report.clone(),
    }
    .start();
    for event_type in [
        EventType::ThresholdShareCreated,
        EventType::EncryptionKeyReceived,
        EventType::InterfoldError,
    ] {
        bus.subscribe(event_type, recorder.clone().recipient());
    }

    let network = NetworkPolicy::local_unrestricted();
    let topic = network.protocols().gossip_topic().to_owned();
    let interface = setup_net_interface(
        network,
        Libp2pKeypair::generate(),
        config.dial.clone(),
        config.quic_port,
        e3_net::DEFAULT_MAX_BUFFERED_NET_EVENTS,
    )?;
    let status = interface.status();
    let interests = party
        .map(|party| HashMap::from([(e3_id.clone(), party)]))
        .unwrap_or_default();
    // The production order: the publisher starts before effects, the converter with them, and
    // publications start at `SyncEnded`.
    DocumentPublisher::setup_before_effects(
        &bus,
        &interface.tx(),
        &interface.application_events(),
        topic,
        interests,
        RecoveredDocumentState::default(),
    );
    EventConverter::setup(&bus);
    bus.publish_without_context(SyncEnded::new())?;

    let mut encryption_keys = Vec::new();
    let mut threshold_shares = Vec::new();
    if let Some(dealer) = party {
        if config.encryption_key_bytes > 0 {
            encryption_keys.push(encryption_key(&e3_id, dealer, config.encryption_key_bytes)?);
        }
        if config.threshold_share_bytes > 0 {
            for recipient in (0..config.committee as u64).filter(|recipient| *recipient != dealer) {
                threshold_shares.push(threshold_share(
                    &e3_id,
                    dealer,
                    recipient,
                    config.threshold_share_bytes,
                )?);
            }
        }
    }

    // Record put and fetch results from the raw event channel.
    let mut events = interface.rx();
    tokio::spawn({
        let report = report.clone();
        let start_at_ms = config.start_at_ms;
        async move {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(RecvError::Lagged(missed)) => {
                        report.lock().unwrap().lagged_events += missed;
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                let ms = now_ms().saturating_sub(start_at_ms);
                let mut report = report.lock().unwrap();
                match event {
                    NetEvent::DhtPutRecordSucceeded { .. } => report.put_successes.push(ms),
                    NetEvent::DhtPutRecordError { error, .. } => {
                        report.put_errors.push((ms, format!("{error:?}")))
                    }
                    NetEvent::DhtGetRecordSucceeded { .. } => report.get_successes.push(ms),
                    NetEvent::DhtGetRecordError { error, .. } => report
                        .get_errors
                        .push((ms, get_error_kind(&error).to_owned())),
                    _ => {}
                }
            }
        }
    });

    let wait = config.start_at_ms.saturating_sub(now_ms());
    sleep(Duration::from_millis(wait)).await;
    let snapshot = status.snapshot();
    {
        let mut report = report.lock().unwrap();
        report.connected_at_start = snapshot.connected_peers.len();
        report.gossip_peers_at_start = snapshot.gossip_subscribed_peers;
    }
    let base = (
        read_counter(&config.interface, "tx_bytes"),
        read_counter(&config.interface, "rx_bytes"),
    );
    // A dealer sends its encryption key first and its threshold shares after it, as in the DKG.
    for event in encryption_keys {
        bus.publish_without_context(event)?;
    }
    for event in threshold_shares {
        bus.publish_without_context(event)?;
    }

    // Run until every member has every document, or until the deadline. Members mark completion
    // in the shared output directory, so that every node keeps serving until the last one is done.
    let done_marker = |index: usize| config.out.join(format!("done-{index}"));
    let mut marked = false;
    loop {
        let elapsed = now_ms().saturating_sub(config.start_at_ms);
        let complete = {
            let mut report = report.lock().unwrap();
            report.traffic.push((
                elapsed,
                read_counter(&config.interface, "tx_bytes").saturating_sub(base.0),
                read_counter(&config.interface, "rx_bytes").saturating_sub(base.1),
            ));
            report.received_all_ms.is_some()
        };
        if complete && !marked {
            fs::write(done_marker(config.index), elapsed.to_string())?;
            marked = true;
        }
        if (!config.hold && (0..config.committee).all(|index| done_marker(index).exists()))
            || Duration::from_millis(elapsed) >= config.deadline
        {
            break;
        }
        sleep(TRAFFIC_SAMPLE).await;
    }

    let mut report = report.lock().unwrap();
    report.ended_ms = now_ms().saturating_sub(config.start_at_ms);
    let path = config.out.join(format!("node-{}.json", config.index));
    fs::write(&path, serde_json::to_vec(&*report)?)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn seconds(ms: Option<u64>) -> String {
    ms.map_or("-".into(), |ms| format!("{:.0}", ms as f64 / 1000.0))
}

fn summarize(dir: &Path) -> Result<()> {
    let mut reports = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.starts_with("node-") && name.ends_with(".json") {
            reports.push(serde_json::from_slice::<NodeReport>(&fs::read(&path)?)?);
        }
    }
    reports.sort_by_key(|report| report.index);
    let Some(first) = reports.first() else {
        bail!("no node reports in {}", dir.display());
    };
    let members: Vec<_> = reports.iter().filter(|r| r.party.is_some()).collect();
    let recipients = first.committee.saturating_sub(1);

    // When each recipient got each document of each dealer, by dealer and kind.
    let mut delivered: BTreeMap<(u64, u32), Vec<u64>> = BTreeMap::new();
    for report in &members {
        for receipt in &report.received {
            delivered
                .entry((receipt.dealer, receipt.kind))
                .or_default()
                .push(receipt.ms);
        }
    }
    println!(
        "{} nodes, {} members. Each member publishes one encryption key document for all members \
         and one threshold share for each of the {recipients} others, and receives {} documents. \
         Times are seconds after the start.",
        reports.len(),
        members.len(),
        first.expected
    );
    println!(
        "node | party | uplink Mbit/s | its shares delivered | its C0 delivered | half its shares at | all its shares at | uploads ok | uploads failed | fetches ok | fetches failed | got every document at | tx MB | rx MB"
    );
    for report in &reports {
        let last = report.traffic.last().copied().unwrap_or_default();
        let times = |kind| {
            let mut times = report
                .party
                .and_then(|party| delivered.get(&(party, kind)).cloned())
                .unwrap_or_default();
            times.sort_unstable();
            times
        };
        let shares = times(KIND_THRESHOLD_SHARE);
        let keys = times(KIND_ENCRYPTION_KEY);
        // The ceil(n/2)-th and the n-th arrival of the dealer's shares.
        let arrival =
            |count: usize| (count > 0 && shares.len() >= count).then(|| shares[count - 1]);
        let expected = if report.party.is_some() {
            recipients
        } else {
            0
        };
        println!(
            "{:>4} | {:>5} | {:>6} | {:>3}/{:<3} | {:>3}/{:<3} | {:>5} | {:>5} | {:>4} | {:>4} | {:>4} | {:>4} | {:>5} | {:>7.1} | {:>7.1}",
            report.index,
            report.party.map_or("-".into(), |p| p.to_string()),
            report
                .uplink_mbit
                .map_or("-".into(), |mbit| format!("{mbit}")),
            shares.len(),
            expected,
            keys.len(),
            expected,
            seconds(arrival(expected.div_ceil(2))),
            seconds(arrival(expected)),
            report.put_successes.len(),
            report.put_errors.len(),
            report.get_successes.len(),
            report.get_errors.len(),
            seconds(report.received_all_ms),
            last.1 as f64 / 1e6,
            last.2 as f64 / 1e6,
        );
    }
    let complete: Vec<_> = members.iter().filter_map(|r| r.received_all_ms).collect();
    println!(
        "members with every document: {}/{}; the last at {} s",
        complete.len(),
        members.len(),
        seconds(complete.iter().max().copied())
    );
    Ok(())
}

#[actix::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("summarize") => summarize(Path::new(&args.next().context("need a directory")?)),
        None => run_node(Config::from_env()?).await,
        Some(other) => bail!("unknown command {other}"),
    }
}
