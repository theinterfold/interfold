// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    effects::{EffectParts, Effects},
    heartbeat::Heartbeat,
};
use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::BlobStore;
use e3_chain::{Account, Contracts, ReadError, Reader, Rpc, Writer};
use e3_data_availability::DataAvailabilityReader;
use e3_engine::{EffectKey, Engine};
use e3_jobs::JobRunner;
use e3_journal::Journal;
use e3_p2p::Network;
use e3_protocol::{
    node::{Input, Node, PeerMessage},
    E3Id, UnixSecs,
};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, warn};

/// How long a failed chain read waits before it runs again.
const RETRY_AFTER: Duration = Duration::from_secs(30);

/// The bonding registry's owner capacity windows start at multiples of this from Unix time zero.
const CAPACITY_WINDOW: UnixSecs = 30 * 24 * 60 * 60;
/// The first refresh waits this long after a start, so a node that restarts in a loop does not
/// refresh at each start.
const FIRST_REFRESH: Duration = Duration::from_secs(10 * 60);
/// A refresh waits this long past a window's start, so the chain's block time is past it too.
const REFRESH_MARGIN: UnixSecs = 60;
const REFRESH_AGAIN: UnixSecs = 60 * 60;

/// The node's settings from its operator.
#[derive(Clone, Debug)]
pub struct Settings {
    pub contracts: Contracts,
    /// Where a node with an empty journal starts reading: the contracts' deployment block.
    pub start_block: u64,
    pub confirmations: u64,
    pub max_log_range: u64,
    pub poll_interval: Duration,
    pub snapshot_every: u64,
    /// Jobs that hold a thread at once; the others wait without one.
    pub job_slots: usize,
}

/// What the node talks to.
pub struct Parts<R, A, N, B> {
    pub operator: PrivateKeySigner,
    pub journal: Journal,
    pub blobs: B,
    pub jobs: JobRunner<B>,
    /// The chain node the reader asks.
    pub rpc: R,
    /// The operator's account that the writer sends from.
    pub account: A,
    pub network: N,
    /// Peer messages from the network.
    pub inbound: mpsc::Receiver<PeerMessage>,
    pub availability: Arc<dyn DataAvailabilityReader>,
    pub heartbeat: Heartbeat,
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("journal: {0}")]
    Engine(#[from] e3_engine::Error),
    #[error("chain logs: {0}")]
    Chain(#[from] e3_chain::DecodeError),
    #[error("the inputs of the node stopped")]
    Stopped,
    #[error("{0} stopped unexpectedly")]
    TaskEnded(&'static str),
    #[error("{0} panicked: {1}")]
    TaskPanicked(&'static str, String),
}

pub(crate) enum Event {
    /// A chain fact or a peer message.
    Input(Input),
    /// The result of one of the node's effects: applied, then the effect is done.
    Result(EffectKey, Input),
    /// An effect that finished without a result.
    Done(EffectKey),
    Fatal(NodeError),
}

/// Runs the node until `stop` completes, or until its inputs, its journal, its chain logs or one
/// of its essential tasks fail.
pub async fn run<R, A, N, B>(
    settings: Settings,
    parts: Parts<R, A, N, B>,
    stop: impl Future<Output = ()>,
) -> Result<(), NodeError>
where
    R: Rpc + Clone + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: BlobStore,
{
    let genesis = Node::new(parts.operator.address());
    let (mut engine, pending) = Engine::open(parts.journal, genesis, settings.snapshot_every)?;
    // A stop can come between ending an E3's work and finishing its effects; that work is over.
    let (pending, over): (Vec<_>, Vec<_>) = pending.into_iter().partition(|pending| {
        engine
            .machine()
            .owes(&pending.effect.e3(), pending.effect.scope())
    });
    for pending in over {
        engine.acknowledge(pending.key)?;
    }
    sweep(&parts.blobs, engine.machine());
    let mut admitted = engine.machine().operators();
    parts.network.admit(admitted.clone());
    let chain_id = settings.contracts.chain_id;
    let from = engine
        .machine()
        .applied(chain_id)
        .map_or(settings.start_block, |at| at.block);
    let (events, mut receiver) = mpsc::channel(1_024);
    let mut contracts = settings.contracts.clone();
    let machine = engine.machine();
    contracts
        .randomness
        .extend(machine.randomness_providers(chain_id));
    contracts
        .slashing
        .extend(machine.slashing_managers(chain_id));
    let reader = Reader::new(
        parts.rpc.clone(),
        contracts,
        settings.confirmations,
        settings.max_log_range,
        from,
        settings.poll_interval,
    );
    let mut essential = JoinSet::new();
    let (heartbeat, poll, sender) = (parts.heartbeat, settings.poll_interval, events.clone());
    essential.spawn(async move {
        read_chain(reader, heartbeat, sender, poll).await;
        "the chain reader"
    });
    let sender = events.clone();
    let inbound = parts.inbound;
    essential.spawn(async move {
        forward_peers(inbound, sender).await;
        "the network"
    });
    let writer = Arc::new(Writer::new(
        parts.account,
        parts.blobs.clone(),
        settings.contracts,
    ));
    let (refresher, operator) = (writer.clone(), parts.operator.address());
    essential.spawn(async move {
        refresh_each_window(refresher, operator).await;
        "the operator refresh"
    });
    let mut effects = Effects::new(EffectParts {
        rpc: Arc::new(parts.rpc),
        operator: parts.operator,
        blobs: parts.blobs,
        jobs: Arc::new(parts.jobs),
        writer,
        network: Arc::new(parts.network),
        availability: parts.availability,
        events,
        job_slots: settings.job_slots,
    });
    let mut queue: VecDeque<Event> = effects.dispatch(pending).into();
    tokio::pin!(stop);
    loop {
        let event = match queue.pop_front() {
            Some(event) => event,
            None => tokio::select! {
                event = next_event(&mut receiver, engine.next_deadline()) => event?,
                ended = essential.join_next() => return Err(ended_task(ended)),
                () = &mut stop => {
                    // Producers first, so nothing new starts while the work stops. What did not
                    // finish stays in the outbox for the next start.
                    essential.abort_all();
                    effects.stop_all();
                    return Ok(());
                }
            },
        };
        let (input, answers) = match event {
            Event::Input(input) => (input, None),
            Event::Result(key, input) => (input, Some(key)),
            Event::Done(key) => {
                engine.acknowledge(key)?;
                continue;
            }
            Event::Fatal(error) => return Err(error),
        };
        debug!(input = %brief(&input), "applying");
        let working: BTreeSet<E3Id> = engine.machine().working().copied().collect();
        let (next, pending) = engine.apply(now(), input)?;
        engine = next;
        let operators = engine.machine().operators();
        if operators != admitted {
            effects.network.admit(operators.clone());
            admitted = operators;
        }
        if let Some(key) = answers {
            engine.acknowledge(key)?;
        }
        queue.extend(effects.dispatch(pending));
        for key in effects.stop_ended(engine.machine()) {
            engine.acknowledge(key)?;
        }
        let still: BTreeSet<&E3Id> = engine.machine().working().collect();
        for e3 in working.iter().filter(|e3| !still.contains(e3)) {
            if let Err(error) = effects.blobs.close(*e3) {
                warn!(%e3, %error, "deleting the blobs of ended work failed");
            }
            if let Err(error) = effects.jobs.close(*e3) {
                warn!(%e3, %error, "deleting the proving files of ended work failed");
            }
        }
    }
}

/// An essential task ended while the node runs: the process should end, so its supervisor can
/// restart it, rather than run on without the task.
fn ended_task(ended: Option<Result<&'static str, tokio::task::JoinError>>) -> NodeError {
    match ended {
        Some(Ok(task)) => NodeError::TaskEnded(task),
        Some(Err(error)) => NodeError::TaskPanicked("an essential task", error.to_string()),
        None => NodeError::Stopped,
    }
}

/// Refreshes the operator in each owner capacity window, right after it starts. The node does so
/// whatever the identity policy: the chain offers no view of the policy, and a refresh is a call a
/// month. A refresh counts for the window of its block, which can be the window before when it
/// lands near a window's start, so the node refreshes again an hour in.
async fn refresh_each_window<A, B>(writer: Arc<Writer<A, B>>, operator: Address)
where
    A: Account + Send + Sync + 'static,
    B: BlobStore,
{
    tokio::time::sleep(FIRST_REFRESH).await;
    loop {
        let window = now() / CAPACITY_WINDOW;
        writer.refresh_operator(operator).await;
        let again = window * CAPACITY_WINDOW + REFRESH_AGAIN;
        if now() < again {
            sleep_until(again).await;
            writer.refresh_operator(operator).await;
        }
        sleep_until((window + 1) * CAPACITY_WINDOW + REFRESH_MARGIN).await;
    }
}

async fn sleep_until(at: UnixSecs) {
    tokio::time::sleep(Duration::from_secs(at.saturating_sub(now()))).await;
}

/// Deletes the blobs of the E3s whose work `machine` no longer holds, at a start: the node closes
/// each E3 whose work ends while it runs.
fn sweep(blobs: &impl BlobStore, machine: &Node) {
    let working = |e3: &E3Id| machine.e3(e3).is_some_and(|state| state.has_work());
    if let Err(error) = blobs.retain(working) {
        warn!(%error, "deleting the blobs of ended work failed");
    }
}

/// The next event, or a tick at the machine's next deadline.
async fn next_event(
    receiver: &mut mpsc::Receiver<Event>,
    deadline: Option<UnixSecs>,
) -> Result<Event, NodeError> {
    let wait = deadline.map(|at| Duration::from_secs(at.saturating_sub(now())));
    tokio::select! {
        event = receiver.recv() => event.ok_or(NodeError::Stopped),
        _ = sleep(wait) => Ok(Event::Input(Input::Tick)),
    }
}

async fn sleep(wait: Option<Duration>) {
    match wait {
        Some(wait) => tokio::time::sleep(wait).await,
        None => std::future::pending().await,
    }
}

/// The start of a value's debug form, for logs.
pub(crate) fn brief(value: &impl std::fmt::Debug) -> String {
    let mut text = format!("{value:?}");
    if let Some((cut, _)) = text.char_indices().nth(200) {
        text.truncate(cut);
        text.push('…');
    }
    text
}

pub(crate) fn now() -> UnixSecs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

async fn read_chain<R: Rpc>(
    mut reader: Reader<R>,
    mut heartbeat: Heartbeat,
    events: mpsc::Sender<Event>,
    poll: Duration,
) {
    loop {
        let read = reader.poll().await;
        if read.is_ok() {
            heartbeat.beat(now(), reader.head(), reader.read_to());
        }
        match read {
            Ok(facts) => {
                for fact in facts {
                    if events.send(Event::Input(Input::Chain(fact))).await.is_err() {
                        return;
                    }
                }
                reader.wait().await;
            }
            Err(ReadError::Rpc(failure)) => {
                warn!(%failure, "reading the chain failed; trying again");
                tokio::time::sleep(poll.max(RETRY_AFTER)).await;
            }
            Err(ReadError::Decode(failure)) => {
                let _ = events.send(Event::Fatal(failure.into())).await;
                return;
            }
        }
    }
}

async fn forward_peers(mut inbound: mpsc::Receiver<PeerMessage>, events: mpsc::Sender<Event>) {
    while let Some(message) = inbound.recv().await {
        if events
            .send(Event::Input(Input::Announced(message)))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
