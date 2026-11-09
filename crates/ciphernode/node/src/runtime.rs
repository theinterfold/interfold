// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    effects::{EffectParts, Effects},
    heartbeat::Heartbeat,
    notes::NoteFeed,
    status::{self, Board},
};
use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::BlobStore;
use e3_chain::{Account, Contracts, ReadError, Reader, Rpc, Writer};
use e3_data_availability::DataAvailabilityReader;
use e3_engine::{EffectKey, Engine};
use e3_jobs::JobRunner;
use e3_journal::Journal;
use e3_p2p::{Inbox, Network};
use e3_protocol::{
    node::{Classified, Input, Node},
    E3Id, UnixSecs,
};
use e3_utils::limited::Limited;
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
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
/// A log line about messages the node dropped comes at most this often.
const REFUSED_LOG: Duration = Duration::from_secs(60);
/// How often the status page's picture of the node is brought up to date.
const BOARD_UPDATE: Duration = Duration::from_secs(5);

/// The node's settings from its operator.
#[derive(Clone, Debug)]
pub struct Settings {
    pub contracts: Contracts,
    /// Where a node with an empty journal starts reading: the contracts' deployment block.
    pub start_block: u64,
    pub confirmations: u64,
    pub max_log_range: u64,
    pub poll_interval: Duration,
    /// How long the reader may go without a successful read before it has first caught up.
    pub startup_timeout: Duration,
    pub snapshot_every: u64,
    /// Where the read-only status page is served, if anywhere.
    pub status_port: Option<u16>,
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
    /// Peer messages from the network, read one at a time when the node is ready for one.
    pub inbox: Inbox,
    pub availability: Arc<dyn DataAvailabilityReader>,
    pub heartbeat: Heartbeat,
    pub notes: NoteFeed,
    /// Where `notes` keeps its feed, which the status page reads.
    pub notes_dir: PathBuf,
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
    #[error(
        "no read of the chain succeeded for {waited:?} before the node first caught up: {failure}"
    )]
    ChainSilent { waited: Duration, failure: String },
}

pub(crate) enum Event {
    /// A chain fact or a peer message.
    Input(Input),
    /// The result of one of the node's effects: applied, then the effect is done.
    Result(EffectKey, Input),
    /// An effect that finished without a result.
    Done(EffectKey),
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
    let genesis_operator = parts.operator.address();
    let genesis = Node::new(genesis_operator);
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
    let board = Board::new(genesis_operator, chain_id);
    let _status = settings.status_port.map(|port| {
        let serving = status::serve(port, board.clone(), parts.notes_dir.clone());
        AbortOnDrop(tokio::spawn(serving))
    });
    let mut essential: JoinSet<NodeError> = JoinSet::new();
    let (heartbeat, poll, sender) = (parts.heartbeat, settings.poll_interval, events.clone());
    let startup_timeout = settings.startup_timeout;
    essential.spawn(read_chain(
        reader,
        heartbeat,
        board.clone(),
        sender,
        poll,
        startup_timeout,
    ));
    let writer = Arc::new(Writer::new(
        parts.account,
        parts.blobs.clone(),
        settings.contracts,
    ));
    let (refresher, operator) = (writer.clone(), parts.operator.address());
    essential.spawn(async move {
        refresh_each_window(refresher, operator).await;
        NodeError::TaskEnded("the operator refresh")
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
        notes: parts.notes,
        job_slots: settings.job_slots,
    });
    let mut queue: VecDeque<Event> = effects.dispatch(pending).into();
    let inbox = parts.inbox;
    let refused = Limited::new(REFUSED_LOG);
    let mut board_update = tokio::time::interval(BOARD_UPDATE);
    tokio::pin!(stop);
    loop {
        let event = match queue.pop_front() {
            Some(event) => event,
            None => tokio::select! {
                event = next_event(&mut receiver, engine.next_deadline()) => event?,
                message = inbox.next() => {
                    let Some(message) = message else {
                        return Err(NodeError::TaskEnded("the network"));
                    };
                    if engine.machine().classify(now(), &message) == Classified::Drop {
                        if let Some(held_back) = refused.pass() {
                            debug!(e3 = %message.e3, held_back, "a peer's message is of no use");
                        }
                        continue;
                    }
                    Event::Input(Input::Announced(message))
                }
                _ = board_update.tick() => {
                    board.machine(engine.machine());
                    board.peers(effects.network.connected());
                    continue;
                }
                ended = essential.join_next() => return Err(ended_task(ended)),
                () = &mut stop => {
                    // Producers first, so nothing new starts while the work stops. What did not
                    // finish stays in the outbox for the next start. The peers hear last.
                    essential.abort_all();
                    effects.stop_all();
                    effects.network.close().await;
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
fn ended_task(ended: Option<Result<NodeError, tokio::task::JoinError>>) -> NodeError {
    match ended {
        Some(Ok(reason)) => reason,
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

/// Stops a task when the node stops.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
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

/// Reads the chain for as long as the node runs. Until the first catch-up, a chain node that stops
/// answering ends the process for its supervisor: this one may never serve the node's logs. A long
/// catch-up that keeps reading is fine, and after it the reader waits out any outage.
async fn read_chain<R: Rpc>(
    mut reader: Reader<R>,
    mut heartbeat: Heartbeat,
    board: Board,
    events: mpsc::Sender<Event>,
    poll: Duration,
    startup_timeout: Duration,
) -> NodeError {
    let mut last_read = Some(Instant::now());
    loop {
        let read = reader.poll().await;
        if read.is_ok() {
            heartbeat.beat(now(), reader.head(), reader.read_to());
            board.chain_read(reader.head(), reader.read_to());
            last_read = (!reader.caught_up() && last_read.is_some()).then(Instant::now);
        }
        match read {
            Ok(facts) => {
                for fact in facts {
                    if events.send(Event::Input(Input::Chain(fact))).await.is_err() {
                        return NodeError::Stopped;
                    }
                }
                reader.wait().await;
            }
            Err(ReadError::Rpc(failure)) => {
                warn!(%failure, "reading the chain failed; trying again");
                if let Some(waited) = last_read
                    .map(|read| read.elapsed())
                    .filter(|waited| *waited >= startup_timeout)
                {
                    let failure = failure.to_string();
                    return NodeError::ChainSilent { waited, failure };
                }
                tokio::time::sleep(poll.max(RETRY_AFTER)).await;
            }
            Err(ReadError::Decode(failure)) => return failure.into(),
        }
    }
}

#[cfg(test)]
mod tests;
