// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::heartbeat::Heartbeat;
use alloy_primitives::{keccak256, Address};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::BlobStore;
use e3_chain::{Account, Contracts, ReadError, Reader, Rpc, Writer};
use e3_data_availability::{DataAvailabilityReader, DataReference};
use e3_engine::{EffectKey, Engine, Pending};
use e3_jobs::JobRunner;
use e3_journal::Journal;
use e3_p2p::Network;
use e3_protocol::{
    node::{
        Effect, Eligibility, EligibilityRead, Fetch, Fetched, Input, Job, JobDone, Node,
        PeerMessage, Signed, Signing, Submission,
    },
    wire::Envelope,
    E3Id, UnixSecs,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::Infallible,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinHandle},
};
use tracing::{debug, error, warn};

/// How long a failed chain read waits before it runs again, and the first wait of a failed job,
/// fetch or submission; each later attempt of those waits twice as long, up to ten minutes, or a
/// minute for a ciphertext fetch: the decryption window that needs it is short.
const RETRY_AFTER: Duration = Duration::from_secs(30);
const LONGEST_RETRY: Duration = Duration::from_secs(600);
const LONGEST_FETCH_RETRY: Duration = Duration::from_secs(60);

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
}

enum Event {
    /// A chain fact or a peer message.
    Input(Input),
    /// The result of one of the node's effects: applied, then the effect is done.
    Result(EffectKey, Input),
    /// An effect that finished without a result.
    Done(EffectKey),
    Fatal(NodeError),
}

/// Runs the node until its inputs stop or its journal or chain logs fail.
pub async fn run<R, A, N, B>(settings: Settings, parts: Parts<R, A, N, B>) -> NodeError
where
    R: Rpc + Clone + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: BlobStore,
{
    match start(settings, parts).await {
        Ok(never) => match never {},
        Err(error) => error,
    }
}

async fn start<R, A, N, B>(
    settings: Settings,
    parts: Parts<R, A, N, B>,
) -> Result<Infallible, NodeError>
where
    R: Rpc + Clone + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: BlobStore,
{
    let genesis = Node::new(parts.operator.address());
    let (mut engine, pending) = Engine::open(parts.journal, genesis, settings.snapshot_every)?;
    // A stop can come between ending an E3's work and finishing its effects; that work is over.
    let (pending, over): (Vec<_>, Vec<_>) = pending
        .into_iter()
        .partition(|pending| engine.machine().needs(&pending.effect));
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
    tokio::spawn(read_chain(
        reader,
        parts.heartbeat,
        events.clone(),
        settings.poll_interval,
    ));
    tokio::spawn(forward_peers(parts.inbound, events.clone()));
    let mut effects = Effects {
        rpc: Arc::new(parts.rpc),
        operator: parts.operator,
        blobs: parts.blobs.clone(),
        jobs: Arc::new(parts.jobs),
        writer: Arc::new(Writer::new(parts.account, parts.blobs, settings.contracts)),
        network: Arc::new(parts.network),
        availability: parts.availability,
        events,
        tasks: BTreeMap::new(),
    };
    tokio::spawn(refresh_each_window(
        effects.writer.clone(),
        effects.operator.address(),
    ));
    let mut queue: VecDeque<Event> = effects.dispatch(pending).into();
    loop {
        let event = match queue.pop_front() {
            Some(event) => event,
            None => next_event(&mut receiver, engine.next_deadline()).await?,
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
fn brief(value: &impl std::fmt::Debug) -> String {
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

/// Carries out the machine's effects. Each effect stays in the outbox until it is done: a job, a
/// signature or a fetch once its result is journaled, a gossip once it is published, a
/// submission once the writer finished it, and any effect of an E3 the machine dropped.
struct Effects<R, A, N, B> {
    rpc: Arc<R>,
    operator: PrivateKeySigner,
    blobs: B,
    jobs: Arc<JobRunner<B>>,
    writer: Arc<Writer<A, B>>,
    network: Arc<N>,
    availability: Arc<dyn DataAvailabilityReader>,
    events: mpsc::Sender<Event>,
    /// The jobs, submissions and fetches that run, by E3, and whether each serves live work.
    tasks: BTreeMap<E3Id, Vec<(EffectKey, AbortHandle, bool)>>,
}

impl<R, A, N, B> Effects<R, A, N, B>
where
    R: Rpc + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: BlobStore,
{
    /// Starts each effect; returns the events of the effects that finish at once.
    fn dispatch(&mut self, pending: Vec<Pending<Effect>>) -> Vec<Event> {
        let mut now = Vec::new();
        for Pending { key, effect } in pending {
            debug!(effect = %brief(&effect), "dispatching");
            let live = effect.serves_live_work();
            let (e3, task) = match effect {
                Effect::Sign(signing) => {
                    now.push(Event::Result(key, self.sign(signing)));
                    continue;
                }
                Effect::Gossip(message) => {
                    self.gossip(key, message);
                    continue;
                }
                Effect::Run(job) => (job.e3, self.run(key, job)),
                Effect::Submit(submission) => (submission.e3, self.submit(key, submission)),
                Effect::Fetch(fetch) => (fetch.e3, self.fetch(key, fetch)),
                Effect::FetchBlobs(message) => (message.e3, self.fetch_blobs(key, message)),
                Effect::ReadEligibility(read) => (read.e3, self.read_eligibility(key, read)),
            };
            let tasks = self.tasks.entry(e3).or_default();
            tasks.push((key, task.abort_handle(), live));
        }
        now
    }

    /// Stops the tasks that `machine` no longer needs, as `Node::needs` judges them: those of the
    /// E3s it dropped, and those of live work in E3s the chain failed or completed. Their effects
    /// are done.
    fn stop_ended(&mut self, machine: &Node) -> Vec<EffectKey> {
        let mut ended = Vec::new();
        self.tasks.retain(|e3, tasks| {
            tasks.retain(|(key, task, live)| {
                if task.is_finished() {
                    return false;
                }
                let needed = machine.needs_of(e3, *live);
                if !needed {
                    task.abort();
                    ended.push(*key);
                }
                needed
            });
            !tasks.is_empty()
        });
        ended
    }

    /// A submission whose calls cannot be built, for a blob the store cannot read now, is built
    /// again later.
    fn submit(&self, key: EffectKey, submission: Submission) -> JoinHandle<()> {
        let (writer, events) = (self.writer.clone(), self.events.clone());
        tokio::spawn(async move {
            let mut wait = RETRY_AFTER;
            loop {
                match writer.submit(&submission).await {
                    Ok(()) => {
                        let _ = events.send(Event::Done(key)).await;
                        return;
                    }
                    Err(failure) => error!(e3 = %submission.e3, %failure, "the submission failed"),
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(LONGEST_RETRY);
            }
        })
    }

    /// A job that fails, as for a full disk, runs again until it succeeds or the node no longer
    /// needs it.
    fn run(&self, key: EffectKey, job: Job) -> JoinHandle<()> {
        let (jobs, events) = (self.jobs.clone(), self.events.clone());
        tokio::spawn(async move {
            let mut wait = RETRY_AFTER;
            loop {
                let (runner, work) = (jobs.clone(), job.clone());
                match tokio::task::spawn_blocking(move || runner.run(&work, &Default::default()))
                    .await
                {
                    Ok(Ok(result)) => {
                        let done = Input::Job(JobDone { e3: job.e3, result });
                        let _ = events.send(Event::Result(key, done)).await;
                        return;
                    }
                    Ok(Err(failure)) => error!(e3 = %job.e3, %failure, "job failed"),
                    Err(panic) => error!(e3 = %job.e3, %panic, "job panicked"),
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(LONGEST_RETRY);
            }
        })
    }

    fn sign(&self, signing: Signing) -> Input {
        let signatures = signing
            .hashes
            .iter()
            .map(|hash| {
                let signature = self
                    .operator
                    .sign_hash_sync(hash)
                    .expect("a local key signs any hash");
                signature.as_bytes().to_vec().into()
            })
            .collect();
        Input::Signed(Signed {
            e3: signing.e3,
            purpose: signing.purpose,
            signatures,
        })
    }

    fn gossip(&self, key: EffectKey, message: PeerMessage) {
        let sent_at = now();
        let signature = self
            .operator
            .sign_hash_sync(&Envelope::signing_hash(&message, sent_at))
            .expect("a local key signs any hash");
        let envelope = Envelope {
            message,
            sent_at,
            signature: signature.as_bytes().to_vec().into(),
        };
        let (network, events) = (self.network.clone(), self.events.clone());
        tokio::spawn(async move {
            let e3 = envelope.message.e3;
            // A message the network lost goes again under the re-send rule.
            if let Err(failure) = network.publish(envelope).await {
                warn!(%e3, %failure, "gossip failed");
            }
            let _ = events.send(Event::Done(key)).await;
        });
    }

    fn fetch_blobs(&self, key: EffectKey, message: PeerMessage) -> JoinHandle<()> {
        let (network, events) = (self.network.clone(), self.events.clone());
        tokio::spawn(async move {
            match network.fetch(message.clone()).await {
                Ok(()) => {
                    let _ = events.send(Event::Result(key, Input::Peer(message))).await;
                }
                // The sender's re-send announces the message again.
                Err(failure) => {
                    debug!(e3 = %message.e3, %failure, "fetching a peer's blobs failed");
                    let _ = events.send(Event::Done(key)).await;
                }
            }
        })
    }

    /// Reads which operators may hold a seat until the machine stops waiting for the answer; a
    /// failed or late read answers that the node does not know.
    fn read_eligibility(&self, key: EffectKey, read: EligibilityRead) -> JoinHandle<()> {
        let (rpc, events) = (self.rpc.clone(), self.events.clone());
        tokio::spawn(async move {
            let limit = Duration::from_secs(read.by.saturating_sub(now()));
            let answer = tokio::time::timeout(limit, rpc.eligible(&read.operators, read.at)).await;
            let eligible = match answer {
                Ok(Ok(eligible)) => Some(eligible),
                Ok(Err(failure)) => {
                    warn!(e3 = %read.e3, %failure, "reading who may hold a seat failed");
                    None
                }
                Err(_) => {
                    warn!(e3 = %read.e3, "reading who may hold a seat took too long");
                    None
                }
            };
            let answer = Input::Eligibility(Eligibility {
                e3: read.e3,
                eligible,
            });
            let _ = events.send(Event::Result(key, answer)).await;
        })
    }

    fn fetch(&self, key: EffectKey, fetch: Fetch) -> JoinHandle<()> {
        let (availability, blobs, events) = (
            self.availability.clone(),
            self.blobs.clone(),
            self.events.clone(),
        );
        tokio::spawn(async move {
            let reference = DataReference {
                content_hash: fetch.data.hash.0,
                block_number: fetch.data.block,
                leaf_index: fetch.data.leaf,
            };
            let mut wait = RETRY_AFTER;
            loop {
                match availability.retrieve(reference).await {
                    Ok(bytes) if keccak256(&bytes) == fetch.data.hash => {
                        match blobs.put(fetch.e3, &bytes) {
                            Ok(blob) => {
                                let fetched = Input::Fetched(Fetched { e3: fetch.e3, blob });
                                let _ = events.send(Event::Result(key, fetched)).await;
                                return;
                            }
                            Err(failure) => {
                                error!(e3 = %fetch.e3, %failure, "storing a ciphertext failed")
                            }
                        }
                    }
                    Ok(_) => warn!(e3 = %fetch.e3, "the availability layer sent other bytes"),
                    Err(failure) => {
                        warn!(e3 = %fetch.e3, %failure, "fetching the ciphertext failed")
                    }
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(LONGEST_FETCH_RETRY);
            }
        })
    }
}
