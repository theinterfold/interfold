// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::keccak256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::Blobs;
use e3_chain::{Account, Contracts, ReadError, Reader, Rpc, Writer};
use e3_data_availability::{DataAvailabilityReader, DataReference};
use e3_engine::{EffectKey, Engine, Pending};
use e3_jobs::JobRunner;
use e3_journal::Journal;
use e3_p2p::Network;
use e3_protocol::{
    node::{
        Effect, Fetch, Fetched, Input, Job, JobDone, Node, PeerMessage, Signed, Signing, Submission,
    },
    wire::Envelope,
    E3Id, UnixSecs,
};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinHandle},
};
use tracing::{debug, error, warn};

/// How long a failed job or chain read waits before it runs again, and the first wait of a failed
/// fetch; each later fetch waits twice as long, up to ten minutes.
const RETRY_AFTER: Duration = Duration::from_secs(30);
const LONGEST_FETCH_RETRY: Duration = Duration::from_secs(600);

/// Attempts of a failed job: five minutes outlast a full disk being cleared, and a job that fails
/// for its inputs fails every time.
const JOB_ATTEMPTS: u32 = 10;

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
    R: Rpc + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: Blobs + Clone + Send + Sync + 'static,
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
    R: Rpc + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: Blobs + Clone + Send + Sync + 'static,
{
    let genesis = Node::new(parts.operator.address());
    let (mut engine, pending) = Engine::open(parts.journal, genesis, settings.snapshot_every)?;
    let chain_id = settings.contracts.chain_id;
    let from = engine
        .machine()
        .applied(chain_id)
        .map_or(settings.start_block, |at| at.block);
    let (events, mut receiver) = mpsc::channel(1_024);
    let reader = Reader::new(
        parts.rpc,
        settings.contracts.clone(),
        settings.confirmations,
        settings.max_log_range,
        from,
    );
    tokio::spawn(read_chain(reader, events.clone(), settings.poll_interval));
    tokio::spawn(forward_peers(parts.inbound, events.clone()));
    let mut effects = Effects {
        operator: parts.operator,
        blobs: parts.blobs.clone(),
        jobs: Arc::new(parts.jobs),
        writer: Arc::new(Writer::new(parts.account, parts.blobs, settings.contracts)),
        network: Arc::new(parts.network),
        availability: parts.availability,
        events,
        tasks: BTreeMap::new(),
    };
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
        let (next, pending) = engine.apply(now(), input)?;
        engine = next;
        if let Some(key) = answers {
            engine.acknowledge(key)?;
        }
        queue.extend(effects.dispatch(pending));
        for key in effects.stop_ended(engine.machine()) {
            engine.acknowledge(key)?;
        }
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

fn now() -> UnixSecs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
}

async fn read_chain<R: Rpc>(mut reader: Reader<R>, events: mpsc::Sender<Event>, poll: Duration) {
    loop {
        match reader.poll().await {
            Ok(facts) if facts.is_empty() => tokio::time::sleep(poll).await,
            Ok(facts) => {
                for fact in facts {
                    if events.send(Event::Input(Input::Chain(fact))).await.is_err() {
                        return;
                    }
                }
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
            .send(Event::Input(Input::Peer(message)))
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
struct Effects<A, N, B> {
    operator: PrivateKeySigner,
    blobs: B,
    jobs: Arc<JobRunner<B>>,
    writer: Arc<Writer<A, B>>,
    network: Arc<N>,
    availability: Arc<dyn DataAvailabilityReader>,
    events: mpsc::Sender<Event>,
    /// The jobs, submissions and fetches that run, by E3.
    tasks: BTreeMap<E3Id, Vec<(EffectKey, AbortHandle)>>,
}

impl<A, N, B> Effects<A, N, B>
where
    A: Account + Send + Sync + 'static,
    N: Network,
    B: Blobs + Clone + Send + Sync + 'static,
{
    /// Starts each effect; returns the events of the effects that finish at once.
    fn dispatch(&mut self, pending: Vec<Pending<Effect>>) -> Vec<Event> {
        let mut now = Vec::new();
        for Pending { key, effect } in pending {
            debug!(effect = %brief(&effect), "dispatching");
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
            };
            let tasks = self.tasks.entry(e3).or_default();
            tasks.push((key, task.abort_handle()));
        }
        now
    }

    /// Stops the tasks of the E3s `machine` no longer holds; their effects are done.
    fn stop_ended(&mut self, machine: &Node) -> Vec<EffectKey> {
        let mut ended = Vec::new();
        self.tasks.retain(|e3, tasks| {
            tasks.retain(|(_, task)| !task.is_finished());
            if machine.e3(e3).is_some() {
                return !tasks.is_empty();
            }
            for (key, task) in tasks.drain(..) {
                task.abort();
                ended.push(key);
            }
            false
        });
        ended
    }

    fn submit(&self, key: EffectKey, submission: Submission) -> JoinHandle<()> {
        let (writer, events) = (self.writer.clone(), self.events.clone());
        tokio::spawn(async move {
            match writer.submit(&submission).await {
                Ok(()) => {
                    let _ = events.send(Event::Done(key)).await;
                }
                // The submission stays in the outbox, so the next start tries it again.
                Err(failure) => error!(e3 = %submission.e3, %failure, "the submission failed"),
            }
        })
    }

    fn run(&self, key: EffectKey, job: Job) -> JoinHandle<()> {
        let (jobs, events) = (self.jobs.clone(), self.events.clone());
        tokio::spawn(async move {
            for _ in 0..JOB_ATTEMPTS {
                let (runner, work) = (jobs.clone(), job.clone());
                match tokio::task::spawn_blocking(move || runner.run(&work)).await {
                    Ok(Ok(result)) => {
                        let done = Input::Job(JobDone { e3: job.e3, result });
                        let _ = events.send(Event::Result(key, done)).await;
                        return;
                    }
                    Ok(Err(failure)) => error!(e3 = %job.e3, %failure, "job failed"),
                    Err(panic) => error!(e3 = %job.e3, %panic, "job panicked"),
                }
                tokio::time::sleep(RETRY_AFTER).await;
            }
            // The job stays in the outbox, so the next start runs it again; meanwhile the
            // machine's deadlines end the work that waits for it.
            error!(e3 = %job.e3, "job given up until the node restarts");
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
                    Ok(bytes) if keccak256(&bytes) == fetch.data.hash => match blobs.put(&bytes) {
                        Ok(blob) => {
                            let fetched = Input::Fetched(Fetched { e3: fetch.e3, blob });
                            let _ = events.send(Event::Result(key, fetched)).await;
                            return;
                        }
                        Err(failure) => {
                            error!(e3 = %fetch.e3, %failure, "storing a ciphertext failed")
                        }
                    },
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
