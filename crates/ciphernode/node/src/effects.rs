// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Carries out the machine's effects. Each effect stays in the outbox until it is done: a job, a
//! signature or a fetch once its result is journaled, a gossip once it is published, a submission
//! once the writer finished it, and any effect the machine no longer owes.

use crate::{
    notes::NoteFeed,
    runtime::{now, Event},
};
use alloy_primitives::keccak256;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::BlobStore;
use e3_chain::{Account, Rpc, Writer};
use e3_data_availability::{DataAvailabilityReader, DataReference};
use e3_engine::{EffectKey, Pending};
use e3_jobs::{Attempt, Cancel, JobError, JobRunner};
use e3_p2p::Network;
use e3_protocol::{
    node::{
        BlobFetch, Effect, Eligibility, EligibilityRead, Fetch, FetchFailed, Fetched, Input, Job,
        JobDone, Node, PeerMessage, Scope, Signed, Signing, Submission,
    },
    wire::Envelope,
    E3Id,
};
use e3_utils::limited::Limited;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Semaphore},
    task::{AbortHandle, JoinHandle},
};
use tracing::{debug, error, warn};

/// A wait between attempts that doubles up to a limit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Backoff {
    wait: Duration,
    longest: Duration,
}

impl Backoff {
    /// A node that cannot start yet has nothing else to do.
    pub(crate) const STARTUP: Self = Self::new(1, 30);
    /// A failed job is this node's own: a key check near its cutoff cannot wait long.
    const JOB: Self = Self::new(5, 60);
    const SUBMISSION: Self = Self::new(30, 600);
    /// The decryption window that needs a ciphertext is short.
    const CIPHERTEXT: Self = Self::new(30, 60);

    const fn new(first: u64, longest: u64) -> Self {
        Self {
            wait: Duration::from_secs(first),
            longest: Duration::from_secs(longest),
        }
    }

    pub(crate) fn next(&mut self) -> Duration {
        let wait = self.wait;
        self.wait = (self.wait * 2).min(self.longest);
        wait
    }
}

/// A running job reports itself after this long, then at doubling intervals up to the last.
const FIRST_REPORT: Duration = Duration::from_secs(5 * 60);
const LONGEST_REPORT: Duration = Duration::from_secs(30 * 60);
/// At most one job-failure line goes out per this long.
const FAILURE_LOG: Duration = Duration::from_secs(30);

/// An effect under way.
struct Task {
    key: EffectKey,
    scope: Scope,
    handle: AbortHandle,
    /// Reaches a job's blocking work, which aborting the task cannot stop.
    cancel: Option<Cancel>,
}

impl Task {
    fn stop(&self) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        self.handle.abort();
    }
}

pub(crate) struct Effects<R, A, N, B> {
    pub(crate) rpc: Arc<R>,
    pub(crate) operator: PrivateKeySigner,
    pub(crate) blobs: B,
    pub(crate) jobs: Arc<JobRunner<B>>,
    pub(crate) writer: Arc<Writer<A, B>>,
    pub(crate) network: Arc<N>,
    pub(crate) availability: Arc<dyn DataAvailabilityReader>,
    pub(crate) events: mpsc::Sender<Event>,
    notes: NoteFeed,
    /// Places for jobs: one waiting beyond them holds no blocking thread.
    job_slots: Arc<Semaphore>,
    job_failures: Arc<Limited>,
    tasks: BTreeMap<E3Id, Vec<Task>>,
}

/// What `Effects` is made of.
pub(crate) struct EffectParts<R, A, N, B> {
    pub(crate) rpc: Arc<R>,
    pub(crate) operator: PrivateKeySigner,
    pub(crate) blobs: B,
    pub(crate) jobs: Arc<JobRunner<B>>,
    pub(crate) writer: Arc<Writer<A, B>>,
    pub(crate) network: Arc<N>,
    pub(crate) availability: Arc<dyn DataAvailabilityReader>,
    pub(crate) events: mpsc::Sender<Event>,
    pub(crate) notes: NoteFeed,
    pub(crate) job_slots: usize,
}

impl<R, A, N, B> Effects<R, A, N, B>
where
    R: Rpc + Send + Sync + 'static,
    A: Account + Send + Sync + 'static,
    N: Network,
    B: BlobStore,
{
    pub(crate) fn new(parts: EffectParts<R, A, N, B>) -> Self {
        Self {
            rpc: parts.rpc,
            operator: parts.operator,
            blobs: parts.blobs,
            jobs: parts.jobs,
            writer: parts.writer,
            network: parts.network,
            availability: parts.availability,
            events: parts.events,
            notes: parts.notes,
            job_slots: Arc::new(Semaphore::new(parts.job_slots.max(1))),
            job_failures: Arc::new(Limited::new(FAILURE_LOG)),
            tasks: BTreeMap::new(),
        }
    }

    /// Starts each effect; returns the events of the effects that finish at once.
    pub(crate) fn dispatch(&mut self, pending: Vec<Pending<Effect>>) -> Vec<Event> {
        let mut now = Vec::new();
        for Pending { key, effect } in pending {
            debug!(effect = %crate::runtime::brief(&effect), "dispatching");
            let (e3, scope) = (effect.e3(), effect.scope());
            let mut cancel = None;
            let handle = match effect {
                Effect::Sign(signing) => {
                    now.push(Event::Result(key, self.sign(signing)));
                    continue;
                }
                Effect::Note(note) => {
                    self.notes.record(crate::runtime::now(), note);
                    now.push(Event::Done(key));
                    continue;
                }
                Effect::Gossip(message) => self.gossip(key, message),
                Effect::Run(job) => {
                    let token = Cancel::default();
                    cancel = Some(token.clone());
                    self.run(key, job, token)
                }
                Effect::Submit(submission) => self.submit(key, submission),
                Effect::Fetch(fetch) => self.fetch(key, fetch),
                Effect::FetchBlobs(fetch) => self.fetch_blobs(key, fetch),
                Effect::ReadEligibility(read) => self.read_eligibility(key, read),
            };
            self.tasks.entry(e3).or_default().push(Task {
                key,
                scope,
                handle: handle.abort_handle(),
                cancel,
            });
        }
        now
    }

    /// Stops the tasks the machine no longer owes. Their effects are done.
    pub(crate) fn stop_ended(&mut self, machine: &Node) -> Vec<EffectKey> {
        let mut ended = Vec::new();
        self.tasks.retain(|e3, tasks| {
            tasks.retain(|task| {
                if task.handle.is_finished() {
                    return false;
                }
                let owed = machine.owes(e3, task.scope);
                if !owed {
                    task.stop();
                    ended.push(task.key);
                }
                owed
            });
            !tasks.is_empty()
        });
        ended
    }

    /// Stops all work for a shutdown. The effects stay in the outbox for the next start.
    pub(crate) fn stop_all(&mut self) {
        for task in self.tasks.values().flatten() {
            task.stop();
        }
    }

    /// A submission whose calls cannot be built, for a blob the store cannot read now, is built
    /// again later.
    fn submit(&self, key: EffectKey, submission: Submission) -> JoinHandle<()> {
        let (writer, events) = (self.writer.clone(), self.events.clone());
        tokio::spawn(async move {
            let mut backoff = Backoff::SUBMISSION;
            loop {
                match writer.submit(&submission).await {
                    Ok(()) => {
                        let _ = events.send(Event::Done(key)).await;
                        return;
                    }
                    Err(failure) => error!(e3 = %submission.e3, %failure, "the submission failed"),
                }
                tokio::time::sleep(backoff.next()).await;
            }
        })
    }

    /// A job that fails, as for a full disk, runs again until it succeeds or the node no longer
    /// owes it. Its attempts after the first use less memory.
    fn run(&self, key: EffectKey, job: Job, cancel: Cancel) -> JoinHandle<()> {
        let (jobs, events, slots) = (
            self.jobs.clone(),
            self.events.clone(),
            self.job_slots.clone(),
        );
        let failures = self.job_failures.clone();
        tokio::spawn(async move {
            let Ok(_slot) = slots.acquire_owned().await else {
                return;
            };
            let mut backoff = Backoff::JOB;
            for number in 0.. {
                let attempt = Attempt {
                    number,
                    cancel: cancel.clone(),
                };
                let (runner, work) = (jobs.clone(), job.clone());
                let blocking = tokio::task::spawn_blocking(move || runner.run(&work, &attempt));
                let failure = match reporting(&job, blocking).await {
                    Ok(Ok(result)) => {
                        let done = Input::Job(JobDone { e3: job.e3, result });
                        let _ = events.send(Event::Result(key, done)).await;
                        return;
                    }
                    Ok(Err(JobError::Cancelled)) => return,
                    Ok(Err(failure)) => format!("{failure:#}"),
                    Err(panic) => format!("it panicked: {panic}"),
                };
                if let Some(held_back) = failures.pass() {
                    error!(e3 = %job.e3, attempt = number, held_back, %failure, "a job failed");
                }
                tokio::time::sleep(backoff.next()).await;
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

    fn gossip(&self, key: EffectKey, message: PeerMessage) -> JoinHandle<()> {
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
        })
    }

    fn fetch_blobs(&self, key: EffectKey, fetch: BlobFetch) -> JoinHandle<()> {
        let (network, events) = (self.network.clone(), self.events.clone());
        tokio::spawn(async move {
            let BlobFetch { message, attempt } = fetch;
            let result = match network.fetch(message.clone()).await {
                Ok(()) => Input::Peer(message),
                // The sender's re-send announces the message again.
                Err(failure) => {
                    debug!(e3 = %message.e3, %failure, "fetching a peer's blobs failed");
                    Input::FetchFailed(FetchFailed {
                        e3: message.e3,
                        sender: message.sender,
                        kind: message.body.kind(),
                        id: message.id(),
                        attempt,
                    })
                }
            };
            let _ = events.send(Event::Result(key, result)).await;
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
            let mut backoff = Backoff::CIPHERTEXT;
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
                tokio::time::sleep(backoff.next()).await;
            }
        })
    }
}

/// Waits for a job's blocking work, and says so while it takes long: a proof under the secure
/// parameters can run for hours.
async fn reporting<T>(job: &Job, mut work: JoinHandle<T>) -> Result<T, tokio::task::JoinError> {
    let started = Instant::now();
    let mut wait = FIRST_REPORT;
    loop {
        match tokio::time::timeout(wait, &mut work).await {
            Ok(result) => return result,
            Err(_) => {
                let elapsed = started.elapsed();
                warn!(e3 = %job.e3, work = job.work.name(), ?elapsed, "a job is still running");
                wait = (wait * 2).min(LONGEST_REPORT);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backoff_doubles_up_to_its_limit() {
        let mut backoff = Backoff::new(5, 12);
        let waits: Vec<u64> = (0..4).map(|_| backoff.next().as_secs()).collect();
        assert_eq!(waits, [5, 10, 12, 12]);
    }

    /// A failed key check has to retry well inside the key cutoff.
    #[test]
    fn jobs_retry_within_a_minute() {
        let mut backoff = Backoff::JOB;
        assert_eq!(backoff.next(), Duration::from_secs(5));
        for _ in 0..8 {
            assert!(backoff.next() <= Duration::from_secs(60));
        }
    }
}
