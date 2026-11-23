// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs the jobs that the v2 protocol asks for. A job's inputs and results are blob references
//! into one store that the network adapter shares; a secret is stored sealed with the node's
//! cipher, so the machine and its journal only ever hold a reference to ciphertext.

mod accusation;
mod decryption;
mod dkg;
mod placeholder;
mod proofs;
#[cfg(any(test, feature = "testing"))]
mod requester;
#[cfg(test)]
mod tests;
mod trbfv;

pub use e3_blobs::{BlobStore, Blobs, E3Blobs, MemoryBlobs};
pub use e3_zk_prover::Cancel;
pub use proofs::{Circuits, Proofs};
#[cfg(any(test, feature = "testing"))]
pub use requester::encrypt;
pub use trbfv::{crypto_configs, profile};

use alloy_primitives::{keccak256, B256};
use e3_crypto::Cipher;
use e3_protocol::{
    node::{Job, Work, WorkResult},
    E3Id, SealedRef,
};
use e3_trbfv::shares::{BfvEncryptedShare, ShamirShare};
use proofs::Prover;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng, TryRngCore};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, PoisonError,
    },
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error(transparent)]
    Blob(#[from] e3_blobs::BlobError),
    #[error("parameter set {0} is not supported by this node")]
    UnsupportedParams(u8),
    #[error("the request's BFV profile: {0}")]
    Profile(#[from] e3_fhe_params::BfvProfileError),
    #[error("sealing: {0}")]
    Seal(String),
    #[error("{0}")]
    Crypto(String),
    #[error("the node no longer needs this job")]
    Cancelled,
}

impl JobError {
    /// With the error's whole chain of causes, which can say which member's input was bad.
    pub(crate) fn crypto(error: impl Display) -> Self {
        Self::Crypto(format!("{error:#}"))
    }
}

/// A dealer's own shares, kept in plaintext and sealed, for its decryption key.
#[derive(Serialize, Deserialize)]
pub(crate) struct OwnShareRows {
    pub(crate) sk: ShamirShare,
    pub(crate) esi: Vec<ShamirShare>,
}

/// What a dealer sends one recipient: its shares, encrypted to the recipient's C0 key.
#[derive(Serialize, Deserialize)]
pub(crate) struct RecipientCiphertexts {
    pub(crate) sk: BfvEncryptedShare,
    pub(crate) esi: Vec<BfvEncryptedShare>,
}

/// A member's decryption key: its summed secret-key and smudging-noise shares, sealed.
#[derive(Serialize, Deserialize)]
pub(crate) struct SealedDecryptionKey {
    pub(crate) sk_poly_sum: Vec<u8>,
    pub(crate) es_poly_sum: Vec<Vec<u8>>,
}

/// One attempt at a job. The first attempt is number zero.
#[derive(Clone, Debug, Default)]
pub struct Attempt {
    pub number: u32,
    pub cancel: Cancel,
}

/// How a node runs its jobs.
#[derive(Clone, Copy, Debug)]
pub struct JobLimits {
    /// Threads for checks and threshold cryptography: the machine's, less those kept for the
    /// node's own loops.
    pub threads: usize,
    /// Names this node and its build. A kept value belongs to one node, and a proof made by a
    /// release with other circuits is not taken.
    pub scope: B256,
}

/// Boundary for running protocol jobs, implemented by [`JobRunner`].
pub trait JobExecutor: Send + Sync + 'static {
    fn run(&self, job: &Job, attempt: &Attempt) -> Result<WorkResult, JobError>;
    fn close(&self, e3: E3Id) -> std::io::Result<()>;
    fn cancel_dkg_prefold(&self, _e3: E3Id) {}
}

pub(crate) type DoneSignal = Arc<(Mutex<bool>, Condvar)>;
pub(crate) type PrefoldRegistration = (Cancel, Arc<AtomicBool>, DoneSignal);

struct PrefoldSlot {
    cancel: Cancel,
    stop_launching: Arc<AtomicBool>,
    done: DoneSignal,
}

#[derive(Default)]
pub(crate) struct Prefolds {
    entries: Mutex<HashMap<E3Id, PrefoldSlot>>,
}

impl Prefolds {
    /// Registers a new background pre-fold for `e3`, cancelling any prior one without blocking.
    pub(crate) fn register(&self, e3: E3Id) -> PrefoldRegistration {
        let cancel = Cancel::default();
        let stop_launching = Arc::new(AtomicBool::new(false));
        let done = Arc::new((Mutex::new(false), Condvar::new()));
        let slot = PrefoldSlot {
            cancel: cancel.clone(),
            stop_launching: Arc::clone(&stop_launching),
            done: Arc::clone(&done),
        };
        if let Some(old) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(e3, slot)
        {
            old.stop_launching.store(true, Ordering::Release);
            old.cancel.cancel();
        }
        (cancel, stop_launching, done)
    }

    /// Signals a background pre-fold to let any in-flight `bb` step finish (so foreground
    /// `FoldProofs` can join it via single-flight) but launch no further steps.
    pub(crate) fn pause_new_steps(&self, e3: E3Id) {
        if let Some(slot) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&e3)
        {
            slot.stop_launching.store(true, Ordering::Release);
        }
    }

    /// Immediately cancels any background pre-fold for `e3` without blocking the caller.
    pub(crate) fn cancel(&self, e3: E3Id) {
        if let Some(slot) = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&e3)
        {
            slot.stop_launching.store(true, Ordering::Release);
            slot.cancel.cancel();
        }
    }

    /// Cancels any background pre-fold for `e3` and waits for its thread to finish before disk
    /// cleanup removes the E3 work directory.
    pub(crate) fn cancel_and_wait(&self, e3: E3Id) {
        let slot = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&e3);
        if let Some(slot) = slot {
            slot.stop_launching.store(true, Ordering::Release);
            slot.cancel.cancel();
            let (lock, ready) = &*slot.done;
            let mut finished = lock.lock().unwrap_or_else(PoisonError::into_inner);
            while !*finished {
                finished = ready.wait(finished).unwrap_or_else(PoisonError::into_inner);
            }
        }
    }

    pub(crate) fn mark_finished(&self, e3: E3Id, done: &Arc<(Mutex<bool>, Condvar)>) {
        let mut map = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = map.get(&e3) {
            if Arc::ptr_eq(&slot.done, done) {
                map.remove(&e3);
            }
        }
        drop(map);
        let (lock, ready) = &**done;
        let mut finished = lock.lock().unwrap_or_else(PoisonError::into_inner);
        *finished = true;
        ready.notify_all();
    }

    fn cancel_all_and_wait(&self) {
        let slots: Vec<PrefoldSlot> = self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, slot)| slot)
            .collect();
        for slot in &slots {
            slot.stop_launching.store(true, Ordering::Release);
            slot.cancel.cancel();
        }
        for slot in slots {
            let (lock, ready) = &*slot.done;
            let mut finished = lock.lock().unwrap_or_else(PoisonError::into_inner);
            while !*finished {
                finished = ready.wait(finished).unwrap_or_else(PoisonError::into_inner);
            }
        }
    }
}

pub struct JobRunner<S> {
    blobs: S,
    cipher: Cipher,
    proofs: Proofs,
    /// Pure-CPU pool for fast verification checks and BFV math. Proving jobs run on the caller's
    /// blocking thread and never park this pool while waiting on `ProveGate` or running `bb`.
    check_pool: Arc<ThreadPool>,
    scope: B256,
    prefolds: Arc<Prefolds>,
}

impl<S> Drop for JobRunner<S> {
    fn drop(&mut self) {
        self.prefolds.cancel_all_and_wait();
    }
}

impl<S: BlobStore> JobRunner<S> {
    pub fn new(
        blobs: S,
        cipher: Cipher,
        proofs: Proofs,
        limits: JobLimits,
    ) -> Result<Self, JobError> {
        let check_pool = ThreadPoolBuilder::new()
            .num_threads(limits.threads.max(1))
            .thread_name(|index| format!("job-cpu-{index}"))
            .build()
            .map_err(JobError::crypto)?;
        Ok(Self {
            blobs,
            cipher,
            proofs,
            check_pool: Arc::new(check_pool),
            scope: limits.scope,
            prefolds: Arc::new(Prefolds::default()),
        })
    }

    /// Cancels any speculative DKG pre-fold running in the background for `e3`.
    pub fn cancel_dkg_prefold(&self, e3: E3Id) {
        self.prefolds.cancel(e3);
    }

    /// Deletes the proving files of an E3 whose work ended. Any background pre-fold for `e3` is
    /// cancelled and joined first so it cannot write back into the removed directory.
    pub fn close(&self, e3: E3Id) -> std::io::Result<()> {
        self.prefolds.cancel_and_wait(e3);
        match &self.proofs {
            Proofs::Circuits(circuits) => circuits.close(e3),
            #[cfg(any(test, feature = "testing"))]
            Proofs::Placeholder => Ok(()),
        }
    }

    pub fn run(&self, job: &Job, attempt: &Attempt) -> Result<WorkResult, JobError> {
        if attempt.cancel.is_cancelled() {
            return Err(JobError::Cancelled);
        }
        let execute = || {
            if attempt.cancel.is_cancelled() {
                return Err(JobError::Cancelled);
            }
            let jobs = self.jobs(job, attempt)?;
            match &job.work {
                Work::Dkg(work) => jobs.run_dkg(&job.params, work).map(WorkResult::Dkg),
                Work::Decryption(work) => jobs
                    .run_decryption(&job.params, work)
                    .map(WorkResult::Decryption),
                Work::Accusation(work) => jobs
                    .run_accusation(&job.params, work)
                    .map(WorkResult::Accusation),
            }
        };
        // Non-proving jobs (checks, accusations) run on `check_pool` so their parallel math and
        // verification work is never starved by proving jobs waiting on `ProveGate`.
        if job.work.proves() {
            execute()
        } else {
            self.check_pool.install(execute)
        }
    }

    fn jobs<'a>(
        &'a self,
        job: &Job,
        attempt: &'a Attempt,
    ) -> Result<Jobs<'a, E3Blobs<S>, S>, JobError> {
        let encoded = bincode::serialize(job).map_err(JobError::crypto)?;
        let (prover, circuits) = match &self.proofs {
            Proofs::Circuits(circuits) => (
                Some(circuits.for_attempt(attempt)),
                Some((**circuits).clone()),
            ),
            #[cfg(any(test, feature = "testing"))]
            Proofs::Placeholder => (None, None),
        };
        Ok(Jobs {
            e3: job.e3,
            job: keccak256(encoded),
            scope: self.scope,
            blobs: self.blobs.of(job.e3),
            blob_store: Some(&self.blobs),
            cipher: &self.cipher,
            prover,
            circuits,
            check_pool: &self.check_pool,
            prefolds: Some(&self.prefolds),
        })
    }
}

impl<S: BlobStore> JobExecutor for JobRunner<S> {
    fn run(&self, job: &Job, attempt: &Attempt) -> Result<WorkResult, JobError> {
        JobRunner::run(self, job, attempt)
    }

    fn close(&self, e3: E3Id) -> std::io::Result<()> {
        JobRunner::close(self, e3)
    }

    fn cancel_dkg_prefold(&self, e3: E3Id) {
        JobRunner::cancel_dkg_prefold(self, e3);
    }
}

/// A job's view: the store of its E3, and the circuits as this attempt uses them.
struct Jobs<'a, B, S = MemoryBlobs> {
    e3: E3Id,
    /// The hash of the job, the same for every attempt and after a restart.
    job: B256,
    scope: B256,
    blobs: B,
    blob_store: Option<&'a S>,
    cipher: &'a Cipher,
    prover: Option<Prover<'a>>,
    circuits: Option<Circuits>,
    check_pool: &'a ThreadPool,
    prefolds: Option<&'a Arc<Prefolds>>,
}

impl<B: Blobs, S> Jobs<'_, B, S> {
    fn seal(&self, secret: &[u8]) -> Result<SealedRef, JobError> {
        Ok(self.blobs.put_sealed(&self.sealed(secret)?)?)
    }

    fn unseal(&self, secret: &SealedRef) -> Result<Vec<u8>, JobError> {
        self.opened(&self.blobs.get_sealed(secret)?)
    }

    fn sealed(&self, secret: &[u8]) -> Result<Vec<u8>, JobError> {
        let mut secret = secret.to_vec();
        self.cipher
            .encrypt_data(&mut secret)
            .map_err(|error| JobError::Seal(error.to_string()))
    }

    fn opened(&self, sealed: &[u8]) -> Result<Vec<u8>, JobError> {
        self.cipher
            .decrypt_data(sealed)
            .map_err(|error| JobError::Seal(error.to_string()))
    }

    /// A random generator for this job's `purpose`. Everything random in a job comes from one
    /// seed, drawn from the operating system once, sealed and saved before any of it is used, so a
    /// job that runs again after a restart has the same inputs and its finished proofs still fit.
    fn rng(&self, purpose: &str) -> Result<ChaCha20Rng, JobError> {
        let key = keccak256(
            [
                b"seed".as_slice(),
                self.scope.as_slice(),
                self.job.as_slice(),
            ]
            .concat(),
        );
        let seed = match self.blobs.kept(&key)? {
            Some(sealed) => Zeroizing::new(self.opened(&sealed)?),
            None => {
                let mut seed = Zeroizing::new(vec![0u8; 32]);
                OsRng.try_fill_bytes(&mut seed).map_err(JobError::crypto)?;
                self.blobs.keep(&key, &self.sealed(&seed)?)?;
                seed
            }
        };
        let derived = Zeroizing::new(keccak256([seed.as_slice(), purpose.as_bytes()].concat()).0);
        Ok(ChaCha20Rng::from_seed(*derived))
    }
}
