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
pub use trbfv::crypto_configs;

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
use std::fmt::Display;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error(transparent)]
    Blob(#[from] e3_blobs::BlobError),
    #[error("parameter set {0} is not supported by this node")]
    UnsupportedParams(u8),
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

pub struct JobRunner<S> {
    blobs: S,
    cipher: Cipher,
    proofs: Proofs,
    /// Every job runs here, so checks and cryptography together use at most its threads.
    pool: ThreadPool,
    scope: B256,
}

impl<S: BlobStore> JobRunner<S> {
    pub fn new(
        blobs: S,
        cipher: Cipher,
        proofs: Proofs,
        limits: JobLimits,
    ) -> Result<Self, JobError> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(limits.threads.max(1))
            .thread_name(|index| format!("job-{index}"))
            .build()
            .map_err(JobError::crypto)?;
        Ok(Self {
            blobs,
            cipher,
            proofs,
            pool,
            scope: limits.scope,
        })
    }

    /// Deletes the proving files of an E3 whose work ended. A proof still under way removes its
    /// own files when it ends.
    pub fn close(&self, e3: E3Id) -> std::io::Result<()> {
        match &self.proofs {
            Proofs::Circuits(circuits) => circuits.close(e3),
            #[cfg(any(test, feature = "testing"))]
            Proofs::Placeholder => Ok(()),
        }
    }

    pub fn run(&self, job: &Job, attempt: &Attempt) -> Result<WorkResult, JobError> {
        self.pool.install(|| {
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
        })
    }

    fn jobs<'a>(
        &'a self,
        job: &Job,
        attempt: &'a Attempt,
    ) -> Result<Jobs<'a, E3Blobs<S>>, JobError> {
        let encoded = bincode::serialize(job).map_err(JobError::crypto)?;
        Ok(Jobs {
            e3: job.e3,
            job: keccak256(encoded),
            scope: self.scope,
            blobs: self.blobs.of(job.e3),
            cipher: &self.cipher,
            prover: match &self.proofs {
                Proofs::Circuits(circuits) => Some(circuits.for_attempt(attempt)),
                #[cfg(any(test, feature = "testing"))]
                Proofs::Placeholder => None,
            },
        })
    }
}

/// A job's view: the store of its E3, and the circuits as this attempt uses them.
struct Jobs<'a, B> {
    e3: E3Id,
    /// The hash of the job, the same for every attempt and after a restart.
    job: B256,
    scope: B256,
    blobs: B,
    cipher: &'a Cipher,
    prover: Option<Prover<'a>>,
}

impl<B: Blobs> Jobs<'_, B> {
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
