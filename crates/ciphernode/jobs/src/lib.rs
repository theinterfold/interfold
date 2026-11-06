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
pub use proofs::{Circuits, Proofs};
#[cfg(any(test, feature = "testing"))]
pub use requester::encrypt;
pub use trbfv::crypto_configs;

use e3_crypto::Cipher;
use e3_protocol::{
    node::{Job, Work, WorkResult},
    BlobRef, E3Id,
};
use e3_trbfv::shares::{BfvEncryptedShare, ShamirShare};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

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
}

impl JobError {
    pub(crate) fn crypto(error: impl Display) -> Self {
        Self::Crypto(error.to_string())
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

pub struct JobRunner<S> {
    blobs: S,
    cipher: Cipher,
    proofs: Proofs,
}

impl<S: BlobStore> JobRunner<S> {
    pub fn new(blobs: S, cipher: Cipher, proofs: Proofs) -> Self {
        Self {
            blobs,
            cipher,
            proofs,
        }
    }

    /// Deletes the proving files of an E3 whose work ended. A proof still under way removes its
    /// own files when it ends.
    pub fn close(&self, e3: E3Id) -> std::io::Result<()> {
        match &self.proofs {
            Proofs::Circuits(circuits) => circuits.close(e3),
            Proofs::Placeholder => Ok(()),
        }
    }

    pub fn run(&self, job: &Job) -> Result<WorkResult, JobError> {
        let jobs = self.jobs(job.e3);
        match &job.work {
            Work::Dkg(work) => jobs.run_dkg(&job.params, work).map(WorkResult::Dkg),
            Work::Decryption(work) => jobs
                .run_decryption(&job.params, work)
                .map(WorkResult::Decryption),
            Work::Accusation(work) => jobs
                .run_accusation(&job.params, work)
                .map(WorkResult::Accusation),
        }
    }
}

impl<S: BlobStore> JobRunner<S> {
    fn jobs(&self, e3: E3Id) -> Jobs<'_, E3Blobs<S>> {
        Jobs {
            e3,
            blobs: self.blobs.of(e3),
            cipher: &self.cipher,
            proofs: &self.proofs,
        }
    }
}

/// A job's view: the blobs of its E3.
struct Jobs<'a, B> {
    e3: E3Id,
    blobs: B,
    cipher: &'a Cipher,
    proofs: &'a Proofs,
}

impl<B: Blobs> Jobs<'_, B> {
    fn seal(&self, secret: &[u8]) -> Result<BlobRef, JobError> {
        let mut secret = secret.to_vec();
        let sealed = self
            .cipher
            .encrypt_data(&mut secret)
            .map_err(|error| JobError::Seal(error.to_string()))?;
        Ok(self.blobs.put(&sealed)?)
    }

    fn unseal(&self, blob: &BlobRef) -> Result<Vec<u8>, JobError> {
        self.cipher
            .decrypt_data(&self.blobs.get(blob)?)
            .map_err(|error| JobError::Seal(error.to_string()))
    }
}
