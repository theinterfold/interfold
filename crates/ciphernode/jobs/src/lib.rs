// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs the jobs that the v2 protocol asks for. A job's inputs and results are blob references
//! into one store that the network adapter shares; a secret is stored sealed with the node's
//! cipher, so the machine and its journal only ever hold a reference to ciphertext.

mod decryption;
mod dkg;
mod placeholder;
#[cfg(any(test, feature = "testing"))]
mod requester;
#[cfg(test)]
mod tests;
mod trbfv;

pub use e3_blobs::{Blobs, MemoryBlobs};
#[cfg(any(test, feature = "testing"))]
pub use requester::encrypt;

use e3_crypto::Cipher;
use e3_protocol::{
    node::{Job, Work, WorkResult},
    BlobRef,
};
use e3_trbfv::shares::{BfvEncryptedShare, ShamirShare};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error(transparent)]
    MissingBlob(#[from] e3_blobs::MissingBlob),
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

pub struct JobRunner<B> {
    blobs: B,
    cipher: Cipher,
}

impl<B: Blobs> JobRunner<B> {
    pub fn new(blobs: B, cipher: Cipher) -> Self {
        Self { blobs, cipher }
    }

    pub fn run(&self, job: &Job) -> Result<WorkResult, JobError> {
        match &job.work {
            Work::Dkg(work) => self.run_dkg(&job.params, work).map(WorkResult::Dkg),
            Work::Decryption(work) => self
                .run_decryption(&job.params, work)
                .map(WorkResult::Decryption),
        }
    }

    fn seal(&self, secret: &[u8]) -> Result<BlobRef, JobError> {
        let mut secret = secret.to_vec();
        let sealed = self
            .cipher
            .encrypt_data(&mut secret)
            .map_err(|error| JobError::Seal(error.to_string()))?;
        Ok(self.blobs.put(&sealed))
    }

    fn unseal(&self, blob: &BlobRef) -> Result<Vec<u8>, JobError> {
        self.cipher
            .decrypt_data(&self.blobs.get(blob)?)
            .map_err(|error| JobError::Seal(error.to_string()))
    }
}
