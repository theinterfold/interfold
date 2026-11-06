// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs the jobs that the v2 protocol asks for. A job's inputs and results are blob references
//! into one store that the network adapter shares; a secret is stored sealed with the node's
//! cipher, so the machine and its journal only ever hold a reference to ciphertext.

mod blobs;
mod dkg;

pub use blobs::{Blobs, MemoryBlobs};

use e3_crypto::Cipher;
use e3_fhe_params::BfvPreset;
use e3_protocol::{
    node::{CryptoParams, Job, Work, WorkResult},
    BlobRef,
};

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("blob {0:?} is not in the store")]
    MissingBlob(BlobRef),
    #[error("parameter set {0} is not supported by this node")]
    UnsupportedParams(u8),
    #[error("sealing: {0}")]
    Seal(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
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
            Work::Decryption(_) => Err(JobError::NotImplemented("decryption")),
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
}

/// The request's threshold preset; the DKG encrypts shares under its DKG counterpart.
fn threshold_preset(params: &CryptoParams) -> Result<BfvPreset, JobError> {
    BfvPreset::from_on_chain_param_set(params.param_set)
        .ok_or(JobError::UnsupportedParams(params.param_set))
}

fn dkg_preset(params: &CryptoParams) -> Result<BfvPreset, JobError> {
    threshold_preset(params)?
        .dkg_counterpart()
        .ok_or(JobError::UnsupportedParams(params.param_set))
}
