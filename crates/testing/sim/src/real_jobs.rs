// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::Jobs;
use e3_crypto::Cipher;
use e3_jobs::{Blobs, JobRunner, MemoryBlobs};
use e3_protocol::{
    node::{CryptoParams, Job, WorkResult},
    BlobRef,
};

/// The nodes' real job runners, each with its own cipher, over one blob store that stands in for
/// the network's; the requester encrypts `message` under the committee key.
pub struct RealJobs {
    blobs: MemoryBlobs,
    runners: Vec<JobRunner<MemoryBlobs>>,
    message: Vec<u64>,
}

impl RealJobs {
    pub fn new(nodes: usize, message: Vec<u64>) -> Self {
        let blobs = MemoryBlobs::default();
        let runtime = tokio::runtime::Runtime::new().expect("a runtime for the ciphers");
        let runners = (0..nodes)
            .map(|node| {
                let cipher = runtime
                    .block_on(Cipher::from_password(&format!("node {node}")))
                    .expect("a cipher");
                JobRunner::new(blobs.clone(), cipher)
            })
            .collect();
        Self {
            blobs,
            runners,
            message,
        }
    }

    pub fn blobs(&self) -> &MemoryBlobs {
        &self.blobs
    }
}

impl Jobs for RealJobs {
    fn run(&mut self, node: usize, job: &Job) -> WorkResult {
        self.runners[node]
            .run(job)
            .expect("an honest node's job succeeds")
    }

    fn ciphertext(&mut self, params: &CryptoParams, public_key: BlobRef) -> BlobRef {
        e3_jobs::encrypt(&self.blobs, params, &public_key, &self.message)
            .expect("the committee key encrypts")
    }
}

impl RealJobs {
    /// The plaintext values in a published plaintext blob.
    pub fn values(&self, plaintext: &BlobRef) -> Vec<u64> {
        let bytes = self.blobs.get(plaintext).expect("a published plaintext");
        bytes
            .chunks(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight-byte values")))
            .collect()
    }
}
