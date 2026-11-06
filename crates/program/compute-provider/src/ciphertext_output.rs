// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::compute_input::ComputeInput;
use crate::policy::InputPolicy;

pub trait ComputeProvider {
    type Output: Send + Sync;

    /// Proves the computation over `input`, under the same [`InputPolicy`] the caller published
    /// with.
    ///
    /// The policy is passed rather than chosen here. A prover that picked its own would decide a
    /// different leaf layout and a different selected input set from the one
    /// [`crate::ComputeManager::start`] returned the ciphertext for, and the two only disagree
    /// where it matters: an E3 program hashes the published ciphertext into the digest it rebuilds,
    /// so any divergence makes the round unpublishable and names no cause.
    fn prove(&self, input: &ComputeInput, policy: InputPolicy) -> Self::Output;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ComputeResult {
    pub ciphertext_hash: Vec<u8>,
    pub ciphertext_commitment: Vec<u8>,
    pub params_hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
}
