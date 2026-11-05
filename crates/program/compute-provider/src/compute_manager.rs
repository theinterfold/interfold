// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ciphertext_output::ComputeProvider;
use crate::compute_input::{ComputeError, ComputeInput, FHEInputs, PublishedData};
use crate::merkle_tree_builder::Batching;
use crate::policy::InputPolicy;
use crate::FHEProcessor;

pub struct ComputeManager<P>
where
    P: ComputeProvider + Send + Sync,
{
    input: ComputeInput,
    provider: P,
    processor: FHEProcessor,
}

impl<P> ComputeManager<P>
where
    P: ComputeProvider + Send + Sync,
{
    pub fn new(provider: P, fhe_inputs: FHEInputs, fhe_processor: FHEProcessor) -> Self {
        Self::with_published(provider, fhe_inputs, Vec::new(), fhe_processor)
    }

    /// Carries what the E3 program published alongside each ciphertext, which its
    /// [`crate::InputPolicy`] reads to build leaves and select inputs.
    pub fn with_published(
        provider: P,
        fhe_inputs: FHEInputs,
        published: Vec<PublishedData>,
        fhe_processor: FHEProcessor,
    ) -> Self {
        Self {
            provider,
            input: ComputeInput {
                fhe_inputs,
                published,
            },
            processor: fhe_processor,
        }
    }

    /// Proves the computation and returns the ciphertext to publish.
    ///
    /// The ciphertext comes from the same selection the proof covers. Running the processor over
    /// the full input set here instead would publish bytes the receipt does not describe: an E3
    /// program hashes the published ciphertext into the digest it rebuilds, so any excluded input
    /// would make every round unpublishable.
    ///
    /// One policy reaches both, from this one argument. Letting the provider choose its own would
    /// reopen the same gap one layer down: the ciphertext returned here and the one the receipt
    /// describes would be selected by different rules, and nothing would compare them.
    pub fn start(&mut self, policy: InputPolicy) -> Result<(P::Output, Vec<u8>), ComputeError> {
        self.start_batched(policy, Batching::Sequential)
    }

    /// As [`Self::start`], choosing how the per-input commitments are scheduled.
    ///
    /// Restores the batching that `ComputeManager` carried before it was removed, in the one place
    /// where it is safe. The removed version chunked the *round*: each chunk was proved separately
    /// and its result fed into a final tally with a hardcoded index, which left the leaves no
    /// longer bound to input positions. Here the round is whole and only the commitment
    /// recomputation is scheduled across threads, so the root is unchanged.
    ///
    /// Useful on a host proving a large round. It does nothing for the zkVM guest, which is single
    /// threaded and takes this crate without the `parallel` feature.
    pub fn start_batched(
        &mut self,
        policy: InputPolicy,
        batching: Batching,
    ) -> Result<(P::Output, Vec<u8>), ComputeError> {
        let (_, ciphertext) = self.input.run_batched(self.processor, policy, batching)?;

        Ok((self.provider.prove(&self.input, policy), ciphertext))
    }
}
