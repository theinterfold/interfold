// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The unproved development runner: runs the program natively and answers with a mock proof.

use anyhow::Result;
use e3_compute_provider::{
    ComputeInput, ComputeManager, ComputeProvider, ComputeResult, FHEProcessor, InputPolicy,
};
use e3_program_server::E3ProgramServer;

struct MockProofProvider {
    committee_public_key_hash: [u8; 32],
    processor: FHEProcessor,
}

impl ComputeProvider for MockProofProvider {
    type Output = ComputeResult;

    fn prove(&self, input: &ComputeInput, policy: InputPolicy) -> Self::Output {
        // The policy comes from the caller rather than from the program here. Reading it twice
        // would let the ciphertext this run publishes and the one it proves be selected by
        // different rules, which is the divergence the argument exists to remove.
        //
        // This dev provider stands in for the zkVM, where a failure aborts the guest. Panicking
        // with the reason keeps that behaviour while naming the input that could not be used.
        input
            .process_bound(self.processor, policy, self.committee_public_key_hash)
            .expect("the Secure Process rejected its inputs")
    }
}

fn encode_mock_compute_proof(seal: &[u8], result: &ComputeResult) -> Result<Vec<u8>> {
    let params_hash: [u8; 32] = result
        .params_hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("parameter hash must be 32 bytes"))?;
    let input_root: [u8; 32] = result
        .merkle_root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("input root must be 32 bytes"))?;
    let padded_seal_len = seal.len().div_ceil(32) * 32;
    let seal_len = u64::try_from(seal.len())?;
    let mut encoded = vec![0_u8; 128 + padded_seal_len];

    encoded[31] = 96;
    encoded[32..64].copy_from_slice(&params_hash);
    encoded[64..96].copy_from_slice(&input_root);
    encoded[120..128].copy_from_slice(&seal_len.to_be_bytes());
    encoded[128..128 + seal.len()].copy_from_slice(seal);

    Ok(encoded)
}

pub(crate) async fn serve(processor: FHEProcessor, policy: InputPolicy) -> Result<()> {
    let server = E3ProgramServer::builder(move |job| async move {
        // `with_published`, not `new`: a program whose policy reads the commitment or the slot
        // needs what the E3 program published, and `new` supplies none of it.
        let committee_public_key_hash = job.domain.committee_public_key_hash;
        let mut manager = ComputeManager::with_published(
            MockProofProvider {
                committee_public_key_hash,
                processor,
            },
            job.inputs,
            job.published,
            processor,
        )
        .with_committee_public_key_hash(committee_public_key_hash);
        let (result, ciphertext) = manager.start(policy)?;
        let proof = encode_mock_compute_proof(&[3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5], &result)?;

        Ok((proof, ciphertext))
    })
    .build()?;

    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_proof_uses_the_current_solidity_envelope() {
        let result = ComputeResult {
            ciphertext_hash: vec![0; 32],
            ciphertext_commitment: vec![0; 32],
            params_hash: vec![0x22; 32],
            merkle_root: vec![0x33; 32],
        };

        let encoded = encode_mock_compute_proof(&[1, 2, 3], &result).unwrap();

        assert_eq!(encoded.len(), 160);
        assert_eq!(encoded[31], 96);
        assert_eq!(&encoded[32..64], &[0x22; 32]);
        assert_eq!(&encoded[64..96], &[0x33; 32]);
        assert_eq!(&encoded[120..128], &3_u64.to_be_bytes());
        assert_eq!(&encoded[128..131], &[1, 2, 3]);
        assert!(encoded[131..].iter().all(|byte| *byte == 0));
    }
}
