// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Stand-ins for proofs until the prover is wired in: a placeholder's public input commits to the
//! bytes that the real proof binds, so checks that compare commitments still run, and it proves
//! nothing.

use crate::{Blobs, JobError};
use alloy_primitives::keccak256;
use e3_protocol::proof::{ProofType, ZkProof};

pub(crate) fn proof(
    blobs: &impl Blobs,
    proof_type: ProofType,
    bound: &[u8],
) -> Result<ZkProof, JobError> {
    Ok(ZkProof {
        data: blobs.put(&[b"placeholder".as_slice(), &[proof_type as u8]].concat())?,
        public_inputs: vec![keccak256(bound)],
    })
}

pub(crate) fn commits_to(proof: &ZkProof, bound: &[u8]) -> bool {
    proof.public_inputs == [keccak256(bound)]
}

pub(crate) fn statements(proofs: &[(ProofType, ZkProof)]) -> Vec<u8> {
    proofs
        .iter()
        .flat_map(|(_, proof)| proof.public_inputs.iter().flat_map(|word| word.0))
        .collect()
}
