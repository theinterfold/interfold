// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Stand-ins for proofs where no prover runs: a placeholder's public input commits to the bytes
//! that the real proof binds, so checks that compare commitments still run, and it proves nothing.
//! Only the mock verifiers of a test deployment accept them.

use crate::{Blobs, JobError};
use alloy_primitives::{keccak256, Address, B256, U256};
use e3_protocol::{
    accusation::Verdict,
    dkg::DkgProofs,
    proof::{ProofType, ZkProof},
};

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

/// A C5 stand-in whose public inputs follow the real proof's layout where the node reads them:
/// `6 + 3H` inputs, the roster's committee slots at `[2, 2 + H)`, and the key commitment last.
pub(crate) fn key_aggregation(
    blobs: &impl Blobs,
    committee: &[Address],
    roster: &[Address],
    commitment: B256,
) -> Result<ZkProof, JobError> {
    let mut inputs = vec![B256::ZERO; 6 + 3 * roster.len()];
    for (slot, member) in roster.iter().enumerate() {
        let party = crate::trbfv::party(committee, *member)?;
        inputs[2 + slot] = B256::from(U256::from(party));
    }
    *inputs.last_mut().expect("at least six inputs") = commitment;
    Ok(ZkProof {
        data: blobs.put(
            &[
                b"placeholder".as_slice(),
                &[ProofType::C5PkAggregation as u8],
            ]
            .concat(),
        )?,
        public_inputs: inputs,
    })
}

pub(crate) fn commits_to(proof: &ZkProof, bound: &[u8]) -> bool {
    proof.public_inputs == [keccak256(bound)]
}

pub(crate) fn statements(proofs: &DkgProofs) -> Vec<u8> {
    let c3 = proofs.c3a.values().chain(proofs.c3b.values()).flatten();
    [
        &proofs.c0,
        &proofs.c1,
        &proofs.c2a,
        &proofs.c2b,
        &proofs.c4a,
    ]
    .into_iter()
    .chain(c3)
    .chain(&proofs.c4b)
    .flat_map(|proof| proof.public_inputs.iter().flat_map(|word| word.0))
    .collect()
}

/// A placeholder proves nothing, so a check that finds its commitment wrong cannot tell a bad
/// proof from bad bytes: the message is invalid, and no one is accused.
pub(crate) fn verdict(committed: bool) -> Verdict {
    match committed {
        true => Verdict::Valid,
        false => Verdict::Invalid,
    }
}
