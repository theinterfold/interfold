// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The accusation job: whether an accused proof fails, checked by every member that votes.

use crate::{Blobs, JobError, Jobs};
use e3_protocol::{
    accusation::{AccusationWork, AccusationWorkResult},
    node::CryptoParams,
};

impl<B: Blobs> Jobs<'_, B> {
    pub(crate) fn run_accusation(
        &self,
        params: &CryptoParams,
        work: &AccusationWork,
    ) -> Result<AccusationWorkResult, JobError> {
        let AccusationWork::Verify { proof_type, proof } = work;
        let fails = match self.prover() {
            Some(prover) => !self
                .verdict(prover, params, [(*proof_type, proof)])?
                .is_valid(),
            // A placeholder proves nothing, so no member is slashed for one.
            None => false,
        };
        Ok(AccusationWorkResult::Verified {
            proof_type: *proof_type,
            proof: proof.clone(),
            fails,
            data_hash: self.data_hash(proof)?,
        })
    }
}
