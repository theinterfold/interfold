// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Effect execution for public-key aggregation.

use super::*;
use alloy::primitives::Address;

mod aggregate_dkg_proofs;
mod aggregate_public_key;
mod fold_node_proofs;
mod handle_compute_results;
mod node_proof_deadline;
mod publish_result;
mod recovery;
mod verify_key_proofs;

impl PublicKeyAggregator {
    pub fn handle_member_expelled(
        &mut self,
        node: Address,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |state| {
            PublicKeyAggregation::handle_member_expelled(state, node)
        })
    }
}
