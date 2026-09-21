// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Effect execution for public-key aggregation.

use super::*;
use alloy::primitives::Address;

mod aggregate_dkg_proofs;
mod aggregate_lbfv;
mod aggregate_public_key;
mod collect_lbfv_contributions;
mod complete_lbfv_verification;
mod fold_node_proofs;
mod handle_compute_results;
mod publish_result;
mod recovery;
mod redrive_lbfv_aggregation;
mod verify_key_proofs;

#[cfg(test)]
pub(in crate::actors::publickey_aggregator) use redrive_lbfv_aggregation::LBFV_ROW_CORRELATION_TIMEOUT_SECS;

impl PublicKeyAggregator {
    pub fn handle_member_expelled(
        &mut self,
        node: Address,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let selected = self.recovery.try_get()?.selected_roster;
        let selected_member_expelled = self
            .state
            .get()
            .and_then(|state| state.party_id_for_node(node))
            .is_some_and(|party_id| {
                selected
                    .as_ref()
                    .is_some_and(|selected| selected.contains(&party_id))
            });
        if selected_member_expelled {
            warn!(
                e3_id = %self.e3_id,
                %node,
                "A selected DKG roster member was expelled; the fixed H-row proof cannot continue"
            );
            self.bus.publish(
                E3Failed {
                    e3_id: self.e3_id.clone(),
                    failed_at_stage: E3Stage::CommitteeFinalized,
                    reason: FailureReason::InsufficientCommitteeMembers,
                },
                ec.clone(),
            )?;
            return Ok(());
        }
        self.state.try_mutate(ec, |state| {
            PublicKeyAggregation::handle_member_expelled(state, node)
        })
    }
}
