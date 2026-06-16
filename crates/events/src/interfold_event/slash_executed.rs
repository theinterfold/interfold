// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Emitted when a slash proposal is executed on-chain.
///
/// This event is read from the SlashingManager contract logs.
/// The `CommitteeExpulsionHandler` reacts to this to update local committee state.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SlashExecuted {
    /// The E3 computation this slash relates to.
    pub e3_id: E3id,
    /// On-chain proposal ID.
    pub proposal_id: u128,
    /// Address of the slashed operator.
    pub operator: Address,
    /// Hash of the slash reason.
    pub reason: [u8; 32],
    /// Amount of ticket collateral slashed.
    pub ticket_amount: u128,
    /// Amount of license bond slashed.
    pub license_amount: u128,
}

impl Display for SlashExecuted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SlashExecuted {{ e3_id: {}, proposal_id: {}, operator: {} }}",
            self.e3_id, self.proposal_id, self.operator
        )
    }
}

/// Emitted when a committee member is expelled from an E3 committee.
///
/// Read from the CiphernodeRegistry contract logs after slashing triggers expulsion.
/// The `CommitteeExpulsionHandler` uses this to update the local committee view
/// and check viability (whether remaining active members >= threshold M).
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitteeMemberExpelled {
    /// The E3 computation from which the member was expelled.
    pub e3_id: E3id,
    /// Address of the expelled committee member.
    pub node: Address,
    /// Hash of the slash reason that caused the expulsion.
    pub reason: [u8; 32],
    /// Number of active committee members remaining after expulsion.
    pub active_count_after: u64,
    /// Party ID (position in the committee list) of the expelled member.
    /// `None` when read from chain (not yet resolved); `Some(id)` after
    /// enrichment by the Sortition actor.
    pub party_id: Option<u64>,
}

impl Display for CommitteeMemberExpelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommitteeMemberExpelled {{ e3_id: {}, node: {}, active_count_after: {}, party_id: {:?} }}",
            self.e3_id, self.node, self.active_count_after, self.party_id
        )
    }
}
