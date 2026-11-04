// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use alloy::primitives::Address;

use e3_events::{prelude::*, Die, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashSet;
use tracing::info;

use crate::PublicKeyAggregator;

/// Buffers `KeyshareCreated` events until `CommitteeFinalized` arrives.
pub struct KeyshareCreatedFilterBuffer {
    dest: Addr<PublicKeyAggregator>,
    /// Finalized committee in canonical party-id order. A membership set is insufficient here:
    /// accepting a real member under another member's `party_id` poisons the DKG roster.
    committee: Option<Vec<String>>,
    buffer: Vec<InterfoldEvent>,
    expelled_nodes: HashSet<Address>,
}

fn committee_member_matches(committee: &[String], party_id: u64, node: &str) -> bool {
    let Some(expected) = usize::try_from(party_id)
        .ok()
        .and_then(|index| committee.get(index))
        .and_then(|member| member.parse::<Address>().ok())
    else {
        return false;
    };
    node.parse::<Address>()
        .is_ok_and(|address| address == expected)
}

fn address_matches(node: &str, expected: Address) -> bool {
    node.parse::<Address>()
        .is_ok_and(|address| address == expected)
}

impl KeyshareCreatedFilterBuffer {
    pub fn new(dest: Addr<PublicKeyAggregator>) -> Self {
        Self {
            dest,
            committee: None,
            buffer: Vec::new(),
            expelled_nodes: HashSet::new(),
        }
    }

    fn forward(dest: &Addr<PublicKeyAggregator>, event: InterfoldEvent) {
        dest.do_send(event);
    }

    fn process_buffered_events(&mut self) {
        if let Some(ref committee) = self.committee {
            for event in self.buffer.drain(..) {
                match event.get_data() {
                    InterfoldEventData::KeyshareCreated(data)
                        if committee_member_matches(committee, data.party_id, &data.node)
                            && !data
                                .node
                                .parse::<Address>()
                                .is_ok_and(|node| self.expelled_nodes.contains(&node)) =>
                    {
                        Self::forward(&self.dest, event);
                    }
                    InterfoldEventData::CommitteeMemberExpelled(data)
                        if data.party_id.is_none() =>
                    {
                        Self::forward(&self.dest, event);
                    }
                    InterfoldEventData::CommitteeMemberExcluded(data)
                        if data.party_id.is_none() =>
                    {
                        Self::forward(&self.dest, event);
                    }
                    InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                        Self::forward(&self.dest, event);
                    }
                    _ => {}
                }
            }
        }
    }
}

impl Actor for KeyshareCreatedFilterBuffer {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for KeyshareCreatedFilterBuffer {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _ctx: &mut Self::Context) -> Self::Result {
        match msg.get_data() {
            InterfoldEventData::KeyshareCreated(data) => match &self.committee {
                Some(committee)
                    if committee_member_matches(committee, data.party_id, &data.node)
                        && !data
                            .node
                            .parse::<Address>()
                            .is_ok_and(|node| self.expelled_nodes.contains(&node)) =>
                {
                    Self::forward(&self.dest, msg);
                }
                None => {
                    self.buffer.push(msg);
                }
                _ => {}
            },
            InterfoldEventData::CommitteeFinalized(data) => {
                let mut data = data.clone();
                data.sort_by_address();
                self.committee = Some(data.committee);
                self.process_buffered_events();
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node;
                if !self.expelled_nodes.insert(node_addr) {
                    return;
                }
                self.buffer.retain(|event| {
                    !matches!(
                        event.get_data(),
                        InterfoldEventData::KeyshareCreated(share)
                            if address_matches(&share.node, node_addr)
                    )
                });

                if self.committee.is_some() {
                    info!(
                        "KeyshareCreatedFilterBuffer: removing expelled node {} from committee filter (e3_id={})",
                        node_addr, data.e3_id
                    );
                }

                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node;
                if !self.expelled_nodes.insert(node_addr) {
                    return;
                }
                self.buffer.retain(|event| {
                    !matches!(
                        event.get_data(),
                        InterfoldEventData::KeyshareCreated(share)
                            if address_matches(&share.node, node_addr)
                    )
                });

                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::AggregatorChanged(_) => {
                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                self.buffer.clear();
                Self::forward(&self.dest, msg);
            }
            _ => {
                Self::forward(&self.dest, msg);
            }
        }
    }
}

impl Handler<Die> for KeyshareCreatedFilterBuffer {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::{address_matches, committee_member_matches};
    use alloy::primitives::Address;

    const A: &str = "0x1111111111111111111111111111111111111111";
    const B: &str = "0x2222222222222222222222222222222222222222";

    #[test]
    fn committee_membership_is_bound_to_party_slot() {
        let committee = vec![A.to_owned(), B.to_owned()];
        assert!(committee_member_matches(&committee, 0, A));
        assert!(committee_member_matches(&committee, 1, B));
        assert!(!committee_member_matches(&committee, 0, B));
        assert!(!committee_member_matches(&committee, 1, A));
        assert!(!committee_member_matches(&committee, 2, A));
        assert!(!committee_member_matches(&committee, 0, "not-an-address"));
    }

    #[test]
    fn committee_address_comparison_is_case_insensitive() {
        let committee = vec!["0xAbCd000000000000000000000000000000000000".to_owned()];
        assert!(committee_member_matches(
            &committee,
            0,
            "0xabcd000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn expelled_address_comparison_is_case_insensitive() {
        let expelled = "0xAbCd000000000000000000000000000000000000"
            .parse::<Address>()
            .unwrap();
        assert!(address_matches(
            "0xabcd000000000000000000000000000000000000",
            expelled
        ));
    }
}
