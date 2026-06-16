// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;

use e3_events::{prelude::*, AggregatorChanged, Die, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashSet;
use tracing::{info, warn};

use crate::PublicKeyAggregator;

/// Buffers `KeyshareCreated` events until `CommitteeFinalized` arrives.
pub struct KeyshareCreatedFilterBuffer {
    dest: Addr<PublicKeyAggregator>,
    committee: Option<HashSet<String>>,
    buffer: Vec<InterfoldEvent>,
    expelled_nodes: HashSet<String>,
    is_aggregator: bool,
}

impl KeyshareCreatedFilterBuffer {
    pub fn new(dest: Addr<PublicKeyAggregator>) -> Self {
        Self {
            dest,
            committee: None,
            buffer: Vec::new(),
            expelled_nodes: HashSet::new(),
            is_aggregator: false,
        }
    }

    fn process_buffered_events(&mut self) {
        if !self.is_aggregator {
            return;
        }

        if let Some(ref committee) = self.committee {
            let before = self.buffer.len();
            let mut forwarded = 0usize;
            let mut dropped = 0usize;
            for event in self.buffer.drain(..) {
                match event.get_data() {
                    InterfoldEventData::KeyshareCreated(data)
                        if committee.contains(&data.node)
                            && !self.expelled_nodes.contains(&data.node) =>
                    {
                        forwarded += 1;
                        self.dest.do_send(event);
                    }
                    InterfoldEventData::CommitteeMemberExpelled(data)
                        if data.party_id.is_none() =>
                    {
                        self.dest.do_send(event);
                    }
                    InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                        self.dest.do_send(event);
                    }
                    _ => {
                        dropped += 1;
                    }
                }
            }
            info!(
                before,
                forwarded, dropped, "KeyshareCreatedFilterBuffer: flushed buffer"
            );
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
                    if self.is_aggregator
                        && committee.contains(&data.node)
                        && !self.expelled_nodes.contains(&data.node) =>
                {
                    self.dest.do_send(msg);
                }
                None => {
                    info!(
                        node = %data.node,
                        "KeyshareCreatedFilterBuffer: buffering KeyshareCreated — committee not yet known"
                    );
                    self.buffer.push(msg);
                }
                Some(committee)
                    if committee.contains(&data.node)
                        && !self.expelled_nodes.contains(&data.node) =>
                {
                    info!(
                        node = %data.node,
                        "KeyshareCreatedFilterBuffer: buffering KeyshareCreated — not yet aggregator"
                    );
                    self.buffer.push(msg);
                }
                Some(committee) if !committee.contains(&data.node) => {
                    warn!(
                        node = %data.node,
                        committee = ?committee,
                        "KeyshareCreatedFilterBuffer: dropping KeyshareCreated — node not in committee"
                    );
                }
                _ => {}
            },
            InterfoldEventData::CommitteeFinalized(data) => {
                self.committee = Some(data.committee.iter().cloned().collect());
                self.process_buffered_events();
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node.to_string();
                self.expelled_nodes.insert(node_addr.clone());
                self.buffer.retain(|event| {
                    !matches!(
                        event.get_data(),
                        InterfoldEventData::KeyshareCreated(share) if share.node == node_addr
                    )
                });

                if let Some(ref mut committee) = self.committee {
                    info!(
                        "KeyshareCreatedFilterBuffer: removing expelled node {} from committee filter (e3_id={})",
                        node_addr, data.e3_id
                    );
                    committee.remove(&node_addr);
                }

                if self.is_aggregator {
                    self.dest.do_send(msg);
                } else {
                    self.buffer.push(msg);
                }
            }
            InterfoldEventData::AggregatorChanged(AggregatorChanged { is_aggregator, .. }) => {
                self.is_aggregator = *is_aggregator;
                self.process_buffered_events();
            }
            InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                self.dest.do_send(msg);
            }
            _ => {
                if self.is_aggregator {
                    self.dest.do_send(msg);
                }
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
