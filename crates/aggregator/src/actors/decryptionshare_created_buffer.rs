// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use e3_events::{prelude::*, AggregatorChanged, Die, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashSet;

use crate::ThresholdPlaintextAggregator;

pub struct DecryptionshareCreatedBuffer {
    dest: Addr<ThresholdPlaintextAggregator>,
    buffer: Vec<InterfoldEvent>,
    expelled_parties: HashSet<u64>,
    is_aggregator: bool,
}

impl DecryptionshareCreatedBuffer {
    pub fn new(dest: Addr<ThresholdPlaintextAggregator>) -> Self {
        Self::new_with_aggregator_state(dest, false)
    }

    pub fn new_with_aggregator_state(
        dest: Addr<ThresholdPlaintextAggregator>,
        is_aggregator: bool,
    ) -> Self {
        Self {
            dest,
            buffer: Vec::new(),
            expelled_parties: HashSet::new(),
            is_aggregator,
        }
    }

    fn flush(&mut self) {
        if !self.is_aggregator {
            return;
        }

        for event in self.buffer.drain(..) {
            match event.get_data() {
                InterfoldEventData::DecryptionshareCreated(data)
                    if !self.expelled_parties.contains(&data.party_id) =>
                {
                    self.dest.do_send(event);
                }
                InterfoldEventData::CommitteeMemberExpelled(data) if data.party_id.is_some() => {
                    self.dest.do_send(event);
                }
                InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                    self.dest.do_send(event);
                }
                _ => {}
            }
        }
    }
}

impl Actor for DecryptionshareCreatedBuffer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for DecryptionshareCreatedBuffer {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _ctx: &mut Self::Context) -> Self::Result {
        match msg.get_data() {
            InterfoldEventData::DecryptionshareCreated(data) => {
                if self.expelled_parties.contains(&data.party_id) {
                    return;
                }

                if self.is_aggregator {
                    self.dest.do_send(msg);
                } else {
                    self.buffer.push(msg);
                }
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                let Some(party_id) = data.party_id else {
                    return;
                };

                self.expelled_parties.insert(party_id);
                self.buffer.retain(|event| {
                    !matches!(
                        event.get_data(),
                        InterfoldEventData::DecryptionshareCreated(share)
                            if share.party_id == party_id
                    )
                });

                if self.is_aggregator {
                    self.dest.do_send(msg);
                } else {
                    self.buffer.push(msg);
                }
            }
            InterfoldEventData::AggregatorChanged(AggregatorChanged { is_aggregator, .. }) => {
                self.is_aggregator = *is_aggregator;
                self.flush();
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

impl Handler<Die> for DecryptionshareCreatedBuffer {
    type Result = ();

    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
