// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use e3_events::{prelude::*, Die, InterfoldEvent, InterfoldEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashSet;

use crate::ThresholdPlaintextAggregator;

pub struct DecryptionshareCreatedBuffer {
    dest: Addr<ThresholdPlaintextAggregator>,
    expelled_parties: HashSet<u64>,
}

impl DecryptionshareCreatedBuffer {
    pub fn new(dest: Addr<ThresholdPlaintextAggregator>) -> Self {
        Self {
            dest,
            expelled_parties: HashSet::new(),
        }
    }

    fn forward(dest: &Addr<ThresholdPlaintextAggregator>, event: InterfoldEvent) {
        dest.do_send(event);
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

                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                let Some(party_id) = data.party_id else {
                    return;
                };

                if !self.expelled_parties.insert(party_id) {
                    return;
                }
                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                let Some(party_id) = data.party_id else {
                    return;
                };

                if !self.expelled_parties.insert(party_id) {
                    return;
                }
                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::AggregatorChanged(_) => {
                Self::forward(&self.dest, msg);
            }
            InterfoldEventData::E3RequestComplete(_) | InterfoldEventData::Shutdown(_) => {
                Self::forward(&self.dest, msg);
            }
            _ => {
                Self::forward(&self.dest, msg);
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
