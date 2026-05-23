// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use e3_events::{prelude::*, AggregatorChanged, Die, EnclaveEvent, EnclaveEventData};
use e3_utils::MAILBOX_LIMIT;
use std::collections::HashSet;
use tracing::{info, warn};

use crate::ThresholdPlaintextAggregator;

pub struct DecryptionshareCreatedBuffer {
    dest: Addr<ThresholdPlaintextAggregator>,
    buffer: Vec<EnclaveEvent>,
    expelled_parties: HashSet<u64>,
    is_aggregator: bool,
}

impl DecryptionshareCreatedBuffer {
    pub fn new(dest: Addr<ThresholdPlaintextAggregator>) -> Self {
        Self {
            dest,
            buffer: Vec::new(),
            expelled_parties: HashSet::new(),
            is_aggregator: false,
        }
    }

    fn flush(&mut self) {
        if !self.is_aggregator {
            return;
        }

        let before = self.buffer.len();
        let mut forwarded = 0usize;
        let mut dropped = 0usize;
        for event in self.buffer.drain(..) {
            match event.get_data() {
                EnclaveEventData::DecryptionshareCreated(data)
                    if !self.expelled_parties.contains(&data.party_id) =>
                {
                    forwarded += 1;
                    self.dest.do_send(event);
                }
                EnclaveEventData::CommitteeMemberExpelled(data) if data.party_id.is_some() => {
                    forwarded += 1;
                    self.dest.do_send(event);
                }
                EnclaveEventData::E3RequestComplete(_) | EnclaveEventData::Shutdown(_) => {
                    forwarded += 1;
                    self.dest.do_send(event);
                }
                _ => {
                    dropped += 1;
                }
            }
        }
        info!(
            before,
            forwarded, dropped, "DecryptionshareCreatedBuffer: flushed buffer"
        );
    }
}

impl Actor for DecryptionshareCreatedBuffer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<EnclaveEvent> for DecryptionshareCreatedBuffer {
    type Result = ();

    fn handle(&mut self, msg: EnclaveEvent, _ctx: &mut Self::Context) -> Self::Result {
        match msg.get_data() {
            EnclaveEventData::DecryptionshareCreated(data) => {
                if self.expelled_parties.contains(&data.party_id) {
                    warn!(
                        party_id = data.party_id,
                        "DecryptionshareCreatedBuffer: dropping DecryptionshareCreated — party is expelled"
                    );
                    return;
                }

                if self.is_aggregator {
                    self.dest.do_send(msg);
                } else {
                    info!(
                        party_id = data.party_id,
                        "DecryptionshareCreatedBuffer: buffering DecryptionshareCreated — not yet aggregator"
                    );
                    self.buffer.push(msg);
                }
            }
            EnclaveEventData::CommitteeMemberExpelled(data) => {
                let Some(party_id) = data.party_id else {
                    return;
                };

                self.expelled_parties.insert(party_id);
                self.buffer.retain(|event| {
                    !matches!(
                        event.get_data(),
                        EnclaveEventData::DecryptionshareCreated(share)
                            if share.party_id == party_id
                    )
                });

                if self.is_aggregator {
                    self.dest.do_send(msg);
                } else {
                    self.buffer.push(msg);
                }
            }
            EnclaveEventData::AggregatorChanged(AggregatorChanged { is_aggregator, .. }) => {
                info!(
                    is_aggregator,
                    buffered_events = self.buffer.len(),
                    "DecryptionshareCreatedBuffer: AggregatorChanged — is_aggregator={is_aggregator}, buffered={}",
                    self.buffer.len()
                );
                self.is_aggregator = *is_aggregator;
                self.flush();
            }
            EnclaveEventData::E3RequestComplete(_) | EnclaveEventData::Shutdown(_) => {
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
