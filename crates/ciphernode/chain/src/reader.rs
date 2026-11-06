// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{decode, Contracts, DecodeError, Decoded, PendingRead, RawLog, RpcError};
use alloy_primitives::Address;
use alloy_primitives::U256;
use e3_protocol::{
    dkg::DkgTiming,
    node::{ChainEvent, ChainFact, CommitteeRequest, CommitteeSeed},
    UnixSecs,
};
use std::collections::BTreeSet;
use std::future::Future;

/// What the reader needs from a chain node.
pub trait Rpc {
    /// The newest block's number.
    fn head(&self) -> impl Future<Output = Result<u64, RpcError>> + Send;

    /// The logs of the contracts at `addresses` in blocks `from..=to`, with their blocks'
    /// timestamps.
    fn logs(
        &self,
        addresses: &[Address],
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<RawLog>, RpcError>> + Send;

    /// The registry's sortition state of `e3`.
    fn sortition(
        &self,
        e3: U256,
        block: u64,
    ) -> impl Future<Output = Result<Sortition, RpcError>> + Send;

    /// The stage deadlines of `e3`; each is zero until its stage begins.
    fn deadlines(
        &self,
        e3: U256,
        block: u64,
    ) -> impl Future<Output = Result<Deadlines, RpcError>> + Send;

    /// The DKG window `e3` froze.
    fn dkg_window(
        &self,
        e3: U256,
        block: u64,
    ) -> impl Future<Output = Result<UnixSecs, RpcError>> + Send;

    /// The request-time bound of `e3`'s lifecycle.
    fn lifecycle_deadline(
        &self,
        e3: U256,
        block: u64,
    ) -> impl Future<Output = Result<UnixSecs, RpcError>> + Send;
}

/// The registry's sortition state of one E3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sortition {
    pub ticket_price: U256,
    /// The randomness deadline until the registry accepts the randomness, then the deadline for
    /// tickets.
    pub committee_deadline: UnixSecs,
    /// Once the registry accepted the randomness.
    pub seed: Option<U256>,
}

/// The deadlines after which the contract fails an E3 in each stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlines {
    pub dkg: UnixSecs,
    pub compute: UnixSecs,
    pub decryption: UnixSecs,
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The chain node failed; the next poll repeats the work.
    #[error("chain node: {0}")]
    Rpc(#[from] RpcError),
    /// A log the node cannot read safely; ingestion stops.
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// Reads one chain's confirmed logs as facts, in order.
pub struct Reader<R> {
    rpc: R,
    contracts: Contracts,
    /// Blocks closer to the head than this may still be replaced.
    confirmations: u64,
    max_range: u64,
    /// How many blocks the next `logs` request covers. Providers cap a request's blocks or logs
    /// with different limits, so a failed request halves it and a successful one doubles it, up
    /// to `max_range`.
    range: u64,
    /// The first block not read yet.
    next: u64,
}

impl<R: Rpc> Reader<R> {
    /// A reader that starts at block `from`: the block of the node's last applied fact, which it
    /// reads again because the node skips facts it applied, or the contracts' deployment block.
    pub fn new(
        rpc: R,
        contracts: Contracts,
        confirmations: u64,
        max_range: u64,
        from: u64,
    ) -> Self {
        let max_range = max_range.max(1);
        Self {
            rpc,
            contracts,
            confirmations,
            max_range,
            range: max_range,
            next: from,
        }
    }

    /// The facts of the next confirmed blocks, in log order; none when no block was confirmed
    /// since the last poll. A failed poll returns no facts and leaves the reader where it was.
    pub async fn poll(&mut self) -> Result<Vec<ChainEvent>, ReadError> {
        let head = self.rpc.head().await?;
        let Some(confirmed) = head
            .checked_sub(self.confirmations)
            .filter(|confirmed| *confirmed >= self.next)
        else {
            return Ok(Vec::new());
        };
        let to = confirmed.min(self.next.saturating_add(self.range - 1));
        let decoded = loop {
            let addresses = self.contracts.addresses();
            let logs = match self.rpc.logs(&addresses, self.next, to).await {
                Ok(logs) => {
                    self.range = self.range.saturating_mul(2).min(self.max_range);
                    logs
                }
                Err(error) => {
                    self.range = (self.range / 2).max(1);
                    return Err(error.into());
                }
            };
            let decoded = decode(&self.contracts, &logs)?;
            let providers: BTreeSet<Address> = decoded
                .iter()
                .filter_map(|decoded| match decoded {
                    Decoded::Fact(ChainEvent {
                        fact: ChainFact::RandomnessProvider { provider },
                        ..
                    }) => Some(*provider),
                    _ => None,
                })
                .filter(|provider| !self.contracts.randomness.contains(provider))
                .collect();
            if providers.is_empty() {
                break decoded;
            }
            // The new providers' fulfillments in these blocks were filtered out.
            self.contracts.randomness.extend(providers);
        };
        let mut events = Vec::new();
        for decoded in decoded {
            match decoded {
                Decoded::Fact(event) => events.push(event),
                Decoded::Read(read) => events.extend(self.read(read, confirmed).await?),
            }
        }
        self.next = to + 1;
        Ok(events)
    }

    /// The fact a read completes, from the state at the confirmed head `block`, which a node that
    /// prunes old state still has. Every value read here is written once, at or before its log's
    /// block, except the committee deadline: the registry moves it when it accepts the
    /// randomness, and a request read after that carries the seed too.
    async fn read(&self, read: PendingRead, block: u64) -> Result<Option<ChainEvent>, RpcError> {
        let (at, time, fact) = match read {
            PendingRead::Request {
                at,
                time,
                e3,
                params,
                interfold,
                attestation,
                owner_cap,
            } => {
                let sortition = self.rpc.sortition(e3.number, block).await?;
                let request = CommitteeRequest {
                    time,
                    ticket_price: sortition.ticket_price,
                    owner_cap,
                    dkg_window: self.rpc.dkg_window(e3.number, block).await?,
                    lifecycle_deadline: self.rpc.lifecycle_deadline(e3.number, block).await?,
                };
                let fact = ChainFact::E3Requested {
                    e3,
                    params,
                    interfold,
                    attestation,
                    request,
                    committee_deadline: sortition.committee_deadline,
                    seed: sortition.seed,
                };
                (at, time, fact)
            }
            PendingRead::DkgTiming {
                at,
                time,
                e3,
                members,
            } => {
                let dkg = DkgTiming {
                    deadline: self.rpc.deadlines(e3.number, block).await?.dkg,
                    window: self.rpc.dkg_window(e3.number, block).await?,
                };
                (at, time, ChainFact::CommitteeFinalized { e3, members, dkg })
            }
            PendingRead::Seed { at, time, e3 } => {
                let sortition = self.rpc.sortition(e3.number, block).await?;
                let Some(seed) = sortition.seed else {
                    return Ok(None);
                };
                let seed = CommitteeSeed {
                    seed,
                    deadline: sortition.committee_deadline,
                };
                (at, time, ChainFact::SeedReady { e3, seed })
            }
            PendingRead::Key {
                at,
                time,
                e3,
                committee,
                roster,
                commitment,
            } => {
                let fact = ChainFact::KeyPublished {
                    e3,
                    committee,
                    roster,
                    commitment,
                    compute_deadline: self.rpc.deadlines(e3.number, block).await?.compute,
                };
                (at, time, fact)
            }
            PendingRead::Ciphertext {
                at,
                time,
                e3,
                ciphertext,
            } => {
                let fact = ChainFact::CiphertextReady {
                    e3,
                    ciphertext,
                    deadline: self.rpc.deadlines(e3.number, block).await?.decryption,
                };
                (at, time, fact)
            }
        };
        Ok(Some(ChainEvent { at, time, fact }))
    }
}

#[cfg(test)]
mod tests;
