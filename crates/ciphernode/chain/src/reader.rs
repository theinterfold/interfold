// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{decode, Contracts, DecodeError, Decoded, PendingRead, RawLog, RpcError};
use alloy_primitives::Address;
use alloy_primitives::U256;
use e3_evm::log_window::LogWindow;
use e3_protocol::{
    dkg::DkgTiming,
    node::{ChainEvent, ChainFact, CommitteeRequest, CommitteeSeed},
    UnixSecs,
};
use futures::{stream::BoxStream, StreamExt};
use std::collections::BTreeSet;
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, warn};

/// A reader waiting for announcements still reads this often, so the health check sees it read
/// and a log the chain node did not announce, as across a reconnection, is read late rather than
/// never.
const LONGEST_WAIT: Duration = Duration::from_secs(60);

/// The longest the reader waits for one answer. A chain node can hold a request without ever
/// answering it; the request then fails the poll, and the next poll asks again.
const LONGEST_ANSWER: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
#[error("the chain node did not answer in {LONGEST_ANSWER:?}")]
struct Unanswered;

/// The answer to `request`, or a failure once the chain node took too long.
async fn answer<T, E: From<RpcError>>(request: impl Future<Output = Result<T, E>>) -> Result<T, E> {
    tokio::time::timeout(LONGEST_ANSWER, request)
        .await
        .unwrap_or_else(|_| Err(RpcError::new(Unanswered).into()))
}

/// Why a chain node gave no logs.
#[derive(Debug, thiserror::Error)]
pub enum LogsError {
    /// The provider refuses this many blocks or logs in one answer; fewer would do.
    #[error("the provider refused the range: {0}")]
    TooWide(RpcError),
    #[error(transparent)]
    Failed(#[from] RpcError),
}

/// What the reader needs from a chain node.
pub trait Rpc {
    /// The newest block's number.
    fn head(&self) -> impl Future<Output = Result<u64, RpcError>> + Send;

    /// The blocks of the new logs of the contracts at `addresses`, as the chain node announces
    /// them from now on; none when it cannot announce, as over HTTP. The stream ends when the node
    /// stops announcing, and dropping it stops the announcements.
    fn announce(
        &self,
        addresses: &[Address],
    ) -> impl Future<Output = Result<Option<BoxStream<'static, u64>>, RpcError>> + Send;

    /// The logs of the contracts at `addresses` in blocks `from..=to`, with their blocks'
    /// timestamps.
    fn logs(
        &self,
        addresses: &[Address],
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<RawLog>, LogsError>> + Send;

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

    /// Which of `operators` the bonding registry finds eligible at `at`.
    fn eligible(
        &self,
        operators: &[Address],
        at: UnixSecs,
    ) -> impl Future<Output = Result<BTreeSet<Address>, RpcError>> + Send;
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

/// The chain node's announcements of the contracts' new logs.
enum Announcements {
    /// Not asked for yet, or asked for other contracts than the reader reads now.
    Unasked,
    /// The reader polls for the rest of the run: the chain node cannot announce, as over HTTP, or
    /// left a request unanswered for a minute, and a late answer to a repeated request would leave
    /// a subscription that nothing ends.
    Off,
    /// The request failed, or the announcements stopped: the reader polls until it asks again at
    /// `retry`.
    Failed { retry: Instant },
    Active {
        addresses: Vec<Address>,
        blocks: BoxStream<'static, u64>,
    },
}

/// Reads one chain's confirmed logs as facts, in order.
pub struct Reader<R> {
    rpc: R,
    contracts: Contracts,
    /// Blocks closer to the head than this may still be replaced.
    confirmations: u64,
    /// How many blocks the next `logs` request covers. A provider's limit does not change, so what
    /// the provider refused is not asked of it again.
    window: LogWindow,
    /// The first block not read yet.
    next: u64,
    /// The chain node's head at the last poll.
    head: u64,
    /// The wait between polls of a chain node that announces nothing, and while an announced block
    /// lacks its confirmations.
    poll: Duration,
    announcements: Announcements,
    /// The newest block that may hold a log the chain node did not announce or the reader did not
    /// read.
    announced: Option<u64>,
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
        poll: Duration,
    ) -> Self {
        Self {
            rpc,
            contracts,
            confirmations,
            window: LogWindow::with_max(max_range),
            next: from,
            head: 0,
            poll,
            announcements: Announcements::Unasked,
            announced: None,
        }
    }

    /// The chain node's head at the last poll.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// The last block whose logs the reader delivered.
    pub fn read_to(&self) -> u64 {
        self.next.saturating_sub(1)
    }

    /// The newest confirmed block, while one is unread.
    fn unread(&self) -> Option<u64> {
        self.head
            .checked_sub(self.confirmations)
            .filter(|confirmed| *confirmed >= self.next)
    }

    /// Whether the last poll left no confirmed block unread.
    pub fn caught_up(&self) -> bool {
        self.unread().is_none()
    }

    /// The facts of the next confirmed blocks, in log order; none when no block was confirmed
    /// since the last poll. A failed poll returns no facts and leaves the reader where it was.
    pub async fn poll(&mut self) -> Result<Vec<ChainEvent>, ReadError> {
        self.head = answer(self.rpc.head()).await?;
        let Some(confirmed) = self.unread() else {
            return Ok(Vec::new());
        };
        let (to, decoded) = loop {
            let (to, logs) = self.fetch(confirmed).await?;
            let decoded = decode(&self.contracts, &logs)?;
            let (mut providers, mut managers) = (BTreeSet::new(), BTreeSet::new());
            for decoded in &decoded {
                match decoded {
                    Decoded::Fact(ChainEvent {
                        fact: ChainFact::RandomnessProvider { provider },
                        ..
                    }) if !self.contracts.randomness.contains(provider) => {
                        providers.insert(*provider);
                    }
                    Decoded::Fact(ChainEvent {
                        fact: ChainFact::SlashingManager { manager },
                        ..
                    }) if !self.contracts.slashing.contains(manager) => {
                        managers.insert(*manager);
                    }
                    _ => {}
                }
            }
            if providers.is_empty() && managers.is_empty() {
                break (to, decoded);
            }
            // The new contracts' logs in these blocks were filtered out.
            self.contracts.randomness.extend(providers);
            self.contracts.slashing.extend(managers);
        };
        let mut events = Vec::new();
        for decoded in decoded {
            match decoded {
                Decoded::Fact(event) => events.push(event),
                Decoded::Read(read) => events.extend(Self::read(&self.rpc, read, confirmed).await?),
            }
        }
        self.next = to + 1;
        Ok(events)
    }

    /// The logs from the next block on, in as many blocks up to `confirmed` as the provider serves
    /// at once, and the last of those blocks. A refused range is asked for again at once in fewer
    /// blocks; a provider that refuses a single block has no range limit to learn.
    async fn fetch(&mut self, confirmed: u64) -> Result<(u64, Vec<RawLog>), ReadError> {
        let addresses = self.contracts.addresses();
        loop {
            let to = self.window.end_for(self.next, confirmed);
            match answer(self.rpc.logs(&addresses, self.next, to)).await {
                Ok(logs) => return Ok((to, logs)),
                Err(LogsError::Failed(failure)) => return Err(failure.into()),
                Err(LogsError::TooWide(refusal)) => {
                    if !self.window.shrink() {
                        let refusal = format!("the provider refuses even one block: {refusal}");
                        return Err(RpcError(refusal.into()).into());
                    }
                    let blocks = self.window.width();
                    match self.window.is_narrow() {
                        true => warn!(
                            blocks, %refusal,
                            "the provider allows few blocks per request, so reading history is \
                             slow; an endpoint with a wider limit reads it faster"
                        ),
                        false => debug!(blocks, %refusal, "asking the provider for fewer blocks"),
                    }
                }
            }
        }
    }

    /// Waits after a successful poll until the chain may hold a log the reader has not read. It
    /// returns at once while confirmed blocks are unread. Otherwise it waits for the chain node to
    /// announce a log after them; while an announced block lacks its confirmations, or when the
    /// node announces nothing, it waits for the poll interval. With the request for announcements,
    /// it waits `LONGEST_WAIT` at most.
    pub async fn wait(&mut self) {
        if self.unread().is_some() {
            return;
        }
        let deadline = Instant::now() + LONGEST_WAIT;
        self.subscribe(deadline).await;
        let next = self.next;
        let poll = (Instant::now() + self.poll).min(deadline);
        let Announcements::Active { blocks, .. } = &mut self.announcements else {
            tokio::time::sleep_until(poll).await;
            return;
        };
        if self.announced.is_some_and(|block| block >= next) {
            tokio::time::sleep_until(poll).await;
            return;
        }
        loop {
            match tokio::time::timeout_at(deadline, blocks.next()).await {
                Ok(Some(block)) if block >= next => {
                    self.announced = Some(block);
                    return;
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    warn!("the chain node stopped announcing logs; polling it for now");
                    self.announcements = failed();
                    return;
                }
                Err(_) => return,
            }
        }
    }

    /// Asks the chain node, by `deadline`, to announce the logs of the contracts the reader reads,
    /// unless it does already, is off, or failed less than `LONGEST_WAIT` ago. The blocks up to the
    /// head at that point were not announced, so the reader polls until it has read them.
    async fn subscribe(&mut self, deadline: Instant) {
        let addresses = self.contracts.addresses();
        match &self.announcements {
            Announcements::Active {
                addresses: covered, ..
            } if *covered == addresses => return,
            Announcements::Off => return,
            Announcements::Failed { retry } if Instant::now() < *retry => return,
            _ => {}
        }
        let rpc = &self.rpc;
        let asked = tokio::time::timeout_at(deadline, async {
            let Some(blocks) = rpc.announce(&addresses).await? else {
                return Ok(None);
            };
            Ok::<_, RpcError>(Some((blocks, rpc.head().await?)))
        });
        self.announcements = match asked.await {
            Ok(Ok(None)) => Announcements::Off,
            Ok(Ok(Some((blocks, head)))) => {
                self.announced = self.announced.max(Some(head));
                Announcements::Active { addresses, blocks }
            }
            Ok(Err(failure)) => {
                warn!(%failure, "the chain node refused to announce logs; polling it for now");
                failed()
            }
            Err(_) => {
                warn!("the chain node did not answer a request to announce logs; polling it");
                Announcements::Off
            }
        };
    }

    /// The fact a read completes, from the state at the confirmed head `block`, which a node that
    /// prunes old state still has. Every value read here is written once, at or before its log's
    /// block, except the committee deadline: the registry moves it when it accepts the
    /// randomness, and a request read after that carries the seed too.
    async fn read(rpc: &R, read: PendingRead, block: u64) -> Result<Option<ChainEvent>, RpcError> {
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
                let sortition = answer(rpc.sortition(e3.number, block)).await?;
                let request = CommitteeRequest {
                    time,
                    ticket_price: sortition.ticket_price,
                    owner_cap,
                    dkg_window: answer(rpc.dkg_window(e3.number, block)).await?,
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
                    deadline: answer(rpc.deadlines(e3.number, block)).await?.dkg,
                    window: answer(rpc.dkg_window(e3.number, block)).await?,
                };
                (at, time, ChainFact::CommitteeFinalized { e3, members, dkg })
            }
            PendingRead::Seed { at, time, e3 } => {
                let sortition = answer(rpc.sortition(e3.number, block)).await?;
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
                anchors,
            } => {
                let fact = ChainFact::KeyPublished {
                    e3,
                    committee,
                    roster,
                    commitment,
                    compute_deadline: answer(rpc.deadlines(e3.number, block)).await?.compute,
                    anchors,
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
                    deadline: answer(rpc.deadlines(e3.number, block)).await?.decryption,
                };
                (at, time, fact)
            }
        };
        Ok(Some(ChainEvent { at, time, fact }))
    }
}

/// Announcements that failed now, asked for again after `LONGEST_WAIT`.
fn failed() -> Announcements {
    Announcements::Failed {
        retry: Instant::now() + LONGEST_WAIT,
    }
}

#[cfg(test)]
mod tests;
