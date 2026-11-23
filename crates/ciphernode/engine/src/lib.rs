// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs a [`Machine`] durably. Each input, with the time it was applied, is journaled in the same
//! store transaction as the effects it produced and, when due, a snapshot of the new state. A
//! restart loads the latest snapshot and replays the journal after it; effects stay in the outbox
//! until an adapter acknowledges them.

mod memory;

pub use memory::MemoryStore;

use bincode::Options;
use e3_protocol::{Machine, UnixSecs};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// An effect's place in the outbox: the step that emitted it and its position in that step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EffectKey {
    pub seq: u64,
    pub index: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Pending<E> {
    pub key: EffectKey,
    pub effect: E,
}

/// The bytes one step commits, all in one transaction.
pub struct Step {
    pub seq: u64,
    pub entry: Vec<u8>,
    pub effects: Vec<(EffectKey, Vec<u8>)>,
    pub snapshot: Option<Vec<u8>>,
    /// The effect this step answers, which ends with it.
    pub answers: Option<EffectKey>,
}

/// One operation inside [`Engine::apply_batch`].
pub enum BatchOp<I> {
    /// Step the machine with `input`, optionally answering a prior effect in the same commit.
    Step {
        now: UnixSecs,
        input: I,
        answers: Option<EffectKey>,
    },
    /// Acknowledge a previously emitted durable effect without stepping the machine.
    Ack(EffectKey),
}

/// A batch of steps, acknowledgments, and optional final snapshot committed in one transaction.
#[derive(Default)]
pub struct BatchCommit {
    pub steps: Vec<Step>,
    pub acks: Vec<EffectKey>,
    /// When present, captures the state after step `seq` (typically the final step in `steps`).
    pub snapshot: Option<(u64, Vec<u8>)>,
}

/// What a store holds when the engine opens it.
#[derive(Clone, Debug, Default)]
pub struct Stored {
    /// The latest snapshot and the step it was taken after.
    pub snapshot: Option<(u64, Vec<u8>)>,
    /// The journal entries after the snapshot, in order.
    pub journal: Vec<(u64, Vec<u8>)>,
    /// The effects not acknowledged yet, in order.
    pub outbox: Vec<(EffectKey, Vec<u8>)>,
}

pub trait Store {
    fn read(&self) -> Result<Stored, StoreError>;
    fn commit(&mut self, step: Step) -> Result<(), StoreError>;
    fn acknowledge(&mut self, key: EffectKey) -> Result<(), StoreError>;
    /// Keeps `snapshot` as the state after step `seq`, the last one committed.
    fn checkpoint(&mut self, seq: u64, snapshot: Vec<u8>) -> Result<(), StoreError>;
    /// Commits a batch of steps and acknowledgments atomically (one transaction / one fsync).
    fn commit_batch(&mut self, batch: BatchCommit) -> Result<(), StoreError> {
        for step in batch.steps {
            self.commit(step)?;
        }
        for key in batch.acks {
            self.acknowledge(key)?;
        }
        if let Some((seq, snapshot)) = batch.snapshot {
            self.checkpoint(seq, snapshot)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StoreError(pub Box<dyn std::error::Error + Send + Sync>);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("encoding: {0}")]
    Encoding(#[from] bincode::Error),
}

/// The machine a store's contents rebuild, without the store: what a read-only look at a stopped
/// node's journal needs. It reads everything a start reads, so what passes here starts.
pub fn restore<M: Machine + DeserializeOwned>(stored: Stored, genesis: M) -> Result<M, Error>
where
    M::Input: DeserializeOwned,
    M::Effect: DeserializeOwned,
{
    Ok(recover(stored, genesis)?.0)
}

/// The machine, its last step, the steps since its snapshot, and the effects still pending.
type Recovered<M> = (M, u64, u64, Vec<Pending<<M as Machine>::Effect>>);

fn recover<M: Machine + DeserializeOwned>(stored: Stored, genesis: M) -> Result<Recovered<M>, Error>
where
    M::Input: DeserializeOwned,
    M::Effect: DeserializeOwned,
{
    let (machine, last_seq, steps_since_snapshot) =
        replay(stored.snapshot, stored.journal, genesis)?;
    let pending = stored
        .outbox
        .into_iter()
        .map(|(key, bytes)| {
            Ok(Pending {
                key,
                effect: decode(&bytes)?,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok((machine, last_seq, steps_since_snapshot, pending))
}

/// The machine, its last step, and the steps since its snapshot.
fn replay<M: Machine + DeserializeOwned>(
    snapshot: Option<(u64, Vec<u8>)>,
    journal: Vec<(u64, Vec<u8>)>,
    genesis: M,
) -> Result<(M, u64, u64), Error>
where
    M::Input: DeserializeOwned,
{
    let (mut machine, mut last_seq) = match snapshot {
        Some((seq, bytes)) => (decode(&bytes)?, seq),
        None => (genesis, 0),
    };
    let mut steps_since_snapshot = 0;
    for (seq, bytes) in journal {
        let entry: Entry<M::Input> = decode(&bytes)?;
        // The step's effects were committed with it; replay only rebuilds the state.
        machine.step(entry.now, entry.input);
        last_seq = seq;
        steps_since_snapshot += 1;
    }
    Ok((machine, last_seq, steps_since_snapshot))
}

#[derive(Serialize, Deserialize)]
struct Entry<I> {
    now: UnixSecs,
    input: I,
}

/// An engine with the effects it returned: still pending after `open`, new after `apply`.
pub type Running<M, S> = (Engine<M, S>, Vec<Pending<<M as Machine>::Effect>>);

pub struct Engine<M: Machine, S: Store> {
    machine: M,
    store: S,
    next_seq: u64,
    steps_since_snapshot: u64,
    snapshot_every: u64,
}

impl<M: Machine, S: Store> Engine<M, S> {
    /// Restore the machine from `store`, or start from `genesis` when the store is empty. Returns
    /// the effects that are still pending.
    pub fn open(store: S, genesis: M, snapshot_every: u64) -> Result<Running<M, S>, Error> {
        let (machine, last_seq, steps_since_snapshot, pending) = recover(store.read()?, genesis)?;
        let engine = Self {
            machine,
            store,
            next_seq: last_seq + 1,
            steps_since_snapshot,
            snapshot_every: snapshot_every.max(1),
        };
        Ok((engine, pending))
    }

    /// Step the machine with `input` and commit the step. On error the engine is gone: its state
    /// may be ahead of the store, so the caller restarts from the store.
    pub fn apply(self, now: UnixSecs, input: M::Input) -> Result<Running<M, S>, Error> {
        self.step(now, input, None)
    }

    /// As [`Self::apply`], for the input that answers the effect at `key`: the effect ends in the
    /// same commit, so a crash cannot leave an answered effect to run again.
    pub fn answer(
        self,
        now: UnixSecs,
        input: M::Input,
        key: EffectKey,
    ) -> Result<Running<M, S>, Error> {
        self.step(now, input, Some(key))
    }

    /// Apply a batch of steps and acknowledgments in a single durable store commit.
    ///
    /// On error the engine is consumed because in-memory state may be ahead of the store, matching
    /// [`Self::apply`].
    pub fn apply_batch<I>(mut self, ops: I) -> Result<Running<M, S>, Error>
    where
        I: IntoIterator<Item = BatchOp<M::Input>>,
    {
        let mut batch = BatchCommit::default();
        let mut all_pending = Vec::new();
        let mut seq = self.next_seq;
        let mut steps_applied = 0u64;

        for op in ops {
            match op {
                BatchOp::Step {
                    now,
                    input,
                    answers,
                } => {
                    let entry = bincode::serialize(&Entry { now, input: &input })?;
                    let effects = self.machine.step(now, input);
                    let mut encoded = Vec::new();
                    for (index, effect) in effects.into_iter().enumerate() {
                        let key = EffectKey {
                            seq,
                            index: index as u32,
                        };
                        if M::is_durable_effect(&effect) {
                            encoded.push((key, bincode::serialize(&effect)?));
                        }
                        all_pending.push(Pending { key, effect });
                    }
                    batch.steps.push(Step {
                        seq,
                        entry,
                        effects: encoded,
                        snapshot: None,
                        answers,
                    });
                    seq += 1;
                    steps_applied += 1;
                }
                BatchOp::Ack(key) => {
                    batch.acks.push(key);
                }
            }
        }

        if batch.steps.is_empty() && batch.acks.is_empty() {
            return Ok((self, all_pending));
        }

        let snapshot_due =
            steps_applied > 0 && self.steps_since_snapshot + steps_applied >= self.snapshot_every;
        if snapshot_due {
            let last_seq = seq - 1;
            batch.snapshot = Some((last_seq, bincode::serialize(&self.machine)?));
        }

        self.store.commit_batch(batch)?;
        self.next_seq = seq;
        self.steps_since_snapshot = if snapshot_due {
            0
        } else {
            self.steps_since_snapshot + steps_applied
        };
        Ok((self, all_pending))
    }

    fn step(
        mut self,
        now: UnixSecs,
        input: M::Input,
        answers: Option<EffectKey>,
    ) -> Result<Running<M, S>, Error> {
        let seq = self.next_seq;
        let entry = bincode::serialize(&Entry { now, input: &input })?;
        let effects = self.machine.step(now, input);
        let pending: Vec<Pending<M::Effect>> = effects
            .into_iter()
            .enumerate()
            .map(|(index, effect)| Pending {
                key: EffectKey {
                    seq,
                    index: index as u32,
                },
                effect,
            })
            .collect();
        let encoded = pending
            .iter()
            .filter(|p| M::is_durable_effect(&p.effect))
            .map(|p| Ok((p.key, bincode::serialize(&p.effect)?)))
            .collect::<Result<_, Error>>()?;
        let snapshot_due = self.steps_since_snapshot + 1 >= self.snapshot_every;
        let snapshot = match snapshot_due {
            true => Some(bincode::serialize(&self.machine)?),
            false => None,
        };
        self.store.commit(Step {
            seq,
            entry,
            effects: encoded,
            snapshot,
            answers,
        })?;
        self.next_seq = seq + 1;
        self.steps_since_snapshot = match snapshot_due {
            true => 0,
            false => self.steps_since_snapshot + 1,
        };
        Ok((self, pending))
    }

    pub fn acknowledge(&mut self, key: EffectKey) -> Result<(), Error> {
        Ok(self.store.acknowledge(key)?)
    }

    /// Snapshots the state after the last step, so the store holds no journal entry past its
    /// snapshot: only the snapshot and the outbox describe the node. A clean stop leaves the store
    /// so, and a later release that changes their encoding needs to convert only those two.
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        if self.steps_since_snapshot == 0 {
            return Ok(());
        }
        let snapshot = bincode::serialize(&self.machine)?;
        self.store.checkpoint(self.next_seq - 1, snapshot)?;
        self.steps_since_snapshot = 0;
        Ok(())
    }

    pub fn machine(&self) -> &M {
        &self.machine
    }

    pub fn next_deadline(&self) -> Option<UnixSecs> {
        self.machine.next_deadline()
    }
}

/// What the engine stored, which `bincode::serialize` wrote. The bytes' length bounds what decoding
/// may allocate, so damaged data fails to decode instead of exhausting memory, and bytes left over
/// fail it too.
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_protocol::Tick;

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Tally {
        total: u64,
        last_applied_at: UnixSecs,
    }

    #[derive(Serialize, Deserialize)]
    enum TallyInput {
        Add(u64),
        Tick,
    }

    impl From<Tick> for TallyInput {
        fn from(_: Tick) -> Self {
            TallyInput::Tick
        }
    }

    impl Machine for Tally {
        type Input = TallyInput;
        type Effect = u64;

        fn step(&mut self, now: UnixSecs, input: TallyInput) -> Vec<u64> {
            self.last_applied_at = now;
            match input {
                TallyInput::Add(amount) => {
                    self.total += amount;
                    vec![self.total]
                }
                TallyInput::Tick => vec![],
            }
        }

        fn next_deadline(&self) -> Option<UnixSecs> {
            None
        }
    }

    fn apply_all<S: Store>(
        mut engine: Engine<Tally, S>,
        inputs: &[(UnixSecs, u64)],
    ) -> (Engine<Tally, S>, Vec<Pending<u64>>) {
        let mut all = Vec::new();
        for (now, amount) in inputs {
            let (next, pending) = engine.apply(*now, TallyInput::Add(*amount)).unwrap();
            engine = next;
            all.extend(pending);
        }
        (engine, all)
    }

    /// Damaged bytes fail to decode: a length past the end of the data, and bytes left over.
    #[test]
    fn damaged_bytes_fail_to_decode() {
        let past_the_end = u64::MAX.to_le_bytes();
        assert!(decode::<Vec<u64>>(&past_the_end).is_err());
        let mut left_over = bincode::serialize(&7u64).unwrap();
        assert_eq!(decode::<u64>(&left_over).unwrap(), 7);
        left_over.push(0);
        assert!(decode::<u64>(&left_over).is_err());
    }

    /// What a read-only look passes, a start must be able to read: the outbox too.
    #[test]
    fn restoring_reads_the_outbox_as_a_start_does() {
        let stored = Stored {
            outbox: vec![(EffectKey { seq: 1, index: 0 }, vec![0xff])],
            ..Stored::default()
        };
        assert!(restore(stored, Tally::default()).is_err());
    }

    /// After a checkpoint the store holds the state in its snapshot alone, with the effects still
    /// pending.
    #[test]
    fn a_checkpoint_leaves_no_journal_past_the_snapshot() {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Tally::default(), 100).unwrap();
        let (mut engine, pending) = apply_all(engine, &[(10, 1), (20, 2), (30, 3)]);
        engine.acknowledge(pending[0].key).unwrap();
        engine.checkpoint().unwrap();
        drop(engine);

        let stored = store.read().unwrap();
        assert_eq!(stored.snapshot.as_ref().map(|(seq, _)| *seq), Some(3));
        assert!(stored.journal.is_empty());
        let (restarted, pending) = Engine::open(store, Tally::default(), 100).unwrap();
        assert_eq!(restarted.machine().total, 6);
        let left: Vec<u64> = pending.into_iter().map(|p| p.effect).collect();
        assert_eq!(left, [3, 6]);
        let (mut restarted, _) = restarted.apply(40, TallyInput::Add(4)).unwrap();
        restarted.checkpoint().unwrap();
        assert_eq!(restarted.machine().total, 10);
    }

    #[test]
    fn a_restart_restores_the_state_and_the_unacknowledged_effects() {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Tally::default(), 100).unwrap();
        let (mut engine, pending) = apply_all(engine, &[(10, 1), (20, 2), (30, 3)]);
        engine.acknowledge(pending[1].key).unwrap();
        drop(engine);

        let (restarted, pending) = Engine::open(store, Tally::default(), 100).unwrap();
        assert_eq!(
            restarted.machine(),
            &Tally {
                total: 6,
                last_applied_at: 30
            }
        );
        let effects: Vec<u64> = pending.into_iter().map(|p| p.effect).collect();
        assert_eq!(effects, vec![1, 6]);
    }

    #[test]
    fn a_snapshot_and_the_journal_after_it_restore_the_same_state() {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Tally::default(), 2).unwrap();
        let (engine, _) = apply_all(engine, &[(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]);
        drop(engine);

        let (restarted, _) = Engine::open(store, Tally::default(), 2).unwrap();
        assert_eq!(
            restarted.machine(),
            &Tally {
                total: 15,
                last_applied_at: 5
            }
        );
    }

    struct FailingStore {
        inner: MemoryStore,
        fail: bool,
    }

    impl Store for FailingStore {
        fn read(&self) -> Result<Stored, StoreError> {
            self.inner.read()
        }

        fn commit(&mut self, step: Step) -> Result<(), StoreError> {
            match self.fail {
                true => Err(StoreError("disk full".into())),
                false => self.inner.commit(step),
            }
        }

        fn acknowledge(&mut self, key: EffectKey) -> Result<(), StoreError> {
            self.inner.acknowledge(key)
        }

        fn checkpoint(&mut self, seq: u64, snapshot: Vec<u8>) -> Result<(), StoreError> {
            self.inner.checkpoint(seq, snapshot)
        }
    }

    #[test]
    fn a_failed_commit_leaves_the_store_at_the_previous_step() {
        let memory = MemoryStore::default();
        let failing = FailingStore {
            inner: memory.clone(),
            fail: false,
        };
        let (engine, _) = Engine::open(failing, Tally::default(), 100).unwrap();
        let (mut engine, _) = engine.apply(10, TallyInput::Add(1)).unwrap();
        engine.store.fail = true;
        assert!(engine.apply(20, TallyInput::Add(2)).is_err());

        let (restarted, pending) = Engine::open(memory, Tally::default(), 100).unwrap();
        assert_eq!(restarted.machine().total, 1);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn apply_batch_commits_steps_acks_and_snapshot_atomically() {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Tally::default(), 3).unwrap();
        let (engine, first) = engine.apply(1, TallyInput::Add(1)).unwrap();
        let (engine, batched) = engine
            .apply_batch([
                BatchOp::Ack(first[0].key),
                BatchOp::Step {
                    now: 2,
                    input: TallyInput::Add(2),
                    answers: None,
                },
                BatchOp::Step {
                    now: 3,
                    input: TallyInput::Add(3),
                    answers: None,
                },
            ])
            .unwrap();
        assert_eq!(batched.len(), 2);
        drop(engine);

        let stored = store.read().unwrap();
        assert_eq!(stored.snapshot.as_ref().map(|(seq, _)| *seq), Some(3));
        assert!(stored.journal.is_empty());
        let (restarted, pending) = Engine::open(store, Tally::default(), 3).unwrap();
        assert_eq!(restarted.machine().total, 6);
        let values: Vec<u64> = pending.into_iter().map(|p| p.effect).collect();
        assert_eq!(values, vec![3, 6]);
    }
}
