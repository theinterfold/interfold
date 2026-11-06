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
        let stored = store.read()?;
        let (mut machine, mut last_seq) = match stored.snapshot {
            Some((seq, bytes)) => (decode(&bytes)?, seq),
            None => (genesis, 0),
        };
        let mut steps_since_snapshot = 0;
        for (seq, bytes) in stored.journal {
            let entry: Entry<M::Input> = decode(&bytes)?;
            // The step's effects were committed with it; replay only rebuilds the state.
            machine.step(entry.now, entry.input);
            last_seq = seq;
            steps_since_snapshot += 1;
        }
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
    pub fn apply(mut self, now: UnixSecs, input: M::Input) -> Result<Running<M, S>, Error> {
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

    pub fn machine(&self) -> &M {
        &self.machine
    }

    pub fn next_deadline(&self) -> Option<UnixSecs> {
        self.machine.next_deadline()
    }
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    Ok(bincode::deserialize(bytes)?)
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
}
