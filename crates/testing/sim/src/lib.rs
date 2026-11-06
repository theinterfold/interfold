// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs v2 nodes in one process with virtual time and crashes. Each node also feeds a shadow copy
//! of its machine that never crashes and never touches a store; the node must always produce the
//! same effects as its shadow and end in the same state.

use alloy_primitives::Address;
use e3_engine::{Engine, MemoryStore};
use e3_protocol::{
    node::{Input, Node},
    Machine, UnixSecs,
};

pub struct SimNode {
    me: Address,
    store: MemoryStore,
    engine: Option<Engine<Node, MemoryStore>>,
    shadow: Node,
    snapshot_every: u64,
}

impl SimNode {
    pub fn new(me: Address, snapshot_every: u64) -> Self {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Node::new(me), snapshot_every)
            .expect("a fresh memory store opens");
        Self {
            me,
            store,
            engine: Some(engine),
            shadow: Node::new(me),
            snapshot_every,
        }
    }

    pub fn apply(&mut self, now: UnixSecs, input: Input) {
        let engine = self.engine.take().expect("the node is running");
        let (engine, pending) = engine
            .apply(now, input.clone())
            .expect("a memory store commits");
        let effects: Vec<_> = pending.into_iter().map(|p| p.effect).collect();
        assert_eq!(effects, self.shadow.step(now, input));
        self.engine = Some(engine);
    }

    /// Drop the running engine without warning and open a new one on the same store.
    pub fn crash_and_restart(&mut self) {
        self.engine = None;
        let (engine, _) = Engine::open(self.store.clone(), Node::new(self.me), self.snapshot_every)
            .expect("the store reopens");
        self.engine = Some(engine);
    }

    pub fn node(&self) -> &Node {
        self.engine.as_ref().expect("the node is running").machine()
    }

    pub fn shadow(&self) -> &Node {
        &self.shadow
    }
}
