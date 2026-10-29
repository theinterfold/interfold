// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure replay gate for idempotent EVM publication intents.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

/// Process-local gate rebuilt from durable EventStore facts during startup replay.
///
/// The gate retains one intent for each semantic key until the transaction reaches a terminal
/// outcome. Replayed intents cannot start side effects before `EffectsEnabled`.
pub(crate) struct ReplaySubmissionGate<K, V> {
    effects_enabled: bool,
    pending: HashMap<K, V>,
    in_flight: HashSet<K>,
}

impl<K, V> Default for ReplaySubmissionGate<K, V> {
    fn default() -> Self {
        Self {
            effects_enabled: false,
            pending: HashMap::new(),
            in_flight: HashSet::new(),
        }
    }
}

impl<K, V> ReplaySubmissionGate<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Retain the first durable intent for a key. Replay duplicates do not replace it.
    pub(crate) fn record(&mut self, key: K, intent: V) {
        self.pending.entry(key).or_insert(intent);
    }

    pub(crate) fn enable_effects(&mut self) {
        self.effects_enabled = true;
    }

    /// Start a retained intent when effects are enabled and no submission is in flight.
    pub(crate) fn start(&mut self, key: &K) -> Option<V> {
        if !self.effects_enabled || self.in_flight.contains(key) {
            return None;
        }

        let intent = self.pending.get(key)?.clone();
        self.in_flight.insert(key.clone());
        Some(intent)
    }

    pub(crate) fn pending_keys(&self) -> Vec<K> {
        self.pending.keys().cloned().collect()
    }

    pub(crate) fn contains(&self, key: &K) -> bool {
        self.pending.contains_key(key)
    }

    /// Finish an attempt. Terminal outcomes remove the intent; retryable outcomes retain it.
    pub(crate) fn finish(&mut self, key: &K, terminal: bool) {
        self.in_flight.remove(key);
        if terminal {
            self.pending.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replayed_intent_waits_for_effects() {
        let mut gate = ReplaySubmissionGate::new();
        gate.record(7, "result");

        assert_eq!(gate.start(&7), None);
        gate.enable_effects();
        assert_eq!(gate.start(&7), Some("result"));
    }

    #[test]
    fn duplicate_intent_cannot_start_while_submission_is_in_flight() {
        let mut gate = ReplaySubmissionGate::new();
        gate.record(7, "first");
        gate.record(7, "duplicate");
        gate.enable_effects();

        assert_eq!(gate.pending_keys(), vec![7]);
        assert_eq!(gate.start(&7), Some("first"));
        assert_eq!(gate.start(&7), None);
    }

    #[test]
    fn retryable_failure_retains_the_intent() {
        let mut gate = ReplaySubmissionGate::new();
        gate.record(7, "result");
        gate.enable_effects();
        assert_eq!(gate.start(&7), Some("result"));

        gate.finish(&7, false);

        assert!(gate.contains(&7));
        assert_eq!(gate.start(&7), Some("result"));
    }

    #[test]
    fn terminal_outcome_removes_the_intent() {
        let mut gate = ReplaySubmissionGate::new();
        gate.record(7, "result");
        gate.enable_effects();
        assert_eq!(gate.start(&7), Some("result"));

        gate.finish(&7, true);

        assert!(!gate.contains(&7));
        assert_eq!(gate.start(&7), None);
    }
}
