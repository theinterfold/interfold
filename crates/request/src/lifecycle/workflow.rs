// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Pure, actor-free E3 lifecycle tracking service.
//!
//! The Interfold node is choreographed: each subsystem reacts to protocol events
//! independently. Historically there was no single, durable source of truth for
//! "what stage is this E3 at?". [`E3LifecycleService`] fills that gap. It is a
//! pure observer over the lifecycle-bearing events on the bus: it maintains a
//! monotonic, per-E3 [`E3Stage`] map that can be persisted and rehydrated on
//! restart so the node always knows the stage of every in-flight E3.
//!
//! The service is intentionally additive and side-effect free. It does NOT emit
//! protocol events or drive subsystems — the owning actor decides what to do
//! with the [`LifecycleDecision`] (persist, log, surface invalid transitions).

use e3_events::{E3Stage, E3id, InterfoldEventData};
use std::collections::HashMap;

/// Outcome of observing a single event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleDecision {
    /// The event advanced the E3 to a later stage.
    Advanced {
        e3_id: E3id,
        from: E3Stage,
        to: E3Stage,
    },
    /// The event moved the E3 into a terminal stage (`Complete` or `Failed`).
    Terminal { e3_id: E3id, stage: E3Stage },
    /// The event maps to a stage the E3 has already reached or passed; ignored.
    Unchanged { e3_id: E3id, stage: E3Stage },
    /// The event implied an earlier stage than the E3 has already reached.
    /// Surfaced so callers can log it; the tracked stage is left untouched.
    Regressed {
        e3_id: E3id,
        current: E3Stage,
        attempted: E3Stage,
    },
    /// The event carries no lifecycle meaning.
    NotLifecycle,
}

/// Monotonic rank used to order stages. `Failed` is terminal and ranks highest
/// so that, once failed, no later observation can move the E3 elsewhere.
fn rank(stage: &E3Stage) -> u8 {
    match stage {
        E3Stage::None => 0,
        E3Stage::Requested => 1,
        E3Stage::CommitteeFinalized => 2,
        E3Stage::KeyPublished => 3,
        E3Stage::CiphertextReady => 4,
        E3Stage::Complete => 5,
        E3Stage::Failed => 6,
    }
}

/// Maps an event to the `(e3_id, stage)` it implies, if any.
fn implied(event: &InterfoldEventData) -> Option<(E3id, E3Stage)> {
    match event {
        InterfoldEventData::E3Requested(d) => Some((d.e3_id.clone(), E3Stage::Requested)),
        InterfoldEventData::CommitteePublished(d) => Some((d.e3_id.clone(), E3Stage::KeyPublished)),
        InterfoldEventData::CommitteeFinalized(d) => {
            Some((d.e3_id.clone(), E3Stage::CommitteeFinalized))
        }
        InterfoldEventData::CiphertextOutputPublished(d) => {
            Some((d.e3_id.clone(), E3Stage::CiphertextReady))
        }
        InterfoldEventData::PlaintextOutputPublished(d) => {
            Some((d.e3_id.clone(), E3Stage::Complete))
        }
        InterfoldEventData::E3RequestComplete(d) => Some((d.e3_id.clone(), E3Stage::Complete)),
        InterfoldEventData::E3Failed(d) => Some((d.e3_id.clone(), E3Stage::Failed)),
        // `E3StageChanged` carries the authoritative stage directly.
        InterfoldEventData::E3StageChanged(d) => Some((d.e3_id.clone(), d.new_stage.clone())),
        _ => None,
    }
}

/// Pure per-E3 lifecycle stage tracker.
#[derive(Debug, Clone, Default)]
pub struct E3LifecycleService {
    stages: HashMap<E3id, E3Stage>,
}

impl E3LifecycleService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a service from a persisted snapshot.
    pub fn from_snapshot(stages: HashMap<E3id, E3Stage>) -> Self {
        Self { stages }
    }

    /// Returns a serializable snapshot of the current stage map.
    pub fn snapshot(&self) -> HashMap<E3id, E3Stage> {
        self.stages.clone()
    }

    /// Returns the tracked stage for an E3, or `E3Stage::None` if unknown.
    pub fn stage(&self, e3_id: &E3id) -> E3Stage {
        self.stages.get(e3_id).cloned().unwrap_or(E3Stage::None)
    }

    /// Returns the E3 ids that are tracked but not yet in a terminal stage.
    pub fn active(&self) -> Vec<E3id> {
        self.stages
            .iter()
            .filter(|(_, stage)| !is_terminal(stage))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Observes an event and updates the tracked stage monotonically.
    pub fn observe(&mut self, event: &InterfoldEventData) -> LifecycleDecision {
        let Some((e3_id, implied_stage)) = implied(event) else {
            return LifecycleDecision::NotLifecycle;
        };

        let current = self.stage(&e3_id);

        // Once terminal, the stage is frozen.
        if is_terminal(&current) {
            return LifecycleDecision::Unchanged {
                e3_id,
                stage: current,
            };
        }

        match rank(&implied_stage).cmp(&rank(&current)) {
            std::cmp::Ordering::Greater => {
                self.stages.insert(e3_id.clone(), implied_stage.clone());
                if is_terminal(&implied_stage) {
                    LifecycleDecision::Terminal {
                        e3_id,
                        stage: implied_stage,
                    }
                } else {
                    LifecycleDecision::Advanced {
                        e3_id,
                        from: current,
                        to: implied_stage,
                    }
                }
            }
            std::cmp::Ordering::Equal => LifecycleDecision::Unchanged {
                e3_id,
                stage: current,
            },
            std::cmp::Ordering::Less => LifecycleDecision::Regressed {
                e3_id,
                current,
                attempted: implied_stage,
            },
        }
    }
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
