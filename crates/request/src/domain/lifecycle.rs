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

fn is_terminal(stage: &E3Stage) -> bool {
    matches!(stage, E3Stage::Complete | E3Stage::Failed)
}

/// Maps an event to the `(e3_id, stage)` it implies, if any.
fn implied(event: &InterfoldEventData) -> Option<(E3id, E3Stage)> {
    match event {
        InterfoldEventData::E3Requested(d) => Some((d.e3_id.clone(), E3Stage::Requested)),
        InterfoldEventData::CommitteePublished(d) => {
            Some((d.e3_id.clone(), E3Stage::CommitteeFinalized))
        }
        InterfoldEventData::CommitteeFinalized(d) => {
            Some((d.e3_id.clone(), E3Stage::CommitteeFinalized))
        }
        InterfoldEventData::PublicKeyAggregated(d) => {
            Some((d.e3_id.clone(), E3Stage::KeyPublished))
        }
        InterfoldEventData::CiphertextOutputPublished(d) => {
            Some((d.e3_id.clone(), E3Stage::CiphertextReady))
        }
        InterfoldEventData::PlaintextAggregated(d) => Some((d.e3_id.clone(), E3Stage::Complete)),
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
mod tests {
    use super::*;
    use e3_events::{E3Failed, E3Requested, E3StageChanged, FailureReason};

    fn id(n: &str) -> E3id {
        E3id::new(n, 1)
    }

    fn requested(n: &str) -> InterfoldEventData {
        InterfoldEventData::E3Requested(E3Requested {
            e3_id: id(n),
            ..Default::default()
        })
    }

    fn stage_changed(n: &str, from: E3Stage, to: E3Stage) -> InterfoldEventData {
        InterfoldEventData::E3StageChanged(E3StageChanged {
            e3_id: id(n),
            previous_stage: from,
            new_stage: to,
        })
    }

    fn failed(n: &str, stage: E3Stage) -> InterfoldEventData {
        InterfoldEventData::E3Failed(E3Failed {
            e3_id: id(n),
            failed_at_stage: stage,
            reason: FailureReason::DKGTimeout,
        })
    }

    #[test]
    fn unknown_e3_is_stage_none() {
        let svc = E3LifecycleService::new();
        assert_eq!(E3Stage::None, svc.stage(&id("x")));
    }

    #[test]
    fn requested_advances_from_none() {
        let mut svc = E3LifecycleService::new();
        let decision = svc.observe(&requested("a"));
        assert_eq!(
            LifecycleDecision::Advanced {
                e3_id: id("a"),
                from: E3Stage::None,
                to: E3Stage::Requested
            },
            decision
        );
        assert_eq!(E3Stage::Requested, svc.stage(&id("a")));
    }

    #[test]
    fn stage_advances_monotonically() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&requested("a"));
        let d = svc.observe(&stage_changed(
            "a",
            E3Stage::Requested,
            E3Stage::KeyPublished,
        ));
        assert!(matches!(d, LifecycleDecision::Advanced { .. }));
        assert_eq!(E3Stage::KeyPublished, svc.stage(&id("a")));
    }

    #[test]
    fn out_of_order_earlier_stage_is_regressed_and_ignored() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&stage_changed("a", E3Stage::None, E3Stage::KeyPublished));
        let d = svc.observe(&requested("a"));
        assert_eq!(
            LifecycleDecision::Regressed {
                e3_id: id("a"),
                current: E3Stage::KeyPublished,
                attempted: E3Stage::Requested
            },
            d
        );
        // Tracked stage is unchanged.
        assert_eq!(E3Stage::KeyPublished, svc.stage(&id("a")));
    }

    #[test]
    fn same_stage_is_unchanged() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&requested("a"));
        let d = svc.observe(&requested("a"));
        assert_eq!(
            LifecycleDecision::Unchanged {
                e3_id: id("a"),
                stage: E3Stage::Requested
            },
            d
        );
    }

    #[test]
    fn failure_is_terminal_and_frozen() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&requested("a"));
        let d = svc.observe(&failed("a", E3Stage::Requested));
        assert_eq!(
            LifecycleDecision::Terminal {
                e3_id: id("a"),
                stage: E3Stage::Failed
            },
            d
        );
        // Further lifecycle events do not move a terminal E3.
        let d2 = svc.observe(&stage_changed("a", E3Stage::Failed, E3Stage::Complete));
        assert_eq!(
            LifecycleDecision::Unchanged {
                e3_id: id("a"),
                stage: E3Stage::Failed
            },
            d2
        );
        assert_eq!(E3Stage::Failed, svc.stage(&id("a")));
    }

    #[test]
    fn active_excludes_terminal_e3s() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&requested("a"));
        svc.observe(&requested("b"));
        svc.observe(&failed("b", E3Stage::Requested));
        let active = svc.active();
        assert_eq!(vec![id("a")], active);
    }

    #[test]
    fn non_lifecycle_event_is_ignored() {
        let mut svc = E3LifecycleService::new();
        let d = svc.observe(&InterfoldEventData::Shutdown(e3_events::Shutdown));
        assert_eq!(LifecycleDecision::NotLifecycle, d);
    }

    #[test]
    fn snapshot_roundtrip_preserves_stages() {
        let mut svc = E3LifecycleService::new();
        svc.observe(&requested("a"));
        svc.observe(&stage_changed(
            "a",
            E3Stage::Requested,
            E3Stage::CiphertextReady,
        ));
        svc.observe(&requested("b"));

        let snap = svc.snapshot();
        let restored = E3LifecycleService::from_snapshot(snap);
        assert_eq!(E3Stage::CiphertextReady, restored.stage(&id("a")));
        assert_eq!(E3Stage::Requested, restored.stage(&id("b")));
    }
}
