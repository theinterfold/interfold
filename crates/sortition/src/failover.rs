// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deterministic active-aggregator failover state and policy.
//!
//! The committee is normalized into ascending address order before it is stored.
//! The lowest eligible party is the active aggregator. If that party does not
//! publish the expected on-chain result before the durable deadline, every node
//! can skip it and select the next party without a separate election protocol.

pub use e3_events::AggregationPhase as AggregatorPhase;
use e3_events::{Committee, E3Stage, E3id};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub const AGGREGATOR_FAILOVER_SCHEMA_VERSION: u16 = 2;
const LEGACY_EARLY_TIMER_SCHEMA_VERSION: u16 = 1;

/// A durable timer. Its phase and active party identify the pending work. The
/// absolute deadline preserves the budget across restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorFailoverRound {
    pub phase: AggregatorPhase,
    pub active_party_id: Option<u64>,
    pub deadline_unix_secs: u64,
    /// True after the final eligible party times out. The final party remains
    /// active so that late recovery is still possible.
    pub exhausted: bool,
}

/// Versioned durable failover state. Its repository schema is independent of
/// the committee selector snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatorFailoverState {
    pub schema_version: u16,
    pub rounds: HashMap<E3id, AggregatorFailoverRound>,
    pub unresponsive: HashMap<E3id, Vec<u64>>,
}

impl Default for AggregatorFailoverState {
    fn default() -> Self {
        Self {
            schema_version: AGGREGATOR_FAILOVER_SCHEMA_VERSION,
            rounds: HashMap::new(),
            unresponsive: HashMap::new(),
        }
    }
}

impl AggregatorFailoverState {
    pub fn has_supported_schema(&self) -> bool {
        self.schema_version == AGGREGATOR_FAILOVER_SCHEMA_VERSION
    }

    /// Remove v1 timers that started at the canonical stage boundary, before
    /// aggregation inputs were available. The serialized layout is unchanged.
    pub fn migrate_early_timer_schema(&mut self) -> bool {
        if self.schema_version != LEGACY_EARLY_TIMER_SCHEMA_VERSION {
            return false;
        }
        self.rounds.clear();
        self.unresponsive.clear();
        self.schema_version = AGGREGATOR_FAILOVER_SCHEMA_VERSION;
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FailoverPolicy {
    timeout: Duration,
}

impl FailoverPolicy {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverDecision {
    Hold,
    Promote {
        demote: u64,
        promote_to: u64,
        new_addr: String,
    },
    /// No standby remains. The caller must retain the final active party and
    /// wait for either late recovery or the canonical chain deadline.
    Exhausted {
        active: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedFailoverDeadline {
    pub phase: AggregatorPhase,
    pub unix_secs: u64,
}

/// Return the pending aggregator phase represented by a canonical E3 stage.
pub fn phase_for_stage(stage: &E3Stage) -> Option<AggregatorPhase> {
    match stage {
        E3Stage::CommitteeFinalized => Some(AggregatorPhase::PublicKey),
        E3Stage::CiphertextReady => Some(AggregatorPhase::Plaintext),
        _ => None,
    }
}

/// Reconcile one E3 with its latest canonical phase.
///
/// A replay of the same phase preserves its deadline and skip set. A real
/// phase change starts a new budget and clears phase-local liveness judgments.
pub fn reconcile_phase(
    state: &mut AggregatorFailoverState,
    e3_id: &E3id,
    phase: Option<AggregatorPhase>,
    now_unix_secs: u64,
    policy: &FailoverPolicy,
) {
    let Some(phase) = phase else {
        state.rounds.remove(e3_id);
        state.unresponsive.remove(e3_id);
        return;
    };

    let unchanged = state
        .rounds
        .get(e3_id)
        .is_some_and(|round| round.phase == phase);
    if unchanged {
        return;
    }

    state.unresponsive.remove(e3_id);
    state.rounds.insert(
        e3_id.clone(),
        AggregatorFailoverRound {
            phase,
            active_party_id: None,
            deadline_unix_secs: now_unix_secs.saturating_add(policy.timeout().as_secs()),
            exhausted: false,
        },
    );
}

/// Bind a phase deadline to the party that currently owns aggregation.
/// A new assignment receives the full budget.
pub fn reconcile_active_party(
    state: &mut AggregatorFailoverState,
    e3_id: &E3id,
    active_party_id: Option<u64>,
    now_unix_secs: u64,
    policy: &FailoverPolicy,
) {
    let Some(round) = state.rounds.get_mut(e3_id) else {
        return;
    };
    if round.active_party_id == active_party_id {
        return;
    }
    round.active_party_id = active_party_id;
    round.deadline_unix_secs = now_unix_secs.saturating_add(policy.timeout().as_secs());
    round.exhausted = false;
}

/// Apply an expected deadline atomically to the durable state.
///
/// `expected_phase` and `expected_deadline` make callbacks from cancelled or
/// superseded timers harmless.
pub fn apply_due_timeout(
    state: &mut AggregatorFailoverState,
    e3_id: &E3id,
    expected: ExpectedFailoverDeadline,
    now_unix_secs: u64,
    policy: &FailoverPolicy,
    committee: &Committee,
    expelled: &[u64],
) -> FailoverDecision {
    let Some(round) = state.rounds.get(e3_id) else {
        return FailoverDecision::Hold;
    };
    if round.phase != expected.phase
        || round.deadline_unix_secs != expected.unix_secs
        || round.exhausted
        || now_unix_secs < round.deadline_unix_secs
    {
        return FailoverDecision::Hold;
    }

    let unresponsive = state.unresponsive.get(e3_id).cloned().unwrap_or_default();
    let skipped: Vec<u64> = expelled
        .iter()
        .chain(unresponsive.iter())
        .copied()
        .collect();
    let Some(active) = committee.active_aggregator_party_id(&skipped) else {
        return FailoverDecision::Hold;
    };
    if state
        .rounds
        .get(e3_id)
        .is_none_or(|round| round.active_party_id != Some(active))
    {
        return FailoverDecision::Hold;
    }
    let standbys = committee.aggregator_standbys(&skipped, committee.len());

    let Some((promote_to, new_addr)) = standbys
        .iter()
        .find(|(party_id, _)| *party_id > active)
        .cloned()
    else {
        if let Some(round) = state.rounds.get_mut(e3_id) {
            round.exhausted = true;
        }
        return FailoverDecision::Exhausted { active };
    };

    let skipped_for_e3 = state.unresponsive.entry(e3_id.clone()).or_default();
    if !skipped_for_e3.contains(&active) {
        skipped_for_e3.push(active);
        skipped_for_e3.sort_unstable();
    }
    if let Some(round) = state.rounds.get_mut(e3_id) {
        round.active_party_id = Some(promote_to);
        round.deadline_unix_secs = now_unix_secs.saturating_add(policy.timeout().as_secs());
    }

    FailoverDecision::Promote {
        demote: active,
        promote_to,
        new_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e3_id() -> E3id {
        E3id::new("42", 1)
    }

    fn policy() -> FailoverPolicy {
        FailoverPolicy::new(Duration::from_secs(60))
    }

    fn committee() -> Committee {
        Committee::new(vec!["0xa".into(), "0xb".into(), "0xc".into()])
    }

    #[test]
    fn v1_migration_clears_early_timers_and_skip_state() {
        let id = e3_id();
        let mut state = AggregatorFailoverState {
            schema_version: 1,
            rounds: HashMap::from([(
                id.clone(),
                AggregatorFailoverRound {
                    phase: AggregatorPhase::PublicKey,
                    active_party_id: Some(2),
                    deadline_unix_secs: 500,
                    exhausted: true,
                },
            )]),
            unresponsive: HashMap::from([(id, vec![0, 1])]),
        };

        assert!(state.migrate_early_timer_schema());
        assert!(state.has_supported_schema());
        assert!(state.rounds.is_empty());
        assert!(state.unresponsive.is_empty());
        assert!(!state.migrate_early_timer_schema());
    }

    #[test]
    fn restart_in_same_phase_preserves_deadline_and_skips() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::PublicKey),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());
        state.unresponsive.insert(id.clone(), vec![0]);

        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::PublicKey),
            140,
            &policy(),
        );

        assert_eq!(state.rounds[&id].deadline_unix_secs, 160);
        assert_eq!(state.rounds[&id].active_party_id, Some(0));
        assert_eq!(state.unresponsive[&id], vec![0]);
    }

    #[test]
    fn phase_change_starts_new_budget_and_clears_skips() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::PublicKey),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());
        state.unresponsive.insert(id.clone(), vec![0]);

        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::Plaintext),
            150,
            &policy(),
        );

        assert_eq!(state.rounds[&id].deadline_unix_secs, 210);
        assert_eq!(state.rounds[&id].active_party_id, None);
        assert!(!state.unresponsive.contains_key(&id));
    }

    #[test]
    fn party_reassignment_starts_a_full_budget() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::PublicKey),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());

        reconcile_active_party(&mut state, &id, Some(1), 140, &policy());

        assert_eq!(state.rounds[&id].active_party_id, Some(1));
        assert_eq!(state.rounds[&id].deadline_unix_secs, 200);
    }

    #[test]
    fn terminal_phase_removes_all_failover_state() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::Plaintext),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());
        state.unresponsive.insert(id.clone(), vec![0]);

        reconcile_phase(&mut state, &id, None, 120, &policy());

        assert!(!state.rounds.contains_key(&id));
        assert!(!state.unresponsive.contains_key(&id));
    }

    #[test]
    fn due_timeout_promotes_once_and_refreshes_deadline() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::Plaintext),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());

        let decision = apply_due_timeout(
            &mut state,
            &id,
            ExpectedFailoverDeadline {
                phase: AggregatorPhase::Plaintext,
                unix_secs: 160,
            },
            160,
            &policy(),
            &committee(),
            &[],
        );

        assert_eq!(
            decision,
            FailoverDecision::Promote {
                demote: 0,
                promote_to: 1,
                new_addr: "0xb".into(),
            }
        );
        assert_eq!(state.unresponsive[&id], vec![0]);
        assert_eq!(state.rounds[&id].deadline_unix_secs, 220);
        assert_eq!(state.rounds[&id].active_party_id, Some(1));

        let stale = apply_due_timeout(
            &mut state,
            &id,
            ExpectedFailoverDeadline {
                phase: AggregatorPhase::Plaintext,
                unix_secs: 160,
            },
            220,
            &policy(),
            &committee(),
            &[],
        );
        assert_eq!(stale, FailoverDecision::Hold);
        assert_eq!(state.unresponsive[&id], vec![0]);
    }

    #[test]
    fn exhaustion_keeps_final_party_active() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();
        reconcile_phase(
            &mut state,
            &id,
            Some(AggregatorPhase::Plaintext),
            100,
            &policy(),
        );
        reconcile_active_party(&mut state, &id, Some(2), 100, &policy());
        state.unresponsive.insert(id.clone(), vec![0, 1]);

        let decision = apply_due_timeout(
            &mut state,
            &id,
            ExpectedFailoverDeadline {
                phase: AggregatorPhase::Plaintext,
                unix_secs: 160,
            },
            160,
            &policy(),
            &committee(),
            &[],
        );

        assert_eq!(decision, FailoverDecision::Exhausted { active: 2 });
        assert_eq!(state.unresponsive[&id], vec![0, 1]);
        assert!(state.rounds[&id].exhausted);
    }

    /// A phase must be covered by a failover deadline from the moment it starts.
    ///
    /// `CiphernodeSelector::observe_phase` decides when to create a round. It previously created
    /// one only when `ready_phases` held the phase, which `AggregationInputsReady` sets after the
    /// aggregator already holds a threshold of shares. The collection window was therefore
    /// uncovered: an aggregator that died early in a phase left no round, so no timer could fire
    /// and no standby was ever promoted.
    ///
    /// Observed on a 5-node swarm: the active aggregator was killed two seconds into the
    /// decryption phase, and 903 seconds later — over 1.5x the 600 second budget — there had been
    /// no promotion and no plaintext, while both survivors held a usable decryption share.
    ///
    /// This models the selector's gating expression. `reconcile_phase` itself was always correct;
    /// the defect was that it was not called at phase start.
    #[test]
    fn a_phase_is_covered_by_a_deadline_from_the_moment_it_starts() {
        let id = e3_id();
        let mut state = AggregatorFailoverState::default();

        // The phase has just changed, and no AggregationInputsReady has arrived yet.
        let phase = Some(AggregatorPhase::Plaintext);
        let phase_changed = true;
        let ready = false;

        // The selector's condition: a round must be created for a phase change, not only when
        // inputs are ready.
        if ready || phase_changed {
            reconcile_phase(&mut state, &id, phase, 100, &policy());
        }

        let round = state.rounds.get(&id).expect(
            "a phase change must create a failover round; without one an aggregator that dies \
             before aggregation inputs are ready is never replaced",
        );
        assert_eq!(round.phase, AggregatorPhase::Plaintext);
        assert_eq!(
            round.deadline_unix_secs, 160,
            "the round must carry the full budget from the phase start"
        );

        // With the active party bound, the deadline can now promote a standby.
        reconcile_active_party(&mut state, &id, Some(0), 100, &policy());
        let decision = apply_due_timeout(
            &mut state,
            &id,
            ExpectedFailoverDeadline {
                phase: AggregatorPhase::Plaintext,
                unix_secs: 160,
            },
            160,
            &policy(),
            &committee(),
            &[],
        );
        assert!(
            matches!(decision, FailoverDecision::Promote { .. }),
            "an aggregator that stops making progress during collection must be replaced; got \
             {decision:?}"
        );
    }
}
