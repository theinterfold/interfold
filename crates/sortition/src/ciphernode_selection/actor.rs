// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::failover::{
    apply_due_timeout, phase_for_stage, reconcile_active_party, reconcile_phase,
    AggregatorFailoverState, AggregatorPhase, ExpectedFailoverDeadline, FailoverDecision,
    FailoverPolicy,
};
use crate::WithSortitionTicket;
use actix::prelude::*;
use anyhow::Result;
use anyhow::{bail, ensure};
use e3_data::{AutoPersist, Persistable, Repository};
use e3_events::E3RequestComplete;
use e3_events::EventContext;
use e3_events::Sequenced;
use e3_events::TypedEvent;
use e3_events::{
    prelude::*, trap, AggregationInputsReady, AggregatorChanged, BusHandle, CiphernodeSelected,
    CiphertextOutputPublished, Committee, CommitteeFinalized, CommitteeMemberExcluded,
    CommitteeMemberExpelled, E3Failed, E3Requested, E3Stage, E3StageChanged, E3id, EType,
    EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData, PlaintextOutputPublished,
    Shutdown, TicketGenerated, TicketId,
};
use e3_request::E3Meta;
use e3_utils::NotifySync;
use e3_utils::MAILBOX_LIMIT;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

#[path = "handlers.rs"]
mod handlers;

/// Build an `E3Meta` from an `E3Requested` event's fields.
fn e3_meta_from(req: &E3Requested) -> E3Meta {
    E3Meta {
        seed: req.seed,
        threshold_n: req.threshold_n,
        threshold_m: req.threshold_m,
        params_preset: req.params_preset,
        params: req.params.clone(),
        error_size: req.error_size.clone(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CiphernodeSelectorState {
    pub e3_cache: HashMap<E3id, E3Meta>,
    pub committees: HashMap<E3id, Committee>,
    /// Party IDs excluded from current E3 work by an on-chain expulsion or a confirmed local
    /// fallback. This does not alter the canonical committee roster.
    pub expelled: HashMap<E3id, Vec<u64>>,
    pub is_aggregator: HashMap<E3id, bool>,
}

impl CiphernodeSelectorState {
    fn remove_terminal(&mut self, terminal: &HashSet<E3id>) {
        self.e3_cache.retain(|e3_id, _| !terminal.contains(e3_id));
        self.committees.retain(|e3_id, _| !terminal.contains(e3_id));
        self.expelled.retain(|e3_id, _| !terminal.contains(e3_id));
        self.is_aggregator
            .retain(|e3_id, _| !terminal.contains(e3_id));
    }
}

#[derive(Message, Debug, Clone, Copy)]
#[rtype(result = "Result<CiphernodeSelectorState>")]
pub struct GetCiphernodeSelectorState;

const AGGREGATOR_PROGRESS_TIMEOUT: Duration = Duration::from_secs(10 * 60);

trait Clock: Send + Sync {
    fn now_unix_secs(&self) -> u64;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// CiphernodeSelector is an actor that determines if a ciphernode is part of a committee and if so
/// emits a TicketGenerated event (score sortition) to the event bus
pub struct CiphernodeSelector {
    bus: BusHandle,
    address: String,
    state: Persistable<CiphernodeSelectorState>,
    failover: Persistable<AggregatorFailoverState>,
    observed_phases: HashMap<E3id, AggregatorPhase>,
    ready_phases: HashMap<E3id, AggregatorPhase>,
    failover_timers: HashMap<E3id, SpawnHandle>,
    effects_enabled: bool,
    failover_policy: FailoverPolicy,
    clock: Arc<dyn Clock>,
}

impl Actor for CiphernodeSelector {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl CiphernodeSelector {
    pub fn new(
        bus: &BusHandle,
        state: Persistable<CiphernodeSelectorState>,
        failover: Persistable<AggregatorFailoverState>,
        address: &str,
    ) -> Self {
        Self::new_with_clock(
            bus,
            state,
            failover,
            address,
            HashMap::new(),
            Arc::new(SystemClock),
        )
    }

    fn new_with_clock(
        bus: &BusHandle,
        state: Persistable<CiphernodeSelectorState>,
        failover: Persistable<AggregatorFailoverState>,
        address: &str,
        lifecycle: HashMap<E3id, E3Stage>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let observed_phases = lifecycle
            .into_iter()
            .filter_map(|(e3_id, stage)| phase_for_stage(&stage).map(|phase| (e3_id, phase)))
            .collect();
        Self {
            bus: bus.clone(),
            state,
            failover,
            address: address.to_owned(),
            observed_phases,
            ready_phases: HashMap::new(),
            failover_timers: HashMap::new(),
            effects_enabled: false,
            failover_policy: FailoverPolicy::new(AGGREGATOR_PROGRESS_TIMEOUT),
            clock,
        }
    }

    pub async fn attach(
        bus: &BusHandle,
        selector_store: Repository<CiphernodeSelectorState>,
        failover_store: Repository<AggregatorFailoverState>,
        lifecycle: HashMap<E3id, E3Stage>,
        address: &str,
    ) -> Result<Addr<Self>> {
        let mut state = selector_store
            .load_or_default(CiphernodeSelectorState::default())
            .await?;
        let mut failover = failover_store
            .load_or_default(AggregatorFailoverState::default())
            .await?;
        failover.try_mutate_without_context(|mut snapshot| {
            snapshot.migrate_early_timer_schema();
            Ok(snapshot)
        })?;
        ensure!(
            failover
                .get()
                .is_some_and(|snapshot| snapshot.has_supported_schema()),
            "Unsupported aggregator failover snapshot schema"
        );

        // A crash can persist the terminal lifecycle stage before the selector processes the
        // matching completion event. Do not restore roles or timers for work that is already
        // terminal.
        let terminal: HashSet<E3id> = lifecycle
            .iter()
            .filter(|(_, stage)| matches!(stage, E3Stage::Complete | E3Stage::Failed))
            .map(|(e3_id, _)| e3_id.clone())
            .collect();
        let selector_has_terminal = state.get().is_some_and(|snapshot| {
            snapshot
                .e3_cache
                .keys()
                .any(|e3_id| terminal.contains(e3_id))
                || snapshot
                    .committees
                    .keys()
                    .any(|e3_id| terminal.contains(e3_id))
                || snapshot
                    .expelled
                    .keys()
                    .any(|e3_id| terminal.contains(e3_id))
                || snapshot
                    .is_aggregator
                    .keys()
                    .any(|e3_id| terminal.contains(e3_id))
        });
        if selector_has_terminal {
            state.try_mutate_without_context(|mut snapshot| {
                snapshot.remove_terminal(&terminal);
                Ok(snapshot)
            })?;
        }
        let failover_has_terminal = failover.get().is_some_and(|snapshot| {
            snapshot.rounds.keys().any(|e3_id| terminal.contains(e3_id))
                || snapshot
                    .unresponsive
                    .keys()
                    .any(|e3_id| terminal.contains(e3_id))
        });
        if failover_has_terminal {
            failover.try_mutate_without_context(|mut snapshot| {
                snapshot.rounds.retain(|e3_id, _| !terminal.contains(e3_id));
                snapshot
                    .unresponsive
                    .retain(|e3_id, _| !terminal.contains(e3_id));
                Ok(snapshot)
            })?;
        }

        // A crash can occur after failover state is saved but before the role
        // cache is saved. Recompute the cache before any hydrated actor sees it.
        let failover_snapshot = failover.try_get()?;
        let selector_snapshot = state.try_get()?;
        let expected_roles = selector_snapshot
            .committees
            .iter()
            .map(|(e3_id, committee)| {
                let expelled = selector_snapshot
                    .expelled
                    .get(e3_id)
                    .cloned()
                    .unwrap_or_default();
                let unresponsive = failover_snapshot
                    .unresponsive
                    .get(e3_id)
                    .cloned()
                    .unwrap_or_default();
                (
                    e3_id.clone(),
                    committee.effective_aggregator(address, &expelled, &unresponsive),
                )
            })
            .collect::<HashMap<_, _>>();
        if selector_snapshot.is_aggregator != expected_roles {
            state.try_mutate_without_context(|mut snapshot| {
                snapshot.is_aggregator = expected_roles;
                Ok(snapshot)
            })?;
        }

        let addr = CiphernodeSelector::new_with_clock(
            bus,
            state,
            failover,
            address,
            lifecycle,
            Arc::new(SystemClock),
        )
        .start();

        bus.subscribe(EventType::E3Requested, addr.clone().recipient());
        bus.subscribe(EventType::E3RequestComplete, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeFinalized, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeMemberExpelled, addr.clone().recipient());
        bus.subscribe(EventType::CommitteeMemberExcluded, addr.clone().recipient());
        bus.subscribe(
            EventType::CiphertextOutputPublished,
            addr.clone().recipient(),
        );
        bus.subscribe(
            EventType::PlaintextOutputPublished,
            addr.clone().recipient(),
        );
        bus.subscribe(EventType::E3StageChanged, addr.clone().recipient());
        bus.subscribe(EventType::E3Failed, addr.clone().recipient());
        bus.subscribe(EventType::AggregationInputsReady, addr.clone().recipient());
        bus.subscribe(EventType::EffectsEnabled, addr.clone().recipient());
        bus.subscribe(EventType::Shutdown, addr.clone().recipient());

        info!("CiphernodeSelector listening!");
        Ok(addr)
    }

    fn update_aggregator_status(
        &mut self,
        e3_id: &E3id,
        ec: Option<&EventContext<Sequenced>>,
        force_emit: bool,
    ) -> Result<()> {
        let Some(state) = self.state.get() else {
            bail!("Could not get selector state");
        };

        let committee = state
            .committees
            .get(e3_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing finalized committee for {}", e3_id))?;
        let expelled = state.expelled.get(e3_id).cloned().unwrap_or_default();
        let unresponsive = self
            .failover
            .get()
            .and_then(|state| state.unresponsive.get(e3_id).cloned())
            .unwrap_or_default();
        let is_aggregator = committee.effective_aggregator(&self.address, &expelled, &unresponsive);
        let previous = state.is_aggregator.get(e3_id).copied();

        let mutate = |mut selector_state: CiphernodeSelectorState| {
            selector_state
                .is_aggregator
                .insert(e3_id.clone(), is_aggregator);
            Ok(selector_state)
        };
        if let Some(ec) = ec {
            self.state.try_mutate(ec, mutate)?;
        } else {
            self.state.try_mutate_without_context(mutate)?;
        }

        if force_emit || previous != Some(is_aggregator) {
            let event = AggregatorChanged {
                e3_id: e3_id.clone(),
                is_aggregator,
            };
            if let Some(ec) = ec {
                self.bus.publish(event, ec.clone())?;
            } else {
                self.bus.publish_without_context(event)?;
            }
        }

        Ok(())
    }

    fn observe_phase(
        &mut self,
        e3_id: E3id,
        phase: Option<AggregatorPhase>,
        force_emit_role: bool,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let previous_phase = self.observed_phases.get(&e3_id).copied();
        match phase {
            Some(phase) => {
                self.observed_phases.insert(e3_id.clone(), phase);
            }
            None => {
                self.observed_phases.remove(&e3_id);
            }
        }
        let phase_changed = previous_phase != phase;
        if phase_changed {
            self.ready_phases.remove(&e3_id);
        }

        if !self.effects_enabled {
            if force_emit_role
                && self
                    .state
                    .get()
                    .is_some_and(|state| state.committees.contains_key(&e3_id))
            {
                self.update_aggregator_status(&e3_id, Some(ec), true)?;
            }
            return Ok(());
        }

        // Arm the round at the start of a phase as well as when aggregation inputs are ready.
        //
        // `ready_phases` is set by `AggregationInputsReady`, which the aggregator publishes only
        // once it holds a threshold of shares (`VerifyingC6` or later for the plaintext phase).
        // Arming solely on that signal leaves the collection window uncovered: an aggregator that
        // dies between the phase starting and inputs becoming ready is never replaced, because no
        // round exists for the timer to fire on. Observed on a 5-node swarm — the active
        // aggregator was killed two seconds into the decryption phase and the E3 stalled
        // permanently, with the surviving members each holding a usable decryption share.
        //
        // A real phase change re-arms with the full budget, so covering the collection window
        // does not shorten the budget for the work that follows.
        let ready = phase.is_some_and(|phase| self.ready_phases.get(&e3_id) == Some(&phase));
        if phase_changed || phase.is_none() || ready {
            let now = self.clock.now_unix_secs();
            let policy = self.failover_policy;
            self.failover.try_mutate(ec, |mut state| {
                if phase_changed || phase.is_none() {
                    reconcile_phase(&mut state, &e3_id, None, now, &policy);
                }
                if ready || phase_changed {
                    reconcile_phase(&mut state, &e3_id, phase, now, &policy);
                }
                Ok(state)
            })?;
        }

        if self
            .state
            .get()
            .is_some_and(|state| state.committees.contains_key(&e3_id))
        {
            self.reconcile_failover_assignment(&e3_id, Some(ec), ctx)?;
            self.update_aggregator_status(&e3_id, Some(ec), force_emit_role)?;
        } else {
            self.arm_failover_timer(&e3_id, ctx);
        }
        Ok(())
    }

    fn observe_aggregation_inputs_ready(
        &mut self,
        ready: AggregationInputsReady,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let e3_id = ready.e3_id;
        let phase = ready.phase;
        self.ready_phases.insert(e3_id.clone(), phase);
        if !self.effects_enabled || self.observed_phases.get(&e3_id) != Some(&phase) {
            return Ok(());
        }

        let now = self.clock.now_unix_secs();
        let policy = self.failover_policy;
        self.failover.try_mutate(ec, |mut state| {
            reconcile_phase(&mut state, &e3_id, Some(phase), now, &policy);
            Ok(state)
        })?;
        self.reconcile_failover_assignment(&e3_id, Some(ec), ctx)?;
        self.update_aggregator_status(&e3_id, Some(ec), false)
    }

    fn reconcile_after_replay(&mut self, ctx: &mut Context<Self>) -> Result<()> {
        self.effects_enabled = true;
        let now = self.clock.now_unix_secs();
        let policy = self.failover_policy;
        let mut e3_ids: HashSet<E3id> = self.observed_phases.keys().cloned().collect();
        e3_ids.extend(self.ready_phases.keys().cloned());
        if let Some(state) = self.failover.get() {
            e3_ids.extend(state.rounds.keys().cloned());
            e3_ids.extend(state.unresponsive.keys().cloned());
        }

        self.failover.try_mutate_without_context(|mut state| {
            for e3_id in &e3_ids {
                let observed = self.observed_phases.get(e3_id).copied();
                let ready =
                    observed.is_some_and(|phase| self.ready_phases.get(e3_id) == Some(&phase));
                let persisted_matches = state
                    .rounds
                    .get(e3_id)
                    .is_some_and(|round| Some(round.phase) == observed);

                if observed.is_none() || (!persisted_matches && state.rounds.contains_key(e3_id)) {
                    reconcile_phase(&mut state, e3_id, None, now, &policy);
                }
                if ready && !persisted_matches {
                    reconcile_phase(&mut state, e3_id, observed, now, &policy);
                }
                if !state.rounds.contains_key(e3_id) {
                    state.unresponsive.remove(e3_id);
                }
            }
            Ok(state)
        })?;

        for e3_id in e3_ids {
            let result = if self
                .state
                .get()
                .is_some_and(|state| state.committees.contains_key(&e3_id))
            {
                self.reconcile_failover_assignment(&e3_id, None, ctx)
                    .and_then(|()| self.update_aggregator_status(&e3_id, None, false))
            } else {
                self.arm_failover_timer(&e3_id, ctx);
                Ok(())
            };
            if let Err(err) = result {
                error!(
                    e3_id = %e3_id,
                    error = %err,
                    "Failed to reconcile failover state after replay"
                );
                self.bus.err(EType::Sortition, err);
            }
        }
        Ok(())
    }

    fn active_aggregator_party_id(&self, e3_id: &E3id) -> Option<u64> {
        let selector = self.state.get()?;
        let committee = selector.committees.get(e3_id)?;
        let expelled = selector.expelled.get(e3_id).cloned().unwrap_or_default();
        let unresponsive = self
            .failover
            .get()
            .and_then(|state| state.unresponsive.get(e3_id).cloned())
            .unwrap_or_default();
        let skipped = expelled.into_iter().chain(unresponsive).collect::<Vec<_>>();
        committee.active_aggregator_party_id(&skipped)
    }

    fn reconcile_failover_assignment(
        &mut self,
        e3_id: &E3id,
        ec: Option<&EventContext<Sequenced>>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        if !self.effects_enabled {
            return Ok(());
        }
        let active_party_id = self.active_aggregator_party_id(e3_id);
        let now = self.clock.now_unix_secs();
        let policy = self.failover_policy;
        let mutate = |mut state: AggregatorFailoverState| {
            reconcile_active_party(&mut state, e3_id, active_party_id, now, &policy);
            Ok(state)
        };
        if let Some(ec) = ec {
            self.failover.try_mutate(ec, mutate)?;
        } else {
            self.failover.try_mutate_without_context(mutate)?;
        }
        self.arm_failover_timer(e3_id, ctx);
        Ok(())
    }

    fn arm_failover_timer(&mut self, e3_id: &E3id, ctx: &mut Context<Self>) {
        if let Some(handle) = self.failover_timers.remove(e3_id) {
            ctx.cancel_future(handle);
        }
        if !self.effects_enabled {
            return;
        }

        let Some(round) = self
            .failover
            .get()
            .and_then(|state| state.rounds.get(e3_id).cloned())
        else {
            return;
        };
        if round.exhausted || round.active_party_id.is_none() {
            return;
        }

        let delay = Duration::from_secs(
            round
                .deadline_unix_secs
                .saturating_sub(self.clock.now_unix_secs()),
        );
        let timer_e3_id = e3_id.clone();
        let phase = round.phase;
        let deadline = round.deadline_unix_secs;
        let handle = ctx.run_later(delay, move |actor, ctx| {
            actor.failover_timers.remove(&timer_e3_id);
            actor.handle_failover_deadline(timer_e3_id, phase, deadline, ctx);
        });
        self.failover_timers.insert(e3_id.clone(), handle);
    }

    fn handle_failover_deadline(
        &mut self,
        e3_id: E3id,
        expected_phase: AggregatorPhase,
        expected_deadline: u64,
        ctx: &mut Context<Self>,
    ) {
        let result = (|| -> Result<()> {
            let selector = self.state.try_get()?;
            let Some(committee) = selector.committees.get(&e3_id) else {
                return Ok(());
            };
            let expelled = selector.expelled.get(&e3_id).cloned().unwrap_or_default();
            let now = self.clock.now_unix_secs();
            let policy = self.failover_policy;
            let mut decision = FailoverDecision::Hold;
            self.failover.try_mutate_without_context(|mut state| {
                decision = apply_due_timeout(
                    &mut state,
                    &e3_id,
                    ExpectedFailoverDeadline {
                        phase: expected_phase,
                        unix_secs: expected_deadline,
                    },
                    now,
                    &policy,
                    committee,
                    &expelled,
                );
                Ok(state)
            })?;

            match decision {
                FailoverDecision::Hold => {}
                FailoverDecision::Promote {
                    demote,
                    promote_to,
                    new_addr,
                } => {
                    warn!(
                        e3_id = %e3_id,
                        phase = ?expected_phase,
                        demoted_party_id = demote,
                        promoted_party_id = promote_to,
                        promoted_address = new_addr,
                        "Aggregator progress deadline expired; promoting deterministic standby"
                    );
                    self.update_aggregator_status(&e3_id, None, false)?;
                    self.arm_failover_timer(&e3_id, ctx);
                }
                FailoverDecision::Exhausted { active } => {
                    error!(
                        e3_id = %e3_id,
                        phase = ?expected_phase,
                        active_party_id = active,
                        "All aggregator standby budgets expired; retaining final party until canonical deadline"
                    );
                }
            }
            Ok(())
        })();

        if let Err(err) = result {
            self.bus.err(EType::Sortition, err);
        }
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn terminal_selector_entries_are_pruned() {
        let terminal = E3id::new("1", 1);
        let active = E3id::new("2", 1);
        let mut state = CiphernodeSelectorState {
            committees: HashMap::from([
                (terminal.clone(), Committee::new(Vec::new())),
                (active.clone(), Committee::new(Vec::new())),
            ]),
            expelled: HashMap::from([(terminal.clone(), vec![0]), (active.clone(), vec![1])]),
            is_aggregator: HashMap::from([(terminal.clone(), true), (active.clone(), false)]),
            ..Default::default()
        };

        state.remove_terminal(&HashSet::from([terminal.clone()]));

        assert!(!state.committees.contains_key(&terminal));
        assert!(!state.expelled.contains_key(&terminal));
        assert!(!state.is_aggregator.contains_key(&terminal));
        assert!(state.committees.contains_key(&active));
        assert!(state.expelled.contains_key(&active));
        assert!(state.is_aggregator.contains_key(&active));
    }
}
