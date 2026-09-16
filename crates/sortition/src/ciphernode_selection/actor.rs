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
    CiphertextOutputPublished, CommitmentRosterSelected, Committee, CommitteeFinalized,
    CommitteeMemberExcluded, CommitteeMemberExpelled, E3Failed, E3Requested, E3Stage,
    E3StageChanged, E3id, EType, EffectsEnabled, EventType, InterfoldEvent, InterfoldEventData,
    PlaintextOutputPublished, Shutdown, TicketGenerated, TicketId,
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

fn selector_phase_for_stage(stage: &E3Stage, dkg_roster_selected: bool) -> Option<AggregatorPhase> {
    if *stage == E3Stage::CommitteeFinalized && dkg_roster_selected {
        Some(AggregatorPhase::PublicKey)
    } else {
        phase_for_stage(stage)
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
    /// E3s whose first accepted DKG roster already ended the roster failover budget.
    #[serde(default)]
    pub dkg_roster_selected: HashSet<E3id>,
}

impl CiphernodeSelectorState {
    fn remove_terminal(&mut self, terminal: &HashSet<E3id>) {
        self.e3_cache.retain(|e3_id, _| !terminal.contains(e3_id));
        self.committees.retain(|e3_id, _| !terminal.contains(e3_id));
        self.expelled.retain(|e3_id, _| !terminal.contains(e3_id));
        self.is_aggregator
            .retain(|e3_id, _| !terminal.contains(e3_id));
        self.dkg_roster_selected
            .retain(|e3_id| !terminal.contains(e3_id));
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
    announced_active_parties: HashMap<E3id, Option<u64>>,
    failover_timers: HashMap<E3id, SpawnHandle>,
    terminal_e3s: HashSet<E3id>,
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
        let terminal_e3s = lifecycle
            .iter()
            .filter(|(_, stage)| matches!(stage, E3Stage::Complete | E3Stage::Failed))
            .map(|(e3_id, _)| e3_id.clone())
            .collect();
        let roster_selected = state
            .get()
            .map(|state| state.dkg_roster_selected.clone())
            .unwrap_or_default();
        let observed_phases = lifecycle
            .into_iter()
            .filter_map(|(e3_id, stage)| {
                let phase = selector_phase_for_stage(&stage, roster_selected.contains(&e3_id));
                phase.map(|phase| (e3_id, phase))
            })
            .collect();
        Self {
            bus: bus.clone(),
            state,
            failover,
            address: address.to_owned(),
            observed_phases,
            ready_phases: HashMap::new(),
            announced_active_parties: HashMap::new(),
            failover_timers: HashMap::new(),
            terminal_e3s,
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
                || snapshot
                    .dkg_roster_selected
                    .iter()
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
        bus.subscribe(
            EventType::CommitmentRosterSelected,
            addr.clone().recipient(),
        );
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
        let skipped = expelled
            .iter()
            .chain(unresponsive.iter())
            .copied()
            .collect::<Vec<_>>();
        let active_party_id = committee.active_aggregator_party_id(&skipped);
        let is_aggregator = committee.effective_aggregator(&self.address, &expelled, &unresponsive);
        let previous = state.is_aggregator.get(e3_id).copied();
        let active_party_changed =
            self.announced_active_parties.get(e3_id).copied() != Some(active_party_id);

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

        if force_emit || previous != Some(is_aggregator) || active_party_changed {
            let event = AggregatorChanged {
                e3_id: e3_id.clone(),
                active_party_id,
                is_aggregator,
            };
            if let Some(ec) = ec {
                self.bus.publish(event, ec.clone())?;
            } else {
                self.bus.publish_without_context(event)?;
            }
            self.announced_active_parties
                .insert(e3_id.clone(), active_party_id);
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

        let ready = phase.is_some_and(|phase| self.ready_phases.get(&e3_id) == Some(&phase));
        if phase_changed || phase.is_none() || ready {
            let now = self.clock.now_unix_secs();
            let policy = self.failover_policy;
            self.failover.try_mutate(ec, |mut state| {
                if phase_changed || phase.is_none() {
                    reconcile_phase(&mut state, &e3_id, None, now, &policy);
                }
                if ready {
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

    fn observe_dkg_roster_selected(
        &mut self,
        selected: CommitmentRosterSelected,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let e3_id = selected.e3_id;
        if self
            .state
            .get()
            .is_some_and(|state| state.dkg_roster_selected.contains(&e3_id))
        {
            return Ok(());
        }

        self.state.try_mutate(ec, |mut state| {
            state.dkg_roster_selected.insert(e3_id.clone());
            Ok(state)
        })?;
        self.observe_phase(e3_id, Some(AggregatorPhase::PublicKey), false, ec, ctx)
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
    use actix::{Actor, Handler};
    use e3_data::{DataStore, InMemStore};
    use e3_events::{
        hlc_factory::HlcFactory, EventBus, EventBusConfig, EventSource, Sequencer,
        StoreEventRequested, StoreEventResponse, Unsequenced,
    };

    #[derive(Default)]
    struct TestEventStore {
        next_seq: u64,
    }

    impl Actor for TestEventStore {
        type Context = actix::Context<Self>;
    }

    impl Handler<StoreEventRequested> for TestEventStore {
        type Result = ();

        fn handle(&mut self, msg: StoreEventRequested, _: &mut Self::Context) {
            let StoreEventRequested { event, sender } = msg;
            let seq = self.next_seq;
            self.next_seq += 1;
            sender
                .try_send(StoreEventResponse(event.into_sequenced(seq)))
                .expect("sequencer mailbox must accept the stored event response");
        }
    }

    fn test_bus() -> BusHandle {
        let event_bus =
            EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
        let store = TestEventStore::default().start();
        let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
        BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("selector-test")
    }

    fn test_persistable<T>(value: T) -> (Persistable<T>, Repository<T>)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync + 'static,
    {
        let store = InMemStore::new(false).start();
        let repository = Repository::new(DataStore::from_in_mem(&store));
        (repository.send(Some(value)), repository)
    }

    fn test_ec(seq: u64) -> EventContext<Sequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            EffectsEnabled::new().into(),
            None,
            seq.into(),
            None,
            EventSource::Local,
        )
        .into_sequenced(seq)
        .get_ctx()
        .clone()
    }

    #[test]
    fn selected_roster_keeps_public_key_phase_for_replayed_committee_stage() {
        assert_eq!(
            selector_phase_for_stage(&E3Stage::CommitteeFinalized, true),
            Some(AggregatorPhase::PublicKey)
        );
        assert_eq!(
            selector_phase_for_stage(&E3Stage::CommitteeFinalized, false),
            Some(AggregatorPhase::DkgRoster)
        );
    }

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
            dkg_roster_selected: HashSet::from([terminal.clone(), active.clone()]),
            ..Default::default()
        };

        state.remove_terminal(&HashSet::from([terminal.clone()]));

        assert!(!state.committees.contains_key(&terminal));
        assert!(!state.expelled.contains_key(&terminal));
        assert!(!state.is_aggregator.contains_key(&terminal));
        assert!(!state.dkg_roster_selected.contains(&terminal));
        assert!(state.committees.contains_key(&active));
        assert!(state.expelled.contains_key(&active));
        assert!(state.is_aggregator.contains_key(&active));
        assert!(state.dkg_roster_selected.contains(&active));
    }

    #[actix::test]
    async fn ready_standby_is_promoted_after_active_aggregator_timeout() -> Result<()> {
        let e3_id = E3id::new("1", 1);
        let committee = Committee::new(vec!["0xa".into(), "0xb".into()]);
        let selector_state = CiphernodeSelectorState {
            committees: HashMap::from([(e3_id.clone(), committee)]),
            expelled: HashMap::from([(e3_id.clone(), Vec::new())]),
            ..Default::default()
        };
        let (state, _) = test_persistable(selector_state);
        let (failover, failover_repository) = test_persistable(AggregatorFailoverState::default());
        let bus = test_bus();
        let lifecycle = HashMap::from([(e3_id.clone(), E3Stage::CommitteeFinalized)]);
        let mut selector = CiphernodeSelector::new_with_clock(
            &bus,
            state,
            failover,
            "0xb",
            lifecycle,
            Arc::new(SystemClock),
        );
        selector.failover_policy = FailoverPolicy::new(Duration::from_secs(1));
        let selector = selector.start();

        selector.send(EffectsEnabled::new()).await?;
        let ready = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            AggregationInputsReady {
                e3_id: e3_id.clone(),
                phase: AggregatorPhase::DkgRoster,
            }
            .into(),
            None,
            1,
            None,
            EventSource::Local,
        )
        .into_sequenced(0);
        selector.send(ready).await?;

        actix::clock::timeout(Duration::from_secs(3), async {
            loop {
                let state = selector.send(GetCiphernodeSelectorState).await??;
                if state.is_aggregator.get(&e3_id) == Some(&true) {
                    break Ok::<(), anyhow::Error>(());
                }
                actix::clock::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;

        let failover = failover_repository
            .read()
            .await?
            .expect("persisted failover state");
        assert_eq!(failover.unresponsive.get(&e3_id), Some(&vec![0]));
        Ok(())
    }

    #[actix::test]
    async fn standby_observes_leadership_changes_between_other_parties() -> Result<()> {
        let e3_id = E3id::new("standby-leadership", 1);
        let selector_state = CiphernodeSelectorState {
            committees: HashMap::from([(
                e3_id.clone(),
                Committee::new(vec!["0xa".into(), "0xb".into(), "0xc".into()]),
            )]),
            expelled: HashMap::from([(e3_id.clone(), Vec::new())]),
            ..Default::default()
        };
        let (state, _) = test_persistable(selector_state);
        let (failover, _) = test_persistable(AggregatorFailoverState::default());
        let mut selector = CiphernodeSelector::new_with_clock(
            &test_bus(),
            state,
            failover,
            "0xc",
            HashMap::new(),
            Arc::new(SystemClock),
        );

        selector.update_aggregator_status(&e3_id, None, false)?;
        assert_eq!(
            selector.announced_active_parties.get(&e3_id),
            Some(&Some(0))
        );
        assert_eq!(selector.state.try_get()?.is_aggregator[&e3_id], false);

        selector.failover.try_mutate_without_context(|mut state| {
            state.unresponsive.insert(e3_id.clone(), vec![0]);
            Ok(state)
        })?;
        selector.update_aggregator_status(&e3_id, None, false)?;

        assert_eq!(
            selector.announced_active_parties.get(&e3_id),
            Some(&Some(1))
        );
        assert_eq!(selector.state.try_get()?.is_aggregator[&e3_id], false);
        Ok(())
    }

    #[actix::test]
    async fn accepted_roster_starts_public_key_failover_with_a_fresh_budget() -> Result<()> {
        let e3_id = E3id::new("2", 1);
        let committee = Committee::new(vec!["0xa".into(), "0xb".into()]);
        let selector_state = CiphernodeSelectorState {
            committees: HashMap::from([(e3_id.clone(), committee)]),
            expelled: HashMap::from([(e3_id.clone(), Vec::new())]),
            ..Default::default()
        };
        let (state, state_repository) = test_persistable(selector_state);
        let (failover, failover_repository) = test_persistable(AggregatorFailoverState::default());
        let bus = test_bus();
        let lifecycle = HashMap::from([(e3_id.clone(), E3Stage::CommitteeFinalized)]);
        let selector = CiphernodeSelector::new_with_clock(
            &bus,
            state,
            failover,
            "0xa",
            lifecycle,
            Arc::new(SystemClock),
        )
        .start();

        selector.send(EffectsEnabled::new()).await?;
        selector
            .send(TypedEvent::new(
                AggregationInputsReady {
                    e3_id: e3_id.clone(),
                    phase: AggregatorPhase::DkgRoster,
                },
                test_ec(1),
            ))
            .await?;
        assert_eq!(
            failover_repository
                .read()
                .await?
                .expect("roster failover state")
                .rounds[&e3_id]
                .phase,
            AggregatorPhase::DkgRoster
        );

        let selected = CommitmentRosterSelected {
            e3_id: e3_id.clone(),
            party_ids: vec![0],
        };
        selector
            .send(TypedEvent::new(selected.clone(), test_ec(2)))
            .await?;
        assert!(!failover_repository
            .read()
            .await?
            .expect("cleared roster failover state")
            .rounds
            .contains_key(&e3_id));

        selector
            .send(TypedEvent::new(
                AggregationInputsReady {
                    e3_id: e3_id.clone(),
                    phase: AggregatorPhase::PublicKey,
                },
                test_ec(3),
            ))
            .await?;
        assert_eq!(
            failover_repository
                .read()
                .await?
                .expect("public-key failover state")
                .rounds[&e3_id]
                .phase,
            AggregatorPhase::PublicKey
        );

        selector.send(TypedEvent::new(selected, test_ec(4))).await?;
        assert_eq!(
            failover_repository
                .read()
                .await?
                .expect("preserved public-key failover state")
                .rounds[&e3_id]
                .phase,
            AggregatorPhase::PublicKey
        );
        assert!(state_repository
            .read()
            .await?
            .expect("selector state")
            .dkg_roster_selected
            .contains(&e3_id));
        Ok(())
    }

    #[actix::test]
    async fn restart_restores_public_key_phase_after_roster_selection() -> Result<()> {
        let e3_id = E3id::new("3", 1);
        let selector_state = CiphernodeSelectorState {
            dkg_roster_selected: HashSet::from([e3_id.clone()]),
            ..Default::default()
        };
        let (state, _) = test_persistable(selector_state);
        let (failover, _) = test_persistable(AggregatorFailoverState::default());
        let lifecycle = HashMap::from([(e3_id.clone(), E3Stage::CommitteeFinalized)]);
        let selector = CiphernodeSelector::new_with_clock(
            &test_bus(),
            state,
            failover,
            "0xa",
            lifecycle,
            Arc::new(SystemClock),
        );

        assert_eq!(
            selector.observed_phases.get(&e3_id),
            Some(&AggregatorPhase::PublicKey)
        );
        Ok(())
    }
}
