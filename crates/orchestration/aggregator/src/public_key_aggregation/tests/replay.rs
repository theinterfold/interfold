// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::ext::{AggregatorRoleExtension, PublicKeyAggregatorExtension};
use crate::test_support::{commit_replay_past, history_reader};
use crate::PublicKeyRepositoryFactory;
use e3_data::{RepositoriesFactory, Snapshot};
use e3_events::{
    CiphernodeSelected, CommitmentRosterSelected, CommitteeFinalized, EventSource, EventType,
    KeyshareCreated,
};
use e3_fhe::ext::FHE_KEY;
use e3_request::{ContextRepositoryFactory, E3Context, E3ContextParams, E3Extension};
use std::time::Duration;

fn inputs_ready(events: &[InterfoldEvent]) -> bool {
    events.iter().any(|event| {
        matches!(
            event.get_data(),
            InterfoldEventData::AggregationInputsReady(_)
        )
    })
}

struct ReplayedAggregator {
    bus: BusHandle,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    e3_id: E3id,
    fhe: Arc<Fhe>,
    /// The selected committee in party order.
    committee: Vec<String>,
    /// The published keyshares in submission order, with their C1 proofs.
    submissions: Vec<((u64, String, ArcBytes), Option<SignedProofPayload>)>,
    states: Repository<PublicKeyAggregatorState>,
    store: Addr<InMemStore>,
    _ctx: E3Context,
}

/// The first H parties, which the replayed roster selects unless a test replaces it.
fn first_h_parties() -> Vec<u64> {
    (0..CiphernodesCommitteeSize::Minimum.values().h as u64).collect()
}

impl ReplayedAggregator {
    /// The committee filter holds keyshares until this event.
    fn publish_committee(&self) -> Result<()> {
        self.bus.publish_without_context(CommitteeFinalized {
            e3_id: self.e3_id.clone(),
            committee: self.committee.clone(),
            scores: Vec::new(),
            chain_id: 1,
        })
    }

    fn publish_keyshares(&mut self, parties: &[u64], signed: bool) -> Result<()> {
        for &party_id in parties {
            let node = self.committee[party_id as usize].clone();
            let (pubkey, signed_pk_generation_proof) = if signed {
                let (keyshare, proof) = keyshare_with_c1_proof(&self.fhe, &self.e3_id)?;
                (keyshare, Some(proof))
            } else {
                (ArcBytes::from_bytes(&[1]), None)
            };
            self.submissions.push((
                (party_id, node.clone(), pubkey.clone()),
                signed_pk_generation_proof.clone(),
            ));
            self.bus.publish_without_context(KeyshareCreated {
                pubkey,
                e3_id: self.e3_id.clone(),
                node,
                party_id,
                signed_pk_generation_proof,
            })?;
        }
        Ok(())
    }

    fn publish_roster(&self, roster: &[u64]) -> Result<()> {
        self.bus.publish_without_context(CommitmentRosterSelected {
            e3_id: self.e3_id.clone(),
            party_ids: roster.to_vec(),
        })
    }

    /// Publish the keyshares of the first H parties, then the roster that selects them.
    fn publish_selected_keyshares(&mut self, signed: bool) -> Result<()> {
        let selected = first_h_parties();
        self.publish_keyshares(&selected, signed)?;
        self.publish_roster(&selected)
    }

    /// The published keyshares in submission order.
    fn keyshares(&self) -> Vec<ArcBytes> {
        self.submissions
            .iter()
            .map(|((_, _, keyshare), _)| keyshare.clone())
            .collect()
    }

    /// The C1 request that the aggregator dispatches for the keyshares of `roster`.
    fn c1_request(&self, roster: &[u64]) -> ShareVerificationDispatched {
        let (submission_order, c1_proofs): (Vec<_>, Vec<_>) = self
            .submissions
            .iter()
            .filter(|((party_id, _, _), _)| roster.contains(party_id))
            .cloned()
            .unzip();
        PublicKeyAggregation::plan_c1_dispatch(&submission_order, &c1_proofs).request(
            &self.e3_id,
            BfvPreset::InsecureThreshold64,
            CiphernodesCommitteeSize::Minimum,
        )
    }

    /// This node's verifier finds every keyshare of `roster` honest. It publishes its verdict
    /// under the request's event.
    fn publish_c1_verdict(&self, roster: &[u64]) -> Result<()> {
        self.bus
            .publish(c1_verdict(&self.e3_id), test_ctx(self.c1_request(roster)))
    }
}

/// Replay a selection into a context whose effects are off, as startup replay does. The selection
/// creates the aggregator.
async fn replay_selection() -> Result<ReplayedAggregator> {
    let committee_size = CiphernodesCommitteeSize::Minimum.values();
    let (bus, rng, seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let store = InMemStore::new(false).start();
    let committee: Vec<String> = (0..committee_size.n)
        .map(|party| Address::repeat_byte(party as u8 + 1).to_string())
        .collect();
    let mut ctx = E3Context::from_params(E3ContextParams {
        repository: DataStore::from_in_mem(&store)
            .repositories()
            .context(&e3_id),
        e3_id: e3_id.clone(),
        extensions: Arc::new(Vec::new()),
    });
    // The router creates a context with its own flag, which is off while startup replays.
    ctx.set_effects_enabled(false);
    ctx.set_dependency(FHE_KEY, fhe.clone());
    let snapshot = ctx.snapshot()?;
    AggregatorRoleExtension::create(HashMap::from([(e3_id.clone(), true)]))
        .hydrate(&mut ctx, &snapshot)
        .await?;

    let selected = CiphernodeSelected {
        e3_id: e3_id.clone(),
        threshold_m: committee_size.threshold,
        threshold_n: committee_size.n,
        seed,
        error_size: ArcBytes::from_bytes(&[]),
        params_preset: BfvPreset::InsecureThreshold64,
        params: ArcBytes::from_bytes(&[]),
        party_id: 0,
        committee: committee.clone(),
    };
    PublicKeyAggregatorExtension::create(&bus, history_reader(&[])?).on_event(
        &mut ctx,
        &InterfoldEvent::<Unsequenced>::new_with_timestamp(
            selected.into(),
            None,
            1,
            None,
            EventSource::Local,
        )
        .into_sequenced(1),
    );
    let aggregator = ctx
        .get_event_recipient("publickey")
        .expect("the selection creates the aggregator")
        .clone();
    bus.subscribe_all(&[EventType::All], aggregator);

    let states = ctx.repositories().publickey(&e3_id);
    Ok(ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        committee,
        submissions: Vec::new(),
        states,
        store,
        _ctx: ctx,
    })
}

/// Also replay the committee, the selected keyshares and the roster, until the aggregator verifies
/// C1.
async fn replay_until_c1_verification(signed_keyshares: bool) -> Result<ReplayedAggregator> {
    let mut replayed = replay_selection().await?;
    replayed.publish_committee()?;
    replayed.publish_selected_keyshares(signed_keyshares)?;
    assert!(
        reaches_state(&replayed.states, &replayed.bus, |state| matches!(
            state,
            PublicKeyAggregatorState::VerifyingC1 { .. }
        ))
        .await?,
        "the aggregator did not collect the selected keyshares"
    );
    Ok(replayed)
}

fn c1_verdict(e3_id: &E3id) -> ShareVerificationComplete {
    ShareVerificationComplete {
        e3_id: e3_id.clone(),
        kind: VerificationKind::PkGenerationProofs,
        dishonest_parties: BTreeSet::new(),
    }
}

async fn reaches_state(
    states: &Repository<PublicKeyAggregatorState>,
    bus: &BusHandle,
    reached: impl Fn(&PublicKeyAggregatorState) -> bool,
) -> Result<bool> {
    for _ in 0..200 {
        bus.flush_event_pipeline().await?;
        if states.read().await?.as_ref().is_some_and(&reached) {
            return Ok(true);
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    Ok(false)
}

async fn reaches_c5(
    states: &Repository<PublicKeyAggregatorState>,
    bus: &BusHandle,
) -> Result<bool> {
    reaches_state(states, bus, |state| {
        matches!(state, PublicKeyAggregatorState::GeneratingC5Proof { .. })
    })
    .await
}

/// Startup replays logged events before `EffectsEnabled`. An aggregator that a replayed selection
/// creates collects its inputs, but runs no effects until the fence opens.
#[actix::test]
async fn an_aggregator_created_during_replay_waits_for_effects() -> Result<()> {
    let ReplayedAggregator {
        bus, history, _ctx, ..
    } = replay_until_c1_verification(false).await?;
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        !inputs_ready(&events),
        "aggregation ran before EffectsEnabled"
    );

    bus.publish_without_context(EffectsEnabled::new())?;
    for _ in 0..200 {
        bus.flush_event_pipeline().await?;
        if inputs_ready(&history.send(GetEvents::<InterfoldEvent>::new()).await?) {
            return Ok(());
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    panic!("aggregation did not resume at EffectsEnabled")
}

/// Replay also delivers this node's C1 request and verdict while effects are fenced, and puts their
/// delivery IDs in the bus dedup window. The bus would drop the same request dispatched again: the
/// aggregator must apply the replayed verdict.
async fn replayed_c1_verdict_reaches_c5(demoted_before_effects: bool) -> Result<()> {
    let replayed = replay_until_c1_verification(true).await?;
    replayed.publish_c1_verdict(&first_h_parties())?;
    let ReplayedAggregator {
        bus,
        e3_id,
        states,
        _ctx,
        ..
    } = replayed;
    if demoted_before_effects {
        bus.publish_without_context(AggregatorChanged {
            e3_id: e3_id.clone(),
            active_party_id: Some(1),
            is_aggregator: false,
        })?;
    }
    bus.flush_event_pipeline().await?;
    assert!(matches!(
        states.read().await?,
        Some(PublicKeyAggregatorState::VerifyingC1 { .. })
    ));

    bus.publish_without_context(EffectsEnabled::new())?;
    assert!(
        reaches_c5(&states, &bus).await?,
        "the replayed C1 verdict was not applied"
    );
    Ok(())
}

#[actix::test]
async fn an_aggregator_created_during_replay_applies_its_replayed_c1_verdict() -> Result<()> {
    replayed_c1_verdict_reaches_c5(false).await
}

/// "Demotion does not discard work the former aggregator started": the replayed local verdict
/// shows that this node dispatched C1, although replay created it without that record.
#[actix::test]
async fn a_former_aggregator_demoted_during_replay_applies_its_replayed_c1_verdict() -> Result<()> {
    replayed_c1_verdict_reaches_c5(true).await
}

/// The snapshot holds `VerifyingC1`, and the C1 verdict was logged after it. Replay committed a
/// later snapshot, so the store rejects writes under the verdict's own revision.
#[actix::test]
async fn a_restored_aggregator_applies_its_replayed_c1_verdict() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, circuit_h) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let store = InMemStore::new(false).start();
    let states = Repository::new(DataStore::from_in_mem(&store).scope("state"));
    let recoveries = Repository::new(DataStore::from_in_mem(&store).scope("recovery"));
    let mut aggregator = booted_micro_aggregator(
        &bus,
        &fhe,
        &e3_id,
        true,
        states.send(Some(state)),
        recoveries.send(Some(PublicKeyAggregatorRecoveryState {
            selected_roster: Some((0..circuit_h as u64).collect()),
            started_as_aggregator: true,
            ..Default::default()
        })),
    );
    aggregator.effects_enabled = false;
    let (request, _) = aggregator
        .c1_verification_request()
        .expect("the aggregator verifies C1");
    bus.subscribe_all(&[EventType::All], aggregator.start().recipient());

    bus.publish(
        ShareVerificationComplete {
            dishonest_parties: (circuit_h as u64..threshold_n as u64).collect(),
            ..c1_verdict(&e3_id)
        },
        test_ctx(request),
    )?;
    commit_replay_past(&store, &history, |data| {
        matches!(data, InterfoldEventData::ShareVerificationComplete(_))
    })
    .await?;
    bus.publish_without_context(EffectsEnabled::new())?;
    assert!(
        reaches_c5(&states, &bus).await?,
        "the replayed C1 verdict was not applied"
    );
    Ok(())
}

/// Wait until the aggregator dispatches `request`, and return the dispatch event.
async fn dispatched(
    replayed: &ReplayedAggregator,
    request: &ShareVerificationDispatched,
) -> Result<Option<InterfoldEvent>> {
    for _ in 0..200 {
        replayed.bus.flush_event_pipeline().await?;
        let events = replayed
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?;
        if let Some(event) = events.into_iter().find(|event| {
            matches!(
                event.get_data(),
                InterfoldEventData::ShareVerificationDispatched(sent) if sent == request
            )
        }) {
            return Ok(Some(event));
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    Ok(None)
}

/// Replay selects roster A and then roster B while the committee filter holds the keyshares, and
/// then delivers this node's verdict on A's keyshares. When every dealer is honest, the verdicts
/// on A and on B have the same payload. The verdict on A must not complete C1 for B: the
/// aggregator verifies B's keyshares, and applies the verdict that answers that request.
async fn a_c1_verdict_of_a_replaced_roster_is_discarded(verdict_after_effects: bool) -> Result<()> {
    let (roster_a, roster_b) = ([0, 1], [1, 2]);
    let mut replayed = replay_selection().await?;
    replayed.publish_keyshares(&[0, 1, 2], true)?;
    replayed.publish_roster(&roster_a)?;
    replayed.publish_roster(&roster_b)?;
    if verdict_after_effects {
        replayed
            .bus
            .publish_without_context(EffectsEnabled::new())?;
    }
    replayed.publish_c1_verdict(&roster_a)?;
    replayed.bus.flush_event_pipeline().await?;
    assert!(matches!(
        replayed.states.read().await?,
        Some(PublicKeyAggregatorState::Collecting { .. })
    ));

    if !verdict_after_effects {
        replayed
            .bus
            .publish_without_context(EffectsEnabled::new())?;
    }
    replayed.publish_committee()?;
    let dispatch = dispatched(&replayed, &replayed.c1_request(&roster_b))
        .await?
        .expect("the aggregator did not verify the keyshares of the replacement roster");
    assert!(matches!(
        replayed.states.read().await?,
        Some(PublicKeyAggregatorState::VerifyingC1 { .. })
    ));

    replayed
        .bus
        .publish(c1_verdict(&replayed.e3_id), dispatch.get_ctx().clone())?;
    assert!(
        reaches_c5(&replayed.states, &replayed.bus).await?,
        "the verdict on the replacement roster was not applied"
    );
    Ok(())
}

#[actix::test]
async fn a_replayed_c1_verdict_of_a_replaced_roster_is_discarded() -> Result<()> {
    a_c1_verdict_of_a_replaced_roster_is_discarded(false).await
}

/// The verifier can also finish the replaced roster's request after effects resume.
#[actix::test]
async fn a_live_c1_verdict_of_a_replaced_roster_is_discarded() -> Result<()> {
    a_c1_verdict_of_a_replaced_roster_is_discarded(true).await
}

// Replay also delivers this node's C5 proof while effects are fenced. The prover answers the
// replayed proof request with the replayed compute response and the same deterministic signature,
// so the bus drops the proof that the prover sends again: the aggregator must apply the replayed
// one.

/// Boot an aggregator over a `GeneratingC5Proof` for `keyshares` that `store` saved, with effects
/// fenced as during startup replay. Returns the saved state and recovery.
fn fenced_c5_aggregator(
    bus: &BusHandle,
    fhe: &Arc<Fhe>,
    e3_id: &E3id,
    keyshares: Vec<ArcBytes>,
    store: &Addr<InMemStore>,
) -> (
    Repository<PublicKeyAggregatorState>,
    Repository<PublicKeyAggregatorRecoveryState>,
) {
    let mut state = c5_state_without_node_proofs();
    if let PublicKeyAggregatorState::GeneratingC5Proof { keyshare_bytes, .. } = &mut state {
        *keyshare_bytes = keyshares;
    }
    let states = Repository::new(DataStore::from_in_mem(store).scope("state"));
    let recoveries = Repository::new(DataStore::from_in_mem(store).scope("recovery"));
    let mut aggregator = booted_micro_aggregator(
        bus,
        fhe,
        e3_id,
        true,
        states.send(Some(state)),
        recoveries.send(Some(PublicKeyAggregatorRecoveryState::default())),
    );
    aggregator.effects_enabled = false;
    bus.subscribe_all(&[EventType::All], aggregator.start().recipient());
    (states, recoveries)
}

fn c5_proof_logged(data: &InterfoldEventData) -> bool {
    matches!(data, InterfoldEventData::PkAggregationProofSigned(_))
}

fn keyshares(fhe: &Fhe, e3_id: &E3id) -> Result<Vec<ArcBytes>> {
    (0..2)
        .map(|_| Ok(keyshare_with_c1_proof(fhe, e3_id)?.0))
        .collect()
}

/// The snapshot holds `GeneratingC5Proof`, and the C5 proof was logged after it. Replay committed
/// a later snapshot, so the store rejects writes under the proof's own revision.
#[actix::test]
async fn a_restored_aggregator_applies_its_replayed_c5_proof() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let keyshares = keyshares(&fhe, &e3_id)?;
    let proof = signed_c5_proof(&e3_id, c5_signals_for(&fhe, &keyshares)?);
    let store = InMemStore::new(false).start();
    let (states, recoveries) = fenced_c5_aggregator(&bus, &fhe, &e3_id, keyshares, &store);

    bus.publish_without_context(proof)?;
    commit_replay_past(&store, &history, c5_proof_logged).await?;
    bus.publish_without_context(EffectsEnabled::new())?;
    assert!(
        public_key_aggregated(&history).await?,
        "the replayed C5 proof was not applied"
    );
    assert!(
        reaches_state(&states, &bus, |state| matches!(
            state,
            PublicKeyAggregatorState::Complete { .. }
        ))
        .await?,
        "the completed key was not saved"
    );
    assert!(recoveries
        .read()
        .await?
        .is_some_and(|recovery| recovery.pending_publication.is_some()));
    Ok(())
}

/// A replayed C5 proof of other keyshares does not complete the key: the aggregator requests the
/// proof of its current keyshares again.
#[actix::test]
async fn a_replayed_c5_proof_of_other_keyshares_is_discarded() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let other = signed_c5_proof(&e3_id, c5_signals_for(&fhe, &keyshares(&fhe, &e3_id)?)?);
    let store = InMemStore::new(false).start();
    fenced_c5_aggregator(&bus, &fhe, &e3_id, keyshares(&fhe, &e3_id)?, &store);

    bus.publish_without_context(other)?;
    bus.publish_without_context(EffectsEnabled::new())?;
    assert!(c5_proof_requested(&history, &e3_id).await?);
    Ok(())
}

/// Replay created the aggregator, and both its C1 verdict and its C5 proof were logged. Replay
/// committed a later snapshot, so the store rejects writes under the revisions of both results.
#[actix::test]
async fn an_aggregator_created_during_replay_applies_its_replayed_c5_proof() -> Result<()> {
    let replayed = replay_until_c1_verification(true).await?;
    replayed.publish_c1_verdict(&first_h_parties())?;
    let keyshares = replayed.keyshares();
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        states,
        store,
        _ctx,
        ..
    } = replayed;
    bus.publish_without_context(signed_c5_proof(&e3_id, c5_signals_for(&fhe, &keyshares)?))?;
    commit_replay_past(&store, &history, c5_proof_logged).await?;

    bus.publish_without_context(EffectsEnabled::new())?;
    assert!(
        reaches_state(&states, &bus, |state| matches!(
            state,
            PublicKeyAggregatorState::GeneratingC5Proof {
                c5_proof_pending: Some(_),
                ..
            }
        ))
        .await?,
        "the replayed C5 proof was not applied"
    );
    Ok(())
}

/// The committee filter holds keyshares until the committee is finalized, and startup can deliver
/// that chain event after `EffectsEnabled`. The C1 verdict and the C5 proof of this node are then
/// replayed while the aggregator still collects. The filter releases the keyshares with their
/// logged contexts, and replay committed a snapshot past both results, so the store rejects writes
/// under the revisions of the keyshares and of both results.
#[actix::test]
async fn an_aggregator_collecting_during_replay_applies_its_replayed_c5_proof() -> Result<()> {
    let mut replayed = replay_selection().await?;
    replayed.publish_selected_keyshares(true)?;
    replayed.publish_c1_verdict(&first_h_parties())?;
    let keyshares = replayed.keyshares();
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        states,
        store,
        ..
    } = &replayed;
    bus.publish_without_context(signed_c5_proof(e3_id, c5_signals_for(fhe, &keyshares)?))?;
    bus.flush_event_pipeline().await?;
    assert!(matches!(
        states.read().await?,
        Some(PublicKeyAggregatorState::Collecting { .. })
    ));
    commit_replay_past(store, history, c5_proof_logged).await?;

    bus.publish_without_context(EffectsEnabled::new())?;
    replayed.publish_committee()?;
    assert!(
        reaches_state(states, bus, |state| matches!(
            state,
            PublicKeyAggregatorState::GeneratingC5Proof {
                c5_proof_pending: Some(_),
                ..
            }
        ))
        .await?,
        "the replayed C5 proof was not applied"
    );
    Ok(())
}

/// The committee filter can release the keyshares only after `EffectsEnabled`, and replay can
/// demote this node before that. Its replayed local verdict shows that it dispatched C1, so it
/// still finishes C1 and C5 once the keyshares complete the inputs.
#[actix::test]
async fn a_former_aggregator_demoted_while_collecting_finishes_c1_and_c5() -> Result<()> {
    let mut replayed = replay_selection().await?;
    replayed.publish_selected_keyshares(true)?;
    replayed.publish_c1_verdict(&first_h_parties())?;
    let keyshares = replayed.keyshares();
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        states,
        store,
        ..
    } = &replayed;
    bus.publish_without_context(signed_c5_proof(e3_id, c5_signals_for(fhe, &keyshares)?))?;
    bus.publish_without_context(AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    })?;
    commit_replay_past(store, history, c5_proof_logged).await?;

    bus.publish_without_context(EffectsEnabled::new())?;
    bus.flush_event_pipeline().await?;
    assert!(matches!(
        states.read().await?,
        Some(PublicKeyAggregatorState::Collecting { .. })
    ));
    replayed.publish_committee()?;
    assert!(
        reaches_state(states, bus, |state| matches!(
            state,
            PublicKeyAggregatorState::GeneratingC5Proof {
                c5_proof_pending: Some(_),
                ..
            }
        ))
        .await?,
        "the demoted node did not finish its C1 and C5"
    );
    Ok(())
}

/// Recovery records ownership when the active aggregator resumes, even while it still collects.
/// A node demoted before it dispatched C1 holds no verdict of its own, so the keyshares that
/// complete the inputs of the selected roster must not start C1 there.
#[actix::test]
async fn a_node_demoted_before_it_dispatched_c1_does_not_start_it() -> Result<()> {
    let replayed = replay_selection().await?;
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        committee,
        states,
        ..
    } = &replayed;
    replayed.publish_committee()?;
    bus.publish_without_context(EffectsEnabled::new())?;
    bus.flush_event_pipeline().await?;
    bus.publish_without_context(AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    })?;
    let h = CiphernodesCommitteeSize::Minimum.values().h;
    bus.publish_without_context(CommitmentRosterSelected {
        e3_id: e3_id.clone(),
        party_ids: (0..h as u64).collect(),
    })?;
    bus.flush_event_pipeline().await?;
    for (party, node) in committee.iter().take(h).enumerate() {
        let (pubkey, proof) = keyshare_with_c1_proof(fhe, e3_id)?;
        bus.publish_without_context(KeyshareCreated {
            pubkey,
            e3_id: e3_id.clone(),
            node: node.clone(),
            party_id: party as u64,
            signed_pk_generation_proof: Some(proof),
        })?;
    }
    assert!(
        reaches_state(states, bus, |state| matches!(
            state,
            PublicKeyAggregatorState::VerifyingC1 { .. }
        ))
        .await?,
        "the node did not collect the selected keyshares"
    );
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        !events.iter().any(|event| matches!(
            event.get_data(),
            InterfoldEventData::ShareVerificationDispatched(_)
        )),
        "a demoted node started C1 that it never dispatched"
    );
    Ok(())
}

/// Replay selects roster A and then roster B, delivers this node's verdict on A's keyshares, and
/// demotes the node. The verdict shows that the node dispatched A's request, not B's, so B's
/// keyshares, released after `EffectsEnabled`, must neither start C1 there nor take A's verdict.
#[actix::test]
async fn a_demoted_node_does_not_start_c1_for_a_replacement_roster() -> Result<()> {
    let (roster_a, roster_b) = ([0, 1], [1, 2]);
    let mut replayed = replay_selection().await?;
    replayed.publish_keyshares(&[0, 1, 2], true)?;
    replayed.publish_roster(&roster_a)?;
    replayed.publish_roster(&roster_b)?;
    replayed.publish_c1_verdict(&roster_a)?;
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        states,
        ..
    } = &replayed;
    bus.publish_without_context(AggregatorChanged {
        e3_id: e3_id.clone(),
        active_party_id: Some(1),
        is_aggregator: false,
    })?;
    bus.publish_without_context(EffectsEnabled::new())?;
    bus.flush_event_pipeline().await?;
    assert!(
        matches!(
            states.read().await?,
            Some(PublicKeyAggregatorState::Collecting { .. })
        ),
        "the keyshares reached the aggregator before the committee released them"
    );
    replayed.publish_committee()?;
    assert!(
        reaches_state(states, bus, |state| !matches!(
            state,
            PublicKeyAggregatorState::Collecting { .. }
        ))
        .await?,
        "the node did not collect the keyshares of the replacement roster"
    );
    bus.flush_event_pipeline().await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(
        !events.iter().any(|event| matches!(
            event.get_data(),
            InterfoldEventData::ShareVerificationDispatched(_)
        )),
        "a demoted node started C1 for a roster whose request it never dispatched"
    );
    assert!(
        matches!(
            states.read().await?,
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ),
        "a demoted node applied the verdict of a replaced roster"
    );
    Ok(())
}
