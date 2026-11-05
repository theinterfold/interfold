// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::ext::{AggregatorRoleExtension, PublicKeyAggregatorExtension};
use crate::test_support::commit_replay_past;
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
    /// The selected keyshares in party order.
    keyshares: Vec<ArcBytes>,
    states: Repository<PublicKeyAggregatorState>,
    store: Addr<InMemStore>,
    _ctx: E3Context,
}

/// Replay a selection, its committee, the selected keyshares and the roster into a context whose
/// effects are off, as startup replay does, until the aggregator that the selection creates
/// verifies C1.
async fn replay_until_c1_verification(signed_keyshares: bool) -> Result<ReplayedAggregator> {
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
    PublicKeyAggregatorExtension::create(&bus).on_event(
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

    bus.publish_without_context(CommitteeFinalized {
        e3_id: e3_id.clone(),
        committee: committee.clone(),
        scores: Vec::new(),
        chain_id: 1,
    })?;
    let mut keyshares = Vec::new();
    for (party, node) in committee.iter().take(committee_size.h).enumerate() {
        let (pubkey, signed_pk_generation_proof) = if signed_keyshares {
            let (keyshare, proof) = keyshare_with_c1_proof(&fhe, &e3_id)?;
            (keyshare, Some(proof))
        } else {
            (ArcBytes::from_bytes(&[1]), None)
        };
        keyshares.push(pubkey.clone());
        bus.publish_without_context(KeyshareCreated {
            pubkey,
            e3_id: e3_id.clone(),
            node: node.clone(),
            party_id: party as u64,
            signed_pk_generation_proof,
        })?;
    }
    bus.publish_without_context(CommitmentRosterSelected {
        e3_id: e3_id.clone(),
        party_ids: (0..committee_size.h as u64).collect(),
    })?;
    let states = ctx.repositories().publickey(&e3_id);
    for _ in 0..200 {
        bus.flush_event_pipeline().await?;
        if matches!(
            states.read().await?,
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ) {
            return Ok(ReplayedAggregator {
                bus,
                history,
                e3_id,
                fhe,
                keyshares,
                states,
                store,
                _ctx: ctx,
            });
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    panic!("the aggregator did not collect the selected keyshares")
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

/// Replay also delivers this node's C1 verdict while effects are fenced. Replay put the verdict's
/// payload-derived delivery ID in the bus dedup window, so the verdict to a new dispatch would be
/// dropped: the aggregator must apply the replayed one.
async fn replayed_c1_verdict_reaches_c5(demoted_before_effects: bool) -> Result<()> {
    let ReplayedAggregator {
        bus,
        e3_id,
        states,
        _ctx,
        ..
    } = replay_until_c1_verification(true).await?;
    bus.publish_without_context(c1_verdict(&e3_id))?;
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
    bus.subscribe_all(&[EventType::All], aggregator.start().recipient());

    bus.publish_without_context(ShareVerificationComplete {
        dishonest_parties: (circuit_h as u64..threshold_n as u64).collect(),
        ..c1_verdict(&e3_id)
    })?;
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
    let ReplayedAggregator {
        bus,
        history,
        e3_id,
        fhe,
        keyshares,
        states,
        store,
        _ctx,
    } = replay_until_c1_verification(true).await?;
    bus.publish_without_context(c1_verdict(&e3_id))?;
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
