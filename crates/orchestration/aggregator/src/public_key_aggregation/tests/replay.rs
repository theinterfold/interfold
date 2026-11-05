// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::ext::{AggregatorRoleExtension, PublicKeyAggregatorExtension};
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

/// Startup replays logged events before `EffectsEnabled`. An aggregator that a replayed selection
/// creates collects its inputs, but runs no effects until the fence opens.
#[actix::test]
async fn an_aggregator_created_during_replay_waits_for_effects() -> Result<()> {
    let committee_size = CiphernodesCommitteeSize::Minimum.values();
    let (bus, rng, seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let committee: Vec<String> = (0..committee_size.n)
        .map(|party| Address::repeat_byte(party as u8 + 1).to_string())
        .collect();
    let mut ctx = E3Context::from_params(E3ContextParams {
        repository: store.repositories().context(&e3_id),
        e3_id: e3_id.clone(),
        extensions: Arc::new(Vec::new()),
    });
    // The router creates a context with its own flag, which is off while startup replays.
    ctx.set_effects_enabled(false);
    ctx.set_dependency(FHE_KEY, Arc::new(Fhe::new(params, crp, rng)));
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
    for (party, node) in committee.iter().take(committee_size.h).enumerate() {
        bus.publish_without_context(KeyshareCreated {
            pubkey: ArcBytes::from_bytes(&[1]),
            e3_id: e3_id.clone(),
            node: node.clone(),
            party_id: party as u64,
            signed_pk_generation_proof: None,
        })?;
    }
    bus.publish_without_context(CommitmentRosterSelected {
        e3_id: e3_id.clone(),
        party_ids: (0..committee_size.h as u64).collect(),
    })?;
    let repo = ctx.repositories().publickey(&e3_id);
    let mut collected = false;
    for _ in 0..200 {
        bus.flush_event_pipeline().await?;
        if matches!(
            repo.read().await?,
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ) {
            collected = true;
            break;
        }
        actix::clock::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        collected,
        "the aggregator did not collect the selected keyshares"
    );
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
