// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::test_support::history_reader;
use crate::PublicKeyRepositoryFactory;
use e3_data::RepositoriesFactory;
use e3_events::EventSource;

/// A party's fold as the event log holds it. Each party sends its fold once.
fn fold_event(e3_id: &E3id, party_id: u64) -> InterfoldEvent {
    let fold = DKGRecursiveAggregationComplete {
        e3_id: e3_id.clone(),
        party_id,
        aggregated_proof: None,
        fold_attestation: None,
    };
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        fold.into(),
        None,
        party_id as u128 + 1,
        None,
        EventSource::Net,
    )
    .into_sequenced(party_id + 1)
}

fn persisted_fold_parties(state: Option<PublicKeyAggregatorState>) -> BTreeSet<u64> {
    let Some(PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_node_proofs, ..
    }) = state
    else {
        panic!("expected GeneratingC5Proof state");
    };
    dkg_node_proofs.into_keys().collect()
}

/// The aggregator restarts during C1 verification. The folds that it buffered in memory are gone,
/// so it reads them back from the event log and holds them when C5 proof generation starts.
#[actix::test]
async fn restart_during_c1_verification_keeps_the_received_folds() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (state, threshold_n, _, circuit_h) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let honest = (0..circuit_h as u64).collect::<BTreeSet<_>>();
    let folds = honest
        .iter()
        .map(|&party| fold_event(&e3_id, party))
        .collect::<Vec<_>>();
    let repositories = DataStore::from_in_mem(&InMemStore::new(false).start()).repositories();
    let states = repositories.publickey(&e3_id);
    let mut aggregator = booted_micro_aggregator(
        &bus,
        &fhe,
        &e3_id,
        true,
        states.send(Some(state)),
        test_state(PublicKeyAggregatorRecoveryState::default()),
    );
    // Hydration runs before replay enables effects.
    aggregator.effects_enabled = false;

    aggregator
        .recover_dkg_folds(&history_reader(&folds)?, &repositories)
        .await?;
    let aggregator = aggregator.start();
    let effects_enabled = InterfoldEventData::from(EffectsEnabled::new());
    aggregator
        .send(bus.event_from(effects_enabled, None)?.into_sequenced(0))
        .await?;
    aggregator
        .send(c1_verified(
            &e3_id,
            (circuit_h as u64..threshold_n as u64).collect(),
        ))
        .await?;

    assert_eq!(persisted_fold_parties(states.read().await?), honest);
    Ok(())
}

/// The aggregator restarts during C5 proof generation before a newer write saved the folds that it
/// moved into that phase. It reads them back from the event log and saves them.
#[actix::test]
async fn restart_during_c5_proof_generation_keeps_the_received_folds() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, _history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let mut state = c5_state_without_node_proofs();
    let PublicKeyAggregatorState::GeneratingC5Proof {
        dkg_node_proofs,
        honest_party_ids,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    dkg_node_proofs.clear();
    let honest = honest_party_ids.clone();
    let folds = honest
        .iter()
        .map(|&party| fold_event(&e3_id, party))
        .collect::<Vec<_>>();
    let repositories = DataStore::from_in_mem(&InMemStore::new(false).start()).repositories();
    let states = repositories.publickey(&e3_id);
    let mut aggregator = booted_micro_aggregator(
        &bus,
        &fhe,
        &e3_id,
        true,
        states.send(Some(state)),
        test_state(PublicKeyAggregatorRecoveryState::default()),
    );
    aggregator.effects_enabled = false;

    aggregator
        .recover_dkg_folds(&history_reader(&folds)?, &repositories)
        .await?;

    assert_eq!(persisted_fold_parties(states.read().await?), honest);
    Ok(())
}
