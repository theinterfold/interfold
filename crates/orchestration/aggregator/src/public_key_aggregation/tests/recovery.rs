// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::test_support::history_reader;
use crate::PublicKeyRepositoryFactory;
use alloy::signers::local::PrivateKeySigner;
use e3_data::RepositoriesFactory;
use e3_events::{
    ComputeRequestKind, DkgFoldAttestationPayload, EventSource, SignedDkgFoldAttestation,
};
use e3_zk_prover::extract_node_fold_agg_commits;

fn attestation_context() -> DkgFoldAttestationContext {
    DkgFoldAttestationContext {
        registry: Address::repeat_byte(0x11),
        verifying_contract: Address::repeat_byte(0x22),
    }
}

fn party_signer(party_id: u64) -> PrivateKeySigner {
    PrivateKeySigner::from_slice(&[party_id as u8 + 1; 32]).expect("test signer")
}

/// Committee nodes whose keys sign the parties' fold attestations.
fn signing_nodes(parties: std::ops::Range<u64>) -> HashMap<u64, String> {
    parties
        .map(|party_id| (party_id, party_signer(party_id).address().to_string()))
        .collect()
}

/// A party's `node_fold` proof. Its public outputs start with the party ID.
fn node_fold_proof(party_id: u64, committee_n: usize, committee_h: usize) -> Proof {
    let n_moduli = BfvPreset::InsecureThreshold64.metadata().num_moduli;
    // The output count of the `node_fold` layout in `e3_zk_prover`, whose extraction checks it.
    let fields = 11 + committee_n + 2 * (committee_n + committee_h) * n_moduli;
    let mut signals = vec![0; fields * 32];
    signals[24..32].copy_from_slice(&party_id.to_be_bytes());
    Proof::new(
        CircuitName::NodeFold,
        ArcBytes::from_bytes(&[party_id as u8]),
        ArcBytes::from_bytes(&signals),
    )
}

/// A party's attested fold as the event log holds it. Each party sends its fold once.
fn fold_event(
    e3_id: &E3id,
    party_id: u64,
    committee_n: usize,
    committee_h: usize,
) -> Result<InterfoldEvent> {
    let proof = node_fold_proof(party_id, committee_n, committee_h);
    let n_moduli = BfvPreset::InsecureThreshold64.metadata().num_moduli;
    let (_, agg_commits) =
        extract_node_fold_agg_commits(&proof, committee_n, committee_h, n_moduli)?;
    let context = attestation_context();
    let attestation = SignedDkgFoldAttestation::sign(
        DkgFoldAttestationPayload {
            e3_id: e3_id.clone(),
            registry: context.registry,
            verifying_contract: context.verifying_contract,
            party_id,
            agg_commits,
        },
        &party_signer(party_id),
    )?;
    let fold = DKGRecursiveAggregationComplete {
        e3_id: e3_id.clone(),
        party_id,
        aggregated_proof: Some(proof),
        fold_attestation: Some(attestation),
    };
    Ok(InterfoldEvent::<Unsequenced>::new_with_timestamp(
        fold.into(),
        None,
        party_id as u128 + 1,
        None,
        EventSource::Net,
    )
    .into_sequenced(party_id + 1))
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

/// Wait until the aggregator requests a fold step, and return the request.
async fn nodes_fold_step_requested(
    history: &Addr<HistoryCollector<InterfoldEvent>>,
) -> Result<NodesFoldStepRequest> {
    for _ in 0..100 {
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        if let Some(request) = events
            .into_iter()
            .find_map(|event| match event.into_data() {
                InterfoldEventData::ComputeRequest(ComputeRequest {
                    request: ComputeRequestKind::Zk(ZkRequest::NodesFoldStep(request)),
                    ..
                }) => Some(request),
                _ => None,
            })
        {
            return Ok(request);
        }
        actix::clock::sleep(std::time::Duration::from_millis(20)).await;
    }
    anyhow::bail!("the aggregator requested no fold step")
}

/// The aggregator restarts during C1 verification. The folds that it buffered in memory are gone,
/// so it reads them back from the event log and folds them when C5 proof generation starts.
#[actix::test]
async fn restart_during_c1_verification_keeps_the_received_folds() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let (mut state, threshold_n, _, circuit_h) = verifying_c1_non_square_state(&fhe, &e3_id)?;
    let PublicKeyAggregatorState::VerifyingC1 {
        canonical_party_nodes,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    *canonical_party_nodes = signing_nodes(0..threshold_n as u64);
    let honest = (0..circuit_h as u64).collect::<BTreeSet<_>>();
    let folds = honest
        .iter()
        .map(|&party| fold_event(&e3_id, party, threshold_n, circuit_h))
        .collect::<Result<Vec<_>>>()?;
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
    // Hydration runs before replay enables effects, and after the E3 context restored the
    // attestation context.
    aggregator.effects_enabled = false;
    aggregator.dkg_fold_attestation_context = Some(attestation_context());

    aggregator
        .recover_dkg_folds(&history_reader(&folds)?, &repositories)
        .await?;
    let verified = c1_verified(
        &aggregator,
        (circuit_h as u64..threshold_n as u64).collect(),
    );
    let aggregator = aggregator.start();
    let effects_enabled = InterfoldEventData::from(EffectsEnabled::new());
    aggregator
        .send(bus.event_from(effects_enabled, None)?.into_sequenced(0))
        .await?;
    aggregator.send(verified).await?;

    assert_eq!(persisted_fold_parties(states.read().await?), honest);
    let step = nodes_fold_step_requested(&history).await?;
    assert_eq!(step.slot_index, 0);
    assert_eq!(step.inner_proof, node_fold_proof(0, threshold_n, circuit_h));
    Ok(())
}

/// The aggregator restarts during C5 proof generation before a newer write saved the folds that it
/// moved into that phase. It reads them back from the event log, saves them, and folds them.
#[actix::test]
async fn restart_during_c5_proof_generation_keeps_the_received_folds() -> Result<()> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let e3_id = E3id::new("42", 1);
    let fhe = Arc::new(Fhe::new(params, crp, rng));
    let mut state = c5_state_without_node_proofs();
    let PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        dkg_node_proofs,
        honest_party_ids,
        circuit_committee_n,
        circuit_committee_h,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    let (committee_n, committee_h) = (*circuit_committee_n, *circuit_committee_h);
    *party_nodes = signing_nodes(0..committee_n as u64);
    dkg_node_proofs.clear();
    let honest = honest_party_ids.clone();
    let folds = honest
        .iter()
        .map(|&party| fold_event(&e3_id, party, committee_n, committee_h))
        .collect::<Result<Vec<_>>>()?;
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
    aggregator.dkg_fold_attestation_context = Some(attestation_context());

    aggregator
        .recover_dkg_folds(&history_reader(&folds)?, &repositories)
        .await?;
    assert_eq!(persisted_fold_parties(states.read().await?), honest);

    let aggregator = aggregator.start();
    let effects_enabled = InterfoldEventData::from(EffectsEnabled::new());
    aggregator
        .send(bus.event_from(effects_enabled, None)?.into_sequenced(0))
        .await?;
    let step = nodes_fold_step_requested(&history).await?;
    assert_eq!(step.slot_index, 0);
    let first = *honest.first().expect("an honest party");
    assert_eq!(
        step.inner_proof,
        node_fold_proof(first, committee_n, committee_h)
    );
    Ok(())
}
