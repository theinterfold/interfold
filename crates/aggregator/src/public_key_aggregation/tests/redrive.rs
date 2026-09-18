// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Redrive of l-BFV aggregation requests whose response never arrived.

use super::super::effects::LBFV_ROW_CORRELATION_TIMEOUT_SECS;
use super::*;
use e3_events::{ComputeRequestKind, ZkRequest};

struct FixedClock(u64);

impl LbfvRetryClock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

fn redrive_fixture(
    now: u64,
) -> Result<(
    PublicKeyAggregator,
    Addr<HistoryCollector<InterfoldEvent>>,
    E3id,
    e3_committee_hash::LbfvProofDomainContext,
)> {
    use crate::domain::lbfv_contribution_collection::tests::fixture;

    let fixture = fixture();
    let e3_id = fixture.state.e3_id.clone();
    let proof_domain = fixture.state.proof_domain;
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold512.into()))?;
    let aggregator = PublicKeyAggregator::new_with_lbfv_retry_clock(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: e3_id.clone(),
            params_preset: BfvPreset::SecureThreshold16384,
            committee_size: CiphernodesCommitteeSize::Minimum,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: None,
            repositories: Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: None,
            lbfv_publication: None,
            initial_is_aggregator: true,
            effects_enabled: true,
        },
        test_state(generating_c5_state(CorrelationId::new())),
        Arc::new(FixedClock(now)),
    );
    Ok((aggregator, history, e3_id, proof_domain))
}

fn fold_row_zero_ready(
    e3_id: &E3id,
    proof_domain: e3_committee_hash::LbfvProofDomainContext,
    fold_correlation: Option<CorrelationId>,
) -> Result<LbfvAggregationStateV1> {
    let mut aggregation = LbfvAggregationStateV1::new(e3_id.clone(), proof_domain, vec![0, 1])?;
    aggregation.record_public_key_proof(0, dummy_proof(CircuitName::PkAggregation))?;
    aggregation.record_rlk_proof(0, dummy_proof(CircuitName::PkAggregation))?;
    if let Some(correlation) = fold_correlation {
        aggregation.set_fold_correlation(correlation)?;
    }
    Ok(aggregation)
}

#[actix::test]
async fn redrive_republishes_a_timed_out_aggregation_fold() -> Result<()> {
    const NOW: u64 = 10_000;
    let (mut aggregator, history, e3_id, proof_domain) = redrive_fixture(NOW)?;
    let old = CorrelationId::new();
    let ec = test_ctx(EffectsEnabled::new());
    aggregator.replace_lbfv_aggregation(test_state(fold_row_zero_ready(
        &e3_id,
        proof_domain,
        Some(old),
    )?));
    aggregator.lbfv_aggregation_dispatch_at.insert(
        old,
        AggregationDispatch {
            at: NOW - LBFV_ROW_CORRELATION_TIMEOUT_SECS - 1,
            ec: ec.clone(),
        },
    );

    aggregator.redrive_lbfv_aggregation()?;

    let state = aggregator.lbfv_aggregation_state()?.expect("sidecar");
    let Some(new) = state.aggregation_fold_correlation else {
        anyhow::bail!("timed-out fold correlation was not re-dispatched");
    };
    assert_ne!(new, old);
    let event = next_event(&history).await?.into_data();
    assert!(
        matches!(
            event,
            InterfoldEventData::ComputeRequest(request)
            if matches!(
                request.request,
                ComputeRequestKind::Zk(ZkRequest::LbfvAggregationFold(ref fold))
                if fold.row_index == 0 && request.correlation_id == new
            )
        ),
        "expected the fold row-zero request under the new correlation"
    );
    Ok(())
}

#[actix::test]
async fn redrive_leaves_a_fresh_fold_correlation_alone() -> Result<()> {
    const NOW: u64 = 10_000;
    let (mut aggregator, history, e3_id, proof_domain) = redrive_fixture(NOW)?;
    let live = CorrelationId::new();
    let ec = test_ctx(EffectsEnabled::new());
    aggregator.replace_lbfv_aggregation(test_state(fold_row_zero_ready(
        &e3_id,
        proof_domain,
        Some(live),
    )?));
    aggregator.lbfv_aggregation_dispatch_at.insert(
        live,
        AggregationDispatch {
            at: NOW,
            ec: ec.clone(),
        },
    );

    aggregator.redrive_lbfv_aggregation()?;

    let state = aggregator.lbfv_aggregation_state()?.expect("sidecar");
    assert_eq!(state.aggregation_fold_correlation, Some(live));
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}

#[actix::test]
async fn v2_dispatch_redrives_a_missing_aggregation_fold() -> Result<()> {
    const NOW: u64 = 10_000;
    let (mut aggregator, history, e3_id, proof_domain) = redrive_fixture(NOW)?;
    // C5 is signed and the cross-node fold is complete, but the aggregation
    // fold was never dispatched: the V2 probe must dispatch it first.
    let mut state = generating_c5_state(CorrelationId::new());
    let PublicKeyAggregatorState::GeneratingC5Proof {
        party_nodes,
        honest_party_ids,
        nodes_fold_accumulator,
        nodes_fold_completed_slots,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    for party_id in [0, 1] {
        party_nodes.insert(party_id, Address::repeat_byte(party_id as u8).to_string());
        honest_party_ids.insert(party_id);
    }
    *nodes_fold_accumulator = Some(dummy_proof(CircuitName::NodesFoldV2));
    *nodes_fold_completed_slots = 2;
    aggregator.state = test_state(state);
    aggregator.replace_lbfv_aggregation(test_state(fold_row_zero_ready(
        &e3_id,
        proof_domain,
        None,
    )?));

    aggregator.try_dispatch_dkg_aggregation(&test_ctx(EffectsEnabled::new()))?;

    let event = next_event(&history).await?.into_data();
    assert!(
        matches!(
            event,
            InterfoldEventData::ComputeRequest(request)
            if matches!(
                request.request,
                ComputeRequestKind::Zk(ZkRequest::LbfvAggregationFold(ref fold))
                if fold.row_index == 0
            )
        ),
        "expected the V2 probe to dispatch the missing fold row-zero request"
    );
    // The final aggregation itself must wait for the fold chain.
    assert!(aggregator
        .lbfv_aggregation_state()?
        .is_some_and(|state| state.dkg_aggregation_correlation.is_none()));
    Ok(())
}
