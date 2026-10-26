// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The test-only l-BFV committee path that skips proof aggregation
//! (`proof_aggregation_enabled == false`) against the same state with aggregation on.

use super::*;
use e3_events::{
    ComputeRequestKind, LbfvKeyShareDocument, LbfvKeyShareDocumentContextV1,
    LbfvPublicKeyShareDocumentV3, LbfvRelinearizationKeyShareDocumentV2, SignedProofPayload,
    ZkRequest,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_row_count, lbfv_urs_seed};
use fhe::bfv::{CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare};
use fhe_traits::Serialize as FheSerialize;

const PRESET: BfvPreset = BfvPreset::InsecureThresholdLbfv;

fn signed_rows(
    e3_id: &E3id,
    proof_type: ProofType,
    row_count: usize,
    signer: &alloy::signers::local::PrivateKeySigner,
) -> Vec<SignedProofPayload> {
    (0..row_count)
        .map(|_| {
            SignedProofPayload::sign(
                ProofPayload {
                    e3_id: e3_id.clone(),
                    proof_type,
                    proof: dummy_proof(proof_type.circuit_names()[0]),
                },
                signer,
            )
            .unwrap()
        })
        .collect()
}

/// Real key shares for the preset: the aggregation sums them into operational keys.
fn documents(
    e3_id: &E3id,
    proof_domain: e3_committee_hash::LbfvProofDomainContext,
    party_ids: &[u32],
) -> (
    std::collections::BTreeMap<u32, LbfvKeyShareDocument>,
    std::collections::BTreeMap<u32, LbfvKeyShareDocument>,
) {
    let (params, _) = build_pair_for_preset(PRESET).unwrap();
    let crs = CommonRandomPolyVec::from_seed(&params, lbfv_crs_seed(PRESET).unwrap()).unwrap();
    let urs = CommonRandomPolyVec::from_seed(&params, lbfv_urs_seed(PRESET).unwrap()).unwrap();
    let row_count = lbfv_row_count(PRESET).unwrap();
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let mut rng = rand::rng();
    let mut public_keys = std::collections::BTreeMap::new();
    let mut rlks = std::collections::BTreeMap::new();
    for &party_id in party_ids {
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key_share =
            PublicKeyShare::contribute_with_crp(&secret_key, &crs, &mut rng).unwrap();
        let (rlk_share, _witness) =
            RelinKeyShare::contribution_with_crp_extended(&secret_key, &urs, &crs, 0, 0, &mut rng)
                .unwrap();
        let context = LbfvKeyShareDocumentContextV1 {
            e3_id: e3_id.clone(),
            proof_domain,
            proof_session_id: B256::repeat_byte(9),
            party_id,
        };
        public_keys.insert(
            party_id,
            LbfvKeyShareDocument::PublicKeyV3(LbfvPublicKeyShareDocumentV3 {
                context: context.clone(),
                share: ArcBytes::from_bytes(&public_key_share.to_bytes()),
                signed_row_proofs: signed_rows(
                    e3_id,
                    ProofType::LbfvPkGeneration,
                    row_count,
                    &signer,
                ),
            }),
        );
        rlks.insert(
            party_id,
            LbfvKeyShareDocument::RelinearizationKeyV2(LbfvRelinearizationKeyShareDocumentV2 {
                context,
                share: ArcBytes::from_bytes(&rlk_share.to_bytes()),
                signed_row_proofs: signed_rows(e3_id, ProofType::RlkGeneration, row_count, &signer),
            }),
        );
    }
    (public_keys, rlks)
}

struct Fixture {
    aggregator: PublicKeyAggregator,
    history: Addr<HistoryCollector<InterfoldEvent>>,
    e3_id: E3id,
    committee: Vec<Address>,
}

/// An l-BFV aggregator that holds every honest party's key-share documents. `node_proofs` gives
/// each honest party's published node-fold output (`None` is the skipped fold).
fn fixture(
    proof_aggregation_enabled: bool,
    node_proofs: &[(u64, Option<Proof>)],
) -> Result<Fixture> {
    use crate::domain::lbfv_contribution_collection::tests::fixture as collection_fixture;

    let collection = collection_fixture();
    let e3_id = collection.state.e3_id.clone();
    let committee_size = CiphernodesCommitteeSize::Minimum;
    let committee = committee_size.values();
    let committee_addresses = (0..committee.n)
        .map(|index| Address::repeat_byte(index as u8 + 1))
        .collect::<Vec<_>>();
    let honest = (0..committee.h as u32).collect::<Vec<_>>();

    let mut aggregation = LbfvAggregationStateV1::new(
        e3_id.clone(),
        collection.state.proof_domain,
        honest.clone(),
        PRESET,
    )?;
    let (public_keys, rlks) = documents(&e3_id, collection.state.proof_domain, &honest);
    aggregation.public_key_documents = public_keys;
    aggregation.rlk_documents = rlks;

    let state = PublicKeyAggregatorState::GeneratingC5Proof {
        public_key: ArcBytes::from_bytes(&[1]),
        keyshare_bytes: Vec::new(),
        nodes: OrderedSet::from_iter(committee_addresses.iter().map(ToString::to_string)),
        party_nodes: committee_addresses
            .iter()
            .enumerate()
            .map(|(party_id, address)| (party_id as u64, address.to_string()))
            .collect(),
        dkg_node_proofs: node_proofs.iter().cloned().collect(),
        dkg_fold_attestations: HashMap::new(),
        honest_party_ids: honest.iter().map(|party_id| u64::from(*party_id)).collect(),
        dishonest_parties: BTreeSet::new(),
        circuit_committee_n: committee.n,
        circuit_committee_h: committee.h,
        dkg_aggregation_correlation: None,
        dkg_aggregated_proof: None,
        c5_proof_pending: None,
        last_ec: Some(test_ctx(EffectsEnabled::new())),
        nodes_fold_accumulator: None,
        nodes_fold_completed_slots: 0,
        nodes_fold_step_correlation: None,
    };

    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let aggregator = PublicKeyAggregator::new(
        PublicKeyAggregatorParams {
            fhe: Arc::new(Fhe::new(params, crp, rng)),
            bus,
            e3_id: e3_id.clone(),
            params_preset: PRESET,
            committee_size,
            dkg_fold_attestation_context: None,
            recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
            lbfv_collection: None,
            repositories: Repositories::in_mem(),
            local_party_id: 0,
            lbfv_aggregation: Some(test_state(aggregation)),
            lbfv_publication: Some(test_state(LbfvPublicKeyPublicationStateV1::new(
                e3_id.clone(),
            ))),
            initial_is_aggregator: true,
            initial_stage: E3Stage::None,
            effects_enabled: true,
            proof_aggregation_enabled,
        },
        test_state(state),
    );
    Ok(Fixture {
        aggregator,
        history,
        e3_id,
        committee: committee_addresses,
    })
}

async fn events(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<Vec<InterfoldEvent>> {
    // Publication goes through the bus; let it deliver before reading the log.
    actix::clock::sleep(Duration::from_millis(50)).await;
    Ok(history.send(GetEvents::<InterfoldEvent>::new()).await?)
}

fn zk_requests(events: &[InterfoldEvent]) -> Vec<&ZkRequest> {
    events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::ComputeRequest(request) => match &request.request {
                ComputeRequestKind::Zk(zk) => Some(zk),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn publications(events: &[InterfoldEvent]) -> Vec<&LbfvPublicKeyAggregated> {
    events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::LbfvPublicKeyAggregated(publication) => Some(publication),
            _ => None,
        })
        .collect()
}

#[actix::test]
async fn skipped_aggregation_publishes_a_placeholder_and_requests_no_proofs() -> Result<()> {
    let Fixture {
        mut aggregator,
        history,
        e3_id,
        committee,
    } = fixture(false, &[(0, None), (1, None)])?;

    aggregator.try_dispatch_lbfv_aggregation_rows(&test_ctx(EffectsEnabled::new()))?;

    let events = events(&history).await?;
    assert!(
        zk_requests(&events).is_empty(),
        "skipping must dispatch no row, fold or aggregation request: {:?}",
        zk_requests(&events)
    );
    let published = publications(&events);
    assert_eq!(published.len(), 1);
    let publication = published[0];
    assert_eq!(publication.e3_id, e3_id);
    assert_eq!(publication.committee_addresses, committee);
    assert_eq!(
        publication.honest_committee_addresses,
        committee[..aggregator.committee_size.values().h]
    );
    assert_eq!(
        publication.dkg_aggregator_v2_proof.circuit,
        CircuitName::DkgAggregatorV2
    );
    // The placeholder commits to the published key envelope, the commitment the registry binds.
    let row_count = lbfv_row_count(PRESET).unwrap();
    assert_eq!(
        extract_lbfv_key_envelope_commitment(
            &publication.dkg_aggregator_v2_proof,
            aggregator.committee_size.values().h,
            row_count,
        )?,
        publication.pk_commitment
    );
    e3_bfv_client::validate_lbfv_key_envelope(
        &publication.pubkey,
        publication.pk_commitment,
        PRESET,
    )?;
    assert!(publication
        .dkg_attestation_bundle
        .as_ref()
        .is_some_and(|bundle| !bundle.is_empty()));
    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::Complete { .. })
    ));
    Ok(())
}

#[actix::test]
async fn skipped_aggregation_waits_for_every_honest_node_fold_output() -> Result<()> {
    let Fixture {
        mut aggregator,
        history,
        ..
    } = fixture(false, &[(0, None)])?;

    aggregator.try_dispatch_lbfv_aggregation_rows(&test_ctx(EffectsEnabled::new()))?;

    let events = events(&history).await?;
    assert!(publications(&events).is_empty());
    assert!(zk_requests(&events).is_empty());
    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
    ));
    Ok(())
}

#[actix::test]
async fn skipped_aggregation_refuses_a_node_that_did_fold() -> Result<()> {
    let Fixture {
        mut aggregator,
        history,
        ..
    } = fixture(
        false,
        &[
            (0, None),
            (1, Some(dummy_proof(CircuitName::NodeFoldChunked))),
        ],
    )?;

    aggregator.try_dispatch_lbfv_aggregation_rows(&test_ctx(EffectsEnabled::new()))?;

    let events = events(&history).await?;
    assert!(publications(&events).is_empty());
    assert!(matches!(
        aggregator.state.get(),
        Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
    ));
    Ok(())
}

#[actix::test]
async fn enabled_aggregation_still_requests_proofs_and_does_not_publish_a_placeholder() -> Result<()>
{
    let Fixture {
        mut aggregator,
        history,
        ..
    } = fixture(true, &[(0, None), (1, None)])?;

    aggregator.try_dispatch_lbfv_aggregation_rows(&test_ctx(EffectsEnabled::new()))?;

    let events = events(&history).await?;
    assert!(zk_requests(&events)
        .iter()
        .any(|request| matches!(request, ZkRequest::LbfvPkAggregation(_))));
    assert!(publications(&events).is_empty());
    Ok(())
}
