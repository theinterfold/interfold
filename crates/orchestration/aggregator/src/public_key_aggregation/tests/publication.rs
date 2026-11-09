// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The accepted DKG roster decides the key: which keyshares reach C1, the published key and its
//! roster, and who may replace the roster. Every test injects the events that the verifier, prover
//! and sortition layer would emit, so none waits for a deadline.

use super::*;
use std::time::Duration;

type History = Addr<HistoryCollector<InterfoldEvent>>;

const COMMITTEE: CiphernodesCommitteeSize = CiphernodesCommitteeSize::Minimum;

fn node_address(party_id: u64) -> Address {
    Address::repeat_byte(party_id as u8 + 1)
}

struct Dealer {
    party_id: u64,
    keyshare: ArcBytes,
    c1_proof: SignedProofPayload,
}

fn dealers(
    fhe: &Fhe,
    e3_id: &E3id,
    party_ids: impl IntoIterator<Item = u64>,
) -> Result<Vec<Dealer>> {
    party_ids
        .into_iter()
        .map(|party_id| {
            let (keyshare, c1_proof) = keyshare_with_c1_proof(fhe, e3_id)?;
            Ok(Dealer {
                party_id,
                keyshare,
                c1_proof,
            })
        })
        .collect()
}

fn keyshares(dealers: &[&Dealer]) -> Vec<ArcBytes> {
    dealers
        .iter()
        .map(|dealer| dealer.keyshare.clone())
        .collect()
}

/// The aggregation that the dealers' keyshares yield, as the registry receives it.
fn aggregate_key(fhe: &Fhe, dealers: &[&Dealer]) -> Result<ArcBytes> {
    let keyshares = OrderedSet::from(keyshares(dealers));
    Ok(ArcBytes::from_bytes(&fhe.get_aggregate_public_key(
        GetAggregatePublicKey { keyshares },
    )?))
}

fn ordered_nodes(party_ids: &[u64]) -> OrderedSet<String> {
    OrderedSet::from(
        party_ids
            .iter()
            .map(|&party_id| node_address(party_id).to_string())
            .collect::<Vec<_>>(),
    )
}

/// The state of an aggregator that has seen no keyshare.
fn committee_state() -> PublicKeyAggregatorState {
    let committee = COMMITTEE.values();
    PublicKeyAggregatorState::init(
        committee.n,
        committee.threshold,
        Seed([0; 32]),
        (0..committee.n as u64)
            .map(|party_id| (party_id, node_address(party_id).to_string()))
            .collect(),
    )
}

/// `event` as the bus delivers it to the aggregator.
fn delivered<E: Clone + Into<InterfoldEventData>>(event: E) -> TypedEvent<E> {
    TypedEvent::new(event.clone(), test_ctx(event))
}

/// One node's public-key aggregator over its own event bus.
struct KeyNode {
    actor: Addr<PublicKeyAggregator>,
    bus: BusHandle,
    history: History,
    e3_id: E3id,
}

impl KeyNode {
    fn start(
        bus: BusHandle,
        history: History,
        fhe: &Arc<Fhe>,
        e3_id: &E3id,
        is_aggregator: bool,
    ) -> Self {
        let actor = PublicKeyAggregator::new(
            PublicKeyAggregatorParams {
                fhe: fhe.clone(),
                bus: bus.clone(),
                e3_id: e3_id.clone(),
                params_preset: BfvPreset::InsecureThreshold64,
                committee_size: COMMITTEE,
                dkg_fold_attestation_context: None,
                recovery: test_state(PublicKeyAggregatorRecoveryState::default()),
                initial_is_aggregator: is_aggregator,
                initial_stage: E3Stage::None,
                effects_enabled: true,
            },
            test_state(committee_state()),
        )
        .start();
        Self {
            actor,
            bus,
            history,
            e3_id: e3_id.clone(),
        }
    }

    async fn keyshare(&self, dealer: &Dealer) -> Result<()> {
        self.actor
            .send(delivered(KeyshareCreated {
                pubkey: dealer.keyshare.clone(),
                e3_id: self.e3_id.clone(),
                node: node_address(dealer.party_id).to_string(),
                party_id: dealer.party_id,
                signed_pk_generation_proof: Some(dealer.c1_proof.clone()),
            }))
            .await?;
        Ok(())
    }

    async fn roster(&self, party_ids: &[u64]) -> Result<()> {
        let roster = CommitmentRosterSelected {
            e3_id: self.e3_id.clone(),
            party_ids: party_ids.to_vec(),
        };
        self.actor
            .send(self.bus.event_from(roster, None)?.into_sequenced(0))
            .await?;
        Ok(())
    }

    /// The sortition layer's verdict on who aggregates.
    async fn role(&self, is_aggregator: bool) -> Result<()> {
        self.actor
            .send(delivered(AggregatorChanged {
                e3_id: self.e3_id.clone(),
                active_party_id: Some(1),
                is_aggregator,
            }))
            .await?;
        Ok(())
    }

    async fn c1_request(&self) -> Result<ShareVerificationDispatched> {
        Ok(wait_for_event(&self.history, |data| match data {
            InterfoldEventData::ShareVerificationDispatched(request) => Some(request.clone()),
            _ => None,
        })
        .await?
        .expect("the node did not dispatch C1 verification"))
    }

    /// The verifier finds every dealer honest.
    async fn c1_passes(&self, request: ShareVerificationDispatched) -> Result<()> {
        self.actor
            .send(c1_verdict_for(request, BTreeSet::new()))
            .await?;
        Ok(())
    }

    async fn c5_request(&self) -> Result<PkAggregationProofPending> {
        Ok(wait_for_event(&self.history, |data| match data {
            InterfoldEventData::PkAggregationProofPending(pending) => Some(pending.clone()),
            _ => None,
        })
        .await?
        .expect("the node did not request the C5 proof"))
    }

    /// The prover proves the aggregation of `dealers`.
    async fn c5_proved(&self, fhe: &Fhe, dealers: &[&Dealer]) -> Result<()> {
        let proof = signed_c5_proof(&self.e3_id, c5_signals_for(fhe, &keyshares(dealers))?);
        self.actor.send(delivered(proof)).await?;
        Ok(())
    }

    /// Proof aggregation is off: the party's fold carries no proof.
    async fn fold(&self, party_id: u64) -> Result<()> {
        self.actor
            .send(delivered(DKGRecursiveAggregationComplete {
                e3_id: self.e3_id.clone(),
                party_id,
                aggregated_proof: None,
                fold_attestation: None,
            }))
            .await?;
        Ok(())
    }

    async fn published(&self) -> Result<Option<PublicKeyAggregated>> {
        wait_for_event(&self.history, |data| match data {
            InterfoldEventData::PublicKeyAggregated(key) => Some(key.clone()),
            _ => None,
        })
        .await
    }

    /// Whether the node has published the key after letting its mailbox and bus drain.
    async fn has_published(&self) -> Result<bool> {
        actix::clock::sleep(Duration::from_millis(50)).await;
        let events = self
            .history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?;
        Ok(events
            .iter()
            .any(|event| matches!(event.get_data(), InterfoldEventData::PublicKeyAggregated(_))))
    }
}

fn setup() -> Result<(Arc<Fhe>, E3id, BusHandle, History)> {
    let (bus, rng, _seed, params, crp, _errors, history) =
        get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    Ok((
        Arc::new(Fhe::new(params, crp, rng)),
        E3id::new("42", 1),
        bus,
        history,
    ))
}

/// The key aggregates the keyshares of the accepted roster and nothing else, and the node
/// publishes it only after the key proof and every roster party's fold exist. A keyshare of a party
/// outside the committee and the folds of parties outside the roster count for nothing.
#[actix::test]
async fn the_key_is_published_for_the_accepted_roster_once_its_proofs_are_complete() -> Result<()> {
    let (fhe, e3_id, bus, history) = setup()?;
    // Party 7 is outside the committee of N = 3. Party 1 is a committee member that the roster
    // leaves out.
    let all = dealers(&fhe, &e3_id, [0, 1, 2, 7])?;
    let (first, left_out, second, outsider) = (&all[0], &all[1], &all[2], &all[3]);
    let roster = [first, second];
    let node = KeyNode::start(bus, history, &fhe, &e3_id, true);

    for dealer in &all {
        node.keyshare(dealer).await?;
    }
    node.roster(&[0, 2]).await?;

    // C1 verifies the roster's keyshares only.
    let request = node.c1_request().await?;
    assert_eq!(request.kind, VerificationKind::PkGenerationProofs);
    assert_eq!(
        request
            .share_proofs
            .iter()
            .map(|party| party.sender_party_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 2])
    );
    assert!(!node.has_published().await?, "the key preceded C1");
    node.c1_passes(request).await?;

    // C5 proves exactly the roster's aggregation.
    let c5 = node.c5_request().await?;
    assert_eq!(c5.proof_request.keyshare_bytes, keyshares(&roster));
    assert_eq!(c5.proof_request.committee_h, COMMITTEE.values().h);
    assert_eq!(c5.nodes, ordered_nodes(&[0, 2]));
    assert!(!node.has_published().await?, "the key preceded its proof");

    // Folds of the roster complete the key. Others do not count toward it.
    node.fold(outsider.party_id).await?;
    node.fold(left_out.party_id).await?;
    node.fold(0).await?;
    assert!(
        !node.has_published().await?,
        "the key preceded the fold of every roster party"
    );
    node.fold(2).await?;
    node.c5_proved(&fhe, &roster).await?;

    let key = node
        .published()
        .await?
        .expect("the node did not publish the key");
    assert_eq!(key.e3_id, e3_id);
    assert_eq!(key.pubkey, aggregate_key(&fhe, &roster)?);
    assert_ne!(
        key.pubkey,
        aggregate_key(&fhe, &[first, left_out, second])?,
        "a keyshare outside the roster entered the key"
    );
    assert_eq!(key.nodes, ordered_nodes(&[0, 2]));
    assert_eq!(
        key.honest_committee_addresses,
        vec![node_address(0), node_address(2)]
    );
    assert_eq!(
        key.committee_addresses,
        (0..COMMITTEE.values().n as u64)
            .map(node_address)
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// A failover moves aggregation from one node to another while the dealers' keyshares reached the
/// two in different orders. Whichever node the chain accepts, users encrypt to the same key, for the
/// same roster.
#[actix::test]
async fn the_promoted_and_the_demoted_aggregator_publish_the_same_key() -> Result<()> {
    let (fhe, e3_id, bus, history) = setup()?;
    let all = dealers(&fhe, &e3_id, 0..3)?;
    let roster = [&all[0], &all[2]];
    let demoted = KeyNode::start(bus, history, &fhe, &e3_id, true);
    let fixture = EventFixture::new()?;
    let promoted = KeyNode::start(fixture.bus, fixture.history, &fhe, &e3_id, false);

    for dealer in &all {
        demoted.keyshare(dealer).await?;
    }
    for dealer in all.iter().rev() {
        promoted.keyshare(dealer).await?;
    }
    demoted.roster(&[0, 2]).await?;
    promoted.roster(&[0, 2]).await?;

    // The standby verifies nothing until the failover promotes it.
    let first_request = demoted.c1_request().await?;
    assert!(!promoted.has_published().await?);
    promoted.role(true).await?;
    demoted.role(false).await?;
    let promoted_request = promoted.c1_request().await?;

    for (node, request) in [(&demoted, first_request), (&promoted, promoted_request)] {
        node.c1_passes(request).await?;
        node.c5_request().await?;
        node.fold(0).await?;
        node.fold(2).await?;
        node.c5_proved(&fhe, &roster).await?;
    }

    let from_demoted = demoted
        .published()
        .await?
        .expect("the demoted aggregator did not publish the key");
    let from_promoted = promoted
        .published()
        .await?
        .expect("the promoted aggregator did not publish the key");
    assert_eq!(from_demoted.pubkey, aggregate_key(&fhe, &roster)?);
    assert_eq!(from_promoted.pubkey, from_demoted.pubkey);
    assert_eq!(from_promoted.pk_commitment, from_demoted.pk_commitment);
    assert_eq!(from_promoted.nodes, from_demoted.nodes);
    assert_eq!(
        from_promoted.honest_committee_addresses,
        from_demoted.honest_committee_addresses
    );
    assert_eq!(
        from_promoted.committee_addresses,
        from_demoted.committee_addresses
    );
    Ok(())
}

/// Only a roster of H distinct, ascending parties inside the committee can fix the key's dealers.
/// Anything else, such as a party ID beyond N, is an error and leaves no roster behind.
#[actix::test]
async fn an_invalid_roster_is_rejected() -> Result<()> {
    let committee = COMMITTEE.values();
    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(committee_state()).await?;

    for party_ids in [
        vec![0, committee.n as u64],
        vec![0],
        vec![0, 1, 2],
        vec![1, 0],
        vec![1, 1],
    ] {
        let result = aggregator.accept_dkg_roster(
            CommitmentRosterSelected {
                e3_id: e3_id.clone(),
                party_ids: party_ids.clone(),
            },
            test_ctx(EffectsEnabled::new()),
        );
        assert!(result.is_err(), "accepted the roster {party_ids:?}");
        assert_eq!(aggregator.recovery.try_get()?.selected_roster, None);
    }
    Ok(())
}

/// Once C1 verifies a roster's keyshares, a different roster cannot replace it: the C1 verdict and
/// the key proof would otherwise describe different dealers.
#[actix::test]
async fn a_replacement_roster_after_c1_started_is_ignored() -> Result<()> {
    let committee = COMMITTEE.values();
    let (mut aggregator, _history, e3_id) = build_public_key_aggregator(committee_state()).await?;
    let ec = test_ctx(EffectsEnabled::new());
    for party_id in 0..committee.n as u64 {
        aggregator.add_keyshare(
            ArcBytes::from_bytes(&[party_id as u8]),
            node_address(party_id).to_string(),
            party_id,
            Some(c1_proof_with_pk_commitment(&e3_id, [7; 32])),
            &ec,
        )?;
    }
    let roster = |party_ids: &[u64]| CommitmentRosterSelected {
        e3_id: e3_id.clone(),
        party_ids: party_ids.to_vec(),
    };

    aggregator.accept_dkg_roster(roster(&[0, 1]), ec.clone())?;
    aggregator.accept_dkg_roster(roster(&[1, 2]), ec)?;

    assert_eq!(
        aggregator.recovery.try_get()?.selected_roster,
        Some(BTreeSet::from([0, 1]))
    );
    let Some(PublicKeyAggregatorState::VerifyingC1 {
        submission_order, ..
    }) = aggregator.state.get()
    else {
        panic!("expected C1 verification of the first roster");
    };
    assert_eq!(
        submission_order
            .iter()
            .map(|(party_id, _, _)| *party_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    Ok(())
}
