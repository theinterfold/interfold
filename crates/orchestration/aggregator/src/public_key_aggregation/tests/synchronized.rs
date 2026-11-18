// SPDX-License-Identifier: LGPL-3.0-only

//! Native/signature/actor histories below disabled admission. Synthetic proof bodies here do not
//! establish proof validity; the production worker owns recursive verification.

use super::*;
use crate::workflow::publickey_aggregation::synchronized::{PublicationPlan, PublicationRecord};
use crate::PublicKeyRepositoryFactory;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{ensure, Context as _};
use e3_data::{RepositoriesFactory, SledDb, SledStore};
use e3_events::*;
use e3_request::canonical_key::CanonicalPublicKeys;
use fhe::{bfv::SecretKey, mbfv::PublicKeyShare};
use fhe_traits::Serialize as _;
use std::collections::BTreeMap;

const PROFILE: BfvProfile = BfvProfile::SyncDecInsecure64;
const SIZE: CiphernodesCommitteeSize = CiphernodesCommitteeSize::Minimum;

fn field(value: u128) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn proof(circuit: CircuitName, fields: Vec<[u8; 32]>) -> Proof {
    Proof::new(
        circuit,
        ArcBytes::from_bytes(&[1]),
        ArcBytes::from_bytes(&fields.concat()),
    )
}

fn ec() -> EventContext<Sequenced> {
    InterfoldEvent::<Unsequenced>::new_with_timestamp(
        EffectsEnabled::new().into(),
        None,
        1,
        None,
        EventSource::Local,
    )
    .into_sequenced(1)
    .get_ctx()
    .clone()
}

struct Fixture {
    signers: Vec<PrivateKeySigner>,
    selected: CiphernodeSelected,
    interfold: Address,
    keys: CanonicalPublicKeys,
    plan: PublicationPlan,
    shares: BTreeMap<u32, KeyshareCreated>,
    peers: BTreeMap<u32, SynchronizedDkgProofPublished>,
    consents: Vec<SynchronizedDkgConsentPublished>,
    c5: Proof,
    publication: Proof,
}

fn fixture() -> Result<Fixture> {
    let config = e3_zk_config::synchronized::Configs::for_profile(PROFILE, SIZE)?;
    let mut signers = (1..=3)
        .map(|id| format!("{id:064x}").parse())
        .collect::<Result<Vec<PrivateKeySigner>, _>>()?;
    signers.sort_by_key(|s| s.address());
    let members = signers.iter().map(|s| s.address()).collect::<Vec<_>>();
    let interfold = Address::repeat_byte(7);
    let selected = CiphernodeSelected {
        e3_id: E3id::new("2459", 1),
        threshold_m: 1,
        threshold_n: 3,
        params_profile: PROFILE,
        crypto_config_id: PROFILE.crypto_config_id(SIZE)?.0,
        params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&config.threshold)),
        party_id: 1,
        committee: members.iter().map(ToString::to_string).collect(),
        ..Default::default()
    };
    let context = SynchronizedProofContext {
        party_id: 1,
        setup: e3_committee_hash::DkgSetupContext {
            interfold_address: interfold,
            committee_hash: e3_committee_hash::hash_committee_addresses(&members),
            crypto_config_id: selected.crypto_config_id.into(),
        },
    };
    let binding = e3_zk_prover::synchronized::request_binding(&config, &context, &selected.e3_id)?;
    let crp = e3_fhe_params::create_deterministic_crp_from_default_seed(&config.threshold);
    let mut shares = BTreeMap::new();
    let mut commitments = Vec::new();
    for id in [0u32, 2] {
        let mut rng = rand::rng();
        let sk = SecretKey::random(&config.threshold, &mut rng);
        let native = PublicKeyShare::new(&sk, crp.clone(), &mut rng)?;
        let bytes = ArcBytes::from_bytes(&native.to_bytes());
        let commitment = e3_zk_witness::compute_pk_commitment_from_keyshare_bytes(
            &bytes,
            &config.threshold,
            &crp,
        )?;
        commitments.push(commitment);
        let c1 = proof(
            CircuitName::PkGeneration,
            vec![
                field(binding[0]),
                field(binding[1]),
                field(id as u128),
                field(10 + id as u128),
                commitment,
            ],
        );
        shares.insert(
            id,
            KeyshareCreated {
                e3_id: selected.e3_id.clone(),
                party_id: id as u64,
                node: members[id as usize].to_string(),
                pubkey: bytes,
                signed_pk_generation_proof: Some(SignedProofPayload::sign(
                    ProofPayload {
                        e3_id: selected.e3_id.clone(),
                        proof_type: ProofType::C1PkGeneration,
                        proof: c1,
                    },
                    &signers[id as usize],
                )?),
            },
        );
    }
    let mut peers = BTreeMap::new();
    let mut local = None;
    for id in 0..3 {
        let mut context = context.clone();
        context.party_id = id;
        let setup = SynchronizedSetupAnchors {
            binding,
            recipient: id,
            dealers: vec![0, 2],
            threshold_keys: commitments.clone(),
            dealer_batch: field(12),
            sk_commitment: field(20 + id as u128),
            key_bundle: field(30 + id as u128),
        };
        let mut fields = vec![
            field(1),
            field(binding[0]),
            field(binding[1]),
            field(id as u128),
            field(0),
            field(2),
        ];
        fields.extend(&commitments);
        fields.extend([setup.dealer_batch, setup.sk_commitment, setup.key_bundle]);
        let result = proof(CircuitName::NodesFold, fields);
        if id == 1 {
            local = Some(SynchronizedRecipientProofReady {
                e3_id: selected.e3_id.clone(),
                context,
                proof: result,
                setup,
            });
        } else {
            peers.insert(
                id,
                SynchronizedDkgProofPublished::sign(
                    selected.e3_id.clone(),
                    context,
                    SynchronizedDkgProofRole::Recipient,
                    result,
                    &signers[id as usize],
                )?,
            );
        }
    }
    let plan = PublicationPlan::new(
        selected.clone(),
        TypedEvent::new(local.unwrap(), ec()),
        interfold,
    )?;
    let native = plan.c5_request(&shares)?;
    let pk = plan.pk_commitment(&native)?;
    let mut c5 = commitments.clone();
    c5.push(pk);
    let c5 = proof(CircuitName::PkAggregation, c5);
    let mut fields = vec![
        field(1),
        field(2),
        field(binding[0]),
        field(binding[1]),
        field(0),
        field(2),
        field(12),
    ];
    fields.extend(&commitments);
    fields.extend([field(20), field(22), field(30), field(32), pk]);
    let publication = proof(CircuitName::DkgAggregator, fields);
    let frozen = SynchronizedDkgContext {
        registry: Address::repeat_byte(8),
        verifying_contract: interfold,
        crypto_config_id: selected.crypto_config_id,
    };
    let keys = CanonicalPublicKeys::default();
    keys.remember_synchronized_context(selected.e3_id.clone(), frozen)?;
    let consents = [0, 2]
        .into_iter()
        .map(|id| {
            Ok(SynchronizedDkgConsentPublished {
                attestation: SignedSynchronizedDkgAttestation::sign(
                    SynchronizedDkgAttestationPayload {
                        e3_id: selected.e3_id.clone(),
                        context: frozen,
                        setup_binding: plan
                            .local
                            .context
                            .setup
                            .hash(1, selected.e3_id.clone().try_into()?)
                            .0,
                        roster_hash: synchronized_dkg_roster_hash(&[0, 2]),
                        dealer_batch: field(12),
                        pk_commitment: pk,
                        party_id: id,
                        sk_agg_commit: field(20 + id as u128),
                        key_bundle_commit: field(30 + id as u128),
                    },
                    &signers[id as usize],
                )?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(Fixture {
        signers,
        selected,
        interfold,
        keys,
        plan,
        shares,
        peers,
        consents,
        c5,
        publication,
    })
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct Drive(InterfoldEventData, EventContext<Sequenced>);
impl Handler<Drive> for PublicKeyAggregator {
    type Result = Result<()>;
    fn handle(&mut self, msg: Drive, ctx: &mut Self::Context) -> Self::Result {
        self.route_synchronized_publication_definition(&msg.0, &msg.1, ctx)
    }
}

#[derive(Message)]
#[rtype(result = "Option<PublicationRecord>")]
struct Checkpoint;
impl Handler<Checkpoint> for PublicKeyAggregator {
    type Result = MessageResult<Checkpoint>;
    fn handle(&mut self, _: Checkpoint, _: &mut Self::Context) -> Self::Result {
        MessageResult(self.synchronized.as_ref().and_then(|r| r.record.clone()))
    }
}

struct FlushGate(bool, u32);
impl Actor for FlushGate {
    type Context = Context<Self>;
}
impl Handler<Flush> for FlushGate {
    type Result = Result<()>;
    fn handle(&mut self, _: Flush, _: &mut Self::Context) -> Self::Result {
        self.1 += 1;
        ensure!(self.0, "injected publication flush failure {}", self.1);
        Ok(())
    }
}
#[derive(Message)]
#[rtype(result = "u32")]
struct AllowFlush(bool);
impl Handler<AllowFlush> for FlushGate {
    type Result = u32;
    fn handle(&mut self, msg: AllowFlush, _: &mut Self::Context) -> Self::Result {
        self.0 = msg.0;
        self.1
    }
}

async fn actor(
    f: &Fixture,
    store: &DataStore,
    active: bool,
    restored: bool,
) -> Result<(
    Addr<PublicKeyAggregator>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    actor_with_history(f, store, active, restored, &[]).await
}

async fn actor_with_history(
    f: &Fixture,
    store: &DataStore,
    active: bool,
    restored: bool,
    events: &[InterfoldEvent],
) -> Result<(
    Addr<PublicKeyAggregator>,
    Addr<HistoryCollector<InterfoldEvent>>,
)> {
    let initial = PublicKeyAggregatorState::init(
        3,
        1,
        f.selected.seed,
        f.selected
            .committee
            .iter()
            .enumerate()
            .map(|(id, n)| (id as u64, n.clone()))
            .collect(),
    );
    let (mut actor, history, _) = build_public_key_aggregator(initial).await?;
    actor.e3_id = f.selected.e3_id.clone();
    actor.params_profile = PROFILE;
    actor.effects_enabled = false;
    actor.is_aggregator = active;
    let repo = store
        .repositories()
        .synchronized_publication(&f.selected.e3_id);
    actor = actor.with_synchronized_publication(
        repo.clone(),
        f.keys.clone(),
        f.interfold,
        Some(TypedEvent::new(f.selected.clone(), ec())),
    );
    if restored {
        actor
            .recover_synchronized_publication(
                &crate::test_support::history_reader(events)?,
                &e3_request::E3Meta::from(&f.selected),
            )
            .await?;
    }
    Ok((actor.start(), history))
}

async fn drive(
    node: &Addr<PublicKeyAggregator>,
    data: impl Into<InterfoldEventData>,
) -> Result<()> {
    node.send(Drive(data.into(), ec())).await??;
    node.send(Checkpoint).await?;
    Ok(())
}

async fn requests(history: &Addr<HistoryCollector<InterfoldEvent>>) -> Result<Vec<ComputeRequest>> {
    Ok(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .into_iter()
        .filter_map(|event| match event.into_data() {
            InterfoldEventData::ComputeRequest(request) => Some(request),
            _ => None,
        })
        .collect())
}

async fn seed(node: &Addr<PublicKeyAggregator>, f: &Fixture) -> Result<()> {
    // Deliberately deliver authenticated peers before the local verdict fixes the batch.
    for share in f.shares.values() {
        drive(node, share.clone()).await?;
    }
    for peer in f.peers.values() {
        drive(node, peer.clone()).await?;
    }
    drive(node, (*f.plan.local).clone()).await
}

#[actix::test]
async fn synchronized_publication_wrong_domain_cannot_replace_valid_consent() -> Result<()> {
    let f = fixture()?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let (node, _) = actor(&f, &store, true, false).await?;
    seed(&node, &f).await?;
    drive(&node, f.consents[0].clone()).await?;
    let mut payload = f.consents[0].attestation.payload.clone();
    payload.context.registry = Address::repeat_byte(99);
    let bad = SynchronizedDkgConsentPublished {
        attestation: SignedSynchronizedDkgAttestation::sign(payload, &f.signers[0])?,
    };
    assert!(node.send(Drive(bad.clone().into(), ec())).await?.is_err());
    assert_eq!(
        node.send(Checkpoint).await?.unwrap().consents[&0],
        f.consents[0].attestation
    );
    node.send(Die).await?;
    let replayed = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        bad.into(),
        None,
        2,
        None,
        EventSource::Net,
    )
    .into_sequenced(2);
    let (reopened, _) = actor_with_history(&f, &store, true, true, &[replayed]).await?;
    assert_eq!(
        reopened.send(Checkpoint).await?.unwrap().consents[&0],
        f.consents[0].attestation
    );
    reopened.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_publication_provisional_recipient_cannot_erase_early_consent() -> Result<()> {
    let f = fixture()?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let (node, _) = actor(&f, &store, true, false).await?;
    seed(&node, &f).await?;
    drive(&node, f.consents[0].clone()).await?;
    let mut peer = f.peers[&0].clone();
    let mut signals = peer.proof.public_signals.to_vec();
    let last = signals.len() - 1;
    signals[last] ^= 1;
    peer.proof.public_signals = ArcBytes::from_bytes(&signals);
    peer = SynchronizedDkgProofPublished::sign(
        peer.e3_id,
        peer.context,
        peer.role,
        peer.proof,
        &f.signers[0],
    )?;
    drive(&node, peer).await?;
    assert_eq!(
        node.send(Checkpoint).await?.unwrap().consents[&0],
        f.consents[0].attestation
    );
    node.send(Die).await?;
    let (node, history) = actor(&f, &store, true, true).await?;
    assert_eq!(
        node.send(Checkpoint).await?.unwrap().consents[&0],
        f.consents[0].attestation
    );
    drive(&node, f.peers[&0].clone()).await?;
    drive(&node, f.consents[1].clone()).await?;
    drive(&node, EffectsEnabled::new()).await?;
    let c5 = requests(&history).await?.pop().unwrap();
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::PkAggregation(PkAggregationProofResponse {
                proof: f.c5.clone(),
            }),
            c5.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    let wrapper = requests(&history).await?.pop().unwrap();
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Publication {
                proof: f.publication.clone(),
            }),
            wrapper.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .iter()
        .any(|e| matches!(
            e.get_data(),
            InterfoldEventData::SynchronizedDkgPublicationReady(_)
        )));
    node.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_publication_pending_consent_is_not_output_authority() -> Result<()> {
    let f = fixture()?;
    let context = f.keys.synchronized_context(&f.selected.e3_id).unwrap();
    let mut record = PublicationRecord::new(f.selected.clone(), ec());
    record.intake(
        &(*f.plan.local).clone().into(),
        &ec(),
        f.interfold,
        Some(context),
    )?;
    for share in f.shares.values() {
        record.intake(&share.clone().into(), &ec(), f.interfold, Some(context))?;
    }
    for peer in f.peers.values() {
        record.intake(&peer.clone().into(), &ec(), f.interfold, Some(context))?;
    }
    let mut payload = f.consents[0].attestation.payload.clone();
    payload.key_bundle_commit[31] ^= 1;
    let pending = SynchronizedDkgConsentPublished {
        attestation: SignedSynchronizedDkgAttestation::sign(payload, &f.signers[0])?,
    };
    record.intake(&pending.into(), &ec(), f.interfold, Some(context))?;
    record.intake(
        &f.consents[1].clone().into(),
        &ec(),
        f.interfold,
        Some(context),
    )?;
    record.prune_consents(Some(context))?;
    assert_eq!(
        record.consents.len(),
        2,
        "provisional anchors cannot discard pending evidence"
    );
    record.started = true;
    record.c5 = Some(f.c5.clone());
    record.proof = Some(f.publication.clone());
    record.prune_consents(Some(context))?;
    assert!(!record.consents.contains_key(&0));
    assert!(record.output(context)?.is_none());
    record.intake(
        &f.consents[0].clone().into(),
        &ec(),
        f.interfold,
        Some(context),
    )?;
    assert!(record.output(context)?.is_some());
    Ok(())
}

#[actix::test]
async fn synchronized_publication_missing_outcomes_redrive_both_phases() -> Result<()> {
    tokio::time::pause();
    for wrapper in [false, true] {
        let f = fixture()?;
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let (node, history) = actor(&f, &store, true, false).await?;
        seed(&node, &f).await?;
        drive(&node, EffectsEnabled::new()).await?;
        if wrapper {
            let c5 = requests(&history).await?.pop().unwrap();
            drive(
                &node,
                ComputeResponse::zk(
                    ZkResponse::PkAggregation(PkAggregationProofResponse {
                        proof: f.c5.clone(),
                    }),
                    c5.correlation_id,
                    f.selected.e3_id.clone(),
                ),
            )
            .await?;
        }
        let before = requests(&history).await?;
        tokio::time::advance(std::time::Duration::from_secs(61)).await;
        node.send(Checkpoint).await?;
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        node.send(Checkpoint).await?;
        let after = requests(&history).await?;
        assert_eq!(after.len(), before.len() + 1);
        assert_eq!(
            after.last().unwrap().request,
            before.last().unwrap().request
        );
        assert_ne!(
            after.last().unwrap().correlation_id,
            before.last().unwrap().correlation_id
        );
        drive(
            &node,
            E3StageChanged {
                e3_id: f.selected.e3_id.clone(),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage: E3Stage::KeyPublished,
            },
        )
        .await?;
        tokio::time::advance(std::time::Duration::from_secs(120)).await;
        node.send(Checkpoint).await?;
        assert_eq!(requests(&history).await?.len(), after.len());
        node.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_publication_rejects_substitutions_without_reserving_valid_slots() -> Result<()>
{
    tokio::time::pause();
    let f = fixture()?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let (node, history) = actor(&f, &store, true, false).await?;
    drive(&node, (*f.plan.local).clone()).await?;
    let mut peer = f.peers[&0].clone();
    peer.signature = ArcBytes::from_bytes(&[0; 65]);
    assert!(node.send(Drive(peer.into(), ec())).await?.is_err());
    let mut share = f.shares[&0].clone();
    share.pubkey = f.shares[&2].pubkey.clone();
    assert!(node.send(Drive(share.into(), ec())).await?.is_err());
    seed(&node, &f).await?;
    for mutation in [0, 1, 3] {
        let mut payload = f.consents[0].attestation.payload.clone();
        match mutation {
            0 => payload.pk_commitment[31] ^= 1,
            1 => payload.dealer_batch[31] ^= 1,
            2 => payload.key_bundle_commit[31] ^= 1,
            _ => payload.roster_hash[31] ^= 1,
        }
        let candidate = SynchronizedDkgConsentPublished {
            attestation: SignedSynchronizedDkgAttestation::sign(payload, &f.signers[0])?,
        };
        assert!(node.send(Drive(candidate.into(), ec())).await?.is_err());
        assert!(node.send(Checkpoint).await?.unwrap().consents.is_empty());
    }
    assert!(requests(&history).await?.is_empty());
    drive(&node, EffectsEnabled::new()).await?;
    let req = requests(&history).await?.pop().context("missing C5 work")?;
    let wrong = ComputeResponse::zk(
        ZkResponse::PkAggregation(PkAggregationProofResponse {
            proof: f.c5.clone(),
        }),
        CorrelationId::new(),
        f.selected.e3_id.clone(),
    );
    drive(&node, wrong).await?;
    let mut unrelated = req.clone();
    unrelated.correlation_id = CorrelationId::new();
    drive(
        &node,
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("other actor".into())),
            unrelated,
        ),
    )
    .await?;
    assert!(node.send(Checkpoint).await?.unwrap().c5.is_none());
    let correct = ComputeResponse::zk(
        ZkResponse::PkAggregation(PkAggregationProofResponse {
            proof: f.c5.clone(),
        }),
        req.correlation_id,
        f.selected.e3_id.clone(),
    );
    let net_ec = InterfoldEvent::<Unsequenced>::new_with_timestamp(
        correct.clone().into(),
        None,
        2,
        None,
        EventSource::Net,
    )
    .into_sequenced(2)
    .get_ctx()
    .clone();
    assert!(node
        .send(Drive(correct.clone().into(), net_ec))
        .await?
        .is_err());
    drive(&node, correct).await?;
    assert!(matches!(
        requests(&history).await?.last().unwrap().request,
        ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(_))
    ));
    let stale = requests(&history).await?.pop().unwrap();
    for byte in 2..=5 {
        let mut replacement = f.peers[&0].proof.clone();
        replacement.data = ArcBytes::from_bytes(&[byte]);
        drive(
            &node,
            SynchronizedDkgProofPublished::sign(
                f.selected.e3_id.clone(),
                f.peers[&0].context.clone(),
                SynchronizedDkgProofRole::Recipient,
                replacement,
                &f.signers[0],
            )?,
        )
        .await?;
    }
    assert_eq!(requests(&history).await?.len(), 2);
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    node.send(Checkpoint).await?;
    let current = requests(&history).await?.pop().unwrap();
    assert_ne!(stale.correlation_id, current.correlation_id);
    assert_ne!(stale.request, current.request);
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Publication {
                proof: f.publication.clone(),
            }),
            stale.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    assert!(node.send(Checkpoint).await?.unwrap().proof.is_none());
    node.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_publication_retries_local_worker_failures_without_restart() -> Result<()> {
    tokio::time::pause();
    for wrapper in [false, true] {
        for terminate in [false, true] {
            let f = fixture()?;
            let store = DataStore::from_in_mem(&InMemStore::new(false).start());
            let (node, history) = actor(&f, &store, false, false).await?;
            seed(&node, &f).await?;
            drive(&node, EffectsEnabled::new()).await?;
            assert!(requests(&history).await?.is_empty());
            drive(
                &node,
                AggregatorChanged {
                    e3_id: f.selected.e3_id.clone(),
                    active_party_id: Some(1),
                    is_aggregator: true,
                },
            )
            .await?;
            let mut first = requests(&history).await?.pop().unwrap();
            if wrapper {
                drive(
                    &node,
                    ComputeResponse::zk(
                        ZkResponse::PkAggregation(PkAggregationProofResponse {
                            proof: f.c5.clone(),
                        }),
                        first.correlation_id,
                        f.selected.e3_id.clone(),
                    ),
                )
                .await?;
                first = requests(&history).await?.pop().unwrap();
            }
            // The recorded started owner continues its existing work after demotion.
            drive(
                &node,
                AggregatorChanged {
                    e3_id: f.selected.e3_id.clone(),
                    active_party_id: Some(0),
                    is_aggregator: false,
                },
            )
            .await?;
            let count = requests(&history).await?.len();
            let failure =
                |kind| ComputeRequestError::new(ComputeRequestErrorKind::Zk(kind), first.clone());
            drive(&node, failure(ZkError::InvalidParams("bad input".into()))).await?;
            tokio::time::advance(std::time::Duration::from_secs(35)).await;
            node.send(Checkpoint).await?;
            assert_eq!(requests(&history).await?.len(), count);
            let transient = failure(ZkError::ProofGenerationFailed(
                "local VK unavailable".into(),
            ));
            drive(&node, transient.clone()).await?;
            drive(&node, transient).await?; // one coalesced retry, not two
            assert_eq!(requests(&history).await?.len(), count);
            if terminate {
                drive(
                    &node,
                    E3StageChanged {
                        e3_id: f.selected.e3_id.clone(),
                        previous_stage: E3Stage::CommitteeFinalized,
                        new_stage: E3Stage::KeyPublished,
                    },
                )
                .await?;
            }
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            node.send(Checkpoint).await?;
            let after = requests(&history).await?;
            assert_eq!(after.len(), count + usize::from(!terminate));
            if !terminate {
                let retry = after.last().unwrap();
                assert_eq!(retry.request, first.request);
                assert_ne!(retry.correlation_id, first.correlation_id);
                let response = if wrapper {
                    ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Publication {
                        proof: f.publication.clone(),
                    })
                } else {
                    ZkResponse::PkAggregation(PkAggregationProofResponse {
                        proof: f.c5.clone(),
                    })
                };
                drive(
                    &node,
                    ComputeResponse::zk(response, retry.correlation_id, f.selected.e3_id.clone()),
                )
                .await?;
                let saved = node.send(Checkpoint).await?.unwrap();
                assert!(if wrapper {
                    saved.proof.is_some()
                } else {
                    saved.c5.is_some()
                });
            }
            node.send(Die).await?;
        }
    }
    Ok(())
}

#[actix::test]
async fn synchronized_publication_retains_corrected_preplan_c1_with_the_same_native_bytes(
) -> Result<()> {
    let f = fixture()?;
    let corrected = f.shares[&0].clone();
    let mut invalid = corrected.clone();
    let mut payload = invalid
        .signed_pk_generation_proof
        .as_ref()
        .unwrap()
        .payload
        .clone();
    let mut signals = payload.proof.public_signals.to_vec();
    signals[31] ^= 1;
    payload.proof.public_signals = ArcBytes::from_bytes(&signals);
    invalid.signed_pk_generation_proof = Some(SignedProofPayload::sign(payload, &f.signers[0])?);
    assert_eq!(invalid.pubkey, corrected.pubkey);
    assert!(f.plan.keyshare(&invalid).is_err());
    for corrected_first in [false, true] {
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let (node, history) = actor(&f, &store, true, false).await?;
        if corrected_first {
            drive(&node, corrected.clone()).await?;
        }
        let error = node
            .send(Drive(invalid.clone().into(), ec()))
            .await?
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical request or native share"),
            "{error:#}"
        );
        if !corrected_first {
            drive(&node, corrected.clone()).await?;
        }
        drive(&node, f.shares[&2].clone()).await?;
        drive(&node, (*f.plan.local).clone()).await?;
        let saved = node.send(Checkpoint).await?.unwrap();
        assert_eq!(
            saved.shares.get(&0),
            Some(&corrected),
            "corrected first: {corrected_first}"
        );
        drive(&node, EffectsEnabled::new()).await?;
        let request = requests(&history)
            .await?
            .pop()
            .context("corrected C1 did not enable C5")?;
        assert_eq!(
            request.request,
            ComputeRequestKind::Zk(ZkRequest::PkAggregation(f.plan.c5_request(&f.shares)?))
        );
        node.send(Die).await?;
    }
    Ok(())
}

#[actix::test]
async fn synchronized_publication_standby_promotion_demotion_reopen_and_all_h_consent() -> Result<()>
{
    let f = fixture()?;
    let dir = tempfile::tempdir()?;
    let (bus, ..) = get_common_setup(Some(BfvPreset::InsecureThreshold64.into()))?;
    let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
    let (node, history) = actor(&f, &store, false, false).await?;
    let mut early = f.consents[0].attestation.payload.clone();
    early.context.registry = Address::repeat_byte(99);
    assert!(node
        .send(Drive(
            SynchronizedDkgConsentPublished {
                attestation: SignedSynchronizedDkgAttestation::sign(early, &f.signers[0])?,
            }
            .into(),
            ec()
        ))
        .await?
        .is_err());
    seed(&node, &f).await?;
    assert!(node.send(Checkpoint).await?.unwrap().consents.is_empty());
    drive(&node, EffectsEnabled::new()).await?;
    assert!(requests(&history).await?.is_empty());
    drive(
        &node,
        AggregatorChanged {
            e3_id: f.selected.e3_id.clone(),
            active_party_id: Some(1),
            is_aggregator: true,
        },
    )
    .await?;
    let first = requests(&history)
        .await?
        .pop()
        .context("promotion did not start C5")?;
    drive(
        &node,
        AggregatorChanged {
            e3_id: f.selected.e3_id.clone(),
            active_party_id: Some(0),
            is_aggregator: false,
        },
    )
    .await?;
    assert!(node.send(Checkpoint).await?.unwrap().started);
    node.send(Die).await?;
    drop(node);
    store.shutdown().await?;
    drop(store);
    SledDb::close_all_connections();
    let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
    let (node, history) = actor(&f, &store, false, true).await?;
    assert!(requests(&history).await?.is_empty());
    drive(&node, EffectsEnabled::new()).await?;
    let resumed = requests(&history)
        .await?
        .pop()
        .context("demoted owner did not resume")?;
    assert_eq!(first.request, resumed.request);
    assert_ne!(first.correlation_id, resumed.correlation_id);
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::PkAggregation(PkAggregationProofResponse {
                proof: f.c5.clone(),
            }),
            resumed.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    let wrapper = requests(&history).await?.pop().unwrap();
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Publication {
                proof: f.publication.clone(),
            }),
            wrapper.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    drive(&node, f.consents[0].clone()).await?;
    ensure!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .iter()
        .all(|e| !matches!(
            e.get_data(),
            InterfoldEventData::SynchronizedDkgPublicationReady(_)
        )));
    drive(&node, f.consents[1].clone()).await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let ready = events
        .iter()
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::SynchronizedDkgPublicationReady(output) => Some(output),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(ready.len(), 1);
    assert_eq!(
        ready[0]
            .consents
            .iter()
            .map(|s| s.payload.party_id)
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
    let original = ready[0].clone();
    node.send(Die).await?;
    drop(node);
    store.shutdown().await?;
    drop(store);
    SledDb::close_all_connections();
    let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_path_buf())?);
    let (node, history) = actor(&f, &store, false, true).await?;
    drive(&node, EffectsEnabled::new()).await?;
    assert!(requests(&history).await?.is_empty());
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert!(events
        .iter()
        .any(|e| e.get_data() == &InterfoldEventData::from(original.clone())));
    drive(
        &node,
        E3StageChanged {
            e3_id: f.selected.e3_id.clone(),
            previous_stage: E3Stage::CommitteeFinalized,
            new_stage: E3Stage::KeyPublished,
        },
    )
    .await?;
    node.send(Drive(
        E3RequestComplete {
            e3_id: f.selected.e3_id.clone(),
        }
        .into(),
        ec(),
    ))
    .await??;
    assert!(node.send(Checkpoint).await.is_err());
    assert!(store
        .repositories()
        .synchronized_publication(&f.selected.e3_id)
        .read()
        .await?
        .is_none());
    drop(node);
    store.shutdown().await?;
    drop(store);
    SledDb::close_all_connections();
    Ok(())
}

#[actix::test]
async fn synchronized_publication_final_consent_flush_failure_preserves_accepted_progress(
) -> Result<()> {
    tokio::time::pause();
    let f = fixture()?;
    let flush = FlushGate(true, 0).start();
    let store = DataStore::from_in_mem(&InMemStore::new(false).start())
        .with_flush_recipient(flush.clone().recipient());
    let (node, history) = actor(&f, &store, true, false).await?;
    seed(&node, &f).await?;
    drive(&node, EffectsEnabled::new()).await?;
    let c5 = requests(&history).await?.pop().context("missing C5 work")?;
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::PkAggregation(PkAggregationProofResponse {
                proof: f.c5.clone(),
            }),
            c5.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    let wrapper = requests(&history)
        .await?
        .pop()
        .context("missing publication work")?;
    drive(
        &node,
        ComputeResponse::zk(
            ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Publication {
                proof: f.publication.clone(),
            }),
            wrapper.correlation_id,
            f.selected.e3_id.clone(),
        ),
    )
    .await?;
    drive(&node, f.consents[0].clone()).await?;
    let accepted = node.send(Checkpoint).await?.unwrap();
    assert!(accepted.plan.is_some());
    assert_eq!(accepted.proof, Some(f.publication.clone()));
    assert_eq!(
        accepted.consents.keys().copied().collect::<Vec<_>>(),
        vec![0]
    );
    flush.send(AllowFlush(false)).await?;
    drive(&node, f.consents[1].clone()).await?;
    let pending = node.send(Checkpoint).await?.unwrap();
    assert_eq!(pending.plan, accepted.plan);
    assert_eq!(pending.proof, accepted.proof);
    assert_eq!(pending.consents.len(), 2);
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .iter()
        .all(|event| !matches!(
            event.get_data(),
            InterfoldEventData::SynchronizedDkgPublicationReady(_)
        )));
    flush.send(AllowFlush(true)).await?;
    // No redelivery or explicit resume: the owner must retry the retained final consent.
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    node.send(Checkpoint).await?;
    tokio::time::advance(std::time::Duration::from_secs(35)).await;
    node.send(Checkpoint).await?;
    let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let ready = events
        .iter()
        .filter_map(|event| match event.get_data() {
            InterfoldEventData::SynchronizedDkgPublicationReady(output) => Some(output),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].proof, f.publication);
    assert_eq!(
        ready[0].consents,
        f.consents
            .into_iter()
            .map(|message| message.attestation)
            .collect::<Vec<_>>()
    );
    assert_eq!(requests(&history).await?.len(), 2);
    node.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_publication_flush_retry_preserves_workers_roles_and_termination() -> Result<()>
{
    tokio::time::pause();
    for active in [false, true] {
        for terminate in [false, true] {
            let f = fixture()?;
            let flush = FlushGate(true, 0).start();
            let store = DataStore::from_in_mem(&InMemStore::new(false).start())
                .with_flush_recipient(flush.clone().recipient());
            let (node, history) = actor(&f, &store, active, false).await?;
            seed(&node, &f).await?;
            drive(&node, EffectsEnabled::new()).await?;
            let started = requests(&history).await?;
            assert_eq!(started.len(), usize::from(active));
            flush.send(AllowFlush(false)).await?;
            drive(&node, f.consents[0].clone()).await?;
            if active {
                drive(
                    &node,
                    AggregatorChanged {
                        e3_id: f.selected.e3_id.clone(),
                        active_party_id: Some(0),
                        is_aggregator: false,
                    },
                )
                .await?;
            }
            let attempts = flush.send(AllowFlush(false)).await?;
            if terminate {
                drive(
                    &node,
                    E3StageChanged {
                        e3_id: f.selected.e3_id.clone(),
                        previous_stage: E3Stage::CommitteeFinalized,
                        new_stage: E3Stage::KeyPublished,
                    },
                )
                .await?;
            }
            flush.send(AllowFlush(true)).await?;
            tokio::time::advance(std::time::Duration::from_secs(2)).await;
            let record = node.send(Checkpoint).await?.unwrap();
            assert_eq!(
                flush.send(AllowFlush(true)).await?,
                attempts + u32::from(!terminate),
                "active: {active}, terminated: {terminate}"
            );
            assert_eq!(record.consents.len(), 1);
            assert_eq!(record.started, active);
            // Neither a standby nor a demoted owner may spuriously start another C5 attempt.
            assert_eq!(requests(&history).await?.len(), started.len());
            if active && !terminate {
                drive(
                    &node,
                    ComputeResponse::zk(
                        ZkResponse::PkAggregation(PkAggregationProofResponse {
                            proof: f.c5.clone(),
                        }),
                        started[0].correlation_id,
                        f.selected.e3_id.clone(),
                    ),
                )
                .await?;
                assert_eq!(node.send(Checkpoint).await?.unwrap().c5, Some(f.c5));
                assert_eq!(requests(&history).await?.len(), 2);
            }
            node.send(Die).await?;
        }
    }
    Ok(())
}

#[actix::test]
async fn synchronized_publication_disabled_route_is_independent_of_storage_failure() -> Result<()> {
    let f = fixture()?;
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let (node, history) = actor(&f, &store, true, false).await?;
    node.send(
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            (*f.plan.local).clone().into(),
            None,
            1,
            None,
            EventSource::Local,
        )
        .into_sequenced(1),
    )
    .await?;
    assert!(node.send(Checkpoint).await?.unwrap().plan.is_none());
    assert!(requests(&history).await?.is_empty());
    // The same healthy store works below admission; a flush failure cannot mask this guard.
    seed(&node, &f).await?;
    drive(&node, EffectsEnabled::new()).await?;
    assert!(node.send(Checkpoint).await?.unwrap().plan.is_some());
    assert_eq!(requests(&history).await?.len(), 1);
    node.send(Die).await?;
    Ok(())
}

#[actix::test]
async fn synchronized_publication_failed_flush_emits_no_work() -> Result<()> {
    tokio::time::pause();
    let f = fixture()?;
    let flush = FlushGate(false, 0).start();
    let store = DataStore::from_in_mem(&InMemStore::new(false).start())
        .with_flush_recipient(flush.clone().recipient());
    let (node, history) = actor(&f, &store, true, false).await?;
    seed(&node, &f).await?;
    let attempts = flush.send(AllowFlush(false)).await?;
    tokio::time::advance(std::time::Duration::from_secs(35)).await;
    node.send(Checkpoint).await?;
    assert_eq!(flush.send(AllowFlush(false)).await?, attempts);
    drive(&node, EffectsEnabled::new()).await?;
    let retained = node.send(Checkpoint).await?.unwrap();
    assert!(retained.plan.is_some());
    assert_eq!(retained.shares.len(), 2);
    assert_eq!(retained.recipients.len(), 2);
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .iter()
        .all(|event| !matches!(
            event.get_data(),
            InterfoldEventData::ComputeRequest(_)
                | InterfoldEventData::AggregationInputsReady(_)
                | InterfoldEventData::SynchronizedDkgPublicationReady(_)
        )));
    node.send(Die).await?;
    Ok(())
}
