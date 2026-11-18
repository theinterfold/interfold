// SPDX-License-Identifier: LGPL-3.0-only

//! Below-admission actor tests. Synthetic proofs exercise authentication/recovery, not ZK validity.

use super::*;
use actix::{Actor, ActorContext, Handler, Message};
use alloy::signers::local::PrivateKeySigner;
use e3_event_system::test_support::EventFixture;
use e3_fhe_params::BfvProfile;
use e3_utils::ArcBytes;

fn ec(data: impl Into<InterfoldEventData>) -> EventContext<Sequenced> {
    EventContext::<Unsequenced>::from(data.into()).sequence(1)
}

fn field(value: u32) -> [u8; 32] {
    let mut field = [0; 32];
    field[28..].copy_from_slice(&value.to_be_bytes());
    field
}

struct Fixture {
    actor: NodeProofAggregator,
    plan: RecipientPlan,
    leaves: Vec<DKGInnerProofReady>,
    dealers: Vec<SynchronizedDkgProofPublished>,
    signers: Vec<PrivateKeySigner>,
}

fn fixture(bus: &BusHandle, recipient: u32) -> Result<Fixture> {
    let profile = BfvProfile::SyncDecInsecure64;
    let size = CiphernodesCommitteeSize::Minimum;
    let config = Configs::for_profile(profile, size)?;
    let mut signers = (1..=3)
        .map(|id| format!("{id:064x}").parse())
        .collect::<Result<Vec<PrivateKeySigner>, _>>()?;
    signers.sort_by_key(|signer| signer.address());
    let members = signers
        .iter()
        .map(|signer| signer.address())
        .collect::<Vec<_>>();
    let id = E3id::new("2459", 1);
    let context = SynchronizedProofContext {
        party_id: recipient,
        setup: e3_committee_hash::DkgSetupContext {
            interfold_address: Address::repeat_byte(3),
            committee_hash: e3_committee_hash::hash_committee_addresses(&members),
            crypto_config_id: profile.crypto_config_id(size)?,
        },
    };
    let binding = crate::synchronized::request_binding(&config, &context, &id)?;
    let make = |circuit: CircuitName, owner: u32| {
        let mut fields = vec![
            [0; 32];
            config.public_inputs(circuit).unwrap()
                + config.public_outputs(circuit).unwrap()
        ];
        if circuit == CircuitName::PkBfv {
            fields[0] = field(11);
        } else {
            fields[0][16..].copy_from_slice(&binding[0].to_be_bytes());
            fields[1][16..].copy_from_slice(&binding[1].to_be_bytes());
            fields[2] = field(owner);
        }
        if circuit == CircuitName::DkgShareDecryption {
            fields[3] = field(0);
            fields[4] = field(2);
            let end = fields.len();
            fields[end - 2] = field(12);
            fields[end - 1] = field(13);
        }
        if circuit == CircuitName::NodeFold {
            fields[4] = field(20 + owner);
            for party in 0..size.values().n {
                fields[6 + size.values().n * config.threshold.moduli().len() + party] =
                    if party == owner as usize {
                        field(0)
                    } else {
                        field(11)
                    };
            }
        }
        Proof::new(
            circuit,
            ArcBytes::from_bytes(&[7]),
            ArcBytes::from_bytes(&fields.concat()),
        )
    };
    let inputs = SynchronizedRecipientInputsReady {
        e3_id: id.clone(),
        params_profile: profile,
        committee_size: size,
        context: context.clone(),
        dealers: vec![0, 2],
        transport_key: field(11),
        sk_commitment: field(12),
        key_bundle: field(13),
        c2_statements: [0, 2, recipient]
            .into_iter()
            .map(|owner| {
                (
                    owner,
                    make(CircuitName::SkShareComputation, owner).public_signals,
                )
            })
            .collect(),
    };
    let leaves = [
        (0, CircuitName::PkBfv),
        (2, CircuitName::SkShareComputation),
        (9, CircuitName::DkgShareDecryption),
    ]
    .into_iter()
    .map(|(seq, circuit)| DKGInnerProofReady {
        e3_id: id.clone(),
        party_id: recipient.into(),
        seq,
        proof: make(circuit, recipient),
    })
    .collect();
    let dealers = [0, 2]
        .into_iter()
        .map(|owner| {
            let mut context = context.clone();
            context.party_id = owner;
            SynchronizedDkgProofPublished::sign(
                id.clone(),
                context,
                SynchronizedDkgProofRole::Dealer,
                make(CircuitName::NodeFold, owner),
                &signers[owner as usize],
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let mut actor = NodeProofAggregator::new(
        bus,
        signers[recipient as usize].clone(),
        HashMap::new(),
        HashMap::new(),
        true,
    );
    actor.dealer = super::super::dealer::DealerCollection::new(
        HashMap::from([(
            id.clone(),
            E3Meta {
                threshold_m: size.values().threshold,
                threshold_n: size.values().n,
                seed: Seed([0; 32]),
                params_profile: profile,
                crypto_config_id: context.setup.crypto_config_id.into(),
                params: ArcBytes::from_bytes(&e3_fhe_params::encode_bfv_params(&config.threshold)),
                error_size: ArcBytes::from_bytes(&[]),
            },
        )]),
        HashMap::from([(
            id,
            e3_committee::Committee::new(members.iter().map(ToString::to_string).collect()),
        )]),
        HashSet::new(),
        HashMap::new(),
    );
    actor.recovery_repositories = Some(Repositories::in_mem());
    Ok(Fixture {
        actor,
        plan: RecipientPlan::new(inputs)?,
        leaves,
        dealers,
        signers,
    })
}

fn accept(actor: &mut NodeProofAggregator, data: impl Into<InterfoldEventData>) -> Result<()> {
    let data = data.into();
    actor.accept_recipient_input(&data, &ec(data.clone()))
}

fn collect(f: &mut Fixture) -> Result<()> {
    for dealer in &f.dealers {
        accept(&mut f.actor, dealer.clone())?;
    }
    for leaf in &f.leaves {
        accept(&mut f.actor, leaf.clone())?;
    }
    accept(&mut f.actor, f.plan.inputs.clone())
}

fn response(request: &ComputeRequest) -> ComputeResponse {
    let ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)) = &request.request else {
        panic!()
    };
    let SynchronizedDkgProofJob::Recipient { expected, .. } = &work.job else {
        panic!()
    };
    let mut fields = vec![field(0)];
    for binding in expected.binding {
        let mut value = [0; 32];
        value[16..].copy_from_slice(&binding.to_be_bytes());
        fields.push(value);
    }
    fields.push(field(expected.recipient));
    fields.extend(expected.dealers.iter().copied().map(field));
    fields.extend(expected.threshold_keys.clone());
    fields.extend([
        expected.dealer_batch,
        expected.sk_commitment,
        expected.key_bundle,
    ]);
    ComputeResponse::zk(
        ZkResponse::SynchronizedDkg(SynchronizedDkgProofResponse::Recipient {
            proof: Proof::new(
                CircuitName::NodesFold,
                ArcBytes::from_bytes(&[8]),
                ArcBytes::from_bytes(&fields.concat()),
            ),
            setup: expected.clone(),
        }),
        request.correlation_id,
        request.e3_id.clone(),
    )
}

#[actix::test]
async fn recipient_authentication_precedes_slots_and_valid_replacement_survives() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    let mut forged = f.dealers[0].clone();
    forged.signature = f.dealers[1].signature.clone();
    assert!(accept(&mut f.actor, forged).is_err());
    assert!(f.actor.recipient.records.is_empty());
    let mut wrong = f.dealers[0].clone();
    wrong.context.setup.committee_hash = [9; 32].into();
    assert!(accept(&mut f.actor, wrong).is_err());
    for input in [
        InterfoldEventData::from(f.plan.inputs.clone()),
        f.leaves[0].clone().into(),
    ] {
        assert!(f
            .actor
            .accept_recipient_input(&input, &ec(input.clone()).with_source(EventSource::Net))
            .is_err());
    }
    collect(&mut f)?;
    let id = &f.plan.inputs.e3_id;
    assert_eq!(f.actor.recipient.records[id].dealers.len(), 2);
    let mut repeated = f.dealers[0].clone();
    repeated.proof.data = ArcBytes::from_bytes(&[99]);
    repeated = SynchronizedDkgProofPublished::sign(
        repeated.e3_id,
        repeated.context,
        repeated.role,
        repeated.proof,
        &f.signers[0],
    )?;
    accept(&mut f.actor, repeated)?;
    assert_eq!(f.actor.recipient.records[id].dealers[&0], f.dealers[0]);
    Ok(())
}

#[actix::test]
async fn native_c4_fixes_nonprefix_roster_for_all_n_recipients() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    for recipient in 0..3 {
        let mut f = fixture(&bus, recipient)?;
        collect(&mut f)?;
        let id = f.plan.inputs.e3_id.clone();
        let record = &f.actor.recipient.records[&id];
        assert!(f.plan.request(&record.leaves, &record.dealers)?.is_some());
        let mut misplaced = record.leaves.clone();
        let leaf = misplaced.remove(&0).unwrap();
        misplaced.insert(999, leaf);
        assert!(f.plan.request(&misplaced, &record.dealers).is_err());
        let mut replacement = f.plan.inputs.clone();
        replacement.dealers = vec![0, 1];
        assert!(accept(&mut f.actor, replacement).is_err());
        assert_eq!(f.actor.recipient.records[&id].plan.as_ref(), Some(&f.plan));
        let mut wrong = f.leaves[2].clone();
        let mut fields = wrong.proof.public_signals.to_vec();
        fields[5 * 32 - 1] = 1; // different, otherwise well-shaped C4 roster [0,1]
        wrong.proof.public_signals = ArcBytes::from_bytes(&fields);
        assert!(accept(&mut f.actor, wrong).is_err());
    }
    Ok(())
}

#[actix::test]
async fn early_peer_setup_cannot_choose_native_roster_or_poison_replacement() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    let mut early = f.dealers[0].clone();
    // Authenticated sender, wrong native C2 messages. Retained before intent, discarded at fixation.
    let mut fields = early.proof.public_signals.to_vec();
    fields[7 * 32 - 1] = 42;
    early.proof.public_signals = ArcBytes::from_bytes(&fields);
    early = SynchronizedDkgProofPublished::sign(
        early.e3_id,
        early.context,
        early.role,
        early.proof,
        &f.signers[0],
    )?;
    accept(&mut f.actor, early)?;
    accept(&mut f.actor, f.plan.inputs.clone())?;
    assert!(f.actor.recipient.records[&f.plan.inputs.e3_id]
        .dealers
        .is_empty());
    collect(&mut f)?;
    Ok(())
}

#[actix::test]
async fn recipient_result_requires_exact_local_request_and_independent_anchors() -> Result<()> {
    let EventFixture { bus, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    f.actor.publish_recipient_work(&id)?;
    assert!(f.actor.recipient.in_flight.is_empty()); // replay has no effects
    f.actor.dealer.effects = true;
    f.actor.publish_recipient_work(&id)?;
    let request = f.actor.recipient.in_flight[&id].clone();
    let valid = response(&request);
    let mut stale = valid.clone();
    stale.correlation_id = CorrelationId::new();
    assert!(accept(&mut f.actor, stale).is_err());
    let mut wrong_e3 = valid.clone();
    wrong_e3.e3_id = E3id::new("2460", 1);
    accept(&mut f.actor, wrong_e3)?;
    assert!(f
        .actor
        .accept_recipient_input(
            &valid.clone().into(),
            &ec(valid.clone()).with_source(EventSource::Net)
        )
        .is_err());
    let mut wrong = valid.clone();
    if let ComputeResponseKind::Zk(ZkResponse::SynchronizedDkg(
        SynchronizedDkgProofResponse::Recipient { setup, .. },
    )) = &mut wrong.response
    {
        setup.key_bundle = field(99);
    }
    assert!(accept(&mut f.actor, wrong).is_err());
    let mut wrong = valid.clone();
    if let ComputeResponseKind::Zk(ZkResponse::SynchronizedDkg(
        SynchronizedDkgProofResponse::Recipient { proof, .. },
    )) = &mut wrong.response
    {
        let mut fields = proof.public_signals.to_vec();
        *fields.last_mut().unwrap() = 14;
        proof.public_signals = ArcBytes::from_bytes(&fields);
    }
    assert!(accept(&mut f.actor, wrong).is_err());
    let error = ComputeRequestError::new(
        ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("missing VK".into())),
        request.clone(),
    );
    accept(&mut f.actor, error)?;
    assert_eq!(f.actor.recipient.in_flight[&id], request);
    let mut changed = request.clone();
    changed.request = ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(Box::new(
        f.plan
            .request(
                &f.actor.recipient.records[&id].leaves,
                &f.actor.recipient.records[&id].dealers,
            )?
            .unwrap(),
    )));
    if let ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)) = &mut changed.request {
        work.context.party_id = 0;
    }
    assert!(accept(
        &mut f.actor,
        ComputeRequestError::new(
            ComputeRequestErrorKind::Zk(ZkError::ProofGenerationFailed("wrong job".into())),
            changed
        )
    )
    .is_err());
    accept(&mut f.actor, valid)?;
    assert!(f.actor.recipient.records[&id].completed.is_some());
    Ok(())
}

#[derive(Message)]
#[rtype(result = "()")]
struct FlushRecipient(E3id);
impl Handler<FlushRecipient> for NodeProofAggregator {
    type Result = ();
    fn handle(&mut self, msg: FlushRecipient, ctx: &mut Context<Self>) {
        self.flush_recipient_record(&msg.0, self.recipient.records[&msg.0].clone(), ctx);
    }
}

#[derive(Message)]
#[rtype(result = "(bool, bool)")]
struct InspectRecipient(E3id);
impl Handler<InspectRecipient> for NodeProofAggregator {
    type Result = actix::MessageResult<InspectRecipient>;
    fn handle(&mut self, msg: InspectRecipient, _: &mut Context<Self>) -> Self::Result {
        actix::MessageResult((
            self.recipient.records.contains_key(&msg.0),
            self.recipient.in_flight.contains_key(&msg.0),
        ))
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct StopRecipient;
impl Handler<StopRecipient> for NodeProofAggregator {
    type Result = ();
    fn handle(&mut self, _: StopRecipient, ctx: &mut Context<Self>) {
        ctx.stop();
    }
}

#[derive(Default)]
struct FailedFlush {
    recovered: bool,
}
impl Actor for FailedFlush {
    type Context = Context<Self>;
}
impl Handler<Flush> for FailedFlush {
    type Result = Result<()>;
    fn handle(&mut self, _: Flush, _: &mut Context<Self>) -> Self::Result {
        ensure!(self.recovered, "injected flush failure");
        Ok(())
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct RecoverFlush;
impl Handler<RecoverFlush> for FailedFlush {
    type Result = ();
    fn handle(&mut self, _: RecoverFlush, _: &mut Context<Self>) {
        self.recovered = true;
    }
}

#[derive(Message)]
#[rtype(result = "Result<()>")]
struct RetainDealer(SynchronizedDkgProofPublished);
impl Handler<RetainDealer> for NodeProofAggregator {
    type Result = Result<()>;
    fn handle(&mut self, msg: RetainDealer, _: &mut Context<Self>) -> Self::Result {
        let id = msg.0.e3_id.clone();
        accept(self, msg.0)?;
        self.validate_recipient_record(&id, &self.recipient.records[&id])
    }
}

#[actix::test]
async fn recipient_flush_retry_never_persists_a_new_invalid_batch() -> Result<()> {
    tokio::time::pause();
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    f.actor
        .recipient
        .records
        .get_mut(&id)
        .unwrap()
        .dealers
        .remove(&2);
    let directory = tempfile::tempdir()?;
    let store = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let flush = FailedFlush::default().start();
    f.actor.recovery_repositories = Some(Repositories::new(
        store
            .clone()
            .with_flush_recipient(flush.clone().recipient()),
    ));
    f.actor.dealer.effects = true;
    let addr = f.actor.start();
    addr.send(FlushRecipient(id.clone())).await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (true, false)
    );
    let mut mixed = f.dealers[1].clone();
    let mut public = mixed.proof.public_signals.to_vec();
    public[3 * 32 + 31] = 1; // same native C2 provenance, incompatible descendant genealogy
    mixed.proof.public_signals = ArcBytes::from_bytes(&public);
    mixed = SynchronizedDkgProofPublished::sign(
        mixed.e3_id,
        mixed.context,
        mixed.role,
        mixed.proof,
        &f.signers[2],
    )?;
    let error = addr.send(RetainDealer(mixed)).await?.unwrap_err();
    assert!(
        error.to_string().contains("mixed dealer genealogy"),
        "{error:#}"
    );
    flush.send(RecoverFlush).await?;
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    addr.send(InspectRecipient(id.clone())).await?;
    addr.send(StopRecipient).await?;
    store.shutdown().await?;
    drop(store);
    e3_data::SledDb::close_all_connections();
    let reopened = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let record = repository(&Repositories::new(reopened.clone()), &id)
        .read()
        .await?
        .unwrap();
    record.validate()?;
    assert_eq!(record.dealers.len(), 1);
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    reopened.shutdown().await?;
    e3_data::SledDb::close_all_connections();
    Ok(())
}

#[actix::test]
async fn recipient_failed_flush_resumes_compute_and_publication_without_new_inputs() -> Result<()> {
    tokio::time::pause();
    for completed in [true, false] {
        let EventFixture { bus, history, .. } = EventFixture::new()?;
        let mut f = fixture(&bus, 1)?;
        collect(&mut f)?;
        let id = f.plan.inputs.e3_id.clone();
        if completed {
            let record = &f.actor.recipient.records[&id];
            let request = ComputeRequest::zk(
                ZkRequest::SynchronizedDkg(Box::new(
                    f.plan.request(&record.leaves, &record.dealers)?.unwrap(),
                )),
                CorrelationId::new(),
                id.clone(),
            );
            f.actor
                .recipient
                .in_flight
                .insert(id.clone(), request.clone());
            accept(&mut f.actor, response(&request))?;
        }
        let expected = f.actor.recipient.records[&id].clone();
        let repositories = f.actor.recovery_repositories.take().unwrap();
        let flush = FailedFlush::default().start();
        f.actor.recovery_repositories = Some(Repositories::new(
            repositories
                .store
                .with_flush_recipient(flush.clone().recipient()),
        ));
        f.actor.dealer.effects = true;
        let addr = f.actor.start();
        addr.send(FlushRecipient(id.clone())).await?;
        assert_eq!(
            addr.send(InspectRecipient(id.clone())).await?,
            (true, false)
        );
        bus.flush_event_pipeline().await?;
        assert!(history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty());
        flush.send(RecoverFlush).await?;
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        let events = history
            .send(TakeEvents::<InterfoldEvent>::new(if completed {
                2
            } else {
                1
            }))
            .await?;
        assert!(
            !events.timed_out,
            "flush recovery did not resume recipient effects"
        );
        if completed {
            assert_eq!(
                events.events[0].get_data(),
                &InterfoldEventData::from(expected.completed.clone().unwrap())
            );
            let InterfoldEventData::SynchronizedDkgProofPublished(signed) =
                events.events[1].get_data()
            else {
                anyhow::bail!("missing signed recipient publication");
            };
            assert_eq!(signed.proof, expected.completed.unwrap().proof);
            assert_eq!(signed.recover_address()?, f.signers[1].address());
        } else {
            let InterfoldEventData::ComputeRequest(request) = events.events[0].get_data() else {
                anyhow::bail!("missing recipient compute request");
            };
            assert_eq!(
                request.request,
                ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(Box::new(
                    f.plan
                        .request(&expected.leaves, &expected.dealers)?
                        .unwrap()
                )))
            );
        }
    }
    Ok(())
}

#[actix::test]
async fn recipient_terminal_history_cancels_failed_flush_retry() -> Result<()> {
    tokio::time::pause();
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    let repositories = f.actor.recovery_repositories.take().unwrap();
    let flush = FailedFlush::default().start();
    f.actor.recovery_repositories = Some(Repositories::new(
        repositories
            .store
            .with_flush_recipient(flush.clone().recipient()),
    ));
    f.actor.dealer.effects = true;
    let addr = f.actor.start();
    addr.send(FlushRecipient(id.clone())).await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (true, false)
    );
    addr.send(
        InterfoldEvent::new_with_timestamp(
            E3StageChanged {
                e3_id: id.clone(),
                previous_stage: E3Stage::Requested,
                new_stage: E3Stage::KeyPublished,
            }
            .into(),
            None,
            2,
            None,
            EventSource::Evm,
        )
        .into_sequenced(2),
    )
    .await?;
    flush.send(RecoverFlush).await?;
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    assert_eq!(addr.send(InspectRecipient(id)).await?, (false, false));
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    Ok(())
}

#[actix::test]
async fn recipient_physical_restart_reuses_proofs_and_refreshes_correlations() -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    let directory = tempfile::tempdir()?;
    let store = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    f.actor.recovery_repositories = Some(Repositories::new(store.clone()));
    f.actor.dealer.effects = true;
    let addr = f.actor.start();
    addr.send(FlushRecipient(id.clone())).await?;
    assert_eq!(addr.send(InspectRecipient(id.clone())).await?, (true, true));
    bus.flush_event_pipeline().await?;
    let requests = history.send(GetEvents::<InterfoldEvent>::new()).await?;
    let InterfoldEventData::ComputeRequest(first) = requests[0].get_data() else {
        panic!()
    };
    addr.send(StopRecipient).await?;
    store.shutdown().await?;
    e3_data::SledDb::close_all_connections();
    let reopened = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let record = repository(&Repositories::new(reopened.clone()), &id)
        .read()
        .await?
        .unwrap();
    let mut restarted = fixture(&bus, 1)?;
    restarted.actor.validate_recipient_record(&id, &record)?;
    restarted.actor.recipient.records.insert(id.clone(), record);
    restarted.actor.dealer.effects = true;
    restarted.actor.publish_recipient_work(&id)?;
    let second = restarted.actor.recipient.in_flight[&id].clone();
    assert_eq!(second.request, first.request);
    assert_ne!(second.correlation_id, first.correlation_id);
    assert!(accept(&mut restarted.actor, response(first)).is_err());
    accept(&mut restarted.actor, response(&second))?;
    let finished = restarted.actor.recipient.records[&id].clone();
    repository(&Repositories::new(reopened.clone()), &id)
        .write_sync(&finished)
        .await?;
    reopened.shutdown().await?;
    e3_data::SledDb::close_all_connections();
    let reopened = e3_data::DataStore::from_sled_store(&e3_data::SledStore::new(
        &bus,
        &directory.path().to_path_buf(),
    )?);
    let EventFixture {
        bus: new_bus,
        history: new_history,
        ..
    } = EventFixture::new()?;
    let mut restarted = fixture(&new_bus, 1)?;
    let record = repository(&Repositories::new(reopened.clone()), &id)
        .read()
        .await?
        .unwrap();
    restarted.actor.validate_recipient_record(&id, &record)?;
    restarted.actor.recipient.records.insert(id.clone(), record);
    restarted.actor.dealer.effects = true;
    restarted.actor.publish_recipient_work(&id)?;
    restarted.actor.publish_recipient_work(&id)?;
    new_bus.flush_event_pipeline().await?;
    let events = new_history.send(GetEvents::<InterfoldEvent>::new()).await?;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].get_data(),
        &InterfoldEventData::from(finished.completed.clone().unwrap())
    );
    let InterfoldEventData::SynchronizedDkgProofPublished(signed) = events[1].get_data() else {
        panic!()
    };
    assert_eq!(signed.recover_address()?, restarted.actor.signer.address());
    assert_eq!(signed.proof, finished.completed.unwrap().proof);
    reopened.shutdown().await?;
    e3_data::SledDb::close_all_connections();
    Ok(())
}

#[actix::test]
async fn recipient_admission_remains_disabled_and_confirmed_terminal_history_wins() -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    let repositories = f.actor.recovery_repositories.clone().unwrap();
    let metadata = f.actor.dealer.metadata.clone();
    let record = f.actor.recipient.records[&id].clone();
    repository(&repositories, &id).write_sync(&record).await?;
    assert!(recover(&repositories, &metadata, &HashSet::new())
        .await
        .is_err());
    let addr = f.actor.start();
    let event = |data: InterfoldEventData, source| {
        InterfoldEvent::new_with_timestamp(data, None, 1, None, source).into_sequenced(1)
    };
    addr.send(event(EffectsEnabled::new().into(), EventSource::Local))
        .await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (true, false)
    );
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    let terminal: InterfoldEventData = E3StageChanged {
        e3_id: id.clone(),
        previous_stage: E3Stage::Requested,
        new_stage: E3Stage::KeyPublished,
    }
    .into();
    addr.send(event(terminal.clone(), EventSource::Net)).await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (true, false)
    );
    addr.send(event(terminal, EventSource::Evm)).await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (false, false)
    );
    addr.send(event(f.plan.inputs.into(), EventSource::Local))
        .await?;
    assert_eq!(
        addr.send(InspectRecipient(id.clone())).await?,
        (false, false)
    );
    assert!(repository(&repositories, &id).read().await?.is_none());
    repository(&repositories, &id).write_sync(&record).await?;
    recover(&repositories, &metadata, &HashSet::from([id.clone()])).await?;
    assert!(repository(&repositories, &id).read().await?.is_none());
    Ok(())
}
