// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_request::canonical_key::{
    CanonicalDkgAnchors, CanonicalPublicKey, CanonicalPublicKeys, SynchronizedDkgAuthority,
};

pub(super) fn published_key(f: &Fixture) -> Result<CanonicalPublicKey> {
    let input = &f.plan.inputs;
    let id = &input.e3_id;
    let record = &f.actor.recipient.records[id];
    let work = f.plan.request(&record.leaves, &record.dealers)?.unwrap();
    let SynchronizedDkgProofJob::Recipient { expected, .. } = work.job else {
        unreachable!()
    };
    let committee: Vec<_> = f.signers.iter().map(|s| s.address()).collect();
    Ok(CanonicalPublicKey {
        pk_commitment: field(30),
        honest_committee: vec![committee[0], committee[2]],
        committee,
        params_profile: input.params_profile,
        committee_size: input.committee_size,
        interfold_address: input.context.setup.interfold_address,
        dkg_anchors: CanonicalDkgAnchors::Synchronized(SynchronizedDkgAuthority {
            version: 1,
            context: SynchronizedDkgContext {
                registry: Address::repeat_byte(4),
                verifying_contract: Address::repeat_byte(5),
                crypto_config_id: input.context.setup.crypto_config_id.0,
            },
            setup_binding: input
                .context
                .setup
                .hash(id.chain_id(), id.clone().try_into()?)
                .0,
            party_ids: vec![0, 2],
            dealer_batch: expected.dealer_batch,
            threshold_pk_commits: vec![field(20), field(22)],
            sk_agg_commits: vec![field(8); 2],
            key_bundle_commits: vec![field(9); 2],
        }),
    })
}

pub(super) fn install(
    keys: &CanonicalPublicKeys,
    id: &E3id,
    key: CanonicalPublicKey,
) -> Result<()> {
    let CanonicalDkgAnchors::Synchronized(a) = &key.dkg_anchors else {
        unreachable!()
    };
    keys.remember_synchronized_context(id.clone(), a.context)?;
    keys.insert_synchronized_dkg_authority(id.clone(), key)
}

pub(super) fn stage(id: &E3id, previous_stage: E3Stage, new_stage: E3Stage) -> InterfoldEvent {
    InterfoldEvent::new_with_timestamp(
        E3StageChanged {
            e3_id: id.clone(),
            previous_stage,
            new_stage,
        }
        .into(),
        None,
        2,
        Some(2),
        EventSource::Evm,
    )
    .into_sequenced(2)
}

// Invoke the same correlated completion/flush below the disabled profile admission check.
#[derive(Message)]
#[rtype(result = "Result<()>")]
struct Finish(ComputeResponse);
impl Handler<Finish> for NodeProofAggregator {
    type Result = Result<()>;
    fn handle(&mut self, msg: Finish, ctx: &mut Context<Self>) -> Self::Result {
        let id = msg.0.e3_id.clone();
        accept(self, msg.0)?;
        self.flush_recipient_record(&id, self.recipient.records[&id].clone(), ctx);
        Ok(())
    }
}

#[actix::test]
async fn key_publication_before_or_during_a_recipient_join_yields_only_a_durable_local_result(
) -> Result<()> {
    for dispatched in [false, true] {
        let EventFixture { bus, history, .. } = EventFixture::new()?;
        let mut f = fixture(&bus, 1)?;
        collect(&mut f)?;
        let id = f.plan.inputs.e3_id.clone();
        let keys = f.actor.canonical_keys.clone();
        let key = published_key(&f)?;
        let repos = f.actor.recovery_repositories.clone().unwrap();
        f.actor.dealer.effects = true;
        let node = f.actor.start();
        if dispatched {
            node.send(FlushRecipient(id.clone())).await?;
        }
        node.send(stage(
            &id,
            E3Stage::CommitteeFinalized,
            E3Stage::KeyPublished,
        ))
        .await?;
        assert_eq!(
            node.send(InspectRecipient(id.clone())).await?,
            (true, dispatched)
        );
        // The stage can precede the full authority/proof observation. It doesn't authorize work.
        if !dispatched {
            node.send(FlushRecipient(id.clone())).await?;
            assert_eq!(
                node.send(InspectRecipient(id.clone())).await?,
                (true, false)
            );
        }
        install(&keys, &id, key)?;
        node.send(FlushRecipient(id.clone())).await?;
        assert_eq!(node.send(InspectRecipient(id.clone())).await?, (true, true));
        bus.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(events.len(), 1);
        let InterfoldEventData::ComputeRequest(request) = events[0].get_data() else {
            anyhow::bail!("missing recipient join")
        };
        node.send(Finish(response(request))).await??;
        assert_eq!(
            node.send(InspectRecipient(id.clone())).await?,
            (true, false)
        );
        let saved = repository(&repos, &id)
            .read()
            .await?
            .unwrap()
            .completed
            .unwrap();
        bus.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(events.len(), 2, "no peer setup, dealer or publication work");
        assert_eq!(events[1].get_data(), &InterfoldEventData::from(saved));
        let end = if dispatched {
            E3Stage::Failed
        } else {
            E3Stage::Complete
        };
        node.send(stage(&id, E3Stage::KeyPublished, end)).await?;
        assert_eq!(
            node.send(InspectRecipient(id.clone())).await?,
            (false, false)
        );
        assert!(repository(&repos, &id).read().await?.is_none());
    }
    Ok(())
}

#[actix::test]
async fn a_worker_finishing_between_stage_and_authority_can_only_handoff_the_winning_batch(
) -> Result<()> {
    for matching in [false, true] {
        let EventFixture { bus, history, .. } = EventFixture::new()?;
        let mut f = fixture(&bus, 1)?;
        collect(&mut f)?;
        let mut key = published_key(&f)?;
        if !matching {
            let CanonicalDkgAnchors::Synchronized(a) = &mut key.dkg_anchors else {
                unreachable!()
            };
            a.dealer_batch[31] ^= 1;
        }
        let id = f.plan.inputs.e3_id.clone();
        f.actor.dealer.effects = true;
        f.actor.publish_recipient_work(&id)?;
        let request = f.actor.recipient.in_flight[&id].clone();
        f.actor.dealer.ended.insert(id.clone());
        accept(&mut f.actor, response(&request))?;
        f.actor.publish_recipient_work(&id)?;
        bus.flush_event_pipeline().await?;
        assert_eq!(
            history
                .send(GetEvents::<InterfoldEvent>::new())
                .await?
                .len(),
            1
        );
        install(&f.actor.canonical_keys, &id, key)?;
        f.actor.publish_recipient_work(&id)?;
        bus.flush_event_pipeline().await?;
        let events = history.send(GetEvents::<InterfoldEvent>::new()).await?;
        assert_eq!(events.len(), 1 + usize::from(matching));
        if matching {
            assert!(matches!(
                events[1].get_data(),
                InterfoldEventData::SynchronizedRecipientProofReady(_)
            ));
        }
    }
    Ok(())
}

#[actix::test]
async fn late_dispatch_requires_each_local_proof_and_terminal_history_wins_over_pending_work(
) -> Result<()> {
    let EventFixture { bus, history, .. } = EventFixture::new()?;
    let mut f = fixture(&bus, 1)?;
    collect(&mut f)?;
    let id = f.plan.inputs.e3_id.clone();
    install(&f.actor.canonical_keys, &id, published_key(&f)?)?;
    f.actor.dealer.effects = true;
    for leaf in &f.leaves {
        f.actor
            .recipient
            .records
            .get_mut(&id)
            .unwrap()
            .leaves
            .remove(&leaf.seq);
        f.actor.publish_recipient_work(&id)?;
        assert!(!f.actor.recipient.in_flight.contains_key(&id));
        accept(&mut f.actor, leaf.clone())?;
    }
    bus.flush_event_pipeline().await?;
    assert!(history
        .send(GetEvents::<InterfoldEvent>::new())
        .await?
        .is_empty());
    for end in [E3Stage::Failed, E3Stage::Complete] {
        let mut f = fixture(&bus, 1)?;
        collect(&mut f)?;
        install(&f.actor.canonical_keys, &id, published_key(&f)?)?;
        f.actor.dealer.effects = true;
        f.actor.publish_recipient_work(&id)?;
        let request = f.actor.recipient.in_flight[&id].clone();
        let store = repository(f.actor.recovery_repositories.as_ref().unwrap(), &id);
        store.write_sync(&f.actor.recipient.records[&id]).await?;
        let node = f.actor.start();
        node.send(stage(&id, E3Stage::KeyPublished, end)).await?;
        assert_eq!(
            node.send(InspectRecipient(id.clone())).await?,
            (false, false)
        );
        assert!(node.send(Finish(response(&request))).await?.is_err());
        assert!(store.read().await?.is_none());
    }
    Ok(())
}
