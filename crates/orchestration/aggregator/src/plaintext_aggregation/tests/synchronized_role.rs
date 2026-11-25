// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use crate::test_support::{get_common_setup, history_reader, synchronized_opening};
use e3_data::InMemStore;
use e3_events::{AggregatorChanged, Unsequenced};
use e3_zk_prover::{BBPath, ZkBackend, ZkProver};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[derive(Message)]
#[rtype(result = "bool")]
struct Busy;
impl Handler<Busy> for FixedSetPlaintext {
    type Result = bool;
    fn handle(&mut self, _: Busy, _: &mut Context<Self>) -> bool {
        self.running.is_some()
    }
}

// Start at the authorization boundary, after verification of the fixed owners' sequences.
fn ready_rows(actor: &mut FixedSetPlaintext) {
    for (owner, seq) in [(0, 8), (2, 10)] {
        actor.keys.note_synchronized_candidate(&actor.id, seq);
        actor.rows.insert(
            owner,
            (
                seq,
                DecryptionshareCreated {
                    e3_id: actor.id.clone(),
                    party_id: owner,
                    node: String::new(),
                    decryption_share: vec![],
                    signed_decryption_proofs: vec![],
                },
            ),
        );
    }
}

#[actix::test]
async fn reconciled_failure_retires_before_restored_effects() -> Result<()> {
    let (bus, ..) = get_common_setup(None)?;
    let id = E3id::new("42", 1);
    let (keys, _) = synchronized_opening(&id)?;
    let db = DataStore::from_in_mem(&InMemStore::new(false).start());
    for reconciled in [true, false] {
        let scope = db.scope(if reconciled { "reconciled" } else { "proposed" });
        let pin = scope.scope("verified-0");
        pin.write_sync(8u64).await?;
        let (clock, mut reads) = mpsc::unbounded_channel();
        let runtime = DecryptionRuntime {
            pool: e3_task_pool::TaskPool::new(1, 1),
            task_scope: "restored".into(),
            prover: ZkProver::new(&ZkBackend::new(
                BBPath::Custom("unused".into()),
                "unused".into(),
                "unused".into(),
            )),
            timing: Arc::new(move |_| {
                clock.send(()).unwrap();
                Box::pin(async { Ok((100, 99)) })
            }),
        };
        let mut collector = FixedSetPlaintext::new(
            bus.clone(),
            id.clone(),
            keys.clone(),
            runtime,
            history_reader(&[])?,
            scope.clone(),
            true,
            false,
        );
        ready_rows(&mut collector);
        let collector = collector.start();
        // The router sends this local stage directly, before the current boot's effects broadcast.
        let stage = e3_events::E3StageChanged {
            e3_id: id.clone(),
            previous_stage: E3Stage::CiphertextReady,
            new_stage: E3Stage::Failed,
        };
        let seed = bus.event_from(stage, None)?.into_sequenced(11);
        collector
            .send(seed.clone().with_source(EventSource::Net))
            .await?;
        assert_eq!(pin.read_checked::<u64>().await?, Some(8));
        if reconciled {
            collector.send(seed).await?;
        } else {
            let proposal = bus
                .event_from(
                    e3_events::E3Failed {
                        e3_id: id.clone(),
                        failed_at_stage: E3Stage::CiphertextReady,
                        reason: e3_events::FailureReason::DecryptionInvalidShares,
                    },
                    None,
                )?
                .into_sequenced(11);
            collector.send(proposal).await?;
        }
        let enabled = bus
            .event_from(e3_events::EffectsEnabled::new(), None)?
            .into_sequenced(12);
        assert!(
            collector.send(enabled).await.is_err(),
            "failed collector resumed effects"
        );
        assert!(matches!(
            reads.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        assert_eq!(
            pin.read_checked::<u64>().await?,
            (!reconciled).then_some(8),
            "only a terminal stage authorizes erasing the pins"
        );
        assert!(scope
            .scope("started")
            .read_checked::<Vec<u64>>()
            .await?
            .is_none());
    }
    Ok(())
}

#[actix::test]
async fn demotion_during_the_deadline_read_cannot_start_a_new_batch() -> Result<()> {
    let (bus, ..) = get_common_setup(None)?;
    let id = E3id::new("42", 1);
    let (keys, _) = synchronized_opening(&id)?;
    let db = DataStore::from_in_mem(&InMemStore::new(false).start());
    let started = DurableIntent::<Vec<u64>>::new(db.scope("started"));
    // Stop the positive case after the start checkpoint, before any proof work.
    db.scope("result").write_sync(0xffu8).await?;
    let (clock, mut reads) = mpsc::unbounded_channel();
    let rt = DecryptionRuntime {
        pool: e3_task_pool::TaskPool::new(1, 1),
        task_scope: "demotion".into(),
        prover: ZkProver::new(&ZkBackend::new(
            BBPath::Custom("unused".into()),
            "unused".into(),
            "unused".into(),
        )),
        timing: Arc::new(move |_| {
            let (reply, response) = oneshot::channel();
            clock.send(reply).unwrap();
            Box::pin(async { Ok(response.await?) })
        }),
    };
    let mut actor = FixedSetPlaintext::new(
        bus,
        id.clone(),
        keys.clone(),
        rt,
        history_reader(&[])?,
        db,
        true,
        true,
    );
    actor.deadline = Some(100);
    ready_rows(&mut actor);
    let node = actor.start();
    let role = |active| {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            AggregatorChanged {
                e3_id: id.clone(),
                active_party_id: Some(if active { 0 } else { 2 }),
                is_aggregator: active,
            }
            .into(),
            None,
            11,
            None,
            EventSource::Local,
        )
        .into_sequenced(11)
    };
    let until_idle = || async {
        while node.send(Busy).await? {
            tokio::task::yield_now().await;
        }
        Ok::<(), anyhow::Error>(())
    };
    actix::clock::timeout(Duration::from_secs(5), async {
        let pending = reads.recv().await.unwrap();
        node.send(role(false)).await?;
        pending.send((100, 99)).unwrap();
        until_idle().await?;
        assert_eq!(
            started.restore().await?,
            None,
            "demoted node started a batch"
        );
        node.send(role(true)).await?;
        reads.recv().await.unwrap().send((100, 99)).unwrap();
        until_idle().await?;
        assert_eq!(started.restore().await?, Some(vec![8, 10]));
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    Ok(())
}
