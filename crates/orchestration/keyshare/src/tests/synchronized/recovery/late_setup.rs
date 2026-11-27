// SPDX-License-Identifier: LGPL-3.0-only

//! Two local histories of the same mined H publication. The worker barrier controls delivery,
//! not the prover's speed. Each history has its own exclusive setup store.

use super::super::super::publication::{actor, DriveSetup, SetupCheckpoint};
use super::*;
use crate::synchronized::SynchronizedSetupIntent;
use tokio::{sync::oneshot, task::JoinHandle};

pub(super) struct InFlight {
    release: oneshot::Sender<()>,
    result: JoinHandle<Result<SynchronizedRecipientProofReady>>,
}

pub(super) fn dispatch(work: RecipientJoinWork, prover: ZkProver, id: E3id) -> InFlight {
    let (release, released) = oneshot::channel();
    let result = tokio::task::spawn_blocking(move || {
        let result = work.execute(&prover, &id);
        released.blocking_recv()?;
        result
    });
    InFlight { release, result }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    work: &RecipientJoinWork,
    in_flight: InFlight,
    prover: &ZkProver,
    root: &ThresholdKeyshareRecoveryState,
    signer: &PrivateKeySigner,
    stage: InterfoldEvent<Unsequenced>,
    mined: &[InterfoldEvent<Unsequenced>],
    keys: &CanonicalPublicKeys,
    directory: &Path,
    bus: &BusHandle,
) -> Result<SynchronizedSetupIntent> {
    let id = &root
        .ciphernode_selected
        .as_ref()
        .context("missing late selection")?
        .e3_id;
    let owner = work.request.context.party_id as usize;
    let controller = work.request.context.setup.interfold_address;
    let cipher = cipher(owner).await?;
    let stage = stage.into_sequenced(4);
    let mut handoff = None;
    for (name, mut dispatched) in [("in-flight", Some(in_flight)), ("before-dispatch", None)] {
        let path = directory.join(format!("late-setup-{name}"));
        let mut original = None;
        for reopened in [false, true] {
            let store = DataStore::from_sled_store(&SledStore::new(bus, &path)?);
            let (node, setup_bus, outputs) = actor(
                &store,
                root.clone(),
                signer.clone(),
                cipher.clone(),
                controller,
                keys.clone(),
            )
            .await?;
            if !reopened {
                node.send(DriveSetup {
                    result: None,
                    effects: true,
                })
                .await??;
                ensure!(node.send(SetupCheckpoint).await?.is_none());
            }
            node.send(stage.clone()).await?;
            let result = if reopened {
                None
            } else if let Some(pending) = dispatched.take() {
                ensure!(keys.get(id).is_none());
                pending
                    .release
                    .send(())
                    .map_err(|_| anyhow::anyhow!("late worker stopped"))?;
                node.send(DriveSetup {
                    result: Some(TypedEvent::new(pending.result.await??, test_ec(701))),
                    effects: true,
                })
                .await??;
                ensure!(
                    node.send(SetupCheckpoint).await?.is_none(),
                    "stage alone accepted setup"
                );
                ensure!(reopen_history(mined, directory, controller, keys)
                    .await?
                    .is_empty());
                None // Redrive the held result, now with confirmed authority.
            } else {
                let key = keys
                    .get(id)
                    .context("missing registry authority before dispatch")?;
                ensure!(key.matches_late_recipient_work(signer.address(), &work.request));
                Some(TypedEvent::new(work.execute(prover, id)?, test_ec(701)))
            };
            node.send(DriveSetup {
                result,
                effects: true,
            })
            .await??;
            let saved = node
                .send(SetupCheckpoint)
                .await?
                .context("missing late local setup")?;
            if let Some(previous) = &original {
                ensure!(
                    previous == &saved,
                    "reopen changed the exclusive local verdict"
                );
            }
            saved.confirmed_setup(controller, keys, &cipher)?;
            setup_bus.flush_event_pipeline().await?;
            ensure!(
                outputs
                    .send(GetEvents::<InterfoldEvent>::new())
                    .await?
                    .is_empty(),
                "late setup restarted DKG effects"
            );
            original = Some(saved);
            node.send(Die).await?;
            drop(node);
            store.shutdown().await?;
            drop(store);
            SledDb::close_all_connections();
        }
        handoff = original;
    }
    handoff.context("missing reopened outside-H handoff")
}

#[actix::test]
async fn synchronized_reopen_before_c4_cannot_restart_dkg_from_late_ready_or_roster() -> Result<()>
{
    let _exclusive = DISK_RECOVERY.lock().await;
    let mut setup =
        Setup::with_ciphers(vec![cipher(0).await?, cipher(1).await?, cipher(2).await?]).await?;
    let inputs = artifacts(&mut setup, None).await?;
    let owner = 1;
    let id = &setup.selected[owner].e3_id;
    let dir = tempfile::tempdir()?;
    Node::open(dir.path(), owner, &setup, Some(&inputs))
        .await?
        .stop()
        .await?;
    SledDb::close_all_connections();

    let (bus, history) = test_bus();
    let store = DataStore::from_sled_store(&SledStore::new(&bus, &dir.path().to_owned())?);
    let node = Node::restore(store, bus.clone(), history, owner, &setup).await?;
    node.actor
        .send(keyshare_event(
            E3StageChanged {
                e3_id: id.clone(),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage: E3Stage::KeyPublished,
            },
            11,
            EventSource::Evm,
        ))
        .await?;
    node.enable(12).await?;
    let roster = signed_roster(&setup)?;
    for party in DEALERS {
        let ready = DkgCoordination::sign(
            id.clone(),
            setup.interfold,
            party,
            DkgCoordinationKind::Ready,
            roster.dealers.clone(),
            &setup.signers[party as usize],
        )?;
        node.actor
            .send(keyshare_event(ready, 13 + party, EventSource::Net))
            .await?;
    }
    node.actor
        .send(keyshare_event(
            AggregatorChanged {
                e3_id: id.clone(),
                is_aggregator: false,
                active_party_id: Some(0),
            },
            16,
            EventSource::Local,
        ))
        .await?;
    node.actor
        .send(keyshare_event(roster, 17, EventSource::Net))
        .await?;
    node.actor
        .send(keyshare_event(
            AggregatorChanged {
                e3_id: id.clone(),
                is_aggregator: true,
                active_party_id: Some(owner as u64),
            },
            18,
            EventSource::Local,
        ))
        .await?;
    let root = node.root(id).await?;
    ensure!(root.dkg_roster.is_none() && root.synchronized == Some(setup.material[owner].clone()));
    bus.flush_event_pipeline().await?;
    ensure!(
        node.history
            .send(GetEvents::<InterfoldEvent>::new())
            .await?
            .is_empty(),
        "publication restarted DKG without a fixed native C4 intent"
    );
    node.stop().await?;
    SledDb::close_all_connections();
    Ok(())
}
