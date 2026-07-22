// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::E3ContextSnapshot;
use actix::{Actor, Handler};
use async_trait::async_trait;
use e3_data::{InMemStore, RepositoriesFactory};
use e3_events::{hlc_factory::HlcFactory, BusHandle, EventBus, PersistEvent, Sequencer};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct StoreSink;

impl Actor for StoreSink {
    type Context = Context<Self>;
}

impl Handler<PersistEvent> for StoreSink {
    type Result = anyhow::Result<Option<InterfoldEvent>>;

    fn handle(&mut self, _: PersistEvent, _: &mut Self::Context) -> Self::Result {
        Ok(None)
    }
}

struct RecoveryExtension {
    hydrations: Arc<AtomicUsize>,
}

#[async_trait]
impl E3Extension for RecoveryExtension {
    fn on_event(&self, _: &mut E3Context, _: &InterfoldEvent) {}

    async fn hydrate(&self, _: &mut E3Context, _: &E3ContextSnapshot) -> Result<()> {
        self.hydrations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn test_bus() -> BusHandle {
    let event_bus = EventBus::<InterfoldEvent>::default().start();
    let store = StoreSink.start();
    let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
    BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("router-recovery-test")
}

#[actix::test]
async fn mid_e3_context_and_completed_set_survive_hydration() -> Result<()> {
    let active = E3id::new("7", 31337);
    let complete = E3id::new("6", 31337);
    let store = DataStore::from_in_mem(&InMemStore::new(false).start());
    let repositories = store.repositories();
    let router_store = repositories.router();
    router_store
        .repositories()
        .context(&active)
        .write_sync(&E3ContextSnapshot {
            e3_id: active.clone(),
            recipients: vec!["threshold_keyshare".into()],
            dependencies: vec!["meta".into()],
        })
        .await?;

    let hydrations = Arc::new(AtomicUsize::new(0));
    let params = E3RouterParams {
        extensions: Arc::new(vec![Box::new(RecoveryExtension {
            hydrations: hydrations.clone(),
        })]),
        bus: test_bus(),
        store: router_store,
    };
    let recovered = E3Router::from_snapshot(
        params,
        E3RouterSnapshot {
            contexts: vec![active.clone()],
            completed: HashSet::from([complete.clone()]),
        },
    )
    .await?;

    assert!(recovered.contexts.contains_key(&active));
    assert!(recovered.completed.contains(&complete));
    assert_eq!(hydrations.load(Ordering::SeqCst), 1);

    let roundtrip = recovered.snapshot()?;
    assert_eq!(roundtrip.contexts, vec![active]);
    assert_eq!(roundtrip.completed, HashSet::from([complete]));
    Ok(())
}
