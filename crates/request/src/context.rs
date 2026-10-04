// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3Extension, EventBuffer, HetrogenousMap, TypedKey};
use actix::Recipient;
use anyhow::Result;
use async_trait::async_trait;
use e3_data::{
    Checkpoint, FromSnapshotWithParams, Repositories, RepositoriesFactory, Repository, Snapshot,
};
use e3_events::{E3id, InterfoldEvent};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

/// Only installed recipient extensions need deferred delivery.
fn init_recipients(
    extensions: &[Box<dyn E3Extension>],
) -> HashMap<String, Option<Recipient<InterfoldEvent>>> {
    extensions
        .iter()
        .filter_map(|extension| extension.expected_recipient())
        .map(|key| (key.to_owned(), None))
        .collect()
}

/// Context that is set to each event hook. Hooks can use this context to gather dependencies if
/// they need to instantiate struct instances or actors.
pub struct E3Context {
    /// The E3Request's ID
    pub e3_id: E3id,
    /// A way to store InterfoldEvent recipients on the context
    pub recipients: HashMap<String, Option<Recipient<InterfoldEvent>>>, // NOTE: can be a None value
    /// A way to store an extension's dependencies on the context
    pub dependencies: HetrogenousMap,
    /// A Repository for storing this context's data snapshot
    pub repository: Repository<E3ContextSnapshot>,
}

#[derive(Serialize, Deserialize)]
pub struct E3ContextSnapshot {
    pub e3_id: E3id,
    pub recipients: Vec<String>,
    pub dependencies: Vec<String>,
}

impl E3ContextSnapshot {
    pub fn contains(&self, key: &str) -> bool {
        self.recipients.contains(&key.to_string()) || self.dependencies.contains(&key.to_string())
    }
}

pub struct E3ContextParams {
    pub repository: Repository<E3ContextSnapshot>,
    pub e3_id: E3id,
    pub extensions: Arc<Vec<Box<dyn E3Extension>>>,
}

impl E3Context {
    pub fn from_params(params: E3ContextParams) -> Self {
        Self {
            e3_id: params.e3_id,
            repository: params.repository,
            recipients: init_recipients(&params.extensions),
            dependencies: HetrogenousMap::new(),
        }
    }

    /// Return a list of expected recipient keys alongside any values that have or have not been
    /// set.
    fn recipients(&self) -> Vec<(String, Option<Recipient<InterfoldEvent>>)> {
        self.recipients
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn forward_message(&self, msg: &InterfoldEvent, buffer: &mut EventBuffer) {
        self.recipients().into_iter().for_each(|(key, recipient)| {
            if let Some(act) = recipient {
                // Events buffered before this extension existed must remain ahead of the event
                // that caused the extension to be constructed.
                for m in buffer.take(&self.e3_id, &key) {
                    act.do_send(m);
                }
                act.do_send(msg.clone());
            } else {
                buffer.add(&self.e3_id, &key, msg.clone());
            }
        });
    }

    pub fn forward_message_now(&self, msg: &InterfoldEvent) {
        self.recipients().into_iter().for_each(|(_, recipient)| {
            if let Some(act) = recipient {
                act.do_send(msg.clone());
            }
        });
    }

    pub fn set_event_recipient(
        &mut self,
        key: impl Into<String>,
        value: Option<Recipient<InterfoldEvent>>,
    ) {
        self.recipients.insert(key.into(), value);
        self.checkpoint();
    }

    pub fn get_event_recipient(
        &self,
        key: impl Into<String>,
    ) -> Option<&Recipient<InterfoldEvent>> {
        self.recipients
            .get(&key.into())
            .and_then(|opt| opt.as_ref())
    }

    pub fn set_dependency<T>(&mut self, key: TypedKey<T>, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.dependencies.insert(key, value);
        self.checkpoint();
    }

    pub fn get_dependency<T>(&self, key: TypedKey<T>) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.dependencies.get(key)
    }
}

impl RepositoriesFactory for E3Context {
    fn repositories(&self) -> Repositories {
        self.repository().clone().into()
    }
}

#[async_trait]
impl Snapshot for E3Context {
    type Snapshot = E3ContextSnapshot;

    fn snapshot(&self) -> Result<Self::Snapshot> {
        let mut dependencies = self.dependencies.keys();
        dependencies.sort();
        let mut recipients = self
            .recipients
            .iter()
            .filter_map(|(key, recipient)| recipient.as_ref().map(|_| key.clone()))
            .collect::<Vec<_>>();
        recipients.sort();
        Ok(Self::Snapshot {
            e3_id: self.e3_id.clone(),
            dependencies,
            recipients,
        })
    }
}

#[async_trait]
impl FromSnapshotWithParams for E3Context {
    type Params = E3ContextParams;
    async fn from_snapshot(params: Self::Params, snapshot: Self::Snapshot) -> Result<Self> {
        let mut ctx = Self {
            e3_id: params.e3_id,
            repository: params.repository,
            recipients: init_recipients(&params.extensions),
            dependencies: HetrogenousMap::new(),
        };

        for extension in params.extensions.iter() {
            extension.hydrate(&mut ctx, &snapshot).await?;
        }

        Ok(ctx)
    }
}

impl Checkpoint for E3Context {
    fn repository(&self) -> &Repository<E3ContextSnapshot> {
        &self.repository
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContextRepositoryFactory;
    use actix::{Actor, Context, Handler, Message};
    use e3_data::{DataStore, InMemStore};
    use e3_events::{Event, InterfoldEventData, Sequenced};
    use std::sync::{Arc, Mutex};

    struct Recorder(Arc<Mutex<Vec<String>>>);

    impl Actor for Recorder {
        type Context = Context<Self>;
    }

    impl Handler<InterfoldEvent> for Recorder {
        type Result = ();

        fn handle(&mut self, message: InterfoldEvent, _: &mut Self::Context) {
            if let InterfoldEventData::TestEvent(event) = message.get_data() {
                self.0.lock().unwrap().push(event.msg.clone());
            }
        }
    }

    #[derive(Message)]
    #[rtype(result = "Vec<String>")]
    struct Recorded;

    impl Handler<Recorded> for Recorder {
        type Result = Vec<String>;

        fn handle(&mut self, _: Recorded, _: &mut Self::Context) -> Self::Result {
            self.0.lock().unwrap().clone()
        }
    }

    fn event(e3_id: &E3id, label: &str, sequence: u64) -> InterfoldEvent {
        InterfoldEvent::<Sequenced>::test_event(label)
            .e3_id(e3_id.clone())
            .seq(sequence)
            .build()
    }

    #[actix::test]
    async fn buffered_events_precede_the_current_event() {
        let e3_id = E3id::new("7", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut context = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id: e3_id.clone(),
            extensions: Arc::new(Vec::new()),
        });
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder(recorded).start();
        let mut buffer = EventBuffer::default();
        buffer.add(&e3_id, "threshold_keyshare", event(&e3_id, "older", 1));
        context.set_event_recipient("threshold_keyshare", Some(recorder.clone().recipient()));

        context.forward_message(&event(&e3_id, "current", 2), &mut buffer);

        assert_eq!(recorder.send(Recorded).await.unwrap(), ["older", "current"]);
    }

    #[actix::test]
    async fn snapshot_records_only_attached_recipients() {
        let e3_id = E3id::new("7", 1);
        let store = DataStore::from_in_mem(&InMemStore::new(false).start());
        let mut context = E3Context::from_params(E3ContextParams {
            repository: store.repositories().context(&e3_id),
            e3_id,
            extensions: Arc::new(Vec::new()),
        });
        let recorder = Recorder(Arc::new(Mutex::new(Vec::new()))).start();
        context.set_event_recipient("threshold_keyshare", Some(recorder.recipient()));

        let snapshot = context.snapshot().unwrap();

        assert_eq!(snapshot.recipients, ["threshold_keyshare"]);
    }
}
