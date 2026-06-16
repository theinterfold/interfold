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

/// Initialize the HashMap with a list of expected Recipients. In order to know whether or not we
/// should buffer we need to iterate over this list and determine which recipients are missing based
/// on the recipient value is why we set it here to have keys with empty values.
fn init_recipients() -> HashMap<String, Option<Recipient<InterfoldEvent>>> {
    HashMap::from([
        ("keyshare".to_owned(), None),
        ("threshold_keyshare".to_owned(), None),
        ("plaintext".to_owned(), None),
        ("publickey".to_owned(), None),
        ("accusation_manager".to_owned(), None),
        ("commitment_consistency_checker".to_owned(), None),
    ])
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
            recipients: init_recipients(),
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
            // Use composite key of e3_id:recipient_key to scope buffered events per E3 request
            let buffer_key = format!("{}:{}", self.e3_id, key);
            if let Some(act) = recipient {
                act.do_send(msg.clone());
                for m in buffer.take(&buffer_key) {
                    act.do_send(m);
                }
            } else {
                buffer.add(&buffer_key, msg.clone());
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
        Ok(Self::Snapshot {
            e3_id: self.e3_id.clone(),
            dependencies: self.dependencies.keys(),
            recipients: self.recipients.keys().cloned().collect(),
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
            recipients: init_recipients(),
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
