// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use e3_data::{Repositories, Repository};
use e3_events::{
    AggregateId, DkgFoldAttestationContextEstablished, E3Stage, E3id, RequestRouterCheckpoint,
    StoreKeys,
};
use std::collections::HashMap;

use crate::{E3ContextSnapshot, E3Meta, E3RouterSnapshot};

pub trait MetaRepositoryFactory {
    fn meta(&self, e3_id: &E3id) -> Repository<E3Meta>;
}

impl MetaRepositoryFactory for Repositories {
    fn meta(&self, e3_id: &E3id) -> Repository<E3Meta> {
        Repository::new(self.store.scope(StoreKeys::meta(e3_id)))
    }
}

pub trait DkgFoldAttestationContextRepositoryFactory {
    fn dkg_fold_attestation_context(
        &self,
        e3_id: &E3id,
    ) -> Repository<DkgFoldAttestationContextEstablished>;
}

impl DkgFoldAttestationContextRepositoryFactory for Repositories {
    fn dkg_fold_attestation_context(
        &self,
        e3_id: &E3id,
    ) -> Repository<DkgFoldAttestationContextEstablished> {
        Repository::new(
            self.store
                .scope(StoreKeys::dkg_fold_attestation_context(e3_id)),
        )
    }
}

pub trait ContextRepositoryFactory {
    fn context(&self, e3_id: &E3id) -> Repository<E3ContextSnapshot>;
}

impl ContextRepositoryFactory for Repositories {
    fn context(&self, e3_id: &E3id) -> Repository<E3ContextSnapshot> {
        Repository::new(self.store.scope(StoreKeys::context(e3_id)))
    }
}

pub trait RouterRepositoryFactory {
    fn router(&self) -> Repository<E3RouterSnapshot>;
    fn request_router_checkpoint(&self) -> Repository<RequestRouterCheckpoint>;
}

impl RouterRepositoryFactory for Repositories {
    fn router(&self) -> Repository<E3RouterSnapshot> {
        Repository::new(self.store.scope(StoreKeys::router()))
    }

    fn request_router_checkpoint(&self) -> Repository<RequestRouterCheckpoint> {
        Repository::new(self.store.scope(StoreKeys::request_router_checkpoint()))
    }
}

pub trait E3LifecycleRepositoryFactory {
    fn e3_lifecycle(&self) -> Repository<HashMap<E3id, E3Stage>>;
}

impl E3LifecycleRepositoryFactory for Repositories {
    fn e3_lifecycle(&self) -> Repository<HashMap<E3id, E3Stage>> {
        Repository::new(self.store.scope(StoreKeys::e3_lifecycle()))
    }
}

/// Create a router checkpoint for a store that an older binary wrote.
///
/// The sync preflight rebuilds an initial checkpoint from EventStore before it starts the actors.
pub async fn ensure_request_router_checkpoint(
    repositories: &Repositories,
    aggregate_ids: impl IntoIterator<Item = AggregateId>,
) -> Result<()> {
    let checkpoint_store = repositories.request_router_checkpoint();
    if checkpoint_store.read().await?.is_some() {
        return Ok(());
    }

    let replay_cursors = aggregate_ids
        .into_iter()
        .map(|aggregate_id| (aggregate_id, 0))
        .collect::<HashMap<_, _>>();

    checkpoint_store
        .write_sync(&RequestRouterCheckpoint {
            contexts: Vec::new(),
            completed: Default::default(),
            replay_cursors,
            teardown_deadlines: Default::default(),
        })
        .await
}
