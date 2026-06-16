// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::runtime::{Fhe, FheSnapshot};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use e3_data::{FromSnapshotWithParams, Repositories, RepositoriesFactory, Repository, Snapshot};
use e3_events::{
    prelude::*, BusHandle, E3Requested, E3id, EType, InterfoldEvent, InterfoldEventData, StoreKeys,
};
use e3_request::{E3Context, E3ContextSnapshot, E3Extension, TypedKey};
use e3_utils::SharedRng;
use std::sync::Arc;

pub const FHE_KEY: TypedKey<Arc<Fhe>> = TypedKey::new("fhe");

/// Factory for FHE snapshot storage per E3 instance.
pub trait FheRepositoryFactory {
    fn fhe(&self, e3_id: &E3id) -> Repository<FheSnapshot>;
}

impl FheRepositoryFactory for Repositories {
    fn fhe(&self, e3_id: &E3id) -> Repository<FheSnapshot> {
        Repository::new(self.store.scope(StoreKeys::fhe(e3_id)))
    }
}

/// TODO: move these to each package with access on MyStruct::launcher()
pub struct FheExtension {
    rng: SharedRng,
    bus: BusHandle,
}

impl FheExtension {
    pub fn create(bus: &BusHandle, rng: &SharedRng) -> Box<Self> {
        Box::new(Self {
            rng: rng.clone(),
            bus: bus.clone(),
        })
    }
}

const ERROR_FHE_FAILED_TO_DECODE: &str = "Failed to decode encoded FHE params";

#[async_trait]
impl E3Extension for FheExtension {
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent) {
        // Saving the fhe on Committee Requested
        let InterfoldEventData::E3Requested(data) = evt.get_data() else {
            return;
        };

        let E3Requested { params, e3_id, .. } = data.clone();

        let Ok(fhe_inner) = Fhe::from_encoded(&params, self.rng.clone()) else {
            self.bus
                .err(EType::KeyGeneration, anyhow!(ERROR_FHE_FAILED_TO_DECODE));
            return;
        };

        let fhe = Arc::new(fhe_inner);

        // FHE doesn't implement Checkpoint so we are going to store it manually
        let Ok(snapshot) = fhe.snapshot() else {
            self.bus
                .err(EType::KeyGeneration, anyhow!("Failed to get snapshot"));
            return;
        };
        ctx.repositories().fhe(&e3_id).write(&snapshot);
        ctx.set_dependency(FHE_KEY, fhe);
    }

    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &E3ContextSnapshot) -> Result<()> {
        // No ID on the snapshot -> bail without reporting
        if !snapshot.contains("fhe") {
            return Ok(());
        };

        // No Snapshot returned from the store -> bail without reporting
        let Some(snap) = ctx.repositories().fhe(&ctx.e3_id).read().await? else {
            return Ok(());
        };

        let value = Arc::new(Fhe::from_snapshot(self.rng.clone(), snap).await?);
        ctx.set_dependency(FHE_KEY, value);

        Ok(())
    }
}
