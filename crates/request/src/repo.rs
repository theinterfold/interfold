// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{Repositories, Repository};
use e3_events::E3Stage;
use e3_events::E3id;
use e3_events::StoreKeys;
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
}

impl RouterRepositoryFactory for Repositories {
    fn router(&self) -> Repository<E3RouterSnapshot> {
        Repository::new(self.store.scope(StoreKeys::router()))
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
