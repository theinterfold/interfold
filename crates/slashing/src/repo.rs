// SPDX-License-Identifier: LGPL-3.0-only

//! Repository factories for restart-safe slashing state.

use e3_data::{Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::domain::commitment_consistency::CommitmentConsistencySnapshot;

pub(crate) trait CommitmentConsistencyRepositoryFactory {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot>;
}

impl CommitmentConsistencyRepositoryFactory for Repositories {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot> {
        Repository::new(self.store.scope(StoreKeys::commitment_consistency(e3_id)))
    }
}
