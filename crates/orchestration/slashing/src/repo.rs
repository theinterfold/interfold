// SPDX-License-Identifier: LGPL-3.0-only

//! Repository factories for restart-safe slashing state.

use e3_data::{Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::domain::commitment_consistency::CommitmentConsistencySnapshot;
use crate::workflow::accusation_voting::AccusationVotesSnapshot;

pub(crate) trait AccusationVotesRepositoryFactory {
    fn accusation_votes(&self, e3_id: &E3id) -> Repository<AccusationVotesSnapshot>;
}

impl AccusationVotesRepositoryFactory for Repositories {
    fn accusation_votes(&self, e3_id: &E3id) -> Repository<AccusationVotesSnapshot> {
        Repository::new(self.store.scope(StoreKeys::accusation_votes(e3_id)))
    }
}

pub(crate) trait CommitmentConsistencyRepositoryFactory {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot>;
}

impl CommitmentConsistencyRepositoryFactory for Repositories {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot> {
        Repository::new(self.store.scope(StoreKeys::commitment_consistency(e3_id)))
    }
}

#[cfg(test)]
mod layout_lock {
    //! Locks the encoded layout of the commitment consistency snapshot. `e3-tests` locks the public
    //! roots (`crates/tests/tests/layout_lock.rs`) but cannot reach this one.

    use super::*;
    use serde::{de::DeserializeOwned, Serialize};
    use std::path::Path;

    /// Binds `T` to the accessor's value type. The accessor is never called.
    fn repository<T: Serialize + DeserializeOwned>(
        root: &str,
        _accessor: fn(&Repositories) -> Repository<T>,
    ) -> Vec<String> {
        e3_layout_lock::sample_rows::<T, _>(root, |_| String::new())
    }

    #[test]
    fn persisted_layouts_match_the_locked_fixture() {
        let mut rows = repository("commitment_consistency", |r| {
            r.commitment_consistency(&E3id::new("1", 1))
        });
        rows.extend(repository("accusation_votes", |r| {
            r.accusation_votes(&E3id::new("1", 1))
        }));
        e3_layout_lock::assert_fixture(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layout_lock.txt"),
            &rows,
        );
    }
}
