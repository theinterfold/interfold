// SPDX-License-Identifier: LGPL-3.0-only

//! Repository factories for restart-safe slashing state.

use anyhow::{Context as _, Result};
use e3_data::{DataStore, Repositories, Repository};
use e3_events::{E3id, EventContext, RowInstanceNotRepresentable, Sequenced, StoreKeys};
use serde::{de::DeserializeOwned, Serialize};

use crate::domain::commitment_consistency::{
    CommitmentConsistencySnapshot, LbfvCommitmentConsistencySnapshot,
};
use crate::workflow::accusation_voting::{AccusationVotesSnapshot, LbfvAccusationVotesSnapshot};

pub(crate) trait AccusationVotesRepositoryFactory {
    fn accusation_votes(&self, e3_id: &E3id) -> Repository<AccusationVotesSnapshot>;
    fn accusation_votes_lbfv(&self, e3_id: &E3id) -> Repository<LbfvAccusationVotesSnapshot>;
}

impl AccusationVotesRepositoryFactory for Repositories {
    fn accusation_votes(&self, e3_id: &E3id) -> Repository<AccusationVotesSnapshot> {
        Repository::new(self.store.scope(StoreKeys::accusation_votes(e3_id)))
    }

    fn accusation_votes_lbfv(&self, e3_id: &E3id) -> Repository<LbfvAccusationVotesSnapshot> {
        Repository::new(self.store.scope(StoreKeys::accusation_votes_lbfv(e3_id)))
    }
}

pub(crate) trait CommitmentConsistencyRepositoryFactory {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot>;
    fn commitment_consistency_lbfv(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvCommitmentConsistencySnapshot>;
}

impl CommitmentConsistencyRepositoryFactory for Repositories {
    fn commitment_consistency(&self, e3_id: &E3id) -> Repository<CommitmentConsistencySnapshot> {
        Repository::new(self.store.scope(StoreKeys::commitment_consistency(e3_id)))
    }

    fn commitment_consistency_lbfv(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvCommitmentConsistencySnapshot> {
        Repository::new(
            self.store
                .scope(StoreKeys::commitment_consistency_lbfv(e3_id)),
        )
    }
}

/// The saved state of one E3 in the layout of its proving path.
///
/// A trBFV E3 saves `T`, whose bincode layout is persisted and unchanged. An l-BFV E3 saves `L`,
/// which names each proof by its row. The workflow runs on `L`; this repository converts at the
/// store, so the workflow has one form and each path has its own record.
pub(crate) enum PathRepository<T, L> {
    Trbfv(Repository<T>),
    Lbfv(Repository<L>),
}

impl<T, L> PathRepository<T, L>
where
    T: Serialize + DeserializeOwned + TryFrom<L, Error = RowInstanceNotRepresentable>,
    L: Serialize + DeserializeOwned + Clone + From<T>,
{
    /// The saved state, if any, as the workflow's form.
    pub(crate) async fn read_checked(&self) -> Result<Option<L>> {
        Ok(match self {
            Self::Trbfv(repo) => DataStore::from(repo)
                .read_checked::<T>()
                .await?
                .map(L::from),
            Self::Lbfv(repo) => DataStore::from(repo).read_checked::<L>().await?,
        })
    }

    /// Save `state`, converted to the layout of the E3's proving path.
    pub(crate) fn write_with_context(
        &self,
        state: &L,
        context: &EventContext<Sequenced>,
    ) -> Result<()> {
        match self {
            Self::Trbfv(repo) => repo.write_with_context(
                &T::try_from(state.clone()).context("a trBFV E3 saved an l-BFV row")?,
                context,
            ),
            Self::Lbfv(repo) => repo.write_with_context(state, context),
        }
    }

    /// Remove the saved state.
    pub(crate) fn clear_with_context(&self, context: &EventContext<Sequenced>) -> Result<()> {
        match self {
            Self::Trbfv(repo) => {
                DataStore::from(repo).write_with_context(Option::<T>::None, context)
            }
            Self::Lbfv(repo) => {
                DataStore::from(repo).write_with_context(Option::<L>::None, context)
            }
        }
    }
}

#[cfg(test)]
mod layout_lock {
    //! Locks the encoded layout of the commitment consistency snapshot. `e3-tests` locks the public
    //! roots (`crates/testing/system/tests/layout_lock.rs`) but cannot reach this one.

    use super::*;
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
        rows.extend(repository("commitment_consistency_lbfv", |r| {
            r.commitment_consistency_lbfv(&E3id::new("1", 1))
        }));
        rows.extend(repository("accusation_votes_lbfv", |r| {
            r.accusation_votes_lbfv(&E3id::new("1", 1))
        }));
        e3_layout_lock::assert_fixture(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layout_lock.txt"),
            &rows,
        );
    }
}
