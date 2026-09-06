// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_sdk::indexer::SharedStore;

use super::{
    database::SledDB,
    repo::{RoundIndexRepository, TreasuryE3Repository},
};

pub struct AppData {
    db: SharedStore<SledDB>,
}

impl AppData {
    pub fn new(db: SharedStore<SledDB>) -> Self {
        Self { db }
    }

    pub fn store(&self) -> SharedStore<SledDB> {
        self.db.clone()
    }

    pub fn e3(&self, e3_id: impl ToString) -> TreasuryE3Repository<SledDB> {
        TreasuryE3Repository::new(self.db.clone(), e3_id)
    }

    pub fn rounds(&self) -> RoundIndexRepository<SledDB> {
        RoundIndexRepository::new(self.db.clone())
    }
}
