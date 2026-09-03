// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_sdk::indexer::SharedStore;

use super::chain::Chain;
use super::database::SledDB;
use super::repo::RoundRepository;

/// Shared actix state.
pub struct AppData {
    pub store: SharedStore<SledDB>,
    pub db: SledDB,
    pub chain: Chain,
}

impl AppData {
    pub fn round(&self, e3_id: impl ToString) -> RoundRepository {
        RoundRepository::new(self.store.clone(), e3_id)
    }
}
