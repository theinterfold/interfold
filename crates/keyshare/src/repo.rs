// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{DataStore, Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::{ThresholdKeyshareRecoveryState, ThresholdKeyshareState};

pub trait ThresholdKeyshareRepositoryFactory {
    fn threshold_keyshare(&self, e3_id: &E3id) -> Repository<ThresholdKeyshareState>;
    fn threshold_keyshare_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdKeyshareRecoveryState>;
    /// Scoped store for the CKKS relin-ceremony chunk log of one E3: every
    /// received `RelinCeremonyShare` chunk is written ONCE under its own
    /// key (`<round>/<level>/<party>/<index>`), so recovery can re-feed the
    /// machine's `serde(skip)` chunk buffers without the per-event
    /// re-serialization that a snapshot field would cost.
    fn threshold_keyshare_ckks_ceremony(&self, e3_id: &E3id) -> DataStore;
}

impl ThresholdKeyshareRepositoryFactory for Repositories {
    fn threshold_keyshare(&self, e3_id: &E3id) -> Repository<ThresholdKeyshareState> {
        Repository::new(self.store.scope(StoreKeys::threshold_keyshare(e3_id)))
    }

    fn threshold_keyshare_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdKeyshareRecoveryState> {
        Repository::new(
            self.store
                .scope(StoreKeys::threshold_keyshare_recovery(e3_id)),
        )
    }

    fn threshold_keyshare_ckks_ceremony(&self, e3_id: &E3id) -> DataStore {
        self.store
            .scope(format!("//threshold_keyshare_ckks_ceremony/v1/{e3_id}"))
    }
}
