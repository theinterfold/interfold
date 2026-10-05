// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{DurableIntent, Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::{BfvKeyIntent, ThresholdKeyshareRecoveryState, ThresholdKeyshareState};

pub trait ThresholdKeyshareRepositoryFactory {
    fn threshold_keyshare(&self, e3_id: &E3id) -> Repository<ThresholdKeyshareState>;
    fn threshold_keyshare_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdKeyshareRecoveryState>;
    fn threshold_keyshare_recovery_payloads(&self, e3_id: &E3id) -> e3_data::DataStore;
    fn threshold_keyshare_bfv_key(&self, e3_id: &E3id) -> DurableIntent<BfvKeyIntent>;
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

    fn threshold_keyshare_recovery_payloads(&self, e3_id: &E3id) -> e3_data::DataStore {
        self.store
            .base(StoreKeys::threshold_keyshare_recovery_payloads(e3_id))
    }

    /// The record is a node-wide record at its own key, also when an E3 context's repositories make
    /// it, so the deletion guards find it by that key's prefix.
    fn threshold_keyshare_bfv_key(&self, e3_id: &E3id) -> DurableIntent<BfvKeyIntent> {
        DurableIntent::new(
            self.store
                .base(StoreKeys::threshold_keyshare_bfv_key(e3_id)),
        )
    }
}
