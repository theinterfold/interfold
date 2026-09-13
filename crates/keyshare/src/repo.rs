// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::{LbfvGenerationStateV1, ThresholdKeyshareRecoveryState, ThresholdKeyshareState};

pub trait ThresholdKeyshareRepositoryFactory {
    fn threshold_keyshare(&self, e3_id: &E3id) -> Repository<ThresholdKeyshareState>;
    fn threshold_keyshare_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdKeyshareRecoveryState>;
    fn threshold_keyshare_lbfv_generation(&self, e3_id: &E3id)
        -> Repository<LbfvGenerationStateV1>;
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

    fn threshold_keyshare_lbfv_generation(
        &self,
        e3_id: &E3id,
    ) -> Repository<LbfvGenerationStateV1> {
        Repository::new(
            self.store
                .scope(StoreKeys::threshold_keyshare_lbfv_generation(e3_id)),
        )
    }
}
