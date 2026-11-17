// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{Repositories, Repository};
use e3_events::{E3id, StoreKeys};

use crate::{
    PublicKeyAggregatorRecoveryState, PublicKeyAggregatorState,
    ThresholdPlaintextAggregatorRecoveryState, ThresholdPlaintextAggregatorState,
};

pub trait TrBfvPlaintextRepositoryFactory {
    fn trbfv_plaintext(&self, e3_id: &E3id) -> Repository<ThresholdPlaintextAggregatorState>;
    fn trbfv_plaintext_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdPlaintextAggregatorRecoveryState>;
}

impl TrBfvPlaintextRepositoryFactory for Repositories {
    fn trbfv_plaintext(&self, e3_id: &E3id) -> Repository<ThresholdPlaintextAggregatorState> {
        Repository::new(self.store.scope(StoreKeys::plaintext(e3_id)))
    }

    fn trbfv_plaintext_recovery(
        &self,
        e3_id: &E3id,
    ) -> Repository<ThresholdPlaintextAggregatorRecoveryState> {
        Repository::new(self.store.scope(StoreKeys::plaintext_recovery(e3_id)))
    }
}

pub trait PublicKeyRepositoryFactory {
    fn publickey(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorState>;
    fn publickey_recovery(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorRecoveryState>;
    fn synchronized_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<crate::workflow::publickey_aggregation::synchronized::PublicationRecord>;
}

impl PublicKeyRepositoryFactory for Repositories {
    fn synchronized_publication(
        &self,
        e3_id: &E3id,
    ) -> Repository<crate::workflow::publickey_aggregation::synchronized::PublicationRecord> {
        Repository::new(
            self.store
                .scope(StoreKeys::publickey_recovery(e3_id))
                .scope("synchronized-publication/v1"),
        )
    }
    fn publickey(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorState> {
        Repository::new(self.store.scope(StoreKeys::publickey(e3_id)))
    }

    fn publickey_recovery(&self, e3_id: &E3id) -> Repository<PublicKeyAggregatorRecoveryState> {
        Repository::new(self.store.scope(StoreKeys::publickey_recovery(e3_id)))
    }
}
