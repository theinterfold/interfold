// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{Repositories, Repository};
use e3_events::StoreKeys;

use crate::{DataAvailabilityRecoveryState, SlashingWriterRecoveryState};

pub trait EthPrivateKeyRepositoryFactory {
    fn eth_private_key(&self) -> Repository<Vec<u8>>;
}

impl EthPrivateKeyRepositoryFactory for Repositories {
    fn eth_private_key(&self) -> Repository<Vec<u8>> {
        Repository::new(self.store.scope(StoreKeys::eth_private_key()))
    }
}

// Note: the EVM read cursor is NOT stored here. Each aggregate's last ingested block is
// persisted by the snapshot batch router under `StoreKeys::aggregate_block` and restored
// through `SnapshotMeta::to_evm_config` at boot, which is what `HistoricalEvmSyncStart`
// hands to the chain reader as its `from_block`. A previous per-contract
// `EvmReadInterfaceState` repository was declared here but never read or written; it was
// removed so nobody mistakes its absence for "the node re-scans from deploy_block".

pub trait SlashingWriterRepositoryFactory {
    fn slashing_writer_recovery(&self, chain_id: u64) -> Repository<SlashingWriterRecoveryState>;
}

impl SlashingWriterRepositoryFactory for Repositories {
    fn slashing_writer_recovery(&self, chain_id: u64) -> Repository<SlashingWriterRecoveryState> {
        Repository::new(
            self.store
                .scope(StoreKeys::slashing_writer_recovery(chain_id)),
        )
    }
}

pub trait DataAvailabilityRepositoryFactory {
    fn data_availability_recovery(
        &self,
        chain_id: u64,
    ) -> Repository<DataAvailabilityRecoveryState>;
}

impl DataAvailabilityRepositoryFactory for Repositories {
    fn data_availability_recovery(
        &self,
        chain_id: u64,
    ) -> Repository<DataAvailabilityRecoveryState> {
        Repository::new(
            self.store
                .scope(StoreKeys::data_availability_recovery(chain_id)),
        )
    }
}
