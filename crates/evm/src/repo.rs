// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_data::{Repositories, Repository};
use e3_events::StoreKeys;

use crate::EvmReadInterfaceState;

pub trait EthPrivateKeyRepositoryFactory {
    fn eth_private_key(&self) -> Repository<Vec<u8>>;
}

impl EthPrivateKeyRepositoryFactory for Repositories {
    fn eth_private_key(&self) -> Repository<Vec<u8>> {
        Repository::new(self.store.scope(StoreKeys::eth_private_key()))
    }
}

pub trait InterfoldSolReaderRepositoryFactory {
    fn interfold_sol_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState>;
}

impl InterfoldSolReaderRepositoryFactory for Repositories {
    fn interfold_sol_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState> {
        Repository::new(self.store.scope(StoreKeys::interfold_sol_reader(chain_id)))
    }
}

pub trait CiphernodeRegistryReaderRepositoryFactory {
    fn ciphernode_registry_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState>;
}

impl CiphernodeRegistryReaderRepositoryFactory for Repositories {
    fn ciphernode_registry_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState> {
        Repository::new(
            self.store
                .scope(StoreKeys::ciphernode_registry_reader(chain_id)),
        )
    }
}

pub trait BondingRegistryReaderRepositoryFactory {
    fn bonding_registry_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState>;
}

impl BondingRegistryReaderRepositoryFactory for Repositories {
    fn bonding_registry_reader(&self, chain_id: u64) -> Repository<EvmReadInterfaceState> {
        Repository::new(
            self.store
                .scope(StoreKeys::bonding_registry_reader(chain_id)),
        )
    }
}
