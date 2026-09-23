// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::domain::backends::SortitionBackend;
use crate::domain::failover::AggregatorFailoverState;
use crate::domain::node_registry::NodeStateStore;
use crate::{BondOwnerState, CiphernodeSelectorState, SortitionRecoveryState};
use e3_data::{Repositories, Repository};
use e3_events::{Committee, E3id, StoreKeys};
use std::collections::HashMap;

pub trait SortitionRepositoryFactory {
    fn sortition(&self) -> Repository<HashMap<u64, SortitionBackend>>;
}

impl SortitionRepositoryFactory for Repositories {
    fn sortition(&self) -> Repository<HashMap<u64, SortitionBackend>> {
        Repository::new(self.store.scope(StoreKeys::sortition()))
    }
}

pub trait SortitionRecoveryRepositoryFactory {
    fn sortition_admission(&self) -> Repository<crate::AdmissionState>;
    fn sortition_recovery(&self) -> Repository<SortitionRecoveryState>;
    fn sortition_bond_owners(&self) -> Repository<BondOwnerState>;
}

impl SortitionRecoveryRepositoryFactory for Repositories {
    fn sortition_admission(&self) -> Repository<crate::AdmissionState> {
        Repository::new(self.store.scope(StoreKeys::sortition_admission()))
    }
    fn sortition_recovery(&self) -> Repository<SortitionRecoveryState> {
        Repository::new(self.store.scope(StoreKeys::sortition_recovery()))
    }

    fn sortition_bond_owners(&self) -> Repository<BondOwnerState> {
        Repository::new(self.store.scope(StoreKeys::sortition_bond_owners()))
    }
}

pub trait CiphernodeSelectorFactory {
    fn ciphernode_selector(&self) -> Repository<CiphernodeSelectorState>;
}

impl CiphernodeSelectorFactory for Repositories {
    fn ciphernode_selector(&self) -> Repository<CiphernodeSelectorState> {
        Repository::new(self.store.scope(StoreKeys::ciphernode_selector()))
    }
}

pub trait AggregatorFailoverRepositoryFactory {
    fn aggregator_failover(&self) -> Repository<AggregatorFailoverState>;
}

impl AggregatorFailoverRepositoryFactory for Repositories {
    fn aggregator_failover(&self) -> Repository<AggregatorFailoverState> {
        Repository::new(self.store.scope(StoreKeys::aggregator_failover()))
    }
}

pub trait NodeStateRepositoryFactory {
    fn node_state(&self) -> Repository<HashMap<u64, NodeStateStore>>;
}

impl NodeStateRepositoryFactory for Repositories {
    fn node_state(&self) -> Repository<HashMap<u64, NodeStateStore>> {
        Repository::new(self.store.scope(StoreKeys::node_state()))
    }
}

pub trait FinalizedCommitteesRepositoryFactory {
    fn finalized_committees(&self) -> Repository<HashMap<E3id, Committee>>;
}

impl FinalizedCommitteesRepositoryFactory for Repositories {
    fn finalized_committees(&self) -> Repository<HashMap<E3id, Committee>> {
        Repository::new(self.store.scope(StoreKeys::finalized_committees()))
    }
}
