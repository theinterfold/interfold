// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use anyhow::Result;
use e3_ciphernode_builder::global_eventstore_cache::{get_shared_eventstore, EventStoreReader};
use e3_ciphernode_builder::global_store_cache::get_cached_store;
use e3_ciphernode_builder::{get_interfold_bus_handle, EventSystem};
use e3_config::AppConfig;
use e3_data::{DataStore, InMemStore, SledDb, SledStore};
use e3_data::{Repositories, RepositoriesFactory};
use e3_events::{BusHandle, Disabled};
use std::path::PathBuf;

pub fn get_sled_store(bus: &BusHandle<Disabled>, db_file: &PathBuf) -> Result<DataStore> {
    Ok((&SledStore::new(bus, db_file)?).into())
}

pub fn get_in_mem_store() -> DataStore {
    (&InMemStore::new(true).start()).into()
}

pub fn setup_datastore(config: &AppConfig, bus: &BusHandle<Disabled>) -> Result<DataStore> {
    let store: DataStore = if !config.use_in_mem_store() {
        get_sled_store(bus, &config.db_file())?
    } else {
        get_in_mem_store()
    };
    Ok(store)
}

/// Command helper to get a store
pub fn get_repositories(config: &AppConfig) -> Result<Repositories> {
    // We are probably in a socket command so get the shared store
    if let Some(store) = get_cached_store() {
        return Ok(store.repositories());
    }

    // We are probably in a standalone command so setup a fresh data store
    let bus = get_interfold_bus_handle()?;
    let store = setup_datastore(config, &bus)?;
    Ok(store.repositories())
}

/// Command helper to get an eventstore reader for reading events from the event store
pub fn get_eventstore_reader(config: &AppConfig) -> Result<EventStoreReader> {
    // We are probably in a socket command so get the shared eventstore reader
    if let Some(es) = get_shared_eventstore() {
        return Ok(es);
    }

    // We are probably in a standalone command so get a new reader
    let system = EventSystem::persisted(config.log_file(), config.db_file());
    let es = system.eventstore_reader()?;
    Ok(es)
}

pub fn close_all_connections() {
    SledDb::close_all_connections();
}
