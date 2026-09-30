// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `interfold node validate` must report a store that an older release wrote, and name
//! `interfold node reset-data`. The snapshots in such a store use a layout that this binary cannot
//! decode, so the report must not depend on them. The store in this test has no event log, like a
//! store whose event logs this binary can decode.
//!
//! `validate_node` opens its store through the process-wide event bus, and that bus stops with the
//! actix system that started it. This binary therefore holds one test.

use anyhow::Result;
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_config::{AppConfig, UnscopedAppConfig};
use e3_data::{RepositoriesFactory, SledDb};
use e3_entrypoint::helpers::datastore::setup_datastore;
use e3_entrypoint::validate::{validate_node, Severity};
use e3_events::StoreKeys;
use e3_sync::{SyncRepositoryFactory, SCHEMA_VERSION};
use std::path::Path;

fn node_config(root: &Path) -> Result<AppConfig> {
    let config: UnscopedAppConfig = serde_yaml::from_str("node:\n  network: local\n")?;
    config.into_scoped_with_defaults(
        "_default",
        &root.join("data"),
        &root.join("config"),
        &root.to_path_buf(),
    )
}

#[actix::test]
async fn validate_reports_a_store_from_an_older_schema() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = node_config(root.path())?;

    // An older release stamped its schema version and stored a snapshot in its own layout.
    let bus = get_interfold_bus_handle()?;
    let repositories = setup_datastore(&config, &bus)?.repositories();
    repositories
        .schema_version()
        .write_sync(&(SCHEMA_VERSION - 1))
        .await?;
    // The current layout reads these bytes as a map length that exceeds the decode limit.
    repositories
        .store
        .write_batch_sync(vec![(StoreKeys::node_state(), u64::MAX)])
        .await?;
    repositories.store.shutdown().await?;
    SledDb::close_all_connections();

    let report = validate_node(&config, false).await?;
    let schema = report
        .checks
        .iter()
        .find(|check| check.name == "schema")
        .expect("the report has a schema check");
    assert_eq!(schema.severity, Severity::Fail);
    assert!(
        schema.detail.contains("interfold node reset-data"),
        "the schema check must name the reset command: {}",
        schema.detail
    );
    assert!(
        report.checks.iter().any(|check| check.name == "skipped"),
        "the report must say which checks did not run"
    );
    Ok(())
}
