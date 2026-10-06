// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A snapshot that validation cannot read is a failed check in its report. This file has its own
//! test binary: the store helpers that validation uses keep process-wide state.

use anyhow::Result;
use commitlog::{CommitLog, LogOptions};
use e3_config::{AppConfig, UnscopedAppConfig};
use e3_data::SledDb;
use e3_entrypoint::validate::{validate_node, Severity};
use e3_events::{Insert, StoreKeys};
use e3_sync::SCHEMA_VERSION;
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

/// A stored snapshot cursor that does not decode is a failed check in the report, not an error
/// that ends the validation without one.
#[actix::test]
async fn an_unreadable_snapshot_cursor_is_a_failed_check() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = node_config(root.path())?;
    let mut db = SledDb::new(&config.db_file(), "datastore")?;
    db.insert(Insert::new(
        StoreKeys::schema_version(),
        bincode::serialize(&SCHEMA_VERSION)?,
    ))?;
    db.insert(Insert::new(
        StoreKeys::aggregate_seq(e3_events::AggregateId::new(0)),
        vec![1, 2, 3],
    ))?;
    db.flush()?;
    drop(db);
    drop(CommitLog::new(LogOptions::new(e3_utils::enumerate_path(
        &config.log_file(),
        0,
    )))?);

    let report = validate_node(&config, false).await?;

    let check = report
        .checks
        .iter()
        .find(|check| check.name == "snapshot-cursor")
        .expect("the report must check the snapshot cursor");
    assert_eq!(check.severity, Severity::Fail, "{}", report.render());
    assert!(report.checks.iter().any(|check| check.name == "skipped"));
    Ok(())
}
