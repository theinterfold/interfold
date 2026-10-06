// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Schema admission must precede event decoding and tail recovery at each log-opening boundary.

use anyhow::Result;
use commitlog::{CommitLog, LogOptions};
use e3_ciphernode_builder::{CiphernodeBuilder, EventSystem};
use e3_config::{AppConfig, UnscopedAppConfig};
use e3_crypto::Cipher;
use e3_data::SledDb;
use e3_entrypoint::helpers::datastore::get_eventstore_reader;
use e3_entrypoint::validate::{validate_node, Severity};
use e3_events::{Get, Insert, InterfoldEvent, StoreKeys, Unsequenced};
use e3_sync::SCHEMA_VERSION;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Serialized by e3-events at 5357d5d3b62703eab217888aace77d45edad2858 (schema 7).
// Both fixtures round-trip with that serializer and omit the schema-8 bundle signature.
const SCHEMA_SEVEN_EVENTS: [&str; 2] = [
    include_str!("fixtures/threshold-share-schema7.hex"),
    include_str!("fixtures/decryption-key-schema7.hex"),
];

fn node_config(root: &Path) -> Result<AppConfig> {
    let config: UnscopedAppConfig = serde_yaml::from_str("node:\n  network: local\n")?;
    config.into_scoped_with_defaults(
        "_default",
        &root.join("data"),
        &root.join("config"),
        &root.to_path_buf(),
    )
}

fn older_store(config: &AppConfig, fixture: &str, schema: Option<u32>) -> Result<PathBuf> {
    let bytes = hex::decode(fixture.trim())?;
    assert!(InterfoldEvent::<Unsequenced>::from_bytes(&bytes).is_err());
    let mut db = SledDb::new(&config.db_file(), "datastore")?;
    if let Some(schema) = schema {
        db.insert(Insert::new(
            StoreKeys::schema_version(),
            bincode::serialize(&schema)?,
        ))?;
        // A snapshot in an unsupported layout must not obscure the schema error either.
        db.insert(Insert::new(
            StoreKeys::node_state(),
            u64::MAX.to_le_bytes().to_vec(),
        ))?;
    }
    db.flush()?;

    let path = e3_utils::enumerate_path(&config.log_file(), 0);
    let mut log = CommitLog::new(LogOptions::new(&path))?;
    log.append_msg(bytes)?;
    log.flush()?;
    drop(log);
    OpenOptions::new()
        .append(true)
        .open(path.join("00000000000000000000.log"))?
        .write_all(b"torn")?;
    Ok(path)
}

fn log_files(path: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    fs::read_dir(path)?
        .map(|entry| {
            let path = entry?.path();
            Ok((path.clone(), fs::read(path)?))
        })
        .collect()
}

fn assert_schema_error(message: &str, schema: Option<u32>) {
    match schema {
        Some(7) => {
            assert!(message.contains("schema version 7 is older"), "{message}");
            assert!(message.contains("interfold node reset-data"), "{message}");
        }
        Some(_) => {
            assert!(message.contains("newer than this binary"), "{message}");
            assert!(message.contains("backup"), "{message}");
        }
        None => {
            assert!(message.contains("no schema marker"), "{message}");
            assert!(message.contains("interfold node reset-data"), "{message}");
        }
    }
}

#[actix::test]
async fn startup_rejects_older_schema_before_log_recovery() -> Result<()> {
    let cipher = Arc::new(Cipher::from_password("schema-admission-test").await?);
    for fixture in SCHEMA_SEVEN_EVENTS {
        for schema in [Some(7), Some(SCHEMA_VERSION + 1), None] {
            let root = tempfile::tempdir()?;
            let config = node_config(root.path())?;
            let path = older_store(&config, fixture, schema)?;
            let before = log_files(&path)?;
            let error =
                CiphernodeBuilder::new(e3_test_helpers::derive_shared_rng(1, 1), cipher.clone())
                    .with_persistence(&config.log_file(), &config.db_file())
                    .build()
                    .await
                    .expect_err("startup must reject unsupported storage");
            assert_schema_error(&format!("{error:#}"), schema);
            assert_eq!(log_files(&path)?, before);
        }
    }
    Ok(())
}

#[actix::test]
async fn validate_reports_a_store_from_an_older_schema() -> Result<()> {
    for fixture in SCHEMA_SEVEN_EVENTS {
        for schema in [Some(7), Some(SCHEMA_VERSION + 1), None] {
            let root = tempfile::tempdir()?;
            let config = node_config(root.path())?;
            let path = older_store(&config, fixture, schema)?;
            let before = log_files(&path)?;
            for repair in [false, true] {
                let report = validate_node(&config, repair).await?;
                let check = report
                    .checks
                    .iter()
                    .find(|check| check.name == "schema")
                    .expect("the report must check the schema before reading the log");
                assert_eq!(check.severity, Severity::Fail);
                assert_schema_error(&check.detail, schema);
                assert!(report.checks.iter().any(|check| check.name == "skipped"));
                assert!(!report.checks.iter().any(|check| check.name == "event-log"));
                assert_eq!(log_files(&path)?, before);
            }
        }
    }

    // Empty segments and the complete identity pair still permit first boot. Validation does
    // not stamp the marker; startup remains responsible for schema and node-role initialization.
    for identity in [false, true] {
        let root = tempfile::tempdir()?;
        let config = node_config(root.path())?;
        let mut db = SledDb::new(&config.db_file(), "datastore")?;
        if identity {
            for key in [StoreKeys::eth_private_key(), StoreKeys::libp2p_keypair()] {
                db.insert(Insert::new(key, bincode::serialize(&vec![1_u8])?))?;
            }
        }
        let path = e3_utils::enumerate_path(&config.log_file(), 0);
        drop(CommitLog::new(LogOptions::new(path))?);
        let report = validate_node(&config, false).await?;
        assert!(!report.has_failure(), "{}", report.render());
        assert_eq!(db.get(Get::new(StoreKeys::schema_version()))?, None);
    }
    Ok(())
}

/// Validation opens no store where the data directory has none: opening one creates it. A data
/// directory with neither a store nor events belongs to a node that has not started; one with
/// events but no store is broken. An empty folder at the store path, as a mount point, holds no
/// store either, and stays empty.
#[actix::test]
async fn validate_creates_no_store() -> Result<()> {
    for (with_events, empty_folder) in [(false, false), (true, false), (false, true)] {
        let root = tempfile::tempdir()?;
        let config = node_config(root.path())?;
        if empty_folder {
            std::fs::create_dir_all(config.db_file())?;
        }
        if with_events {
            let path = e3_utils::enumerate_path(&config.log_file(), 0);
            let mut log = CommitLog::new(LogOptions::new(&path))?;
            log.append_msg(b"an event")?;
            log.flush()?;
        }
        let report = validate_node(&config, false).await?;
        let check = report
            .checks
            .iter()
            .find(|check| check.name == "store")
            .expect("the report must say that there is no store");
        assert_eq!(
            check.severity,
            if with_events {
                Severity::Fail
            } else {
                Severity::Warn
            },
            "{}",
            report.render()
        );
        if empty_folder {
            assert_eq!(
                std::fs::read_dir(config.db_file())?.count(),
                0,
                "validation wrote into the empty store folder"
            );
        } else {
            assert!(!config.db_file().exists(), "validation created a store");
        }
    }
    Ok(())
}

#[actix::test]
async fn event_reader_rejects_older_schema_before_log_recovery() -> Result<()> {
    for fixture in SCHEMA_SEVEN_EVENTS {
        let root = tempfile::tempdir()?;
        let config = node_config(root.path())?;
        let path = older_store(&config, fixture, Some(7))?;
        let before = log_files(&path)?;
        let error = get_eventstore_reader(&config)
            .expect_err("the event reader must reject unsupported storage");
        assert_schema_error(&format!("{error:#}"), Some(7));
        assert_eq!(log_files(&path)?, before);
    }

    let root = tempfile::tempdir()?;
    let config = node_config(root.path())?;
    let mut db = SledDb::new(&config.db_file(), "datastore")?;
    db.insert(Insert::new(
        StoreKeys::schema_version(),
        bincode::serialize(&SCHEMA_VERSION)?,
    ))?;
    let system = EventSystem::persisted(config.log_file(), config.db_file()).with_fresh_bus();
    system.eventstore_reader()?;
    Ok(())
}

/// A store folder with other content than a store is a damaged store, not a node that has not
/// started; and the event log of a chain that the configuration no longer has still counts.
#[actix::test]
async fn validate_reports_a_damaged_store_and_every_event_log() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = node_config(root.path())?;
    std::fs::create_dir_all(config.db_file())?;
    std::fs::write(config.db_file().join("conf"), b"partial")?;
    let report = validate_node(&config, false).await?;
    let store = report
        .checks
        .iter()
        .find(|check| check.name == "store")
        .expect("a store check");
    assert_eq!(store.severity, Severity::Fail, "{}", report.render());

    let root = tempfile::tempdir()?;
    let config = node_config(root.path())?;
    let path = e3_utils::enumerate_path(&config.log_file(), 7);
    let mut log = CommitLog::new(LogOptions::new(&path))?;
    log.append_msg(b"an event")?;
    log.flush()?;
    let report = validate_node(&config, false).await?;
    let store = report
        .checks
        .iter()
        .find(|check| check.name == "store")
        .expect("a store check");
    assert_eq!(store.severity, Severity::Fail, "{}", report.render());
    Ok(())
}
