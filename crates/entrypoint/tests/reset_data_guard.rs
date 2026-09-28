// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `interfold node reset-data` must not delete a key share that an active E3 needs.
//!
//! All scenarios run in one test. `execute` opens its store through the process-wide event bus,
//! and that bus stops with the actix system that started it. A second test in this binary could
//! stop that system while this test still uses the bus.

use anyhow::Result;
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_config::{AppConfig, UnscopedAppConfig};
use e3_data::{DataStore, Repositories, RepositoriesFactory, SledDb};
use e3_entrypoint::helpers::datastore::setup_datastore;
use e3_entrypoint::nodes::reset_data::execute;
use e3_events::{E3Stage, E3id};
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_request::E3LifecycleRepositoryFactory;
use std::collections::HashMap;
use std::path::Path;

/// A node whose data and configuration directories are under `root`.
fn node_config(root: &Path) -> Result<AppConfig> {
    let config: UnscopedAppConfig = serde_yaml::from_str("node:\n  network: local\n")?;
    config.into_scoped_with_defaults(
        "_default",
        &root.join("data"),
        &root.join("config"),
        &root.to_path_buf(),
    )
}

fn open(config: &AppConfig) -> Result<Repositories> {
    let bus = get_interfold_bus_handle()?;
    Ok(setup_datastore(config, &bus)?.repositories())
}

/// Close the store the way `execute` does, so that `execute` can open it again.
async fn close(repositories: Repositories) -> Result<()> {
    repositories.store.shutdown().await?;
    SledDb::close_all_connections();
    Ok(())
}

/// Store a stage for `e3_id` and a key-share record for it, as a committee member does.
async fn write_state(config: &AppConfig, e3_id: &E3id, stage: E3Stage) -> Result<()> {
    let repositories = open(config)?;
    repositories
        .e3_lifecycle()
        .write_sync(&HashMap::from([(e3_id.clone(), stage)]))
        .await?;
    DataStore::from(repositories.threshold_keyshare(e3_id))
        .write_sync(vec![1_u8, 2, 3])
        .await?;
    close(repositories).await
}

type StoredState = (Option<HashMap<E3id, E3Stage>>, Option<Vec<u8>>);

/// The stage map and the key-share record that the store holds for `e3_id`.
async fn read_state(config: &AppConfig, e3_id: &E3id) -> Result<StoredState> {
    let repositories = open(config)?;
    let stages = repositories.e3_lifecycle().read().await?;
    let key_share = DataStore::from(repositories.threshold_keyshare(e3_id))
        .read::<Vec<u8>>()
        .await?;
    close(repositories).await?;
    Ok((stages, key_share))
}

#[actix::test]
async fn reset_keeps_key_shares_that_active_e3s_need() -> Result<()> {
    let e3_id = E3id::new("42", 1);

    // A key share for an active E3 blocks the reset, and the refusal deletes nothing.
    let active_node = tempfile::tempdir()?;
    let config = node_config(active_node.path())?;
    write_state(&config, &e3_id, E3Stage::KeyPublished).await?;

    let error = execute(&config, false)
        .await
        .expect_err("a key share for an active E3 must block the reset");
    // The CLI prints only the top-level message.
    let message = error.to_string();
    assert!(
        message.contains("E3 1:42 at stage KeyPublished"),
        "the refusal must name the E3 and its stage, got: {message}"
    );
    assert!(
        message.contains("--allow-active-e3s"),
        "the refusal must name the override, got: {message}"
    );
    assert_eq!(
        read_state(&config, &e3_id).await?,
        (
            Some(HashMap::from([(e3_id.clone(), E3Stage::KeyPublished)])),
            Some(vec![1, 2, 3]),
        ),
        "the refusal must not delete any state"
    );

    // The override deletes the state.
    execute(&config, true).await?;
    assert_eq!(read_state(&config, &e3_id).await?, (None, None));

    // A key share for a terminal E3 does not block the reset.
    let finished_node = tempfile::tempdir()?;
    let config = node_config(finished_node.path())?;
    write_state(&config, &e3_id, E3Stage::Complete).await?;
    execute(&config, false).await?;
    assert_eq!(read_state(&config, &e3_id).await?, (None, None));
    Ok(())
}
