// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The purge behind `interfold nodes purge` and `interfold purge-all` must not delete the state or
//! the key file of a running node. It must not delete a key share that an active E3 needs. When it
//! cannot check a node, it must refuse.
//!
//! All scenarios run in one test. `execute` opens stores through the process-wide event bus, and
//! that bus stops with the actix system that started it. A second test in this binary could stop
//! that system while this test still uses the bus.

use anyhow::Result;
use e3_ciphernode_builder::get_interfold_bus_handle;
use e3_config::{AppConfig, UnscopedAppConfig};
use e3_data::{DataStore, RepositoriesFactory, SledDb};
use e3_entrypoint::fence::ProcessFence;
use e3_entrypoint::helpers::datastore::setup_datastore;
use e3_entrypoint::nodes::purge::{execute, PurgeTargets};
use e3_events::{E3Stage, E3id, StoreKeys};
use e3_keyshare::ThresholdKeyshareRepositoryFactory;
use e3_request::E3LifecycleRepositoryFactory;
use std::collections::HashMap;
use std::path::Path;

fn e3_id() -> E3id {
    E3id::new("42", 1)
}

/// A node named `name` with its data in `data_dir` and its key file in `config_dir`. `extra` adds
/// YAML lines to the node's profile.
fn node_with(
    dir: &Path,
    data_dir: &Path,
    config_dir: &Path,
    name: &str,
    extra: &str,
) -> Result<AppConfig> {
    let config: UnscopedAppConfig =
        serde_yaml::from_str(&format!("nodes:\n  {name}:\n    network: local\n{extra}"))?;
    config.into_scoped_with_defaults(
        name,
        &data_dir.to_path_buf(),
        &config_dir.to_path_buf(),
        &dir.to_path_buf(),
    )
}

/// A node named `name` whose data and configuration are in `dir/.interfold`.
fn project_node(dir: &Path, name: &str) -> Result<AppConfig> {
    let root = dir.join(".interfold");
    node_with(dir, &root.join("data"), &root.join("config"), name, "")
}

/// Stores the operator identity, a stage for the test E3, and a key-share record for it, as a
/// committee member does. Also writes the node's key file.
async fn write_state(config: &AppConfig, stage: E3Stage) -> Result<()> {
    let bus = get_interfold_bus_handle()?;
    let repositories = setup_datastore(config, &bus)?.repositories();
    repositories
        .store
        .write_batch_sync(vec![(StoreKeys::eth_private_key(), vec![7_u8; 32])])
        .await?;
    repositories
        .e3_lifecycle()
        .write_sync(&HashMap::from([(e3_id(), stage)]))
        .await?;
    DataStore::from(repositories.threshold_keyshare(&e3_id()))
        .write_sync(vec![1_u8, 2, 3])
        .await?;
    repositories.store.shutdown().await?;
    SledDb::close_all_connections();
    write_key_file(config)
}

/// Creates an empty store, as a local command run with another environment does.
async fn write_empty_store(config: &AppConfig) -> Result<()> {
    let bus = get_interfold_bus_handle()?;
    let repositories = setup_datastore(config, &bus)?.repositories();
    repositories.store.shutdown().await?;
    SledDb::close_all_connections();
    Ok(())
}

fn write_key_file(config: &AppConfig) -> Result<()> {
    std::fs::create_dir_all(config.key_file().parent().unwrap())?;
    std::fs::write(config.key_file(), b"operator key")?;
    Ok(())
}

/// Whether the store and the key file of every node are still present.
fn untouched(nodes: &[&AppConfig]) -> bool {
    nodes
        .iter()
        .all(|node| node.db_file().exists() && node.key_file().exists())
}

fn purged(dir: &Path) -> bool {
    !dir.join(".interfold/data").exists() && !dir.join(".interfold/config").exists()
}

async fn assert_refused(
    targets: &PurgeTargets,
    nodes: &[AppConfig],
    allow_active_e3s: bool,
    expected: &[&str],
) {
    let message = match execute(targets, nodes, allow_active_e3s).await {
        Ok(()) => panic!("the purge must refuse with {expected:?}"),
        Err(error) => error.to_string(),
    };
    // The CLI prints only the top-level message, so it must carry every detail.
    for text in expected {
        assert!(message.contains(text), "expected {text:?} in: {message}");
    }
}

/// The default layout: node `active` holds a key share for an E3 at `KeyPublished`, and node
/// `idle` for a complete E3.
async fn default_layout() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![
        project_node(project.path(), "active")?,
        project_node(project.path(), "idle")?,
    ];
    let (active, idle) = (&nodes[0], &nodes[1]);
    write_state(active, E3Stage::KeyPublished).await?;
    write_state(idle, E3Stage::Complete).await?;

    assert_refused(
        &targets,
        &nodes,
        false,
        &[
            "node `active`",
            "E3 1:42 at stage KeyPublished",
            "--allow-active-e3s",
        ],
    )
    .await;
    assert!(untouched(&[active, idle]));

    // A running node blocks the purge, even with the override.
    let running = ProcessFence::acquire(&idle.db_file(), "idle")?;
    assert_refused(
        &targets,
        &nodes,
        true,
        &["Node `idle` is running", "holds its lock"],
    )
    .await;
    assert!(untouched(&[active, idle]));
    drop(running);

    execute(&targets, &nodes, true).await?;
    assert!(purged(project.path()));

    // Without active key shares, no override is needed.
    let finished = tempfile::tempdir()?;
    let done = project_node(finished.path(), "done")?;
    write_state(&done, E3Stage::Complete).await?;
    execute(&PurgeTargets::in_dir(finished.path()), &[done], false).await?;
    assert!(purged(finished.path()));
    Ok(())
}

/// The node's store is outside the project, as with `E3_DATA_DIR`, and its key file is inside.
/// Deleting the key file makes the stored key share unreadable.
async fn store_outside_the_project() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![node_with(
        project.path(),
        &elsewhere.path().join("data"),
        &project.path().join(".interfold/config"),
        "moved",
        "",
    )?];
    let node = &nodes[0];
    write_state(node, E3Stage::KeyPublished).await?;

    assert_refused(&targets, &nodes, false, &["node `moved`", "KeyPublished"]).await;
    let running = ProcessFence::acquire(&node.db_file(), "moved")?;
    assert_refused(
        &targets,
        &nodes,
        true,
        &["Node `moved` is running", "holds its lock"],
    )
    .await;
    assert!(untouched(&[node]));
    drop(running);

    // With the override, the purge deletes the key file and keeps the store outside the project.
    execute(&targets, &nodes, true).await?;
    assert!(purged(project.path()));
    assert!(node.db_file().exists());
    Ok(())
}

/// The store outside the project is a symbolic link, as when an operator moves the store to
/// another disk. `start` locks the folder of the link, not the folder of the store.
async fn store_behind_a_link() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![node_with(
        project.path(),
        &elsewhere.path().join("data"),
        &project.path().join(".interfold/config"),
        "linked",
        "",
    )?];
    let node = &nodes[0];
    write_state(node, E3Stage::Complete).await?;
    let moved = elsewhere.path().join("disk/linked-db");
    std::fs::create_dir_all(moved.parent().unwrap())?;
    std::fs::rename(node.db_file(), &moved)?;
    std::os::unix::fs::symlink(&moved, node.db_file())?;

    let running = ProcessFence::acquire(&node.db_file(), "linked")?;
    assert_refused(
        &targets,
        &nodes,
        true,
        &["Node `linked` is running", "holds its lock"],
    )
    .await;
    assert!(untouched(&[node]));
    drop(running);
    Ok(())
}

/// The key file's path goes through a symbolic link to the project, and the purge names the project
/// directly. The store is outside the project, so only the key file puts the node in scope.
async fn key_file_through_a_link() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let link = elsewhere.path().join("project");
    std::os::unix::fs::symlink(project.path(), &link)?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![node_with(
        &link,
        &elsewhere.path().join("data"),
        &link.join(".interfold/config"),
        "through",
        "",
    )?];
    let node = &nodes[0];
    write_state(node, E3Stage::Complete).await?;

    let running = ProcessFence::acquire(&node.db_file(), "through")?;
    assert_refused(
        &targets,
        &nodes,
        true,
        &["Node `through` is running", "holds its lock"],
    )
    .await;
    assert!(untouched(&[node]));
    drop(running);
    Ok(())
}

/// Two profiles keep their stores in one folder. The purge checks each store, not each folder.
async fn two_stores_in_one_folder() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let data_dir = elsewhere.path().join("data");
    let config_dir = project.path().join(".interfold/config");
    let nodes = vec![
        node_with(
            project.path(),
            &data_dir,
            &config_dir,
            "one",
            "    db_file: ../shared/one\n",
        )?,
        node_with(
            project.path(),
            &data_dir,
            &config_dir,
            "two",
            "    db_file: ../shared/two\n",
        )?,
    ];
    assert_eq!(nodes[0].db_file().parent(), nodes[1].db_file().parent());
    write_state(&nodes[0], E3Stage::Complete).await?;
    write_state(&nodes[1], E3Stage::KeyPublished).await?;

    assert_refused(&targets, &nodes, false, &["node `two`", "KeyPublished"]).await;
    assert!(untouched(&[&nodes[0], &nodes[1]]));
    Ok(())
}

/// The purge would delete the node's key file, but the store is not at the configured path. The
/// node can run with another `E3_DATA_DIR`.
async fn store_not_found() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![node_with(
        project.path(),
        &elsewhere.path().join("missing"),
        &project.path().join(".interfold/config"),
        "away",
        "",
    )?];
    write_key_file(&nodes[0])?;

    assert_refused(
        &targets,
        &nodes,
        false,
        &["node `away`", "its store is not at", "--allow-active-e3s"],
    )
    .await;
    assert!(nodes[0].key_file().exists());

    execute(&targets, &nodes, true).await?;
    assert!(purged(project.path()));
    Ok(())
}

/// A node folder in the data folder that no configured node names, such as a renamed profile.
async fn folder_without_a_profile() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let stale = project_node(project.path(), "stale")?;
    write_state(&stale, E3Stage::KeyPublished).await?;

    assert_refused(&targets, &[], false, &["node `stale`", "KeyPublished"]).await;
    let running = ProcessFence::acquire(&stale.db_file(), "stale")?;
    assert_refused(
        &targets,
        &[],
        true,
        &["Node `stale` is running", "holds its lock"],
    )
    .await;
    assert!(untouched(&[&stale]));
    drop(running);
    Ok(())
}

/// A key file whose node is neither configured nor stored in the data folder.
async fn key_folder_without_a_node() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let key_file = project.path().join(".interfold/config/ghost/key");
    std::fs::create_dir_all(key_file.parent().unwrap())?;
    std::fs::write(&key_file, b"operator key")?;

    assert_refused(
        &targets,
        &[],
        false,
        &["node `ghost`", "no configured node keeps its key file"],
    )
    .await;
    assert!(key_file.exists());

    execute(&targets, &[], true).await?;
    assert!(purged(project.path()));
    Ok(())
}

/// Another process has the store open without the process lock. sled refuses a second open, so
/// the purge treats the node as running, even with the override.
async fn store_open_elsewhere() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![project_node(project.path(), "open")?];
    write_state(&nodes[0], E3Stage::Complete).await?;

    // A handle outside the store cache holds sled's lock, as another process does.
    let open = sled::open(nodes[0].db_file())?;
    assert_refused(
        &targets,
        &nodes,
        true,
        &["Node `open` is running", "has its store at"],
    )
    .await;
    assert!(untouched(&[&nodes[0]]));
    drop(open);
    Ok(())
}

/// A store without an operator key sits at the configured path. `node validate` leaves such a store
/// when it runs without the node's `E3_DATA_DIR`. It is not the store that the key file protects.
async fn empty_store_at_the_configured_path() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![project_node(project.path(), "decoy")?];
    write_empty_store(&nodes[0]).await?;
    write_key_file(&nodes[0])?;

    assert_refused(
        &targets,
        &nodes,
        false,
        &["node `decoy`", "holds no operator key"],
    )
    .await;
    assert!(untouched(&[&nodes[0]]));
    Ok(())
}

/// A refusal creates nothing, not even the folder of a configured node that never started.
async fn refusal_creates_nothing() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![
        project_node(project.path(), "active")?,
        project_node(project.path(), "later")?,
    ];
    write_state(&nodes[0], E3Stage::KeyPublished).await?;

    assert_refused(&targets, &nodes, false, &["node `active`", "KeyPublished"]).await;
    assert!(!project.path().join(".interfold/data/later").exists());
    Ok(())
}

/// A link in the data folder must lead to a store or a node folder that the purge checks.
async fn links_in_the_data_folder() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![project_node(project.path(), "cn1")?];
    write_state(&nodes[0], E3Stage::Complete).await?;
    let data = project.path().join(".interfold/data");

    std::os::unix::fs::symlink(elsewhere.path(), data.join("outside"))?;
    assert_refused(
        &targets,
        &nodes,
        false,
        &[
            "node `outside`",
            "symbolic link to state that the purge does not check",
        ],
    )
    .await;
    std::fs::remove_file(data.join("outside"))?;

    // A link to a node folder that the purge locks needs no override.
    std::os::unix::fs::symlink(data.join("cn1"), data.join("alias"))?;
    execute(&targets, &nodes, false).await?;
    assert!(purged(project.path()));
    assert!(elsewhere.path().exists());
    Ok(())
}

/// The purge empties the node folders before it deletes the key files. When it stops part of the
/// way, it keeps the key files. A second run finishes without an override.
async fn deletion_order_and_rerun() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![project_node(project.path(), "cn1")?];
    write_state(&nodes[0], E3Stage::Complete).await?;
    let key_folder = nodes[0].key_file().parent().unwrap().to_path_buf();
    let node_folder = project.path().join(".interfold/data/cn1");

    // A key folder without write permission stops the deletion of the key files.
    std::fs::set_permissions(&key_folder, std::fs::Permissions::from_mode(0o555))?;
    let result = execute(&targets, &nodes, false).await;
    std::fs::set_permissions(&key_folder, std::fs::Permissions::from_mode(0o755))?;
    let message = result.expect_err("the purge must stop").to_string();
    assert!(
        message.contains("Part of the state can be gone"),
        "the error must say that part of the state can be gone, got: {message}"
    );
    let left: Vec<_> = std::fs::read_dir(&node_folder)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()?;
    assert_eq!(
        left,
        ["interfold.lock"],
        "the node folder must hold only its lock"
    );
    assert!(
        nodes[0].key_file().exists(),
        "the key file must still exist"
    );

    execute(&targets, &nodes, false).await?;
    assert!(purged(project.path()));
    Ok(())
}

/// The purge would delete the node's event log, but its store is missing. The key file is outside
/// the project, so only the event log puts the node in scope.
async fn event_log_without_a_store() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![node_with(
        project.path(),
        &project.path().join(".interfold/data"),
        &elsewhere.path().join("config"),
        "logged",
        "",
    )?];
    std::fs::create_dir_all(project.path().join(".interfold/data/logged/log.0"))?;

    assert_refused(
        &targets,
        &nodes,
        false,
        &["node `logged`", "its store is not at"],
    )
    .await;
    Ok(())
}

/// A file directly in the configuration folder must be a configured node's key file.
async fn unknown_config_file() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let stray = project.path().join(".interfold/config/stray");
    std::fs::create_dir_all(stray.parent().unwrap())?;
    std::fs::write(&stray, b"operator key")?;

    assert_refused(
        &targets,
        &[],
        false,
        &["node `stray`", "no configured node uses"],
    )
    .await;
    assert!(stray.exists());
    Ok(())
}

/// The purge reports every refusal at once, because the override covers all of them.
async fn every_refusal_at_once() -> Result<()> {
    let project = tempfile::tempdir()?;
    let targets = PurgeTargets::in_dir(project.path());
    let nodes = vec![
        project_node(project.path(), "active")?,
        project_node(project.path(), "decoy")?,
    ];
    write_state(&nodes[0], E3Stage::KeyPublished).await?;
    write_empty_store(&nodes[1]).await?;
    write_key_file(&nodes[1])?;

    assert_refused(
        &targets,
        &nodes,
        false,
        &[
            "for 2 reasons",
            "node `active`",
            "node `decoy`",
            "overrides all of them at once",
        ],
    )
    .await;
    assert!(untouched(&[&nodes[0], &nodes[1]]));
    Ok(())
}

/// The purge refuses a target folder that is a symbolic link, because it does not follow links.
async fn target_is_a_link() -> Result<()> {
    let project = tempfile::tempdir()?;
    let elsewhere = tempfile::tempdir()?;
    std::fs::create_dir_all(project.path().join(".interfold"))?;
    std::os::unix::fs::symlink(elsewhere.path(), project.path().join(".interfold/config"))?;
    assert_refused(
        &PurgeTargets::in_dir(project.path()),
        &[],
        true,
        &["is a symbolic link"],
    )
    .await;
    assert!(project.path().join(".interfold/config").exists());
    Ok(())
}

#[actix::test]
async fn purge_refuses_to_delete_a_running_node_or_an_active_key_share() -> Result<()> {
    default_layout().await?;
    store_outside_the_project().await?;
    store_behind_a_link().await?;
    key_file_through_a_link().await?;
    two_stores_in_one_folder().await?;
    store_not_found().await?;
    folder_without_a_profile().await?;
    key_folder_without_a_node().await?;
    store_open_elsewhere().await?;
    empty_store_at_the_configured_path().await?;
    refusal_creates_nothing().await?;
    links_in_the_data_folder().await?;
    deletion_order_and_rerun().await?;
    event_log_without_a_store().await?;
    unknown_config_file().await?;
    every_refusal_at_once().await?;
    target_is_a_link().await
}
