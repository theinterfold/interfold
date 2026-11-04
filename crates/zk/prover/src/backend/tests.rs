// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::HashMap;

use super::*;
use crate::{
    config::{CircuitInfo, VersionInfo},
    test_utils::get_tempdir,
};
use tokio::fs;

const TEST_CIRCUIT: &str = "default/test/artifact.bin";

fn test_backend(temp_path: &std::path::Path, config: ZkConfig) -> ZkBackend {
    let noir_dir = temp_path.join("noir");
    let bb_binary = BBPath::Default(noir_dir.join("bin").join("bb"));
    let circuits_dir = noir_dir.join("circuits");
    let work_dir = noir_dir.join("work").join("test_node");
    ZkBackend::with_config(bb_binary, circuits_dir, work_dir, config)
}

async fn seed_circuit(backend: &ZkBackend, create_file: bool) -> VersionInfo {
    fs::create_dir_all(&backend.circuits_dir).await.unwrap();
    if create_file {
        let artifact = backend.circuits_dir.join(TEST_CIRCUIT);
        fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        fs::write(&artifact, b"circuit artifact").await.unwrap();
    }

    let mut circuits = HashMap::new();
    circuits.insert(
        TEST_CIRCUIT.to_owned(),
        CircuitInfo {
            file: TEST_CIRCUIT.to_owned(),
            checksum: "unused-by-status".to_owned(),
        },
    );
    VersionInfo {
        circuits_version: Some(backend.config.required_circuits_version.clone()),
        circuits,
        ..Default::default()
    }
}

#[cfg(unix)]
async fn write_bb(backend: &ZkBackend, version: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(&backend.base_dir.join("bin"))
        .await
        .unwrap();
    fs::write(
        &backend.bb_binary,
        format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n"),
    )
    .await
    .unwrap();
    fs::set_permissions(&backend.bb_binary, std::fs::Permissions::from_mode(0o755))
        .await
        .unwrap();
}

#[tokio::test]
async fn test_check_status_full_setup_needed() {
    let temp = get_tempdir().unwrap();
    let backend = test_backend(temp.path(), ZkConfig::default());

    let status = backend.check_status().await;
    assert!(matches!(status, SetupStatus::FullSetupNeeded));

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}

#[tokio::test]
#[cfg(unix)]
async fn test_check_status_ready_when_installed() {
    let temp = get_tempdir().unwrap();
    let config = ZkConfig::default();
    let backend = test_backend(temp.path(), config.clone());

    write_bb(&backend, &config.required_bb_version).await;

    let mut info = seed_circuit(&backend, true).await;
    info.bb_version = Some(config.required_bb_version.clone());
    info.save(&backend.version_file()).await.unwrap();

    let status = backend.check_status().await;
    assert!(matches!(status, SetupStatus::Ready));

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}

#[tokio::test]
async fn test_check_status_bb_needs_update_when_binary_is_invalid() {
    let temp = get_tempdir().unwrap();
    let config = ZkConfig::default();
    let backend = test_backend(temp.path(), config.clone());

    fs::create_dir_all(&backend.base_dir.join("bin"))
        .await
        .unwrap();
    let mut info = seed_circuit(&backend, true).await;
    info.bb_version = Some(config.required_bb_version.clone());
    fs::write(&backend.bb_binary, b"fake bb binary")
        .await
        .unwrap();
    info.save(&backend.version_file()).await.unwrap();

    let status = backend.check_status().await;
    assert!(matches!(status, SetupStatus::BbNeedsUpdate { .. }));

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn test_check_status_bb_needs_update_when_binary_version_mismatches() {
    let temp = get_tempdir().unwrap();
    let config = ZkConfig::default();
    let backend = test_backend(temp.path(), config.clone());

    write_bb(&backend, "0.0.1").await;
    let mut info = seed_circuit(&backend, true).await;
    info.bb_version = Some(config.required_bb_version.clone());
    info.save(&backend.version_file()).await.unwrap();

    let status = backend.check_status().await;
    assert!(matches!(status, SetupStatus::BbNeedsUpdate { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn test_check_status_circuits_need_update_when_recorded_artifact_is_missing() {
    let temp = get_tempdir().unwrap();
    let config = ZkConfig::default();
    let backend = test_backend(temp.path(), config.clone());

    write_bb(&backend, &config.required_bb_version).await;
    let mut info = seed_circuit(&backend, false).await;
    info.bb_version = Some(config.required_bb_version.clone());
    info.save(&backend.version_file()).await.unwrap();

    let status = backend.check_status().await;
    assert!(matches!(status, SetupStatus::CircuitsNeedUpdate { .. }));
}

#[cfg(unix)]
#[tokio::test]
async fn test_check_status_rejects_invalid_circuit_inventory() {
    let temp = get_tempdir().unwrap();
    let backend = test_backend(temp.path(), ZkConfig::default());
    write_bb(&backend, &backend.config.required_bb_version).await;
    let mut info = seed_circuit(&backend, true).await;
    info.bb_version = Some(backend.config.required_bb_version.clone());
    for file in ["", "../outside.bin", "/absolute.bin", "default/test"] {
        info.circuits.get_mut(TEST_CIRCUIT).unwrap().file = file.into();
        info.save(&backend.version_file()).await.unwrap();
        assert!(
            matches!(
                backend.check_status().await,
                SetupStatus::CircuitsNeedUpdate { .. }
            ),
            "{file}"
        );
    }
    // Each key names a valid artifact file, so only the key check can fail.
    for key in ["", "../outside.bin", "/absolute.bin"] {
        info.circuits = HashMap::from([(
            key.to_owned(),
            CircuitInfo {
                file: TEST_CIRCUIT.to_owned(),
                checksum: "unused-by-status".to_owned(),
            },
        )]);
        info.save(&backend.version_file()).await.unwrap();
        assert!(
            matches!(
                backend.check_status().await,
                SetupStatus::CircuitsNeedUpdate { .. }
            ),
            "{key}"
        );
    }
    info.circuits.clear();
    info.save(&backend.version_file()).await.unwrap();
    assert!(matches!(
        backend.check_status().await,
        SetupStatus::CircuitsNeedUpdate { .. }
    ));
}
