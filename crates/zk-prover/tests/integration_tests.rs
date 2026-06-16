// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Integration tests that require network access to download binaries.
//! Run with: cargo test --features integration-tests

#![cfg(feature = "integration-tests")]

mod common;

use common::test_backend;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::dkg::pk::circuit::{PkCircuit, PkCircuitData};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{test_utils::get_tempdir, BbTarget, Provable, SetupStatus, ZkConfig, ZkProver};
use sha2::{Digest, Sha256};
use std::env;
use std::path::Path;

/// Default committee for downloaded release artifacts (minimum matches dev/CI convention).
const RELEASE_COMMITTEE: CiphernodesCommitteeSize = CiphernodesCommitteeSize::Minimum;

fn preset_committee_dir(circuits_dir: &Path, preset: &BfvPreset) -> std::path::PathBuf {
    circuits_dir.join(preset.artifacts_dir_for_committee(RELEASE_COMMITTEE.as_str()))
}

#[tokio::test]
async fn test_full_flow_download_circuits_prove_and_verify() {
    let config = ZkConfig::default();

    let temp = get_tempdir().unwrap();
    let backend = test_backend(temp.path(), config);

    if !backend.using_custom_bb {
        assert!(matches!(
            backend.check_status().await,
            SetupStatus::FullSetupNeeded
        ));

        let result = backend.download_bb().await;
        assert!(result.is_ok(), "download failed: {:?}", result);
        assert!(backend.bb_binary.exists(), "bb binary not found");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&backend.bb_binary).unwrap().permissions();
            assert_eq!(perms.mode() & 0o111, 0o111, "bb should be executable");
        }

        let metadata = std::fs::metadata(&backend.bb_binary).unwrap();
        assert!(metadata.len() > 0, "bb binary should not be empty");

        let version_info = backend.load_version_info().await;
        assert_eq!(
            version_info.bb_version.as_deref(),
            Some(backend.config.required_bb_version.as_str())
        );
        assert!(version_info.last_updated.is_some());

        if backend
            .config
            .bb_checksum_for(BbTarget::current().unwrap())
            .is_some()
        {
            assert!(
                version_info.bb_checksum.is_some(),
                "checksum should be saved in version.json"
            );
        }

        assert!(backend.base_dir.exists());
        assert!(backend.base_dir.join("bin").exists());
    }

    let version = backend.verify_bb().await;
    assert!(version.is_ok(), "bb --version failed: {:?}", version);
    println!("bb version: {}", version.unwrap());

    // --- Step 3: Download circuits ---
    tokio::fs::create_dir_all(&backend.circuits_dir)
        .await
        .unwrap();

    let result = backend.download_circuits().await;
    assert!(result.is_ok(), "download_circuits failed: {:?}", result);

    // Circuit artifacts live under `{preset}/{committee}/{variant}/...` in v0.2.0+ releases.
    let preset = BfvPreset::InsecureThreshold512;
    let preset_dir = preset_committee_dir(&backend.circuits_dir, &preset);
    assert!(
        preset_dir
            .join("default")
            .join("dkg")
            .join("pk")
            .join("pk.json")
            .exists(),
        "expected circuit at {}/default/dkg/pk/pk.json",
        preset_dir.display()
    );
    assert!(
        preset_dir
            .join("default")
            .join("dkg")
            .join("pk")
            .join("pk.vk")
            .exists(),
        "expected VK at {}/default/dkg/pk/pk.vk",
        preset_dir.display()
    );
    assert!(
        preset_dir
            .join("evm")
            .join("dkg")
            .join("pk")
            .join("pk.vk")
            .exists(),
        "expected evm VK at {}/evm/dkg/pk/pk.vk",
        preset_dir.display()
    );

    let result = backend.ensure_installed().await;
    assert!(result.is_ok(), "ensure_installed failed: {:?}", result);
    assert!(matches!(backend.check_status().await, SetupStatus::Ready));

    assert!(backend.bb_binary.exists());
    assert!(backend.circuits_dir.exists());
    assert!(backend.work_dir.exists());
    assert!(backend.base_dir.join("version.json").exists());

    let prover = ZkProver::new(&backend);
    let artifacts_dir = preset.artifacts_dir_for_committee(RELEASE_COMMITTEE.as_str());

    let sample =
        PkCircuitData::generate_sample(preset).expect("sample data generation should succeed");

    let e3_id = "integration-test-full-flow";
    let proof = PkCircuit
        .prove(&prover, &preset, &sample, e3_id, &artifacts_dir)
        .expect("proof generation should succeed");

    assert!(!proof.data.is_empty(), "proof data should not be empty");
    assert!(
        !proof.public_signals.is_empty(),
        "public signals should not be empty"
    );

    let party_id = 0;
    let verified = PkCircuit
        .verify(&prover, &proof, e3_id, party_id, &artifacts_dir)
        .expect("verification call should not error");

    assert!(verified, "proof should verify successfully");

    prover.cleanup(e3_id).unwrap();

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}

#[tokio::test]
async fn test_download_bb_rejects_wrong_checksum() {
    if env::var("E3_CUSTOM_BB").is_ok() {
        return;
    }

    let mut config = ZkConfig::default();

    for checksum in config.bb_checksums.values_mut() {
        *checksum = "0".repeat(64);
    }

    let temp = get_tempdir().unwrap();
    let backend = test_backend(temp.path(), config);

    let result = backend.download_bb().await;
    assert!(
        matches!(result, Err(e3_zk_prover::ZkError::ChecksumMismatch { .. })),
        "expected ChecksumMismatch, got {:?}",
        result
    );

    assert!(!backend.bb_binary.exists());

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}

#[tokio::test]
async fn test_download_circuits_verifies_checksums() {
    let config = ZkConfig::default();
    let temp = get_tempdir().unwrap();
    let backend = test_backend(temp.path(), config);

    let result = backend.download_circuits().await;
    assert!(result.is_ok(), "download_circuits failed: {:?}", result);

    let version_info = backend.load_version_info().await;

    // If the archive included a checksums.json, verify_circuits should have
    // populated version_info.circuits with entries and valid SHA256 hashes.
    if !version_info.circuits.is_empty() {
        for (rel_path, circuit_info) in &version_info.circuits {
            assert_eq!(rel_path, &circuit_info.file);
            assert!(
                !circuit_info.checksum.is_empty(),
                "checksum should not be empty for {}",
                rel_path
            );

            // Re-read the file from disk and verify the stored checksum matches.
            let file_path = backend
                .locate_manifest_artifact(rel_path, &circuit_info.checksum)
                .await
                .unwrap_or_else(|e| {
                    panic!("circuit file should exist on disk for {}: {e:?}", rel_path)
                });

            let data = tokio::fs::read(&file_path).await.unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual_hash = hex::encode(hasher.finalize());

            assert_eq!(
                actual_hash, circuit_info.checksum,
                "stored checksum for {} doesn't match file on disk",
                rel_path
            );
        }
    }

    let temp_path = temp.path().to_path_buf();
    drop(temp);
    assert!(!temp_path.exists());
}
