// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_config::BBPath;
use e3_events::CircuitName;
#[allow(unused_imports)]
pub use e3_test_helpers::{find_anvil, find_bb};
use e3_zk_prover::{ZkBackend, ZkConfig};
use std::{env, path::PathBuf};
use tempfile::TempDir;
use tokio::fs;

/// Root of the compiled circuit artifacts: `{workspace}/circuits/bin/`.
fn circuits_build_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("circuits")
        .join("bin")
}

pub async fn setup_compiled_circuit(backend: &ZkBackend, group: &str, circuit_name: &str) {
    setup_compiled_circuit_for_committee(backend, group, circuit_name, "minimum").await;
}

pub async fn setup_compiled_circuit_for_committee(
    backend: &ZkBackend,
    group: &str,
    circuit_name: &str,
    committee: &str,
) {
    let target_dir = circuits_build_root().join(group).join("target");
    let json_path = target_dir.join(format!("{circuit_name}.json"));
    let vk_evm_path = target_dir.join(format!("{circuit_name}.vk"));
    let vk_evm_hash_path = target_dir.join(format!("{circuit_name}.vk_hash"));
    let vk_recursive_path = target_dir.join(format!("{circuit_name}.vk_recursive"));
    let vk_recursive_hash_path = target_dir.join(format!("{circuit_name}.vk_recursive_hash"));
    let vk_noir_path = target_dir.join(format!("{circuit_name}.vk_noir"));
    let vk_noir_hash_path = target_dir.join(format!("{circuit_name}.vk_noir_hash"));

    assert!(
        json_path.exists(),
        "compiled circuit not found: {} (run `pnpm build:circuits` to compile)",
        json_path.display()
    );
    assert!(
        vk_evm_path.exists(),
        "evm verification key not found: {} (run `pnpm build:circuits` to compile)",
        vk_evm_path.display()
    );

    // Tests use insecure params — fixtures go under insecure-512/{committee}/
    let preset_dir = backend.circuits_dir.join("insecure-512").join(committee);

    // Set up the evm variant directory (keccak VK + hash)
    let evm_dir = preset_dir.join("evm").join(group).join(circuit_name);
    fs::create_dir_all(&evm_dir).await.unwrap();
    fs::copy(&json_path, evm_dir.join(format!("{circuit_name}.json")))
        .await
        .unwrap();
    fs::copy(&vk_evm_path, evm_dir.join(format!("{circuit_name}.vk")))
        .await
        .unwrap();
    if vk_evm_hash_path.exists() {
        fs::copy(
            &vk_evm_hash_path,
            evm_dir.join(format!("{circuit_name}.vk_hash")),
        )
        .await
        .unwrap();
    }

    // Set up the default variant directory (noir-recursive-no-zk VK for wrapper/fold proofs)
    let default_dir = preset_dir.join("default").join(group).join(circuit_name);
    fs::create_dir_all(&default_dir).await.unwrap();
    fs::copy(&json_path, default_dir.join(format!("{circuit_name}.json")))
        .await
        .unwrap();
    // Use .vk_recursive (noir-recursive-no-zk) if available, otherwise fall back to .vk
    let (default_vk_src, default_hash_src) = if vk_recursive_path.exists() {
        (&vk_recursive_path, &vk_recursive_hash_path)
    } else {
        (&vk_evm_path, &vk_evm_hash_path)
    };
    fs::copy(
        default_vk_src,
        default_dir.join(format!("{circuit_name}.vk")),
    )
    .await
    .unwrap();
    if default_hash_src.exists() {
        fs::copy(
            default_hash_src,
            default_dir.join(format!("{circuit_name}.vk_hash")),
        )
        .await
        .unwrap();
    }

    // Set up the recursive variant directory (noir-recursive VK for inner/base proofs)
    let recursive_dir = preset_dir.join("recursive").join(group).join(circuit_name);
    fs::create_dir_all(&recursive_dir).await.unwrap();
    fs::copy(
        &json_path,
        recursive_dir.join(format!("{circuit_name}.json")),
    )
    .await
    .unwrap();
    // Use .vk_noir (noir-recursive) if available, otherwise fall back to .vk_recursive, then .vk
    let (recursive_vk_src, recursive_hash_src) = if vk_noir_path.exists() {
        (&vk_noir_path, &vk_noir_hash_path)
    } else if vk_recursive_path.exists() {
        (&vk_recursive_path, &vk_recursive_hash_path)
    } else {
        (&vk_evm_path, &vk_evm_hash_path)
    };
    fs::copy(
        recursive_vk_src,
        recursive_dir.join(format!("{circuit_name}.vk")),
    )
    .await
    .unwrap();
    if recursive_hash_src.exists() {
        fs::copy(
            recursive_hash_src,
            recursive_dir.join(format!("{circuit_name}.vk_hash")),
        )
        .await
        .unwrap();
    }
}

/// Stages a `recursive_aggregation/*` fold binary for [`CircuitVariant::Default`] (`noir-recursive-no-zk`).
///
/// `pnpm build:circuits` writes `{package}.vk_recursive` (+ `_hash`) under `circuits/bin/recursive_aggregation/<name>/target/`.
/// [`CircuitName::DkgAggregator`] also gets `{package}.vk` / `.vk_hash` (`bb write_vk -t evm`); when present, they are
/// copied into `insecure-512/evm/...` for [`CircuitVariant::Evm`] proving.
pub async fn setup_recursive_aggregation_fold_circuit(backend: &ZkBackend, circuit: CircuitName) {
    let pkg = circuit.as_str();
    let target_dir = circuits_build_root()
        .join("recursive_aggregation")
        .join(pkg)
        .join("target");

    let json_path = target_dir.join(format!("{pkg}.json"));
    let vk_recursive_path = target_dir.join(format!("{pkg}.vk_recursive"));
    let vk_recursive_hash_path = target_dir.join(format!("{pkg}.vk_recursive_hash"));
    let vk_evm_path = target_dir.join(format!("{pkg}.vk"));
    let vk_evm_hash_path = target_dir.join(format!("{pkg}.vk_hash"));

    assert!(
        json_path.exists(),
        "compiled fold circuit JSON not found: {} (run `pnpm build:circuits --group recursive_aggregation`)",
        json_path.display()
    );
    assert!(
        vk_recursive_path.exists(),
        "noir-recursive-no-zk VK not found: {} (aggregation circuits only emit `.vk_recursive`; run `pnpm build:circuits`)",
        vk_recursive_path.display()
    );

    let preset_dir = backend.circuits_dir.join("insecure-512").join("minimum");
    let default_dir = preset_dir.join("default").join(circuit.group()).join(pkg);
    fs::create_dir_all(&default_dir).await.unwrap();
    fs::copy(&json_path, default_dir.join(format!("{pkg}.json")))
        .await
        .unwrap();
    fs::copy(&vk_recursive_path, default_dir.join(format!("{pkg}.vk")))
        .await
        .unwrap();
    if vk_recursive_hash_path.exists() {
        fs::copy(
            &vk_recursive_hash_path,
            default_dir.join(format!("{pkg}.vk_hash")),
        )
        .await
        .unwrap();
    }

    if vk_evm_path.exists() {
        let evm_dir = preset_dir.join("evm").join(circuit.group()).join(pkg);
        fs::create_dir_all(&evm_dir).await.unwrap();
        fs::copy(&json_path, evm_dir.join(format!("{pkg}.json")))
            .await
            .unwrap();
        fs::copy(&vk_evm_path, evm_dir.join(format!("{pkg}.vk")))
            .await
            .unwrap();
        if vk_evm_hash_path.exists() {
            fs::copy(&vk_evm_hash_path, evm_dir.join(format!("{pkg}.vk_hash")))
                .await
                .unwrap();
        }
    }
}

/// Creates a temp ZkBackend with the real bb binary symlinked in.
/// Caller must hold onto the returned TempDir or it gets cleaned up.
pub async fn setup_test_prover(bb: &PathBuf) -> (ZkBackend, TempDir) {
    let target_tmp = env!("CARGO_TARGET_TMPDIR");
    let temp = TempDir::new_in(target_tmp).unwrap();

    let temp_path = temp.path();
    let noir_dir = temp_path.join("noir");
    let bb_binary = BBPath::check(noir_dir.join("bin").join("bb")).unwrap();
    let circuits_dir = noir_dir.join("circuits");
    let work_dir = noir_dir.join("work").join("test_node");
    let backend = ZkBackend::new(bb_binary.clone(), circuits_dir.clone(), work_dir.clone());

    fs::create_dir_all(&backend.circuits_dir).await.unwrap();
    fs::create_dir_all(&backend.work_dir).await.unwrap();
    fs::create_dir_all(backend.base_dir.join("bin"))
        .await
        .unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(bb, &backend.bb_binary).unwrap();

    (backend, temp)
}

/// Reads `circuits/bin/.active-preset.json` (written by `scripts/build-circuits.ts`) and
/// returns the `committee` field, normalised to lower-case (e.g. `"minimum"`, `"micro"`).
/// Returns `None` when the stamp is absent or malformed — callers must treat that as a
/// "circuits not built yet" condition rather than as a specific committee.
pub fn active_bin_committee() -> Option<String> {
    let path = circuits_build_root().join(".active-preset.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("committee")?.as_str().map(|s| s.to_lowercase())
}

/// Returns `true` when the compiled `pk_aggregation` (C5) circuit was built for the **minimum**
/// committee (H=2): `expected_threshold_pk_commitments` array length == 2.
///
/// Tests that hard-code `CiphernodesCommitteeSize::Minimum` samples should call this and skip
/// when it returns `false` — the Minimum samples will not satisfy the compiled circuit's ABI.
///
/// Prefers `.active-preset.json` (cheap stamp check) and falls back to ABI introspection of
/// `pk_aggregation.json` for older builds that pre-date the stamp's `committee` field.
pub fn circuits_compiled_for_minimum() -> bool {
    if let Some(committee) = active_bin_committee() {
        return committee == "minimum";
    }

    let path = circuits_build_root()
        .join("threshold")
        .join("pk_aggregation")
        .join("target")
        .join("pk_aggregation.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false; // artifact absent → can't tell, assume not minimum
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    // `expected_threshold_pk_commitments` is the H-length array in C5's ABI.
    v["abi"]["parameters"]
        .as_array()
        .and_then(|ps| {
            ps.iter()
                .find(|p| {
                    p.get("name")
                        == Some(&serde_json::Value::String(
                            "expected_threshold_pk_commitments".into(),
                        ))
                })
                .and_then(|p| p.get("type")?.get("length")?.as_u64())
        })
        .is_some_and(|len| len == 2) // minimum H == 2
}

/// Lightweight backend for tests that need to override config (e.g. inject bad checksums).
pub fn test_backend(temp_path: &std::path::Path, config: ZkConfig) -> ZkBackend {
    let noir_dir = temp_path.join("noir");
    let bb_binary = match env::var("E3_CUSTOM_BB") {
        Ok(path) => BBPath::Custom(PathBuf::from(path)),
        Err(_) => BBPath::Default(noir_dir.join("bin").join("bb")),
    };
    let circuits_dir = noir_dir.join("circuits");
    let work_dir = noir_dir.join("work").join("test_node");
    ZkBackend::with_config(bb_binary, circuits_dir, work_dir, config)
}
