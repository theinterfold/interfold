// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_fhe_params::BfvPreset;
#[allow(unused_imports)]
pub use e3_test_support::find_bb;
use e3_zk_config::CircuitName;
use e3_zk_prover::{BBPath, ZkBackend, ZkConfig};
use std::{env, path::PathBuf};
use tempfile::TempDir;
use tokio::fs;

/// Explicit committee selection for secure l-BFV proof campaigns; never substitute another pair.
pub fn secure_lbfv_committee() -> e3_committee::CiphernodesCommitteeSize {
    match env::var("INTERFOLD_SECURE_16384_COMMITTEE") {
        Ok(value) => value
            .parse()
            .expect("INTERFOLD_SECURE_16384_COMMITTEE must be minimum, micro, or small"),
        Err(env::VarError::NotPresent) => e3_committee::CiphernodesCommitteeSize::Minimum,
        Err(error) => panic!("invalid INTERFOLD_SECURE_16384_COMMITTEE: {error}"),
    }
}

/// Keep saved proof campaigns for different committees separate, without replacing older runs.
pub fn secure_lbfv_cache_dir(variable: &str) -> Option<PathBuf> {
    env::var_os(variable).map(|root| {
        PathBuf::from(root).join(
            BfvPreset::SecureThreshold16384
                .artifacts_dir_for_committee(secure_lbfv_committee().as_str()),
        )
    })
}

pub async fn find_anvil() -> bool {
    if let Ok(output) = tokio::process::Command::new("which")
        .arg("anvil")
        .output()
        .await
    {
        if output.status.success() {
            return true;
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if std::path::Path::new(&format!("{}/.foundry/bin/anvil", home)).exists() {
            return true;
        }
    }
    false
}

/// Root of the compiled circuit artifacts: `{workspace}/circuits/bin/`.
fn circuits_build_root() -> PathBuf {
    e3_zk_prover::test_utils::workspace_root().join("circuits/bin")
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
    // Tests use insecure params — fixtures go under insecure-64/{committee}/
    let preset_dir = backend
        .circuits_dir
        .join(BfvPreset::InsecureThreshold64.artifacts_dir_for_committee(committee));
    stage_compiled_circuit(
        circuits_build_root().join(group).join("target"),
        preset_dir,
        group,
        circuit_name,
    )
    .await;
}

/// Stages a compiled circuit for `preset`, which must be the active build.
///
/// The package is read from its source tree (`circuits/bin/lbfv/...` for the l-BFV circuits); the
/// artifacts go to the flat `{group}/{name}` directory.
pub async fn setup_compiled_circuit_for_preset(
    backend: &ZkBackend,
    circuit: CircuitName,
    preset: BfvPreset,
    committee: &str,
) {
    assert_active_preset_matches(preset, committee);
    let preset_dir = backend
        .circuits_dir
        .join(preset.artifacts_dir_for_committee(committee));
    stage_compiled_circuit(
        workspace_target_dir(circuit),
        preset_dir,
        circuit.group(),
        circuit.as_str(),
    )
    .await;
}

/// The shared `target` directory of the workspace that builds `circuit`'s package.
fn workspace_target_dir(circuit: CircuitName) -> PathBuf {
    let group = if circuit.is_lbfv() {
        format!("lbfv/{}", circuit.group())
    } else {
        circuit.group().to_owned()
    };
    circuits_build_root().join(group).join("target")
}

async fn stage_compiled_circuit(
    target_dir: PathBuf,
    preset_dir: PathBuf,
    group: &str,
    circuit_name: &str,
) {
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

/// Sets up the final C2 and C4 circuits in every variant and the chunk and limb circuits they are
/// proven through in the `default` variant only, as `pnpm build:circuits` publishes them.
#[allow(dead_code)]
pub async fn setup_chunked_dkg_circuits(backend: &ZkBackend) {
    for circuit in [
        CircuitName::SkShareComputation,
        CircuitName::ESmShareComputation,
        CircuitName::DkgShareDecryption,
    ] {
        setup_compiled_circuit(backend, circuit.group(), circuit.as_str()).await;
    }
    setup_default_recursive_circuits(
        backend,
        &[
            CircuitName::SkShareComputationChain,
            CircuitName::SkShareComputationChainLast,
            CircuitName::ESmShareComputationChain,
            CircuitName::ESmShareComputationChainLast,
            CircuitName::DkgShareDecryptionLimb0,
            CircuitName::DkgShareDecryptionLimb1,
            CircuitName::DkgShareDecryptionLimb2,
        ],
    )
    .await;
}

/// Installs the C3 Chonk circuits: the four stack circuits from the `chonk` workspace, then the
/// tube and accumulate rollups.
#[allow(dead_code)]
pub async fn setup_c3_chonk_circuits(backend: &ZkBackend) {
    setup_default_recursive_circuits(
        backend,
        &[
            CircuitName::C3ChonkApp,
            CircuitName::C3ChonkInitKernel,
            CircuitName::C3ChonkTailKernel,
            CircuitName::C3ChonkHidingKernel,
        ],
    )
    .await;
    for circuit in [CircuitName::C3ChonkTube, CircuitName::C3ChonkAccumulate] {
        setup_recursive_aggregation_fold_circuit(backend, circuit).await;
    }
}

/// Installs the C6 Chonk circuits: the four stack circuits from the `chonk` workspace, then the
/// tube and root rollups, and the C6 tree anchor.
#[allow(dead_code)]
pub async fn setup_c6_chonk_circuits(backend: &ZkBackend) {
    setup_default_recursive_circuits(
        backend,
        &[
            CircuitName::C6ChonkApp,
            CircuitName::C6ChonkInitKernel,
            CircuitName::C6ChonkTailKernel,
            CircuitName::C6ChonkHidingKernel,
        ],
    )
    .await;
    for circuit in [CircuitName::C6ChonkTube, CircuitName::C6ChonkRoot] {
        setup_recursive_aggregation_fold_circuit(backend, circuit).await;
    }
    // The C6 tree anchor keeps the retired `c6_fold` artifact path.
    let anchor = backend
        .circuits_dir
        .join("insecure-64")
        .join("minimum")
        .join("default")
        .join(CircuitName::C6Fold.dir_path());
    fs::create_dir_all(&anchor).await.unwrap();
    fs::copy(
        circuits_build_root().join("recursive_aggregation/c6_fold/target/c6_fold.vk_tree_hash"),
        anchor.join("c6_fold.vk_tree_hash"),
    )
    .await
    .expect("C6 VK-tree anchor; run pnpm build:circuits");
}

/// Installs `circuits` in the `default` variant only, from their workspace's shared target
/// directory.
async fn setup_default_recursive_circuits(backend: &ZkBackend, circuits: &[CircuitName]) {
    for circuit in circuits {
        let pkg = circuit.as_str();
        let target_dir = circuits_build_root().join(circuit.group()).join("target");
        let default_dir = backend
            .circuits_dir
            .join("insecure-64")
            .join("minimum")
            .join("default")
            .join(circuit.group())
            .join(pkg);
        fs::create_dir_all(&default_dir).await.unwrap();
        for (from, to) in [
            ("json", "json"),
            ("vk_recursive", "vk"),
            ("vk_recursive_hash", "vk_hash"),
        ] {
            let source = target_dir.join(format!("{pkg}.{from}"));
            fs::copy(&source, default_dir.join(format!("{pkg}.{to}")))
                .await
                .unwrap_or_else(|e| {
                    panic!("{}: {e} (run `pnpm build:circuits`)", source.display())
                });
        }
    }
}

/// Stages a `recursive_aggregation/*` fold binary for [`CircuitVariant::Default`] (`noir-recursive-no-zk`).
///
/// `pnpm build:circuits` writes `{package}.vk_recursive` (+ `_hash`) under `circuits/bin/recursive_aggregation/<name>/target/`.
/// [`CircuitName::DkgAggregator`] also gets `{package}.vk` / `.vk_hash` (`bb write_vk -t evm`); when present, they are
/// copied into `insecure-64/evm/...` for [`CircuitVariant::Evm`] proving.
pub async fn setup_recursive_aggregation_fold_circuit(backend: &ZkBackend, circuit: CircuitName) {
    let preset_dir = backend.circuits_dir.join("insecure-64").join("minimum");
    stage_recursive_aggregation_fold_circuit(preset_dir, circuit).await;
}

/// [`setup_recursive_aggregation_fold_circuit`] for `preset`, which must be the active build. The
/// l-BFV packages are read from `circuits/bin/lbfv/recursive_aggregation`.
pub async fn setup_recursive_aggregation_fold_circuit_for_preset(
    backend: &ZkBackend,
    circuit: CircuitName,
    preset: BfvPreset,
    committee: &str,
) {
    assert_active_preset_matches(preset, committee);
    let preset_dir = backend
        .circuits_dir
        .join(preset.artifacts_dir_for_committee(committee));
    stage_recursive_aggregation_fold_circuit(preset_dir, circuit).await;
}

async fn stage_recursive_aggregation_fold_circuit(preset_dir: PathBuf, circuit: CircuitName) {
    let pkg = circuit.as_str();
    let target_dir = circuits_build_root()
        .join(circuit.package_path())
        .join("target");

    let json_path = target_dir.join(format!("{pkg}.json"));
    let vk_recursive_path = target_dir.join(format!("{pkg}.vk_recursive"));
    let vk_recursive_hash_path = target_dir.join(format!("{pkg}.vk_recursive_hash"));
    let vk_evm_path = target_dir.join(format!("{pkg}.vk"));
    let vk_evm_hash_path = target_dir.join(format!("{pkg}.vk_hash"));
    let vk_noir_path = target_dir.join(format!("{pkg}.vk_noir"));
    let vk_noir_hash_path = target_dir.join(format!("{pkg}.vk_noir_hash"));

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

    if circuit == CircuitName::NodesFold {
        fs::copy(
            target_dir.join(format!("{pkg}.vk_tree_hash")),
            default_dir.join(format!("{pkg}.vk_tree_hash")),
        )
        .await
        .expect("recursive VK-tree anchor; run pnpm build:circuits");
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

    if vk_noir_path.exists() {
        let recursive_dir = preset_dir.join("recursive").join(circuit.group()).join(pkg);
        fs::create_dir_all(&recursive_dir).await.unwrap();
        fs::copy(&json_path, recursive_dir.join(format!("{pkg}.json")))
            .await
            .unwrap();
        fs::copy(&vk_noir_path, recursive_dir.join(format!("{pkg}.vk")))
            .await
            .unwrap();
        if vk_noir_hash_path.exists() {
            fs::copy(
                &vk_noir_hash_path,
                recursive_dir.join(format!("{pkg}.vk_hash")),
            )
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

/// Reads `circuits/bin/.active-preset.json` (written by `pnpm build:circuits`) and
/// returns the `committee` field, normalised to lower-case (e.g. `"minimum"`, `"micro"`).
/// Returns `None` when the stamp is absent or malformed — callers must treat that as a
/// "circuits not built yet" condition rather than as a specific committee.
pub fn active_bin_committee() -> Option<String> {
    let path = circuits_build_root().join(".active-preset.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("committee")?.as_str().map(|s| s.to_lowercase())
}

pub fn active_bin_preset() -> Option<String> {
    let path = circuits_build_root().join(".active-preset.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("preset")?.as_str().map(str::to_owned)
}

fn assert_active_preset_matches(preset: BfvPreset, committee: &str) {
    let active = active_bin_preset().expect("active circuit preset stamp is required");
    let active_committee =
        active_bin_committee().expect("active circuit committee stamp is required");
    let expected = expected_preset_name(preset, committee);
    assert_eq!(
        active, expected,
        "compiled artifacts use preset {active}, but the test requested {expected}"
    );
    assert_eq!(
        active_committee, committee,
        "compiled artifacts use committee {active_committee}, but the test requested {committee}"
    );
}

pub fn compiled_circuit_artifacts_available(circuit: CircuitName) -> bool {
    let target_dir = workspace_target_dir(circuit);
    let name = circuit.as_str();
    target_dir.join(format!("{name}.json")).is_file()
        && target_dir.join(format!("{name}.vk")).is_file()
}

pub fn recursive_circuit_artifacts_available(circuit: CircuitName) -> bool {
    let target_dir = circuits_build_root()
        .join(circuit.package_path())
        .join("target");
    target_dir
        .join(format!("{}.json", circuit.as_str()))
        .is_file()
        && target_dir
            .join(format!("{}.vk_recursive", circuit.as_str()))
            .is_file()
}

fn expected_preset_name(preset: BfvPreset, committee: &str) -> String {
    preset
        .artifacts_dir_for_committee(committee)
        .split('/')
        .next()
        .unwrap()
        .to_owned()
}

pub fn require_minimum_circuits_for_preset(preset: BfvPreset) -> Option<()> {
    let Some(active) = active_bin_preset() else {
        println!("skipping: active circuit preset stamp is missing");
        return None;
    };
    let Some(committee) = active_bin_committee() else {
        println!("skipping: active circuit committee stamp is missing");
        return None;
    };
    if committee != "minimum" {
        println!(
            "skipping: circuits not compiled for minimum committee. Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
        return None;
    }
    let expected = expected_preset_name(preset, "minimum");
    if active != expected {
        println!("skipping: active preset is {active}, expected {expected}");
        return None;
    }
    Some(())
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
