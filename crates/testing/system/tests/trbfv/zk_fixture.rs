// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit fixtures for the multi-node trBFV scenarios: which committee the local circuits were
//! built for, and a [`ZkBackend`] staged from them (or downloaded when no local build exists).

use anyhow::{ensure, Context, Result};
use e3_test_support::find_bb;
use e3_zk_config::{CircuitName, CircuitVariant};
use e3_zk_prover::test_utils::{get_tempdir, workspace_root};
use e3_zk_prover::{BBPath, CircuitInfo, VersionInfo, ZkBackend};
use std::collections::HashMap;
use std::path::Path;

/// The circuits staged from `circuits/bin` into each variant directory, with the extension
/// `bb write_vk` gave that variant's verification key there. `circuits/bin` is preset-agnostic;
/// only its `.active-preset.json` records which preset and committee it was built for.
const STAGED: [(CircuitVariant, &str, &[CircuitName]); 3] = [
    // Inner proofs: noir-recursive keys.
    (
        CircuitVariant::Recursive,
        "vk_noir",
        &[
            CircuitName::PkBfv,
            CircuitName::PkGeneration,
            CircuitName::SkShareComputation,
            CircuitName::ESmShareComputation,
            CircuitName::ShareEncryption,
            CircuitName::DkgShareDecryption,
            CircuitName::PkAggregation,
            CircuitName::ThresholdShareDecryption,
            CircuitName::DecryptedSharesAggregation,
        ],
    ),
    // Wrapper and fold proofs: noir-recursive-no-zk keys. C5 and C7 are proven this way and folded
    // into the aggregators, so they are staged here too.
    (
        CircuitVariant::Default,
        "vk_recursive",
        &[
            CircuitName::PkAggregation,
            CircuitName::C3Fold,
            CircuitName::C3FoldKernel,
            CircuitName::C6Fold,
            CircuitName::C6FoldKernel,
            CircuitName::C2abFold,
            CircuitName::C3abFold,
            CircuitName::C4abFold,
            CircuitName::NodeFold,
            CircuitName::NodesFold,
            CircuitName::NodesFoldKernel,
            CircuitName::DkgAggregator,
            CircuitName::DecryptionAggregator,
            CircuitName::DecryptedSharesAggregation,
        ],
    ),
    // On-chain verification: the two aggregators and C7.
    (
        CircuitVariant::Evm,
        "vk",
        &[
            CircuitName::DkgAggregator,
            CircuitName::DecryptionAggregator,
            CircuitName::DecryptedSharesAggregation,
        ],
    ),
];

/// Reads the active committee from `circuits/bin/.active-preset.json`, which is written by every
/// `pnpm build:circuits` invocation and is the canonical source for the per-committee layout: the
/// per-committee dist stamp is nested under `dist/circuits/{preset}/{committee}/`, which requires
/// already knowing the committee to locate.
///
/// Falls back to `Minimum` (and warns) when the stamp is missing or pre-dates the `committee`
/// field — same default as the build script, so a freshly cloned repo's minimum circuits work
/// out of the box.
pub fn active_committee() -> e3_committee::CiphernodesCommitteeSize {
    use std::str::FromStr;
    let stamp_path = workspace_root()
        .join("circuits")
        .join("bin")
        .join(".active-preset.json");
    let fallback = e3_committee::CiphernodesCommitteeSize::Minimum;

    let Ok(raw) = std::fs::read_to_string(&stamp_path) else {
        eprintln!(
            "⚠️  {} not found; defaulting to {fallback}. \
             Run `pnpm build:circuits --committee <name>` to make this deterministic.",
            stamp_path.display(),
        );
        return fallback;
    };
    let Ok(stamp) = serde_json::from_str::<serde_json::Value>(&raw) else {
        eprintln!(
            "⚠️  {} is not valid JSON; defaulting to {fallback}.",
            stamp_path.display()
        );
        return fallback;
    };
    let Some(active) = stamp.get("committee").and_then(|v| v.as_str()) else {
        eprintln!(
            "⚠️  {} has no `committee` field (older build); defaulting to {fallback}.",
            stamp_path.display(),
        );
        return fallback;
    };
    e3_committee::CiphernodesCommitteeSize::from_str(active).unwrap_or_else(|e| {
        panic!(
            "{} has unknown committee=\"{active}\": {e}. \
             Expected minimum|micro|small.",
            stamp_path.display()
        )
    })
}

/// Preset that `circuits/bin` was built for, from its `.active-preset.json`. `None` when the
/// stamp is missing, malformed or pre-dates the field, as the circuits then match no preset.
fn active_preset() -> Option<String> {
    let raw = std::fs::read_to_string(
        workspace_root()
            .join("circuits")
            .join("bin")
            .join(".active-preset.json"),
    )
    .ok()?;
    let stamp: serde_json::Value = serde_json::from_str(&raw).ok()?;
    Some(stamp.get("preset")?.as_str()?.to_owned())
}

/// The `dist/circuits/checksums.json` entries of `pair`, or `None` when the manifest is missing
/// or lists nothing for it, so the dist circuits cannot be verified.
async fn dist_manifest_entries(
    dist_circuits: &Path,
    pair: &Path,
) -> Result<Option<Vec<(String, String)>>> {
    let Ok(raw) = tokio::fs::read(dist_circuits.join("checksums.json")).await else {
        return Ok(None);
    };
    let manifest: serde_json::Value = serde_json::from_slice(&raw)?;
    ensure!(
        manifest["algorithm"] == "sha256",
        "dist circuit manifest must use sha256"
    );
    let files: HashMap<String, String> = serde_json::from_value(manifest["files"].clone())?;
    let prefix = format!("{}/", pair.display());
    let entries: Vec<_> = files
        .into_iter()
        .filter(|(file, _)| file.starts_with(&prefix))
        .collect();
    Ok((!entries.is_empty()).then_some(entries))
}

async fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    tokio::fs::copy(src, dst)
        .await
        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let dest = dst.join(entry.file_name());
        if entry.file_type().await?.is_dir() {
            Box::pin(copy_dir_recursive(&entry.path(), &dest)).await?;
        } else {
            copy_file(&entry.path(), &dest).await?;
        }
    }
    Ok(())
}

/// Copies one compiled circuit and its verification key from `circuits/bin` into the
/// `variant` directory of `pair_dir`, under the names the prover loads.
async fn stage_circuit(
    bin: &Path,
    pair_dir: &Path,
    variant: CircuitVariant,
    vk_ext: &str,
    circuit: CircuitName,
) -> Result<()> {
    let name = circuit.as_str();
    let mut src = bin.join(circuit.group());
    if circuit.group() == "recursive_aggregation" {
        src.push(name);
    }
    src.push("target");
    let dst = pair_dir.join(variant.as_str()).join(circuit.dir_path());
    tokio::fs::create_dir_all(&dst).await?;

    copy_file(
        &src.join(format!("{name}.json")),
        &dst.join(format!("{name}.json")),
    )
    .await?;
    copy_file(
        &src.join(format!("{name}.{vk_ext}")),
        &dst.join(format!("{name}.vk")),
    )
    .await?;
    let vk_hash = src.join(format!("{name}.{vk_ext}_hash"));
    // `bb write_vk` leaves `vk_hash` in some aggregation target dirs.
    let vk_hash = if tokio::fs::try_exists(&vk_hash).await? {
        vk_hash
    } else {
        src.join("vk_hash")
    };
    copy_file(&vk_hash, &dst.join(format!("{name}.vk_hash"))).await?;
    if matches!(circuit, CircuitName::NodesFold | CircuitName::C6Fold) {
        let tree_hash = format!("{name}.vk_tree_hash");
        copy_file(&src.join(&tree_hash), &dst.join(&tree_hash)).await?;
    }
    Ok(())
}

async fn collect_circuit_files(circuits_dir: &Path) -> Result<HashMap<String, CircuitInfo>> {
    let status = tokio::process::Command::new("pnpm")
        .current_dir(workspace_root())
        .args(["store:circuits", "checksums", "--dir"])
        .arg(circuits_dir)
        .status()
        .await
        .context("generate integration circuit checksums")?;
    ensure!(
        status.success(),
        "generate integration circuit checksums: {status}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(circuits_dir.join("checksums.json")).await?)?;
    let files: HashMap<String, String> = serde_json::from_value(manifest["files"].clone())?;
    Ok(files
        .into_iter()
        .map(|(file, checksum)| (file.clone(), CircuitInfo { file, checksum }))
        .collect())
}

/// Stages the developer's `bb` and local circuits into `backend`. Returns `false` when no local
/// circuits can be shown to match the active preset and committee, so the caller downloads the
/// pinned release instead.
async fn stage_local_fixture(backend: &ZkBackend, bb: &Path, preset_subdir: &str) -> Result<bool> {
    for dir in [
        backend.bb_binary.parent().unwrap(),
        backend.circuits_dir.as_path(),
        backend.work_dir.as_path(),
    ] {
        tokio::fs::create_dir_all(dir).await?;
    }
    // The installer can replace this binary. Keep the developer's bb isolated from it.
    copy_file(bb, &backend.bb_binary).await?;
    let local_version = backend
        .verify_bb()
        .await
        .context("run local bb --version")?;
    ensure!(
        local_version == backend.config.required_bb_version,
        "local bb is {}, tests need {} ({})",
        local_version,
        backend.config.required_bb_version,
        bb.display()
    );

    let root = workspace_root();
    let committee = active_committee();
    let pair = Path::new(preset_subdir).join(committee.as_str());
    let dist_pair = root.join("dist/circuits").join(&pair);
    let bin = root.join("circuits/bin");
    let pair_dir = backend.circuits_dir.join(&pair);
    let dist_entries = if dist_pair.join("recursive/dkg/pk/pk.json").exists() {
        dist_manifest_entries(&root.join("dist/circuits"), &pair).await?
    } else {
        None
    };
    if let Some(entries) = dist_entries {
        copy_dir_recursive(&dist_pair, &pair_dir).await?;
        // The checksums recorded below would accept whatever was copied, so a corrupted or
        // replaced artifact must fail here, with its original mismatch.
        for (file, checksum) in &entries {
            backend
                .locate_manifest_artifact(file, checksum)
                .await
                .with_context(|| format!("dist artifact {file} disagrees with its manifest"))?;
        }
    } else if bin.join("dkg/target/pk.json").exists()
        && active_preset().as_deref() == Some(preset_subdir)
    {
        for (variant, vk_ext, circuits) in STAGED {
            for &circuit in circuits {
                stage_circuit(&bin, &pair_dir, variant, vk_ext, circuit).await?;
            }
        }
    } else {
        println!(
            "No verifiable local circuit fixtures for preset `{}` \
             (need either dist/circuits/{0}/recursive/dkg/pk/pk.json with an entry for it in \
             dist/circuits/checksums.json, or circuits/bin built for preset `{preset_subdir}` \
             with circuits/bin/.active-preset.json); \
             downloading release circuits via ensure_installed()...",
            pair.display()
        );
        return Ok(false);
    }

    let circuits = collect_circuit_files(&backend.circuits_dir).await?;
    ensure!(
        !circuits.is_empty(),
        "no circuit artifacts found in ZK integration fixture at {}",
        backend.circuits_dir.display()
    );
    // `CiphernodeBuilder` calls `ensure_installed()`, which deletes `circuits_dir` and downloads
    // the release tarball whenever `version.json` does not record the pinned bb/circuits
    // versions and circuit artifacts. That would wipe the fixture tree just staged.
    VersionInfo {
        bb_version: Some(backend.config.required_bb_version.clone()),
        circuits_version: Some(backend.config.required_circuits_version.clone()),
        circuits,
        ..Default::default()
    }
    .save(&backend.version_file())
    .await
    .context("write noir/version.json for integration ZK fixtures")?;
    Ok(true)
}

/// Create a ZkBackend for integration tests.
/// If a local bb binary is found, uses it with fixture files (fast path).
/// Otherwise, calls `ensure_installed()` to download bb + circuits (CI path).
pub async fn setup_test_zk_backend(
    preset_subdir: &'static str,
) -> Result<(ZkBackend, tempfile::TempDir)> {
    let temp = get_tempdir()?;
    let noir_dir = temp.path().join("noir");
    let backend = ZkBackend::new(
        BBPath::Default(noir_dir.join("bin").join("bb")),
        noir_dir.join("circuits"),
        noir_dir.join("work").join("test_node"),
    );
    let staged = match find_bb().await {
        Some(bb) => stage_local_fixture(&backend, &bb, preset_subdir).await?,
        None => {
            println!("bb binary not found locally, downloading via ensure_installed()...");
            false
        }
    };
    if !staged {
        backend
            .ensure_installed()
            .await
            .context("download ZK backend for integration tests")?;
    }
    Ok((backend, temp))
}
