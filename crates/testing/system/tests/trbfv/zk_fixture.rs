// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit fixtures for the multi-node trBFV scenarios: which committee the local circuits were
//! built for, and a [`ZkBackend`] staged from them (or downloaded when no local build exists).

use anyhow::{bail, ensure, Context, Result};
use e3_test_support::find_bb;
use e3_zk_prover::test_utils::get_tempdir;
use e3_zk_prover::{BBPath, CircuitInfo, VersionInfo, ZkBackend};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Monorepo root (`crates/testing/system` → `../../..`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

/// Whether `setup_test_zk_backend` copies from `dist/circuits/<preset>/<committee>/`.
/// Under the new per-committee layout artifacts live under `{preset}/{committee}/recursive/...`.
fn uses_dist_preset_artifacts(preset_subdir: &str, committee_str: &str) -> bool {
    repo_root()
        .join("dist/circuits")
        .join(preset_subdir)
        .join(committee_str)
        .join("recursive/dkg/pk/pk.json")
        .exists()
}

/// Preset stamp path — under the new layout each `{preset}/{committee}` dir has its own stamp.
fn resolve_preset_stamp_path(preset_subdir: &str, committee_str: &str) -> PathBuf {
    if uses_dist_preset_artifacts(preset_subdir, committee_str) {
        repo_root()
            .join("dist/circuits")
            .join(preset_subdir)
            .join(committee_str)
            .join(".build-stamp.json")
    } else {
        repo_root()
            .join("circuits")
            .join("bin")
            .join(".active-preset.json")
    }
}

/// Reads the active committee from `circuits/bin/.active-preset.json`, which is written by every
/// `pnpm build:circuits` invocation and is the canonical source for the new per-committee layout.
///
/// Falls back to `Minimum` (and warns) when the stamp is missing or pre-dates the `committee`
/// field — same default as the build script, so a freshly cloned repo's minimum circuits work
/// out of the box.
pub fn active_committee() -> e3_committee::CiphernodesCommitteeSize {
    use std::str::FromStr;
    // `circuits/bin/.active-preset.json` is written by every build and hydrate. It is the
    // authoritative source under the new per-committee layout because the per-committee dist
    // stamp is nested under `dist/circuits/{preset}/{committee}/`, which requires already
    // knowing the committee to locate.
    let stamp_path = repo_root()
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

async fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let dest = dst.join(entry.file_name());
        if file_type.is_dir() {
            Box::pin(copy_dir_recursive(&entry.path(), &dest)).await?;
        } else {
            tokio::fs::copy(entry.path(), &dest)
                .await
                .with_context(|| {
                    format!(
                        "copy circuit artifact {} -> {}",
                        entry.path().display(),
                        dest.display()
                    )
                })?;
        }
    }
    Ok(())
}

async fn collect_circuit_files(circuits_dir: &Path) -> Result<HashMap<String, CircuitInfo>> {
    let status = tokio::process::Command::new("pnpm")
        .current_dir(repo_root())
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

/// Create a ZkBackend for integration tests.
/// If a local bb binary is found, uses it with fixture files (fast path).
/// Otherwise, calls `ensure_installed()` to download bb + circuits (CI path).
pub async fn setup_test_zk_backend(
    preset_subdir: &'static str,
) -> Result<(ZkBackend, tempfile::TempDir)> {
    let temp = get_tempdir().unwrap();
    let temp_path = temp.path();
    let noir_dir = temp_path.join("noir");
    let bb_binary = noir_dir.join("bin").join("bb");
    let circuits_dir = noir_dir.join("circuits");
    let work_dir = noir_dir.join("work").join("test_node");
    let repo_root = repo_root();
    // Derive committee before constructing any paths — it determines the subdirectory under
    // `dist/circuits/{preset}/{committee}/` in the new per-committee layout.
    let committee = active_committee();
    let committee_str = committee.as_str();
    let dist_preset = repo_root
        .join("dist/circuits")
        .join(preset_subdir)
        .join(committee_str);

    if let Some(bb) = find_bb().await {
        tokio::fs::create_dir_all(bb_binary.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::create_dir_all(&circuits_dir).await.unwrap();
        tokio::fs::create_dir_all(&work_dir).await.unwrap();

        // The installer can replace this binary. Keep the developer's bb isolated from it.
        tokio::fs::copy(&bb, &bb_binary)
            .await
            .context("copy local bb into integration fixture")?;
        let backend = ZkBackend::new(
            BBPath::Default(bb_binary.clone()),
            circuits_dir.clone(),
            work_dir.clone(),
        );
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

        let preset_out = circuits_dir.join(preset_subdir).join(committee_str);
        let circuits_bin_marker = repo_root.join("circuits/bin/dkg/target/pk.json");
        // `circuits/bin` is preset-agnostic on disk — only `.active-preset.json` records which
        // preset+committee the most recent local build targeted. Without it we cannot tell
        // whether `circuits/bin` matches `preset_subdir`, and copying wrong artifacts would
        // silently produce invalid proofs.
        let preset_build_stamp = resolve_preset_stamp_path(preset_subdir, committee_str);

        if uses_dist_preset_artifacts(preset_subdir, committee_str) {
            copy_dir_recursive(&dist_preset, &preset_out).await?;
        } else if !circuits_bin_marker.exists() || !preset_build_stamp.exists() {
            // Either no local build exists, or the local build cannot be proven to match
            // the requested preset; download the pinned release tarball instead.
            println!(
                "No verifiable local circuit fixtures for preset `{}/{}` \
                 (need either dist/circuits/{}/{}/recursive/dkg/pk/pk.json \
                 or circuits/bin + circuits/bin/.active-preset.json); \
                 downloading release circuits via ensure_installed()...",
                preset_subdir, committee_str, preset_subdir, committee_str
            );
            let backend = ZkBackend::new(BBPath::Default(bb_binary), circuits_dir, work_dir);
            backend
                .ensure_installed()
                .await
                .context("download ZK circuits for integration tests")?;
            return Ok((backend, temp));
        } else {
            let circuits_build_root = repo_root.join("circuits").join("bin");
            let dkg_target = circuits_build_root.join("dkg").join("target");
            let threshold_target = circuits_build_root.join("threshold").join("target");
            let c3_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c3_fold")
                .join("target");
            let c3_fold_kernel_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c3_fold_kernel")
                .join("target");
            let c6_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c6_fold")
                .join("target");
            let c6_fold_kernel_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c6_fold_kernel")
                .join("target");
            let c2ab_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c2ab_fold")
                .join("target");
            let c3ab_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c3ab_fold")
                .join("target");
            let c4ab_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("c4ab_fold")
                .join("target");
            let node_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("node_fold")
                .join("target");
            let nodes_fold_target = circuits_build_root
                .join("recursive_aggregation")
                .join("nodes_fold")
                .join("target");
            let nodes_fold_kernel_target = circuits_build_root
                .join("recursive_aggregation")
                .join("nodes_fold_kernel")
                .join("target");
            let dkg_aggregator_target = circuits_build_root
                .join("recursive_aggregation")
                .join("dkg_aggregator")
                .join("target");
            let decryption_aggregator_target = circuits_build_root
                .join("recursive_aggregation")
                .join("decryption_aggregator")
                .join("target");

            // Helper: copy {name}.json + VK artifacts into a destination directory.
            // vk_suffix/vk_hash_suffix select the source VK flavor:
            //   ".vk_noir" / ".vk_noir_hash"       → Recursive variant (inner proofs)
            //   ".vk_recursive" / ".vk_recursive_hash" → Default variant (wrapper/fold proofs)
            //   ".vk" / ".vk_hash"                  → EVM variant
            async fn copy_circuit(
                src_dir: &std::path::Path,
                dst_dir: &std::path::Path,
                name: &str,
                vk_suffix: &str,
                vk_hash_suffix: &str,
            ) -> Result<()> {
                tokio::fs::create_dir_all(dst_dir).await?;
                let copy_file = |src: std::path::PathBuf, dst: std::path::PathBuf| async move {
                    tokio::fs::copy(&src, &dst).await.with_context(|| {
                        format!(
                            "copy circuit artifact {} -> {}",
                            src.display(),
                            dst.display()
                        )
                    })
                };
                copy_file(
                    src_dir.join(format!("{name}.json")),
                    dst_dir.join(format!("{name}.json")),
                )
                .await?;
                copy_file(
                    src_dir.join(format!("{name}{vk_suffix}")),
                    dst_dir.join(format!("{name}.vk")),
                )
                .await?;
                let vk_hash_src = src_dir.join(format!("{name}{vk_hash_suffix}"));
                let vk_hash_src = if tokio::fs::try_exists(&vk_hash_src).await? {
                    vk_hash_src
                } else {
                    // `bb write_vk` leaves `vk_hash` in some aggregation target dirs.
                    src_dir.join("vk_hash")
                };
                copy_file(vk_hash_src, dst_dir.join(format!("{name}.vk_hash"))).await?;
                if matches!(name, "nodes_fold" | "c6_fold") {
                    copy_file(
                        src_dir.join(format!("{name}.vk_tree_hash")),
                        dst_dir.join(format!("{name}.vk_tree_hash")),
                    )
                    .await?;
                }
                Ok(())
            }

            // ── recursive/ variant (inner/base proofs, uses .vk_noir) ──────────
            let preset_dir = circuits_dir.join(preset_subdir).join(committee_str);

            let rv = preset_dir.join("recursive");

            // T0 (pk)
            copy_circuit(
                &dkg_target,
                &rv.join("dkg/pk"),
                "pk",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C1 (pk_generation)
            copy_circuit(
                &threshold_target,
                &rv.join("threshold/pk_generation"),
                "pk_generation",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C2a (sk_share_computation)
            copy_circuit(
                &dkg_target,
                &rv.join("dkg/sk_share_computation"),
                "sk_share_computation",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C2b (e_sm_share_computation)
            copy_circuit(
                &dkg_target,
                &rv.join("dkg/e_sm_share_computation"),
                "e_sm_share_computation",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C3 (share_encryption)
            copy_circuit(
                &dkg_target,
                &rv.join("dkg/share_encryption"),
                "share_encryption",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C4 (dkg/share_decryption)
            copy_circuit(
                &dkg_target,
                &rv.join("dkg/share_decryption"),
                "share_decryption",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C5 (pk_aggregation)
            copy_circuit(
                &threshold_target,
                &rv.join("threshold/pk_aggregation"),
                "pk_aggregation",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C6 (threshold/share_decryption)
            copy_circuit(
                &threshold_target,
                &rv.join("threshold/share_decryption"),
                "share_decryption",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;
            // C7 (decrypted_shares_aggregation)
            copy_circuit(
                &threshold_target,
                &rv.join("threshold/decrypted_shares_aggregation"),
                "decrypted_shares_aggregation",
                ".vk_noir",
                ".vk_noir_hash",
            )
            .await?;

            // ── default/ variant (recursive aggregation bins, uses .vk_recursive) ───

            let dv = preset_dir.join("default");

            // C5 (pk_aggregation) — proven with noir-recursive-no-zk and folded into
            // DkgAggregator, so it must be staged under default/ too.
            copy_circuit(
                &threshold_target,
                &dv.join("threshold/pk_aggregation"),
                "pk_aggregation",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;

            copy_circuit(
                &c3_fold_target,
                &dv.join("recursive_aggregation/c3_fold"),
                "c3_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c3_fold_kernel_target,
                &dv.join("recursive_aggregation/c3_fold_kernel"),
                "c3_fold_kernel",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c6_fold_target,
                &dv.join("recursive_aggregation/c6_fold"),
                "c6_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c6_fold_kernel_target,
                &dv.join("recursive_aggregation/c6_fold_kernel"),
                "c6_fold_kernel",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c2ab_fold_target,
                &dv.join("recursive_aggregation/c2ab_fold"),
                "c2ab_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c3ab_fold_target,
                &dv.join("recursive_aggregation/c3ab_fold"),
                "c3ab_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &c4ab_fold_target,
                &dv.join("recursive_aggregation/c4ab_fold"),
                "c4ab_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &node_fold_target,
                &dv.join("recursive_aggregation/node_fold"),
                "node_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &nodes_fold_target,
                &dv.join("recursive_aggregation/nodes_fold"),
                "nodes_fold",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &nodes_fold_kernel_target,
                &dv.join("recursive_aggregation/nodes_fold_kernel"),
                "nodes_fold_kernel",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &dkg_aggregator_target,
                &dv.join("recursive_aggregation/dkg_aggregator"),
                "dkg_aggregator",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            copy_circuit(
                &decryption_aggregator_target,
                &dv.join("recursive_aggregation/decryption_aggregator"),
                "decryption_aggregator",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;
            // C7 (decrypted_shares_aggregation) — proven with noir-recursive-no-zk and
            // folded into DecryptionAggregator, so it must also be staged under default/.
            copy_circuit(
                &threshold_target,
                &dv.join("threshold/decrypted_shares_aggregation"),
                "decrypted_shares_aggregation",
                ".vk_recursive",
                ".vk_recursive_hash",
            )
            .await?;

            // ── evm/ variant (on-chain verification: DKG aggregator, C7) ───────────

            let ev = preset_dir.join("evm");

            // DKG aggregator — EVM-targeted (folds + C5 verified inside)
            copy_circuit(
                &dkg_aggregator_target,
                &ev.join("recursive_aggregation/dkg_aggregator"),
                "dkg_aggregator",
                ".vk",
                ".vk_hash",
            )
            .await?;
            // Decryption aggregator — EVM-targeted (C6 fold + C7 verified inside)
            copy_circuit(
                &decryption_aggregator_target,
                &ev.join("recursive_aggregation/decryption_aggregator"),
                "decryption_aggregator",
                ".vk",
                ".vk_hash",
            )
            .await?;
            // C7 (decrypted_shares_aggregation) — EVM-targeted
            copy_circuit(
                &threshold_target,
                &ev.join("threshold/decrypted_shares_aggregation"),
                "decrypted_shares_aggregation",
                ".vk",
                ".vk_hash",
            )
            .await?;
        }

        let backend = ZkBackend::new(BBPath::Default(bb_binary), circuits_dir, work_dir);
        let circuits = collect_circuit_files(&backend.circuits_dir).await?;
        if circuits.is_empty() {
            bail!(
                "no circuit artifacts found in ZK integration fixture at {}",
                backend.circuits_dir.display()
            );
        }

        // `CiphernodeBuilder` calls `ensure_installed()`, which deletes `circuits_dir` and downloads
        // the release tarball whenever `version.json` does not record the pinned bb/circuits
        // versions and circuit artifacts. That would wipe the fixture tree we just copied from
        // `circuits/bin/`.
        let version_info = VersionInfo {
            bb_version: Some(backend.config.required_bb_version.clone()),
            circuits_version: Some(backend.config.required_circuits_version.clone()),
            circuits,
            ..Default::default()
        };
        version_info
            .save(&backend.version_file())
            .await
            .expect("write noir/version.json for integration ZK fixtures");

        Ok((backend, temp))
    } else {
        println!("bb binary not found locally, downloading via ensure_installed()...");
        let backend = ZkBackend::new(BBPath::Default(bb_binary), circuits_dir, work_dir);
        backend
            .ensure_installed()
            .await
            .expect("Failed to download and install ZK backend");
        Ok((backend, temp))
    }
}
