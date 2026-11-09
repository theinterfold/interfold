// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit fixtures for the multi-node trBFV scenarios: which committee the local circuits were
//! built for, and a [`ZkBackend`] installed from them (or downloaded when no local build exists).
//! Staging and provenance belong to `e3-zk-build`; admission and installation to `e3-zk-prover`.

use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvPreset;
use e3_test_support::find_bb;
use e3_zk_prover::test_utils::{get_tempdir, workspace_root};
use e3_zk_prover::{BBPath, ZkBackend};
use std::path::{Path, PathBuf};

/// The committee `circuits/bin` was built for, from its build stamp. A checkout without a build
/// uses `Minimum`, the default of `pnpm build:circuits`, whose circuits are also the first
/// download.
pub fn active_committee() -> CiphernodesCommitteeSize {
    let stamp = e3_zk_build::read_active_stamp(workspace_root())
        .expect("circuits/bin/.active-preset.json is invalid; rebuild with `pnpm build:circuits`");
    match stamp {
        Some(stamp) => stamp.committee.parse().unwrap_or_else(|error| {
            panic!(
                "circuits/bin/.active-preset.json has committee={:?}: {error}",
                stamp.committee
            )
        }),
        None => {
            let fallback = CiphernodesCommitteeSize::Minimum;
            eprintln!(
                "circuits/bin/.active-preset.json not found; defaulting to {fallback}. \
                 Run `pnpm build:circuits --committee <name>` to make this deterministic."
            );
            fallback
        }
    }
}

/// A circuits tree holding `{preset}/{committee}` that can be installed without a download:
/// `dist/circuits` when it is current for the pair, else `circuits/bin` staged into `scratch`.
/// `None` when neither is.
fn local_circuits(
    root: &Path,
    preset: &str,
    committee: &str,
    scratch: &Path,
) -> Result<Option<PathBuf>> {
    let pair = Path::new(preset).join(committee);
    let dist = root.join("dist/circuits");
    if e3_zk_build::dist_current(&dist.join(&pair), preset, committee, None)? {
        return Ok(Some(dist));
    }
    if e3_zk_build::bin_current(root, preset, committee, None)? {
        let staged = scratch.join("circuits");
        e3_zk_build::stage_bin(root, &staged.join(&pair))?;
        e3_zk_build::write_checksums(&staged)?;
        return Ok(Some(staged));
    }
    Ok(None)
}

/// Create a ZkBackend for integration tests of `preset` and `committee`.
/// Installs the pair's current local circuits (`dist/circuits`, else a staged `circuits/bin`) when
/// a local bb is found, as CI does. Otherwise (no current local circuits for the pair, or no local
/// bb) calls `ensure_installed()` to download bb + circuits.
pub async fn setup_test_zk_backend(
    preset: BfvPreset,
    committee: CiphernodesCommitteeSize,
) -> Result<(ZkBackend, tempfile::TempDir)> {
    let temp = get_tempdir()?;
    let noir_dir = temp.path().join("noir");
    let preset_dir = preset.artifacts_dir();
    let committee_dir = committee.as_str();
    let local = local_circuits(
        workspace_root(),
        &preset_dir,
        committee_dir,
        &temp.path().join("staged"),
    )?;
    // A custom bb (E3_CUSTOM_BB or PATH) is used and checked whether or not local circuits exist.
    // The installer never replaces a custom binary, so the developer's bb stays untouched.
    let custom_bb = find_bb().await;
    let bb = match &custom_bb {
        Some(bb) => BBPath::Custom(bb.clone()),
        None => BBPath::Default(noir_dir.join("bin").join("bb")),
    };
    let backend = ZkBackend::new(
        bb,
        noir_dir.join("circuits"),
        noir_dir.join("work").join("test_node"),
    );
    if let Some(bb) = &custom_bb {
        let version = backend
            .verify_bb()
            .await
            .context("run local bb --version")?;
        ensure!(
            version == backend.config.required_bb_version,
            "local bb is {version}, tests need {} ({})",
            backend.config.required_bb_version,
            bb.display()
        );
    }
    match (local, &custom_bb) {
        (Some(circuits), Some(_)) => {
            backend
                .install_circuits_dir(&circuits, &[(&preset_dir, committee_dir)])
                .await
                .with_context(|| {
                    format!(
                        "install local circuits for {preset_dir}/{committee_dir} from {}; a \
                         current tree must carry a complete checksums.json (`pnpm store:circuits \
                         checksums --dir <tree>`), or be removed",
                        circuits.display()
                    )
                })?;
        }
        _ => {
            println!(
                "No usable local circuits and bb for {preset_dir}/{committee_dir} (need dist/circuits or circuits/bin \
                 built for it, and bb on PATH or E3_CUSTOM_BB); downloading via ensure_installed()..."
            );
            backend
                .ensure_installed()
                .await
                .context("download ZK backend for integration tests")?;
        }
    }
    Ok((backend, temp))
}
