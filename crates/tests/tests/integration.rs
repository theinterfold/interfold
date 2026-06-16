// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Actor;
use alloy::primitives::{Address, FixedBytes, I256, U256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_ciphernode_builder::{CiphernodeBuilder, EventSystem};
use e3_config::BBPath;
use e3_crypto::Cipher;
use e3_events::{
    hlc::HlcTimestamp, prelude::*, BusHandle, CiphertextOutputPublished, CommitteeFinalized,
    ComputeRequestKind, ComputeResponseKind, ConfigurationUpdated, E3Requested, E3id,
    InterfoldEvent, InterfoldEventData, OperatorActivationChanged, PlaintextAggregated, ProofType,
    Seed, TakeEvents, TicketBalanceUpdated, VerificationKind, ZkRequest, ZkResponse,
};
use e3_fhe_params::DEFAULT_BFV_PRESET;
use e3_fhe_params::{encode_bfv_params, BfvParamSet, BfvPreset};
use e3_multithread::{Multithread, MultithreadReport, ToReport};
use e3_net::events::{GossipData, NetEvent};
use e3_net::NetEventTranslator;
use e3_sortition::{calculate_buffer_size, RegisteredNode, ScoreSortition, Ticket};
use e3_test_helpers::ciphernode_system::{
    CiphernodeHistory, CiphernodeSystem, CiphernodeSystemBuilder,
};
use e3_test_helpers::{
    create_seed_from_u64, derive_shared_rng, find_bb, with_tracing, AddToCommittee,
};
use e3_trbfv::helpers::calculate_error_size;
use e3_trbfv::{TrBFVRequest, TrBFVResponse};
use e3_utils::utility_types::ArcBytes;
use e3_utils::{colorize, rand_eth_addr, Color};
use e3_zk_prover::test_utils::get_tempdir;
use e3_zk_prover::{VersionInfo, ZkBackend};
use fhe::bfv::PublicKey;
use fhe_traits::{DeserializeParametrized, Serialize};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use std::ffi::OsString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{fs, path::PathBuf, sync::Arc};
use tokio::{
    sync::{broadcast, mpsc},
    time::sleep,
};

#[derive(Debug, Clone, Copy)]
struct BenchmarkParams {
    /// Noir artifact preset directory name under `circuits/bin/` (e.g. `secure-8192`).
    preset_subdir: &'static str,
    /// BFV parameter family used for BFV/trBFV computations.
    bfv_preset: BfvPreset,
    /// Statistical security parameter λ used for smudging bound / error_size.
    lambda: usize,
    /// Collector-timeout env var bundle for secure runs.
    collection_timeout_secs: Option<(u64, u64, u64)>,
    /// Expected upper-bounds for history collection (end-to-end wall clock).
    pubkey_flow_timeout: Duration,
    plaintext_flow_timeout: Duration,
}

fn select_benchmark_params() -> BenchmarkParams {
    let benchmark_mode = std::env::var("BENCHMARK_MODE").unwrap_or_else(|_| "insecure".to_string());
    let is_secure_mode = benchmark_mode == "secure";

    let bfv_preset = if is_secure_mode {
        BfvPreset::SecureThreshold8192
    } else {
        DEFAULT_BFV_PRESET
    };

    // λ is part of the preset metadata; using a hard-coded value here will mix parameter
    // families and can invalidate noise/security assumptions.
    let lambda = bfv_preset.metadata().lambda;

    let preset_subdir = if is_secure_mode {
        "secure-8192"
    } else {
        "insecure-512"
    };

    let committee = active_committee(preset_subdir);
    let is_small_committee = committee == e3_zk_helpers::CiphernodesCommitteeSize::Small;

    let collection_timeout_secs = if is_secure_mode && is_small_committee {
        Some((7_200, 46_000, 46_000)) // Small: threshold/dec kept > pubkey_flow
    } else if is_secure_mode {
        Some((1_800, 7_200, 7_200))
    } else {
        None
    };

    let pubkey_flow_timeout = if is_secure_mode && is_small_committee {
        Duration::from_secs(45_000) // Small: conservative upper bound
    } else if is_secure_mode {
        Duration::from_secs(15_000)
    } else {
        Duration::from_secs(5_000)
    };
    let plaintext_flow_timeout = if is_secure_mode && is_small_committee {
        Duration::from_secs(6_000) // Small: conservative upper bound; smaller than DKG
    } else if is_secure_mode {
        Duration::from_secs(3_000)
    } else {
        Duration::from_secs(1_000)
    };

    BenchmarkParams {
        preset_subdir,
        bfv_preset,
        lambda,
        collection_timeout_secs,
        pubkey_flow_timeout,
        plaintext_flow_timeout,
    }
}

/// Registered ciphernodes (excluding the observer collector) for benchmark sortition.
///
/// Production registers enough nodes to fill `N + buffer`; the harness must register at least
/// `threshold_n` so party ids `0..N-1` all exist during encryption-key collection.
fn benchmark_participant_node_count(threshold_m: usize, threshold_n: usize) -> usize {
    threshold_n + calculate_buffer_size(threshold_m, threshold_n)
}

/// Whether `test_trbfv_actor` runs the full recursive fold + aggregator path (default: on).
///
/// Benchmark harness always enables proof aggregation (`run_benchmarks.sh` exports `true`).
fn benchmark_proof_aggregation_enabled() -> bool {
    !matches!(
        std::env::var("BENCHMARK_PROOF_AGGREGATION")
            .unwrap_or_else(|_| "true".into())
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Rayon multithread pool concurrency for benchmark runs (`BENCHMARK_MULTITHREAD_JOBS`, default 1).
fn benchmark_multithread_concurrent_jobs() -> usize {
    std::env::var("BENCHMARK_MULTITHREAD_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(1)
}

static NEXT_BENCHMARK_NODE_RNG_SALT: AtomicU64 = AtomicU64::new(1);

/// One ChaCha20 mutex per ciphernode in `test_trbfv_actor` (see `derive_shared_rng`).
fn next_benchmark_node_rng(base_seed: u64) -> e3_utils::SharedRng {
    let salt = NEXT_BENCHMARK_NODE_RNG_SALT.fetch_add(1, Ordering::Relaxed);
    derive_shared_rng(base_seed, salt)
}

/// Fold attestation verifier address for benchmark JSON reports (env override or default).
fn benchmark_dkg_fold_attestation_verifier_address() -> Option<Address> {
    if !benchmark_proof_aggregation_enabled() {
        return None;
    }
    std::env::var("BENCHMARK_DKG_FOLD_ATTESTATION_VERIFIER")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0".parse().ok())
}

/// Monorepo root (`crates/tests` → `../..`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
fn active_committee(_preset_subdir: &str) -> e3_zk_helpers::CiphernodesCommitteeSize {
    use std::str::FromStr;
    // `circuits/bin/.active-preset.json` is written by every build and hydrate. It is the
    // authoritative source under the new per-committee layout because the per-committee dist
    // stamp is nested under `dist/circuits/{preset}/{committee}/`, which requires already
    // knowing the committee to locate.
    let stamp_path = repo_root()
        .join("circuits")
        .join("bin")
        .join(".active-preset.json");
    let fallback = e3_zk_helpers::CiphernodesCommitteeSize::Minimum;

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
    e3_zk_helpers::CiphernodesCommitteeSize::from_str(active).unwrap_or_else(|e| {
        panic!(
            "{} has unknown committee=\"{active}\": {e}. \
             Expected minimum|micro|small.",
            stamp_path.display()
        )
    })
}

/// Slashing manager address for benchmarks (no live RPC; used as EIP-712
/// `verifyingContract` for accusation vote signatures).
fn benchmark_slashing_manager_address() -> Address {
    let addr = std::env::var("BENCHMARK_SLASHING_MANAGER")
        .unwrap_or_else(|_| "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707".to_string());
    addr.parse()
        .expect("BENCHMARK_SLASHING_MANAGER must be a valid address")
}

/// RAII guard that restores the benchmark-specific collector-timeout env vars on scope exit.
/// This prevents leaking secure-mode tuning into other tests/processes.
struct EnvTimeoutVarsGuard {
    enc: Option<OsString>,
    thr: Option<OsString>,
    dec_shared: Option<OsString>,
}

impl EnvTimeoutVarsGuard {
    fn new() -> Self {
        Self {
            enc: std::env::var_os("E3_ENCRYPTION_KEY_COLLECTION_TIMEOUT_SECS"),
            thr: std::env::var_os("E3_THRESHOLD_SHARE_COLLECTION_TIMEOUT_SECS"),
            dec_shared: std::env::var_os("E3_DECRYPTION_KEY_SHARED_COLLECTION_TIMEOUT_SECS"),
        }
    }
}

impl Drop for EnvTimeoutVarsGuard {
    fn drop(&mut self) {
        fn restore(name: &str, original: &Option<OsString>) {
            if let Some(v) = original {
                std::env::set_var(name, v);
            } else {
                std::env::remove_var(name);
            }
        }

        restore("E3_ENCRYPTION_KEY_COLLECTION_TIMEOUT_SECS", &self.enc);
        restore("E3_THRESHOLD_SHARE_COLLECTION_TIMEOUT_SECS", &self.thr);
        restore(
            "E3_DECRYPTION_KEY_SHARED_COLLECTION_TIMEOUT_SECS",
            &self.dec_shared,
        );
    }
}

/// RAII guard that restores a single env var on scope exit.
#[allow(dead_code)]
struct ScopedEnvVar {
    name: &'static str,
    original: Option<OsString>,
}

impl ScopedEnvVar {
    #[allow(dead_code)]
    fn set(name: &'static str, value: &str) -> Self {
        let original = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, original }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(v) = &self.original {
            std::env::set_var(self.name, v);
        } else {
            std::env::remove_var(self.name);
        }
    }
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

/// Create a ZkBackend for integration tests.
/// If a local bb binary is found, uses it with fixture files (fast path).
/// Otherwise, calls `ensure_installed()` to download bb + circuits (CI path).
async fn setup_test_zk_backend(
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
    let committee = active_committee(preset_subdir);
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

        #[cfg(unix)]
        std::os::unix::fs::symlink(&bb, &bb_binary).unwrap();
        #[cfg(not(unix))]
        compile_error!("Integration tests require unix symlink support");

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

        // `CiphernodeBuilder` calls `ensure_installed()`, which deletes `circuits_dir` and downloads
        // the release tarball whenever `version.json` does not record the pinned bb/circuits
        // versions. That would wipe the fixture tree we just copied from `circuits/bin/`.
        let version_info = VersionInfo {
            bb_version: Some(backend.config.required_bb_version.clone()),
            circuits_version: Some(backend.config.required_circuits_version.clone()),
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

pub fn save_snapshot(file_name: &str, bytes: &[u8]) {
    println!("### WRITING SNAPSHOT TO `{file_name}` ###");
    fs::write(format!("tests/{file_name}"), bytes).unwrap();
}

/// Compute placeholder scores for a committee.
/// Uses ticket_id=0 for each address with the given e3_id and seed.
fn compute_committee_scores(committee: &[String], e3_id: &E3id, seed: Seed) -> Vec<String> {
    use e3_sortition::hash_to_score;
    committee
        .iter()
        .map(|addr| {
            let address: Address = addr.parse().unwrap();
            let score = hash_to_score(address, 0, e3_id.clone(), seed);
            U256::from_be_slice(&score.to_bytes_be()).to_string()
        })
        .collect()
}

/// Determines the committee for a given E3 request using deterministic sortition.
///
/// This function runs the same sortition algorithm that the ciphernodes use internally,
/// ensuring the test committee matches what the nodes will compute.
///
/// # Arguments
/// * `e3_id` - The E3 computation ID
/// * `seed` - The random seed for sortition
/// * `threshold_m` - Minimum nodes required for decryption
/// * `threshold_n` - Committee size
/// * `registered_addrs` - List of node addresses eligible for selection
/// * `collector_addr` - Address of the collector node (for validation)
///
/// # Returns
/// A tuple of (committee_addresses, committee_scores, buffer_addresses)
fn determine_committee(
    e3_id: &E3id,
    seed: Seed,
    threshold_m: usize,
    threshold_n: usize,
    registered_addrs: &[String],
    collector_addr: &str,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let buffer = calculate_buffer_size(threshold_m, threshold_n);
    let total_selection_size = threshold_n + buffer;

    // Calculate tickets based on the same balance/ticket_price ratio as production
    // ticket_price = 10_000_000, balance = 1_000_000_000
    // => num_tickets = 1_000_000_000 / 10_000_000 = 100 tickets per node
    const TICKET_PRICE: u64 = 10_000_000;
    const BALANCE: u64 = 1_000_000_000;
    let num_tickets = BALANCE / TICKET_PRICE;

    let registered_nodes: Vec<RegisteredNode> = registered_addrs
        .iter()
        .map(|addr| {
            let address: Address = addr.parse().unwrap();
            let tickets: Vec<Ticket> = (0..num_tickets)
                .map(|ticket_id| Ticket { ticket_id })
                .collect();
            RegisteredNode { address, tickets }
        })
        .collect();

    let winners = ScoreSortition::new(total_selection_size).get_committee(
        e3_id.clone(),
        seed,
        &registered_nodes,
    )?;

    let committee: Vec<String> = winners
        .iter()
        .take(threshold_n)
        .map(|w| w.address.to_string())
        .collect();

    let committee_scores: Vec<String> = winners
        .iter()
        .take(threshold_n)
        .map(|w| U256::from_be_slice(&w.score.to_bytes_be()).to_string())
        .collect();

    let buffer_nodes: Vec<String> = winners
        .iter()
        .skip(threshold_n)
        .map(|w| w.address.to_string())
        .collect();

    for addr in &committee {
        if addr.eq_ignore_ascii_case(collector_addr) {
            bail!(
                "Collector node was selected in committee. \
                 This should never happen as collector should not be registered for sortition.\n\
                 Collector: {}\n\
                 Registered nodes: {}",
                collector_addr,
                registered_addrs.len()
            );
        }
    }

    Ok((committee, committee_scores, buffer_nodes))
}

/// Lowest-address committee member after `CommitteeFinalized::sort_by_score` (party 0 / active aggregator).
fn active_aggregator_address(
    committee: &[String],
    scores: &[String],
    e3_id: &E3id,
    chain_id: u64,
) -> String {
    let mut finalized = CommitteeFinalized {
        e3_id: e3_id.clone(),
        committee: committee.to_vec(),
        scores: scores.to_vec(),
        chain_id,
    };
    finalized.sort_by_score();
    finalized
        .committee
        .first()
        .cloned()
        .expect("committee must be non-empty")
}

fn find_node_index_by_address(nodes: &CiphernodeSystem, address: &str) -> Result<usize> {
    for (index, node) in nodes.iter().enumerate() {
        if node.address().eq_ignore_ascii_case(address) {
            return Ok(index);
        }
    }

    bail!("Could not find node index for address {address}");
}

#[allow(dead_code)]
async fn expect_node_events_with_timeouts(
    nodes: &CiphernodeSystem,
    index: usize,
    expected: &[&str],
    total_to: Duration,
    per_evt_to: Duration,
) -> Result<CiphernodeHistory> {
    let h = nodes
        .take_history_with_timeouts(index, expected.len(), Some(total_to), Some(per_evt_to))
        .await
        .map_err(|e| anyhow::anyhow!("FAILURE on node {index}: {expected:?} : {e}"))?;

    println!(
        "node {index} >> {:?} == {:?}",
        h.event_types(),
        expected.to_vec()
    );
    h.expect(expected.to_vec());
    Ok(h)
}

fn project_history<F>(history: &[InterfoldEvent], mut projector: F) -> Vec<&'static str>
where
    F: FnMut(&InterfoldEventData) -> Option<&'static str>,
{
    history
        .iter()
        .filter_map(|event| projector(event.get_data()))
        .collect()
}

fn count_projected_events(projected: &[&str], event_type: &str) -> usize {
    projected.iter().filter(|seen| **seen == event_type).count()
}

/// Scan a node history for slashing, accusation, and protocol-fault signals that must not
/// appear on an all-honest benchmark run. Catches regressions such as spurious C2→C4
/// commitment mismatches when N > H that completion-only assertions would miss.
fn collect_honest_run_faults(
    history: &[InterfoldEvent],
    e3_id: &E3id,
    context: &str,
) -> Vec<String> {
    let mut faults = Vec::new();

    for event in history {
        match event.get_data() {
            InterfoldEventData::CommitmentConsistencyCheckComplete(data)
                if data.e3_id == *e3_id && !data.inconsistent_parties.is_empty() =>
            {
                faults.push(format!(
                    "{context}: CommitmentConsistencyCheckComplete kind={:?} inconsistent_parties={:?}",
                    data.kind, data.inconsistent_parties
                ));
            }
            InterfoldEventData::CommitmentConsistencyViolation(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: CommitmentConsistencyViolation accused_party_id={} proof_type={:?}",
                    data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::ProofFailureAccusation(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: ProofFailureAccusation accuser={} accused_party_id={} proof_type={:?}",
                    data.accuser, data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::ProofVerificationFailed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: ProofVerificationFailed accused_party_id={} proof_type={:?}",
                    data.accused_party_id, data.proof_type
                ));
            }
            InterfoldEventData::SignedProofFailed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: SignedProofFailed faulting_node={} proof_type={:?}",
                    data.faulting_node, data.proof_type
                ));
            }
            InterfoldEventData::ShareVerificationComplete(data)
                if data.e3_id == *e3_id && !data.dishonest_parties.is_empty() =>
            {
                faults.push(format!(
                    "{context}: ShareVerificationComplete kind={:?} dishonest_parties={:?}",
                    data.kind, data.dishonest_parties
                ));
            }
            InterfoldEventData::AccusationVote(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: AccusationVote voter={} accusation_id={:?}",
                    data.voter, data.accusation_id
                ));
            }
            InterfoldEventData::CommitteeMemberExpelled(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: CommitteeMemberExpelled node={} party_id={:?}",
                    data.node, data.party_id
                ));
            }
            InterfoldEventData::E3Failed(data) if data.e3_id == *e3_id => {
                faults.push(format!(
                    "{context}: E3Failed stage={:?} reason={:?}",
                    data.failed_at_stage, data.reason
                ));
            }
            InterfoldEventData::InterfoldError(data) => {
                faults.push(format!(
                    "{context}: InterfoldError {:?}: {}",
                    data.err_type, data.message
                ));
            }
            _ => {}
        }
    }

    faults
}

fn assert_honest_run_safeguards(history: &[InterfoldEvent], e3_id: &E3id, context: &str) {
    let faults = collect_honest_run_faults(history, e3_id, context);
    assert!(
        faults.is_empty(),
        "honest-run safeguard failures ({}):\n{}",
        context,
        faults.join("\n")
    );
}

/// Wall seconds between first `start_when` and last `end_when` event in `history` (HLC physical time).
fn history_wall_seconds_between<F1, F2>(
    history: &[InterfoldEvent],
    start_when: F1,
    end_when: F2,
) -> Option<f64>
where
    F1: Fn(&InterfoldEventData) -> bool,
    F2: Fn(&InterfoldEventData) -> bool,
{
    let start = history.iter().find(|e| start_when(e.get_data()))?;
    let end = history.iter().rfind(|e| end_when(e.get_data()))?;
    let start_us = HlcTimestamp::wall_time(start.ts());
    let end_us = HlcTimestamp::wall_time(end.ts());
    (end_us >= start_us).then(|| (end_us - start_us) as f64 / 1_000_000.0)
}

fn publickey_aggregator_marker(data: &InterfoldEventData, e3_id: &E3id) -> Option<&'static str> {
    match data {
        InterfoldEventData::CommitteeFinalized(data) if data.e3_id == *e3_id => {
            Some("CommitteeFinalized")
        }
        InterfoldEventData::CiphernodeSelected(data) if data.e3_id == *e3_id => {
            Some("CiphernodeSelected")
        }
        InterfoldEventData::AggregatorChanged(data)
            if data.e3_id == *e3_id && data.is_aggregator =>
        {
            Some("AggregatorChanged")
        }
        InterfoldEventData::KeyshareCreated(data) if data.e3_id == *e3_id => {
            Some("KeyshareCreated")
        }
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::PkGenerationProofs =>
        {
            Some("ShareVerificationDispatched")
        }
        InterfoldEventData::CommitmentConsistencyCheckRequested(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::PkGenerationProofs =>
        {
            Some("CommitmentConsistencyCheckRequested")
        }
        InterfoldEventData::CommitmentConsistencyCheckComplete(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::PkGenerationProofs =>
        {
            Some("CommitmentConsistencyCheckComplete")
        }
        InterfoldEventData::ProofVerificationPassed(data)
            if data.e3_id == *e3_id && data.proof_type == ProofType::C1PkGeneration =>
        {
            Some("ProofVerificationPassed")
        }
        InterfoldEventData::ShareVerificationComplete(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::PkGenerationProofs =>
        {
            Some("ShareVerificationComplete")
        }
        InterfoldEventData::PkAggregationProofPending(data) if data.e3_id == *e3_id => {
            Some("PkAggregationProofPending")
        }
        InterfoldEventData::PkAggregationProofSigned(data) if data.e3_id == *e3_id => {
            Some("PkAggregationProofSigned")
        }
        InterfoldEventData::DKGRecursiveAggregationComplete(data) if data.e3_id == *e3_id => {
            Some("DKGRecursiveAggregationComplete")
        }
        InterfoldEventData::PublicKeyAggregated(data) if data.e3_id == *e3_id => {
            Some("PublicKeyAggregated")
        }
        _ => None,
    }
}

fn plaintext_aggregator_marker(data: &InterfoldEventData, e3_id: &E3id) -> Option<&'static str> {
    match data {
        InterfoldEventData::CiphertextOutputPublished(data) if data.e3_id == *e3_id => {
            Some("CiphertextOutputPublished")
        }
        InterfoldEventData::DecryptionshareCreated(data) if data.e3_id == *e3_id => {
            Some("DecryptionshareCreated")
        }
        InterfoldEventData::ShareVerificationDispatched(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::ThresholdDecryptionProofs =>
        {
            Some("ShareVerificationDispatched")
        }
        InterfoldEventData::CommitmentConsistencyCheckRequested(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::ThresholdDecryptionProofs =>
        {
            Some("CommitmentConsistencyCheckRequested")
        }
        InterfoldEventData::CommitmentConsistencyCheckComplete(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::ThresholdDecryptionProofs =>
        {
            Some("CommitmentConsistencyCheckComplete")
        }
        InterfoldEventData::ComputeRequest(data)
            if data.e3_id == *e3_id
                && matches!(
                    &data.request,
                    ComputeRequestKind::Zk(ZkRequest::VerifyShareProofs(_))
                        | ComputeRequestKind::TrBFV(TrBFVRequest::CalculateThresholdDecryption(_))
                        | ComputeRequestKind::Zk(ZkRequest::DecryptedSharesAggregation(_))
                        | ComputeRequestKind::Zk(ZkRequest::NodeDkgFold { .. })
                        | ComputeRequestKind::Zk(ZkRequest::DkgAggregation { .. })
                        | ComputeRequestKind::Zk(ZkRequest::DecryptionAggregation { .. })
                ) =>
        {
            Some("ComputeRequest")
        }
        InterfoldEventData::ComputeResponse(data)
            if data.e3_id == *e3_id
                && matches!(
                    &data.response,
                    ComputeResponseKind::Zk(ZkResponse::VerifyShareProofs(_))
                        | ComputeResponseKind::TrBFV(TrBFVResponse::CalculateThresholdDecryption(
                            _
                        ))
                        | ComputeResponseKind::Zk(ZkResponse::DecryptedSharesAggregation(_))
                        | ComputeResponseKind::Zk(ZkResponse::NodeDkgFold(_))
                        | ComputeResponseKind::Zk(ZkResponse::DkgAggregation(_))
                        | ComputeResponseKind::Zk(ZkResponse::DecryptionAggregation(_))
                ) =>
        {
            Some("ComputeResponse")
        }
        InterfoldEventData::ProofVerificationPassed(data)
            if data.e3_id == *e3_id && data.proof_type == ProofType::C6ThresholdShareDecryption =>
        {
            Some("ProofVerificationPassed")
        }
        InterfoldEventData::ShareVerificationComplete(data)
            if data.e3_id == *e3_id && data.kind == VerificationKind::ThresholdDecryptionProofs =>
        {
            Some("ShareVerificationComplete")
        }
        InterfoldEventData::AggregationProofPending(data) if data.e3_id == *e3_id => {
            Some("AggregationProofPending")
        }
        InterfoldEventData::AggregationProofSigned(data) if data.e3_id == *e3_id => {
            Some("AggregationProofSigned")
        }
        InterfoldEventData::PlaintextAggregated(data) if data.e3_id == *e3_id => {
            Some("PlaintextAggregated")
        }
        _ => None,
    }
}

async fn setup_score_sortition_environment(
    bus: &BusHandle,
    eth_addrs: &Vec<String>,
    chain_id: u64,
) -> Result<()> {
    bus.publish_without_context(ConfigurationUpdated {
        parameter: "ticketPrice".to_string(),
        old_value: U256::ZERO,
        new_value: U256::from(10_000_000u64),
        chain_id,
    })?;

    let mut adder = AddToCommittee::new(bus, chain_id);
    for addr in eth_addrs {
        adder.add(addr).await?;

        bus.publish_without_context(TicketBalanceUpdated {
            operator: addr.clone(),
            delta: I256::try_from(1_000_000_000u64).unwrap(),
            new_balance: U256::from(1_000_000_000u64),
            reason: FixedBytes::ZERO,
            chain_id,
        })?;

        bus.publish_without_context(OperatorActivationChanged {
            operator: addr.clone(),
            active: true,
            chain_id,
        })?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum PhaseMetric {
    WallClock,
}

impl PhaseMetric {
    fn as_str(self) -> &'static str {
        match self {
            PhaseMetric::WallClock => "wall_clock",
        }
    }
}

#[derive(Default)]
struct Report {
    inner: Vec<(String, Duration, PhaseMetric)>,
}

fn repeat(ch: char, num: usize) -> String {
    let mut s = String::new();
    while s.len() < num {
        s.push(ch);
    }
    s
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Report {
    pub fn push_wall(&mut self, label: &str, dur: Duration) {
        self.show(label);
        self.inner
            .push((label.to_owned(), dur, PhaseMetric::WallClock));
    }

    pub fn push(&mut self, repo: (&str, Duration)) {
        self.push_wall(repo.0, repo.1);
    }

    pub fn show(&self, label: &str) {
        println!(
            "\n\n {}\n {}{}{}\n {}\n",
            colorize(repeat('#', label.len() + 6), Color::Yellow),
            colorize("## ", Color::Yellow),
            colorize(label.to_uppercase(), Color::White),
            colorize(" ##", Color::Yellow),
            colorize(repeat('#', label.len() + 6), Color::Yellow),
        );
    }

    pub fn serialize(&self) -> String {
        let max_key_len = self
            .inner
            .iter()
            .map(|(k, _, _)| k.len())
            .max()
            .unwrap_or(0);

        self.inner
            .iter()
            .map(|(key, duration, _)| {
                format!(
                    "{:width$}: {:.3}s",
                    key,
                    duration.as_secs_f64(),
                    width = max_key_len
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Test trbfv
#[actix::test]
#[serial_test::serial]
async fn test_trbfv_actor() -> Result<()> {
    let mut report = Report::default();
    report.push(("Starting trbfv actor test", Duration::from_secs(0)));
    let whole_test = Instant::now();
    let _guard = with_tracing("info");

    // NOTE: Here we are trying to make it as clear as possible as to what is going on so attempting to
    // avoid over abstracting test helpers and favouring straight forward single descriptive
    // functions alongside explanations

    ///////////////////////////////////////////////////////////////////////////////////
    // 1. Setup ThresholdKeyshare system
    //
    //   - E3Router
    //   - ThresholdKeyshare
    //   - Multithread actor
    //   - 20 nodes (so as to check for some nodes not getting selected)
    //   - Loopback libp2p simulation
    ///////////////////////////////////////////////////////////////////////////////////

    let setup = Instant::now();

    const BENCHMARK_NODE_RNG_BASE: u64 = 42;

    // Create "trigger" bus
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");

    // Parameters selected by benchmark mode.
    let benchmark_params = select_benchmark_params();
    let _env_guard = EnvTimeoutVarsGuard::new();
    if let Some((enc, threshold, dec_shared)) = benchmark_params.collection_timeout_secs {
        std::env::set_var("E3_ENCRYPTION_KEY_COLLECTION_TIMEOUT_SECS", enc.to_string());
        std::env::set_var(
            "E3_THRESHOLD_SHARE_COLLECTION_TIMEOUT_SECS",
            threshold.to_string(),
        );
        std::env::set_var(
            "E3_DECRYPTION_KEY_SHARED_COLLECTION_TIMEOUT_SECS",
            dec_shared.to_string(),
        );
    }

    let pubkey_flow_timeout = benchmark_params.pubkey_flow_timeout;
    let plaintext_flow_timeout = benchmark_params.plaintext_flow_timeout;

    let params_raw = BfvParamSet::from(benchmark_params.bfv_preset).build_arc();

    // Encoded Params
    let params = ArcBytes::from_bytes(&encode_bfv_params(&params_raw.clone()));

    // round information
    // Committee comes from the build stamp — the test always runs against whatever the circuits
    // in `circuits/bin/` were compiled for, so switching committee is a single
    // `pnpm build:circuits --committee <name>` away with no env var to remember.
    let committee_size = active_committee(benchmark_params.preset_subdir);
    let benchmark_committee = committee_size.values();
    let threshold_m = benchmark_committee.threshold;
    let threshold_n = benchmark_committee.n;
    let committee_h = benchmark_committee.h;
    let participant_count = benchmark_participant_node_count(threshold_m, threshold_n);
    let nodes_spawned = participant_count + 1; // +1 non-registered observer collector
                                               // Statistical security parameter λ used for smudging bound / error_size.
                                               // Comes from the selected BFV preset metadata to avoid mixing parameter families.
                                               // Lambda is secure or insecure depending on the selected preset's security tier.
    let lambda = benchmark_params.bfv_preset.lambda()?;

    let seed = create_seed_from_u64(123);
    let error_size = ArcBytes::from_bytes(&BigUint::to_bytes_be(&calculate_error_size(
        params_raw.clone(),
        threshold_n,
        threshold_m,
        lambda,
    )?));

    // Cipher
    let cipher = Arc::new(Cipher::from_password("I am the music man.").await?);

    // Actor system setup
    let concurrent_jobs = benchmark_multithread_concurrent_jobs();
    let slashing_manager_addr = benchmark_slashing_manager_address();
    let max_threadroom = Multithread::get_max_threads_minus(1);
    let pool_threads = concurrent_jobs.min(max_threadroom).max(1);
    let task_pool = Multithread::create_taskpool(pool_threads, concurrent_jobs);
    let multithread_report = MultithreadReport::new(pool_threads, concurrent_jobs).start();

    // Minimal chain config for in-process benchmarks (no RPC needed).
    // Provides slashing_manager address for EIP-712 accusation vote signatures.
    let bench_chain_config = e3_config::chain_config::ChainConfig {
        enabled: Some(false),
        name: "bench".into(),
        rpc_url: "http://localhost:8545".into(),
        rpc_auth: Default::default(),
        contracts: e3_config::ContractAddresses {
            interfold: e3_config::Contract::AddressOnly(
                "0x0000000000000000000000000000000000000000".into(),
            ),
            ciphernode_registry: e3_config::Contract::AddressOnly(
                "0x0000000000000000000000000000000000000000".into(),
            ),
            bonding_registry: e3_config::Contract::AddressOnly(
                "0x0000000000000000000000000000000000000000".into(),
            ),
            e3_program: None,
            fee_token: None,
            slashing_manager: Some(e3_config::Contract::AddressOnly(
                slashing_manager_addr.to_string(),
            )),
            dkg_fold_attestation_verifier: benchmark_dkg_fold_attestation_verifier_address()
                .map(|a| e3_config::Contract::AddressOnly(a.to_string())),
        },
        finalization_ms: None,
        reorg_confirmations: None,
        chain_id: Some(1),
    };

    // Setup ZK backend for proof generation/verification
    let (zk_backend, _zk_temp) = setup_test_zk_backend(benchmark_params.preset_subdir).await?;

    let nodes = CiphernodeSystemBuilder::new()
        // All nodes run the same binary under the aggregator-committee model.
        // Node 0 stays an observer only because it is excluded from sortition registration.
        // Participant count scales with active committee (N + sortition buffer).
        .add_group(1, || async {
            let node_rng = next_benchmark_node_rng(BENCHMARK_NODE_RNG_BASE);
            let addr = rand_eth_addr(&node_rng);
            println!("Building collector {}!", addr);
            {
                let b = CiphernodeBuilder::new(node_rng, cipher.clone())
                    .with_history_collector()
                    .with_shared_taskpool(&task_pool)
                    .with_multithread_concurrent_jobs(concurrent_jobs)
                    .with_shared_multithread_report(&multithread_report)
                    .with_trbfv()
                    .with_zkproof(zk_backend.clone())
                    .with_signer(PrivateKeySigner::random())
                    .with_pubkey_aggregation()
                    .with_sortition_score()
                    .with_threshold_plaintext_aggregation()
                    .with_forked_bus(bus.event_bus())
                    .with_chains(std::slice::from_ref(&bench_chain_config))
                    .with_logging();
                b.build().await
            }
        })
        .add_group(
            u32::try_from(participant_count).expect("benchmark participant count fits in u32"),
            || async {
                let node_rng = next_benchmark_node_rng(BENCHMARK_NODE_RNG_BASE);
                let addr = rand_eth_addr(&node_rng);
                println!("Building normal {}", &addr);
                {
                    let b = CiphernodeBuilder::new(node_rng, cipher.clone())
                        .with_history_collector()
                        .with_shared_taskpool(&task_pool)
                        .with_multithread_concurrent_jobs(concurrent_jobs)
                        .with_shared_multithread_report(&multithread_report)
                        .with_trbfv()
                        .with_zkproof(zk_backend.clone())
                        .with_signer(PrivateKeySigner::random())
                        .with_pubkey_aggregation()
                        .with_sortition_score()
                        .with_threshold_plaintext_aggregation()
                        .with_forked_bus(bus.event_bus())
                        .with_chains(std::slice::from_ref(&bench_chain_config))
                        .with_logging();
                    b.build().await
                }
            },
        )
        .simulate_libp2p()
        .build()
        .await?;

    report.push(("Setup completed", setup.elapsed()));

    let committee_setup = Instant::now();
    let chain_id = 1u64;

    // Only register nodes 1..=participant_count in sortition (exclude collector at index 0).
    // This ensures the collector is never selected, making the test deterministic.
    // The collector node will observe events as a non-participant.
    let collector_addr = nodes.first().unwrap().address();
    let eth_addrs: Vec<String> = nodes
        .iter()
        .skip(1) // Skip the collector node
        .map(|n| n.address())
        .collect();

    anyhow::ensure!(
        eth_addrs.len() >= threshold_n,
        "benchmark harness: need at least {threshold_n} registered nodes for committee N, got {}",
        eth_addrs.len()
    );

    println!(
        "Test setup: {} registered nodes (pool target {}), committee N={}, collector (observer): {}",
        eth_addrs.len(),
        participant_count,
        threshold_n,
        collector_addr
    );

    setup_score_sortition_environment(&bus, &eth_addrs, chain_id).await?;

    // Flush all events
    nodes.flush_all_history(10000).await?;

    report.push(("Committee Setup Completed", committee_setup.elapsed()));

    ///////////////////////////////////////////////////////////////////////////////////
    // 2. Trigger E3Requested
    //
    //   - threshold_m / threshold_n / committee_h from active committee stamp
    //   - lambda -> calculate_error_size uses the selected BFV preset metadata
    //   - error_size -> calculate using calculate_error_size
    //   - esi_per_ciphertext = 1
    ///////////////////////////////////////////////////////////////////////////////////

    // Prepare round
    let e3_requested_timer = Instant::now();
    // Trigger actor DKG
    let e3_id = E3id::new("0", 1);

    let proof_aggregation_enabled = benchmark_proof_aggregation_enabled();
    println!(
        "Benchmark trbfv: proof_aggregation={proof_aggregation_enabled}, preset={}, pool_threads={pool_threads}, max_concurrent_jobs={concurrent_jobs}",
        benchmark_params.preset_subdir
    );

    let e3_requested = E3Requested {
        e3_id: e3_id.clone(),
        threshold_m,
        threshold_n,
        seed,
        error_size,
        params_preset: benchmark_params.bfv_preset,
        params,
        proof_aggregation_enabled,
    };

    bus.publish_without_context(e3_requested)?;

    sleep(Duration::from_millis(500)).await;

    let (committee, committee_scores, buffer_nodes) = determine_committee(
        &e3_id,
        seed,
        threshold_m,
        threshold_n,
        &eth_addrs,
        &collector_addr,
    )?;

    report.show(&format!(
        "Committee selected: {} nodes, {} buffer nodes",
        committee.len(),
        buffer_nodes.len()
    ));

    let active_aggregator_addr =
        active_aggregator_address(&committee, &committee_scores, &e3_id, chain_id);
    let active_aggregator_index = find_node_index_by_address(&nodes, &active_aggregator_addr)?;

    println!(
        "Resolved active aggregator: node index {} ({})",
        active_aggregator_index, active_aggregator_addr
    );

    nodes.expect_events(&["E3Requested"]).await?;

    bus.publish_without_context(CommitteeFinalized {
        e3_id: e3_id.clone(),
        committee: committee.clone(),
        scores: committee_scores,
        chain_id,
    })?;

    let committee_finalized_timer = Instant::now();

    nodes.expect_events(&["CommitteeFinalized"]).await?;

    report.push((
        "Committee Finalization Complete",
        committee_finalized_timer.elapsed(),
    ));

    // Node 0 is a non-committee observer. It only sees bus-global events and the forwardable
    // gossip events from the active aggregator flow.
    let shares_to_pubkey_agg_timer = Instant::now();
    // KeyshareCreated is gossiped by each committee member (N). The aggregator folds H honest
    // keyshares into PublicKeyAggregated; DKGRecursiveAggregationComplete is one per member (N).
    let ks_n: Vec<&'static str> = vec!["KeyshareCreated"; threshold_n];
    let dkg_n: Vec<&'static str> = vec!["DKGRecursiveAggregationComplete"; threshold_n];
    let mut active_aggregator_c1_c5: Vec<&'static str> = vec![
        "ShareVerificationDispatched",
        "CommitmentConsistencyCheckRequested",
        "CommitmentConsistencyCheckComplete",
    ];
    // C1 verification dispatches ALL N submitted keyshare proofs (the protocol needs to know
    // who's dishonest before it can pick the H honest set), so N ProofVerificationPassed events
    // fire. The aggregator subsequently truncates to H for C5 input only.
    active_aggregator_c1_c5.extend(std::iter::repeat_n("ProofVerificationPassed", threshold_n));
    active_aggregator_c1_c5.extend_from_slice(&[
        "ShareVerificationComplete",
        "PkAggregationProofPending",
        "PkAggregationProofSigned",
    ]);

    let mut expected_events: Vec<&'static str> = vec!["AggregatorChanged"];
    if proof_aggregation_enabled {
        expected_events.extend_from_slice(&ks_n);
        expected_events.extend_from_slice(&dkg_n);
    } else {
        expected_events.extend_from_slice(&dkg_n);
        expected_events.extend_from_slice(&ks_n);
    }
    expected_events.push("PublicKeyAggregated");
    // Gossip can duplicate KeyshareCreated; wait until PublicKeyAggregated rather than a fixed take count.
    let h = nodes
        .take_history_until_last_event(
            0,
            "PublicKeyAggregated",
            Some(pubkey_flow_timeout),
            Some(pubkey_flow_timeout),
        )
        .await
        .map_err(|e| anyhow::anyhow!("FAILURE on node 0 pubkey flow: {e}"))?;
    let actual_types = h.event_types();
    println!("node 0 >> {:?}", actual_types);

    assert_eq!(
        actual_types.first().map(String::as_str),
        Some("AggregatorChanged"),
        "node 0: first event must be AggregatorChanged"
    );
    assert_eq!(
        actual_types.last().map(String::as_str),
        Some("PublicKeyAggregated"),
        "node 0: last event must be PublicKeyAggregated"
    );

    let dkg_parties: HashSet<u64> = h
        .iter()
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::DKGRecursiveAggregationComplete(d) => Some(d.party_id),
            _ => None,
        })
        .collect();
    let ks_parties: HashSet<u64> = h
        .iter()
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::KeyshareCreated(d) => Some(d.party_id),
            _ => None,
        })
        .collect();
    // Unlike KeyshareCreated (cheap, gossiped early — all N arrive before aggregation), the
    // per-node recursive fold proof (DKGRecursiveAggregationComplete) is expensive and late.
    // `PublicKeyAggregated` fires once the aggregator selects and aggregates the honest set, so
    // only the H honest folds are guaranteed to have reached node 0 by this barrier; the extra
    // N-H members' folds race against it (and may land afterward). Assert the guaranteed floor
    // and that every observed fold party is a committee member, not the racy `== N`.
    assert!(
        dkg_parties.len() >= committee_h
            && dkg_parties.len() <= threshold_n
            && dkg_parties.iter().all(|p| (*p as usize) < threshold_n),
        "node 0: expected DKGRecursiveAggregationComplete from {committee_h}..={threshold_n} committee members before PublicKeyAggregated (only the H honest folds are guaranteed by this barrier), got parties {dkg_parties:?}"
    );
    assert_eq!(
        ks_parties.len(),
        threshold_n,
        "node 0: expected KeyshareCreated from each committee member (N={threshold_n}), got parties {ks_parties:?}"
    );
    let pk_agg = h
        .iter()
        .rev()
        .find_map(|e| match e.get_data() {
            InterfoldEventData::PublicKeyAggregated(d) => Some(d),
            _ => None,
        })
        .expect("PublicKeyAggregated in history");
    assert_eq!(
        pk_agg.nodes.len(),
        committee_h,
        "PublicKeyAggregated must list H={committee_h} honest nodes"
    );

    let active_aggregator_history = nodes.get_history(active_aggregator_index).await?;
    let active_aggregator_pubkey_history_len = active_aggregator_history.len();
    let mut expected_active_aggregator_pubkey_events = vec![
        "CommitteeFinalized",
        "CiphernodeSelected",
        "AggregatorChanged",
    ];
    if proof_aggregation_enabled {
        expected_active_aggregator_pubkey_events.extend_from_slice(&ks_n);
    } else {
        expected_active_aggregator_pubkey_events.extend_from_slice(&dkg_n);
        expected_active_aggregator_pubkey_events.extend_from_slice(&ks_n);
    }
    expected_active_aggregator_pubkey_events.extend_from_slice(&active_aggregator_c1_c5);
    if proof_aggregation_enabled {
        expected_active_aggregator_pubkey_events.extend_from_slice(&dkg_n);
    }
    expected_active_aggregator_pubkey_events.push("PublicKeyAggregated");

    // The active aggregator is also a selected committee member, so its node history contains
    // local ThresholdKeyshare DKG work in addition to the public-key aggregation stage. Project
    // only the deterministic pubkey-aggregation signals instead of comparing the whole raw node bus.
    //
    // KeyshareCreated and DKGRecursiveAggregationComplete events are produced independently
    // by each committee member and gossiped in parallel with the active aggregator's own
    // C1→C5 verification flow, so their positions relative to the C1→C5 sub-sequence are
    // non-deterministic. Compare as a multiset plus boundary events rather than strict order.
    let active_aggregator_pubkey_events = project_history(&active_aggregator_history, |data| {
        publickey_aggregator_marker(data, &e3_id)
    });
    let mut actual_sorted = active_aggregator_pubkey_events.clone();
    let mut expected_sorted = expected_active_aggregator_pubkey_events.clone();
    actual_sorted.sort();
    expected_sorted.sort();
    assert_eq!(
        actual_sorted, expected_sorted,
        "Active aggregator public-key flow: event multiset mismatch"
    );
    assert_eq!(
        active_aggregator_pubkey_events.first().copied(),
        Some("CommitteeFinalized"),
        "Active aggregator: first event must be CommitteeFinalized"
    );
    assert_eq!(
        active_aggregator_pubkey_events.last().copied(),
        Some("PublicKeyAggregated"),
        "Active aggregator: last event must be PublicKeyAggregated"
    );

    if let Some(secs) = history_wall_seconds_between(
        &active_aggregator_history,
        |d| {
            matches!(
                d,
                InterfoldEventData::PkAggregationProofPending(data) if data.e3_id == e3_id
            )
        },
        |d| matches!(d, InterfoldEventData::PublicKeyAggregated(data) if data.e3_id == e3_id),
    ) {
        report.push_wall(
            "Aggregator P2: PkAggregation pending -> PublicKeyAggregated (wall)",
            Duration::from_secs_f64(secs),
        );
    }

    report.push_wall(
        "ThresholdShares -> PublicKeyAggregated",
        shares_to_pubkey_agg_timer.elapsed(),
    );

    report.push((
        "E3Request -> PublicKeyAggregated",
        e3_requested_timer.elapsed(),
    ));
    let app_gen_timer = Instant::now();

    // First we get the public key from the collector-visible gossip event.
    println!("Getting public key");
    let Some(pubkey_event) = h.iter().rev().find_map(|event| match event.get_data() {
        InterfoldEventData::PublicKeyAggregated(data) => Some(data.clone()),
        _ => None,
    }) else {
        panic!(
            "Was expecting collector history to contain PublicKeyAggregated, got: {:?}",
            h.event_types()
        );
    };

    let pubkey_bytes = pubkey_event.pubkey.clone();
    let dkg_aggregator_proof = pubkey_event.dkg_aggregator_proof.clone();

    let pubkey = PublicKey::from_bytes(&pubkey_bytes, &params_raw)?;

    println!("Generating inputs this takes some time...");

    // Create the inputs
    let num_votes_per_voter = 3;
    let num_voters = 30;
    let (inputs, numbers) = e3_test_helpers::application::generate_ciphertexts(
        &pubkey,
        num_voters,
        num_votes_per_voter,
    );
    report.push(("Application CT Gen", app_gen_timer.elapsed()));

    let running_app_timer = Instant::now();
    println!("Running application to generate outputs...");
    let outputs =
        e3_test_helpers::application::run_application(&inputs, &pubkey, num_votes_per_voter);
    report.push(("Running FHE Application", running_app_timer.elapsed()));

    let publishing_ct_timer = Instant::now();
    println!("Have outputs. Creating ciphertexts...");
    let ciphertexts = outputs
        .into_iter()
        .map(|ct| ArcBytes::from_bytes(&(*ct).clone().to_bytes()))
        .collect::<Vec<ArcBytes>>();

    // Created the event
    println!("Publishing CiphertextOutputPublished...");
    let ciphertext_published_event = CiphertextOutputPublished {
        ciphertext_output: ciphertexts,
        e3_id: e3_id.clone(),
    };

    bus.publish_without_context(ciphertext_published_event.clone())?;

    println!("CiphertextOutputPublished event has been dispatched!");

    // The collector only sees the shared ciphertext event, gossiped decryption shares, and the
    // final gossiped plaintext output.
    // Only the H honest parties decrypt and gossip a share; the (N - H) extras stay in the
    // full committee but do not participate in decryption.
    let ds_n: Vec<&'static str> = vec!["DecryptionshareCreated"; committee_h];
    let mut expected_events: Vec<&'static str> = vec!["CiphertextOutputPublished"];
    expected_events.extend_from_slice(&ds_n);
    expected_events.push("PlaintextAggregated");

    println!(
        "[bench-progress] waiting for PlaintextAggregated flow on observer node (expected events: {})",
        expected_events.len()
    );
    // Gossip can duplicate DecryptionshareCreated on the collector path (same as KeyshareCreated
    // in the pubkey flow); wait until `PlaintextAggregated` rather than a fixed take count, then
    // assert the multiset matches with duplicates removed.
    let h = nodes
        .take_history_until_last_event(
            0,
            "PlaintextAggregated",
            Some(plaintext_flow_timeout),
            Some(plaintext_flow_timeout),
        )
        .await
        .map_err(|e| anyhow::anyhow!("FAILURE on node 0 plaintext flow: {e}"))?;
    let actual_types = h.event_types();
    println!("node 0 >> {:?}", actual_types);
    assert_eq!(
        actual_types.first().map(String::as_str),
        Some("CiphertextOutputPublished"),
        "collector: first plaintext-flow event must be CiphertextOutputPublished"
    );
    assert_eq!(
        actual_types.last().map(String::as_str),
        Some("PlaintextAggregated"),
        "collector: last plaintext-flow event must be PlaintextAggregated"
    );
    let unique_ds_parties: HashSet<u64> = h
        .iter()
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::DecryptionshareCreated(d) => Some(d.party_id),
            _ => None,
        })
        .collect();
    // All N committee members that received share material attempt decryption and gossip; the
    // aggregator consumes only H. So the number of distinct senders observed at the collector
    // sits in [H, N].
    assert!(
        unique_ds_parties.len() >= committee_h && unique_ds_parties.len() <= threshold_n,
        "collector: expected DecryptionshareCreated from {committee_h}..={threshold_n} distinct parties, got {} parties {unique_ds_parties:?}",
        unique_ds_parties.len()
    );
    println!("[bench-progress] PlaintextAggregated observed on collector path");

    let active_aggregator_history = nodes.get_history(active_aggregator_index).await?;
    let active_aggregator_plaintext_events = project_history(
        &active_aggregator_history[active_aggregator_pubkey_history_len..],
        |data| plaintext_aggregator_marker(data, &e3_id),
    );

    // C6 head layout:
    //   CiphertextOutputPublished, DecryptionshareCreated × K, ShareVerificationDispatched,
    //   CommitmentConsistencyCheckRequested, CommitmentConsistencyCheckComplete
    // where K is in [H, N] plus possible gossip duplicates — every committee member that received
    // share material gossips one, the aggregator selects H. Locate boundaries by name rather than
    // by fixed offset.
    assert_eq!(
        active_aggregator_plaintext_events.first().copied(),
        Some("CiphertextOutputPublished"),
        "active aggregator: first plaintext-flow event must be CiphertextOutputPublished"
    );
    let svd_index = active_aggregator_plaintext_events
        .iter()
        .position(|e| *e == "ShareVerificationDispatched")
        .expect("ShareVerificationDispatched should be present in plaintext flow");
    let pre_svd = &active_aggregator_plaintext_events[1..svd_index];
    assert!(
        pre_svd.iter().all(|e| *e == "DecryptionshareCreated"),
        "active aggregator: only DecryptionshareCreated allowed between CiphertextOutputPublished and ShareVerificationDispatched, got {pre_svd:?}"
    );
    let unique_ds_parties_agg: HashSet<u64> = active_aggregator_history
        [active_aggregator_pubkey_history_len..]
        .iter()
        .take_while(|e| {
            !matches!(
                e.get_data(),
                InterfoldEventData::ShareVerificationDispatched(_)
            )
        })
        .filter_map(|e| match e.get_data() {
            InterfoldEventData::DecryptionshareCreated(d) if d.e3_id == e3_id => Some(d.party_id),
            _ => None,
        })
        .collect();
    assert!(
        unique_ds_parties_agg.len() >= committee_h && unique_ds_parties_agg.len() <= threshold_n,
        "active aggregator: expected DecryptionshareCreated from {committee_h}..={threshold_n} distinct parties before ShareVerificationDispatched, got {} parties {unique_ds_parties_agg:?}",
        unique_ds_parties_agg.len()
    );
    assert_eq!(
        &active_aggregator_plaintext_events[svd_index..svd_index + 3],
        &[
            "ShareVerificationDispatched",
            "CommitmentConsistencyCheckRequested",
            "CommitmentConsistencyCheckComplete",
        ][..],
        "Unexpected active aggregator C6 head after ShareVerificationDispatched"
    );
    let c6_head_end = svd_index + 3;

    let aggregation_pending_index = active_aggregator_plaintext_events
        .iter()
        .position(|event| *event == "AggregationProofPending")
        .expect("AggregationProofPending should be present");
    let c6_body = &active_aggregator_plaintext_events[c6_head_end..aggregation_pending_index];
    assert_eq!(
        count_projected_events(c6_body, "ShareVerificationComplete"),
        1,
        "expected one C6 ShareVerificationComplete before aggregation"
    );
    assert!(
        count_projected_events(c6_body, "ProofVerificationPassed") >= committee_h,
        "expected >= {committee_h} C6 ProofVerificationPassed events before aggregation"
    );
    let c6_compute_requests = count_projected_events(c6_body, "ComputeRequest");
    let c6_compute_responses = count_projected_events(c6_body, "ComputeResponse");
    assert!(
        c6_compute_requests >= 1 && c6_compute_requests == c6_compute_responses,
        "expected paired C6-phase ComputeRequest/ComputeResponse (got {c6_compute_requests} requests, {c6_compute_responses} responses)"
    );

    let aggregation_flow = &active_aggregator_plaintext_events[aggregation_pending_index..];
    let mut expected_aggregation_flow = vec![
        "AggregationProofPending",
        "ComputeRequest",
        "ComputeResponse",
        "AggregationProofSigned",
    ];
    if proof_aggregation_enabled {
        // `DecryptionAggregation`: one compute pair (C6 fold + C7 checked inside the worker).
        expected_aggregation_flow.push("ComputeRequest");
        expected_aggregation_flow.push("ComputeResponse");
    }
    expected_aggregation_flow.push("PlaintextAggregated");

    // Filter out late-arriving DecryptionshareCreated gossip events that can interleave
    // with the aggregation phase when using larger committees.
    let aggregation_flow_filtered: Vec<&str> = aggregation_flow
        .iter()
        .copied()
        .filter(|e| *e != "DecryptionshareCreated")
        .collect();
    assert_eq!(
        aggregation_flow_filtered.as_slice(),
        expected_aggregation_flow.as_slice(),
        "Unexpected active aggregator C7/aggregation flow"
    );
    assert_eq!(
        count_projected_events(aggregation_flow, "AggregationProofSigned"),
        1
    );
    assert_eq!(
        count_projected_events(aggregation_flow, "PlaintextAggregated"),
        1
    );
    let aggregation_signed_index = aggregation_flow
        .iter()
        .position(|event| *event == "AggregationProofSigned")
        .expect("AggregationProofSigned should be present");
    let plaintext_aggregated_index = aggregation_flow
        .iter()
        .position(|event| *event == "PlaintextAggregated")
        .expect("PlaintextAggregated should be present");
    assert!(
        aggregation_signed_index < plaintext_aggregated_index,
        "AggregationProofSigned must precede PlaintextAggregated"
    );
    assert_eq!(
        plaintext_aggregated_index,
        aggregation_flow.len() - 1,
        "PlaintextAggregated must be the last active aggregator completion event"
    );

    if let Some(secs) = history_wall_seconds_between(
        &active_aggregator_history[active_aggregator_pubkey_history_len..],
        |d| {
            matches!(
                d,
                InterfoldEventData::AggregationProofPending(data) if data.e3_id == e3_id
            )
        },
        |d| matches!(d, InterfoldEventData::PlaintextAggregated(data) if data.e3_id == e3_id),
    ) {
        report.push_wall(
            "Aggregator P4: Aggregation pending -> PlaintextAggregated (wall)",
            Duration::from_secs_f64(secs),
        );
    }

    report.push_wall(
        "Ciphertext published -> PlaintextAggregated",
        publishing_ct_timer.elapsed(),
    );

    let (plaintext, decryption_aggregator_proofs) = h
        .iter()
        .rev()
        .find_map(|e| {
            if let InterfoldEventData::PlaintextAggregated(PlaintextAggregated {
                decrypted_output,
                decryption_aggregator_proofs,
                ..
            }) = e.get_data()
            {
                Some((
                    decrypted_output.clone(),
                    decryption_aggregator_proofs.clone(),
                ))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Expected PlaintextAggregated in events, got: {:?}",
                h.event_types()
            )
        })?;

    if proof_aggregation_enabled {
        assert!(
            !decryption_aggregator_proofs.is_empty(),
            "DecryptionAggregator proofs should be present in PlaintextAggregated when proof_aggregation_enabled"
        );
    }

    if let Ok(path) = std::env::var("BENCHMARK_FOLDED_OUTPUT") {
        if let (Some(dkg_proof), Some(dec_proof)) = (
            dkg_aggregator_proof.as_ref(),
            decryption_aggregator_proofs.first(),
        ) {
            let json = format!(
                concat!(
                    "{{\n",
                    "  \"dkg_aggregator\": {{\n",
                    "    \"proof_hex\": \"{}\",\n",
                    "    \"public_inputs_hex\": \"{}\"\n",
                    "  }},\n",
                    "  \"decryption_aggregator\": {{\n",
                    "    \"proof_hex\": \"{}\",\n",
                    "    \"public_inputs_hex\": \"{}\"\n",
                    "  }}\n",
                    "}}\n"
                ),
                to_hex(&dkg_proof.data),
                to_hex(&dkg_proof.public_signals),
                to_hex(&dec_proof.data),
                to_hex(&dec_proof.public_signals),
            );
            fs::write(&path, json)?;
            println!("Wrote folded benchmark proofs to {path}");
        } else {
            println!(
                "BENCHMARK_FOLDED_OUTPUT set but folded proofs unavailable (dkg={}, dec={})",
                dkg_aggregator_proof.is_some(),
                !decryption_aggregator_proofs.is_empty()
            );
        }
    }

    let results = plaintext
        .into_iter()
        .map(|a| decode_bytes_to_vec_u64(&a.extract_bytes()).expect("error decoding bytes"))
        .collect::<Vec<Vec<u64>>>();

    let results: Vec<u64> = results.into_iter().map(|r| *r.first().unwrap()).collect();

    // Show summation result (mod plaintext modulus)
    let plaintext_modulus = params_raw.clone().plaintext();
    let mut expected_result = [0u64; 3];
    for vals in &numbers {
        for j in 0..num_votes_per_voter {
            expected_result[j] = (expected_result[j] + vals[j]) % plaintext_modulus;
        }
    }

    for (i, (res, exp)) in results.iter().zip(expected_result.iter()).enumerate() {
        println!("Tally {i} result = {res} / {exp}");
        assert_eq!(res, exp);
    }

    // All-honest safeguard: scan every participant and the observer for spurious accusations,
    // commitment mismatches (including C4 DecryptionProofs on ThresholdKeyshare), and traps.
    for index in 1..=participant_count {
        let history = nodes.get_history(index).await?;
        assert_honest_run_safeguards(
            &history,
            &e3_id,
            &format!("participant node {index} ({})", nodes[index].address()),
        );
    }
    let observer_history = nodes.get_history(0).await?;
    assert_honest_run_safeguards(&observer_history, &e3_id, "observer node 0");

    let mt_report = multithread_report.send(ToReport).await.unwrap();
    println!("{}", mt_report);

    report.push(("Entire Test", whole_test.elapsed()));
    if let Ok(path) = std::env::var("BENCHMARK_SUMMARY_OUTPUT") {
        let operation_timings_json = mt_report
            .operation_timings_sec()
            .iter()
            .map(|op| {
                format!(
                    "    {{\"name\": \"{}\", \"avg_seconds\": {:.9}, \"runs\": {}, \"total_seconds\": {:.9}}}",
                    json_escape(&op.name),
                    op.avg_seconds,
                    op.runs,
                    op.total_seconds
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        let phase_timings_json = report
            .inner
            .iter()
            .map(|(label, duration, metric)| {
                format!(
                    "    {{\"label\": \"{}\", \"seconds\": {:.9}, \"metric\": \"{}\"}}",
                    json_escape(label),
                    duration.as_secs_f64(),
                    metric.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");

        let folded_section = if let (Some(dkg_proof), Some(dec_proof)) = (
            dkg_aggregator_proof.as_ref(),
            decryption_aggregator_proofs.first(),
        ) {
            format!(
                concat!(
                    "  \"folded_artifacts\": {{\n",
                    "    \"dkg_aggregator\": {{\n",
                    "      \"proof_hex\": \"{}\",\n",
                    "      \"public_inputs_hex\": \"{}\"\n",
                    "    }},\n",
                    "    \"decryption_aggregator\": {{\n",
                    "      \"proof_hex\": \"{}\",\n",
                    "      \"public_inputs_hex\": \"{}\"\n",
                    "    }}\n",
                    "  }}\n"
                ),
                to_hex(&dkg_proof.data),
                to_hex(&dkg_proof.public_signals),
                to_hex(&dec_proof.data),
                to_hex(&dec_proof.public_signals),
            )
        } else {
            String::from("  \"folded_artifacts\": null\n")
        };

        let dkg_fold_verifier_json = benchmark_dkg_fold_attestation_verifier_address()
            .map(|addr| format!("  \"dkg_fold_attestation_verifier\": \"{addr}\",\n"))
            .unwrap_or_default();

        let benchmark_mode =
            std::env::var("BENCHMARK_MODE").unwrap_or_else(|_| "insecure".to_string());
        let benchmark_config_json = format!(
            concat!(
                "  \"benchmark_config\": {{\n",
                "    \"mode\": \"{}\",\n",
                "    \"bfv_preset_subdir\": \"{}\",\n",
                "    \"bfv_preset\": \"{:?}\",\n",
                "    \"lambda\": {},\n",
                "    \"proof_aggregation_enabled\": {},\n",
                "    \"multithread_concurrent_jobs\": {},\n",
                "    \"committee_h\": {},\n",
                "    \"committee_n\": {},\n",
                "    \"committee_t\": {},\n",
                "    \"nodes_spawned\": {},\n",
                "    \"network_model\": \"in_process_bus\",\n",
                "    \"testmode_harness\": true\n",
                "  }},\n"
            ),
            json_escape(&benchmark_mode),
            json_escape(benchmark_params.preset_subdir),
            benchmark_params.bfv_preset,
            benchmark_params.lambda,
            proof_aggregation_enabled,
            concurrent_jobs,
            committee_h,
            threshold_n,
            threshold_m,
            nodes_spawned,
        );

        let summary_json = format!(
            concat!(
                "{{\n",
                "  \"integration_test\": \"test_trbfv_actor\",\n",
                "{benchmark_config_json}",
                "  \"proof_aggregation_enabled\": {},\n",
                "{dkg_fold_verifier_json}",
                "  \"multithread\": {{\n",
                "    \"rayon_threads\": {},\n",
                "    \"max_simultaneous_rayon_tasks\": {},\n",
                "    \"cores_available\": {}\n",
                "  }},\n",
                "  \"operation_timings\": [\n",
                "{}\n",
                "  ],\n",
                "  \"operation_timings_total_seconds\": {:.9},\n",
                "  \"operation_timings_metric\": \"tracked_job_wall\",\n",
                "  \"phase_timings\": [\n",
                "{}\n",
                "  ],\n",
                "{}",
                "}}\n"
            ),
            proof_aggregation_enabled,
            mt_report.rayon_threads(),
            mt_report.max_simultaneous_rayon_tasks(),
            mt_report.cores_available(),
            operation_timings_json,
            mt_report.tracked_total_seconds(),
            phase_timings_json,
            folded_section,
            benchmark_config_json = benchmark_config_json,
            dkg_fold_verifier_json = dkg_fold_verifier_json,
        );
        fs::write(&path, summary_json)?;
        println!("Wrote benchmark summary to {path}");
    }
    println!("{}", report.serialize());

    Ok(())
}

// ============================================================================
// Networking and P2P Tests
// ============================================================================

#[actix::test]
async fn test_p2p_actor_forwards_events_to_network() -> Result<()> {
    use e3_events::{CiphernodeSelected, InterfoldEvent, TakeEvents, Unsequenced};
    use e3_net::events::GossipData;
    use e3_net::{events::NetEvent, NetEventTranslator};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tokio::sync::{broadcast, Mutex};

    // Setup elements in test
    let (cmd_tx, mut cmd_rx) = mpsc::channel(100); // Transmit byte events to the network
    let (event_tx, _) = broadcast::channel(100); // Receive byte events from the network
    let system = EventSystem::new();
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();
    let event_rx = Arc::new(event_tx.subscribe());
    // Pas cmd and event channels to NetEventTranslator
    NetEventTranslator::setup(&bus, &cmd_tx, &event_rx, "my-topic");

    // Capture messages from output on msgs vec
    let msgs: Arc<Mutex<Vec<InterfoldEventData>>> = Arc::new(Mutex::new(Vec::new()));

    let msgs_loop = msgs.clone();

    tokio::spawn(async move {
        // Pull events from command channel
        while let Some(cmd) = cmd_rx.recv().await {
            // If the command is a GossipPublish then extract it and save it whilst sending it to
            // the event bus as if it was gossiped from the network and ended up as an external
            // message this simulates a rebroadcast message
            if let Some(msg) = match cmd {
                e3_net::events::NetCommand::GossipPublish { data, .. } => Some(data),
                _ => None,
            } {
                if let GossipData::GossipBytes(_) = msg {
                    let event: InterfoldEvent<Unsequenced> = msg.clone().try_into().unwrap();
                    let (data, _) = event.split();
                    msgs_loop.lock().await.push(data);
                    event_tx.send(NetEvent::GossipData(msg)).unwrap();
                }
            }
            // if this  manages to broadcast an event to the
            // event bus we will expect to see an extra event on
            // the bus but we don't because we handle this
        }
        anyhow::Ok(())
    });

    let evt_1 = PlaintextAggregated {
        e3_id: E3id::new("1235", 1),
        decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3, 4])],
        decryption_aggregator_proofs: vec![],
    };

    let evt_2 = PlaintextAggregated {
        e3_id: E3id::new("1236", 1),
        decrypted_output: vec![ArcBytes::from_bytes(&[1, 2, 3, 4])],
        decryption_aggregator_proofs: vec![],
    };

    let local_evt_3 = CiphernodeSelected {
        e3_id: E3id::new("1235", 1),
        threshold_m: 2,
        threshold_n: 5,
        ..CiphernodeSelected::default()
    };

    bus.publish_without_context(evt_1.clone())?;
    bus.publish_without_context(evt_2.clone())?;
    bus.publish_without_context(local_evt_3.clone())?; // This is a local event which should not be broadcast to the network

    // check the history of the event bus
    let history = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(3))
        .await?;

    assert_eq!(
        *msgs.lock().await,
        vec![evt_1.clone().into(), evt_2.clone().into()], // notice no local events
        "NetEventTranslator did not transmit correct events to the network"
    );

    assert_eq!(
        history
            .events
            .into_iter()
            .map(|e| e.into_data())
            .collect::<Vec<_>>(),
        vec![evt_1.into(), evt_2.into(), local_evt_3.into()], // all local events that have been broadcast but no
        // events from the loopback
        "NetEventTranslator must not retransmit forwarded event to event bus"
    );

    Ok(())
}

#[actix::test]
async fn test_p2p_actor_forwards_events_to_bus() -> Result<()> {
    let seed = Seed(ChaCha20Rng::seed_from_u64(123).get_seed());

    // Setup elements in test
    let (cmd_tx, _) = mpsc::channel(100); // Transmit byte events to the network
    let (event_tx, event_rx) = broadcast::channel(100); // Receive byte events from the network
    let system = EventSystem::new().with_fresh_bus();
    let bus = system.handle()?.enable("test");
    let history_collector = bus.history();

    NetEventTranslator::setup(&bus, &cmd_tx, &Arc::new(event_rx), "mytopic");

    // Capture messages from output on msgs vec
    let event = E3Requested {
        e3_id: E3id::new("1235", 1),
        threshold_m: 3,
        threshold_n: 3,
        seed,
        params: ArcBytes::from_bytes(&[1, 2, 3, 4]),
        ..E3Requested::default()
    };

    // lets send an event from the network
    let _ = event_tx.send(NetEvent::GossipData(GossipData::GossipBytes(
        bus.event_from(event.clone(), None)?.to_bytes()?,
    )));

    // check the history of the event bus
    let history = history_collector
        .send(TakeEvents::<InterfoldEvent>::new(1))
        .await?;

    assert_eq!(
        history
            .events
            .into_iter()
            .map(|e| e.into_data())
            .collect::<Vec<InterfoldEventData>>(),
        vec![event.into()]
    );

    Ok(())
}

// ============================================================================
// Legacy Tests Pending Port to trBFV
// ============================================================================

/// Test that stopped keyshares retain their state after restart.
/// This test needs to be ported to the new trBFV system once Sync is completed.
// XXX: ENABLE THIS!!
#[actix::test]
#[ignore = "Needs to be ported to trBFV system after Sync is completed"]
async fn test_stopped_keyshares_retain_state() -> Result<()> {
    use e3_bfv_client::{decode_bytes_to_vec_u64, decode_plaintext_to_vec_u64};
    use e3_data::{GetDump, InMemStore};
    use e3_events::{EventBus, EventBusConfig, GetEvents, Shutdown, TakeEvents};
    use e3_test_helpers::{create_random_eth_addrs, get_common_setup, simulate_libp2p_net};
    use fhe::{
        bfv::PublicKey,
        mbfv::{AggregateIter, PublicKeyShare},
    };
    use fhe_traits::Serialize;
    use std::time::Duration;
    use tokio::time::sleep;

    async fn setup_local_ciphernode(
        bus: &BusHandle,
        rng: &e3_utils::SharedRng,
        logging: bool,
        _addr: &str,
        store: Option<actix::Addr<InMemStore>>,
        cipher: &Arc<Cipher>,
        zk_backend: ZkBackend,
    ) -> Result<e3_ciphernode_builder::CiphernodeHandle> {
        let mut builder = CiphernodeBuilder::new(rng.clone(), cipher.clone())
            .with_trbfv()
            .with_zkproof(zk_backend)
            .with_signer(PrivateKeySigner::random())
            .with_forked_bus(bus.event_bus())
            .with_history_collector()
            .with_error_collector()
            .with_pubkey_aggregation()
            .with_threshold_plaintext_aggregation()
            .with_sortition_score();

        if let Some(ref in_mem_store) = store {
            builder = builder.with_in_mem_datastore(in_mem_store);
        }

        if logging {
            builder = builder.with_logging()
        }

        let node = builder.build().await?;
        Ok(node)
    }

    async fn create_local_ciphernodes(
        bus: &BusHandle,
        rng: &e3_utils::SharedRng,
        count: u32,
        cipher: &Arc<Cipher>,
        zk_backend: ZkBackend,
    ) -> Result<Vec<e3_ciphernode_builder::CiphernodeHandle>> {
        let eth_addrs = create_random_eth_addrs(count);
        let mut result = vec![];
        for addr in &eth_addrs {
            println!("Setting up eth addr: {}", addr);
            let tuple =
                setup_local_ciphernode(bus, rng, true, addr, None, cipher, zk_backend.clone())
                    .await?;
            result.push(tuple);
        }
        simulate_libp2p_net(&result).await;
        Ok(result)
    }

    let (zk_backend, _zk_temp) =
        setup_test_zk_backend(select_benchmark_params().preset_subdir).await?;

    let e3_id = E3id::new("1234", 1);
    let (rng, cn1_address, cn1_data, cn2_address, cn2_data, cipher, history, params, crpoly) = {
        let (bus, rng, seed, params, crpoly, _, _) = get_common_setup(None)?;
        let cipher = Arc::new(Cipher::from_password("Don't tell anyone my secret").await?);
        let ciphernodes =
            create_local_ciphernodes(&bus, &rng, 2, &cipher, zk_backend.clone()).await?;
        let eth_addrs = ciphernodes.iter().map(|n| n.address()).collect::<Vec<_>>();

        setup_score_sortition_environment(&bus, &eth_addrs, 1).await?;

        let [cn1, cn2] = &ciphernodes.as_slice() else {
            panic!("Not enough elements")
        };

        // Send e3request
        bus.publish_without_context(E3Requested {
            e3_id: e3_id.clone(),
            threshold_m: 2,
            threshold_n: 2,
            seed,
            params: ArcBytes::from_bytes(&encode_bfv_params(&params)),
            ..E3Requested::default()
        })?;

        bus.publish_without_context(CommitteeFinalized {
            e3_id: e3_id.clone(),
            committee: eth_addrs.clone(),
            scores: compute_committee_scores(&eth_addrs, &e3_id, seed),
            chain_id: 1,
        })?;

        let history_collector = cn1.history().unwrap();
        let error_collector = cn1.errors().unwrap();
        let history = history_collector
            .send(TakeEvents::<e3_events::InterfoldEvent>::new(14))
            .await?;
        let errors = error_collector.send(GetEvents::new()).await?;

        assert_eq!(errors.len(), 0);

        // SEND SHUTDOWN!
        bus.publish_without_context(Shutdown)?;

        // This is probably overkill but required to ensure that all the data is written
        sleep(Duration::from_secs(1)).await;

        // Unwrap does not matter as we are in a test
        let cn1_dump = cn1.in_mem_store().unwrap().send(GetDump).await??;
        let cn2_dump = cn2.in_mem_store().unwrap().send(GetDump).await??;

        (
            rng,
            cn1.address(),
            cn1_dump,
            cn2.address(),
            cn2_dump,
            cipher,
            history,
            params,
            crpoly,
        )
    };

    let bus = EventSystem::in_mem()
        .with_event_bus(
            EventBus::<e3_events::InterfoldEvent>::new(EventBusConfig { deduplicate: true })
                .start(),
        )
        .handle()?
        .enable("cn2");
    let cn1 = setup_local_ciphernode(
        &bus,
        &rng,
        true,
        &cn1_address,
        Some(InMemStore::from_dump(cn1_data, true)?.start()),
        &cipher,
        zk_backend.clone(),
    )
    .await?;
    let cn2 = setup_local_ciphernode(
        &bus,
        &rng,
        true,
        &cn2_address,
        Some(InMemStore::from_dump(cn2_data, true)?.start()),
        &cipher,
        zk_backend.clone(),
    )
    .await?;
    let history_collector = cn1.history().unwrap();
    simulate_libp2p_net(&[cn1, cn2]).await;

    println!("getting collector from cn1.6");

    // get the public key from history.
    let pubkey: PublicKey = history
        .events
        .iter()
        .filter_map(|evt| match evt.get_data() {
            InterfoldEventData::KeyshareCreated(data) => {
                PublicKeyShare::deserialize(&data.pubkey, &params, crpoly.clone()).ok()
            }
            _ => None,
        })
        .aggregate()?;

    // Publish the ciphertext
    use e3_test_helpers::encrypt_ciphertext;
    let raw_plaintext = vec![vec![4, 5]];
    let (ciphertext, expected) = encrypt_ciphertext(&params, pubkey, raw_plaintext)?;
    bus.publish_without_context(CiphertextOutputPublished {
        ciphertext_output: ciphertext
            .iter()
            .map(|ct| ArcBytes::from_bytes(&ct.to_bytes()))
            .collect(),
        e3_id: e3_id.clone(),
    })?;

    let history = history_collector
        .send(TakeEvents::<e3_events::InterfoldEvent>::new(5))
        .await?;

    let actual = history
        .events
        .into_iter()
        .filter_map(|e| match e.into_data() {
            InterfoldEventData::PlaintextAggregated(data) => Some(data),
            _ => None,
        })
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .clone();

    assert_eq!(
        actual
            .decrypted_output
            .iter()
            .map(|b| decode_bytes_to_vec_u64(b).unwrap())
            .collect::<Vec<Vec<u64>>>(),
        expected
            .iter()
            .map(|p| decode_plaintext_to_vec_u64(p).unwrap())
            .collect::<Vec<Vec<u64>>>()
    );

    Ok(())
}

/// Test that duplicate E3 IDs work correctly with different chain IDs.
/// This test needs to be ported to use trBFV instead of legacy keyshare.
#[actix::test]
#[ignore = "Needs to be ported to trBFV system"]
async fn test_duplicate_e3_id_with_different_chain_id() -> Result<()> {
    use e3_events::{OrderedSet, PublicKeyAggregated, TakeEvents};
    use e3_test_helpers::{
        create_random_eth_addrs, create_shared_rng_from_u64, get_common_setup, simulate_libp2p_net,
    };
    use fhe::{
        bfv::{BfvParameters, PublicKey, SecretKey},
        mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare},
    };
    use fhe_traits::Serialize;

    type PkSkShareTuple = (PublicKeyShare, SecretKey, String);

    async fn setup_local_ciphernode(
        bus: &BusHandle,
        rng: &e3_utils::SharedRng,
        logging: bool,
        _addr: &str,
        store: Option<actix::Addr<e3_data::InMemStore>>,
        cipher: &Arc<Cipher>,
        zk_backend: ZkBackend,
    ) -> Result<e3_ciphernode_builder::CiphernodeHandle> {
        let mut builder = CiphernodeBuilder::new(rng.clone(), cipher.clone())
            .with_trbfv()
            .with_zkproof(zk_backend)
            .with_signer(PrivateKeySigner::random())
            .with_forked_bus(bus.event_bus())
            .with_history_collector()
            .with_error_collector()
            .with_pubkey_aggregation()
            .with_threshold_plaintext_aggregation()
            .with_sortition_score();

        if let Some(ref in_mem_store) = store {
            builder = builder.with_in_mem_datastore(in_mem_store);
        }

        if logging {
            builder = builder.with_logging()
        }

        let node = builder.build().await?;
        Ok(node)
    }

    async fn create_local_ciphernodes(
        bus: &BusHandle,
        rng: &e3_utils::SharedRng,
        count: u32,
        cipher: &Arc<Cipher>,
        zk_backend: ZkBackend,
    ) -> Result<Vec<e3_ciphernode_builder::CiphernodeHandle>> {
        let eth_addrs = create_random_eth_addrs(count);
        let mut result = vec![];
        for addr in &eth_addrs {
            println!("Setting up eth addr: {}", addr);
            let tuple =
                setup_local_ciphernode(bus, rng, true, addr, None, cipher, zk_backend.clone())
                    .await?;
            result.push(tuple);
        }
        simulate_libp2p_net(&result).await;
        Ok(result)
    }

    fn generate_pk_share(
        params: &Arc<BfvParameters>,
        crp: &CommonRandomPoly,
        rng: &e3_utils::SharedRng,
        addr: &str,
    ) -> Result<PkSkShareTuple> {
        let sk = SecretKey::random(params, &mut *rng.lock().unwrap());
        let pk = PublicKeyShare::new(&sk, crp.clone(), &mut *rng.lock().unwrap())?;
        Ok((pk, sk, addr.to_owned()))
    }

    fn generate_pk_shares(
        params: &Arc<BfvParameters>,
        crp: &CommonRandomPoly,
        rng: &e3_utils::SharedRng,
        eth_addrs: &Vec<String>,
    ) -> Result<Vec<PkSkShareTuple>> {
        let mut result = vec![];
        for addr in eth_addrs {
            result.push(generate_pk_share(params, crp, rng, addr)?);
        }
        Ok(result)
    }

    fn aggregate_public_key(shares: &[PkSkShareTuple]) -> Result<PublicKey> {
        Ok(shares.iter().map(|(pk, _, _)| pk.clone()).aggregate()?)
    }

    // Setup
    let (bus, rng, seed, params, crpoly, _, _) = get_common_setup(None)?;
    let cipher = Arc::new(Cipher::from_password("Don't tell anyone my secret").await?);
    let (zk_backend, _zk_temp) =
        setup_test_zk_backend(select_benchmark_params().preset_subdir).await?;

    // Setup actual ciphernodes and dispatch add events
    let ciphernodes = create_local_ciphernodes(&bus, &rng, 3, &cipher, zk_backend.clone()).await?;
    let eth_addrs = ciphernodes.iter().map(|tup| tup.address()).collect();

    setup_score_sortition_environment(&bus, &eth_addrs, 1).await?;
    setup_score_sortition_environment(&bus, &eth_addrs, 2).await?;

    // Send the computation requested event
    bus.publish_without_context(E3Requested {
        e3_id: E3id::new("1234", 1),
        threshold_m: 2,
        threshold_n: 5,
        seed,
        params: ArcBytes::from_bytes(&encode_bfv_params(&params)),
        ..E3Requested::default()
    })?;

    bus.publish_without_context(CommitteeFinalized {
        e3_id: E3id::new("1234", 1),
        committee: eth_addrs.clone(),
        scores: compute_committee_scores(&eth_addrs, &E3id::new("1234", 1), seed),
        chain_id: 1,
    })?;

    // Generate the test shares and pubkey
    let rng_test = create_shared_rng_from_u64(42);
    let test_pubkey = aggregate_public_key(&generate_pk_shares(
        &params, &crpoly, &rng_test, &eth_addrs,
    )?)?;
    let history_collector = ciphernodes.last().unwrap().history().unwrap();
    let history = history_collector
        .send(TakeEvents::<e3_events::InterfoldEvent>::new(28))
        .await?;

    let actual_pubkey_agg_1 = match history.events.last().cloned().unwrap().into_data() {
        e3_events::InterfoldEventData::PublicKeyAggregated(ev) => ev,
        other => panic!("expected PublicKeyAggregated, got {other:?}"),
    };
    assert_eq!(
        history.events.last().cloned().unwrap().into_data(),
        PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&test_pubkey.to_bytes()),
            e3_id: E3id::new("1234", 1),
            nodes: OrderedSet::from(eth_addrs.clone()),
            committee_addresses: actual_pubkey_agg_1.committee_addresses.clone(),
            honest_committee_addresses: actual_pubkey_agg_1.honest_committee_addresses.clone(),
            pk_commitment: actual_pubkey_agg_1.pk_commitment,
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        }
        .into()
    );

    // Send the computation requested event
    bus.publish_without_context(E3Requested {
        e3_id: E3id::new("1234", 2),
        threshold_m: 2,
        threshold_n: 5,
        seed,
        params: ArcBytes::from_bytes(&encode_bfv_params(&params)),
        ..E3Requested::default()
    })?;

    bus.publish_without_context(CommitteeFinalized {
        e3_id: E3id::new("1234", 2),
        committee: eth_addrs.clone(),
        scores: compute_committee_scores(&eth_addrs, &E3id::new("1234", 2), seed),
        chain_id: 2,
    })?;

    let test_pubkey = aggregate_public_key(&generate_pk_shares(
        &params, &crpoly, &rng_test, &eth_addrs,
    )?)?;

    let history = history_collector
        .send(TakeEvents::<e3_events::InterfoldEvent>::new(8))
        .await?;

    let actual_pubkey_agg_2 = match history.events.last().cloned().unwrap().into_data() {
        e3_events::InterfoldEventData::PublicKeyAggregated(ev) => ev,
        other => panic!("expected PublicKeyAggregated, got {other:?}"),
    };
    assert_eq!(
        history.events.last().cloned().unwrap().into_data(),
        PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&test_pubkey.to_bytes()),
            e3_id: E3id::new("1234", 2),
            nodes: OrderedSet::from(eth_addrs.clone()),
            committee_addresses: actual_pubkey_agg_2.committee_addresses.clone(),
            honest_committee_addresses: actual_pubkey_agg_2.honest_committee_addresses.clone(),
            pk_commitment: actual_pubkey_agg_2.pk_commitment,
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        }
        .into()
    );

    Ok(())
}
