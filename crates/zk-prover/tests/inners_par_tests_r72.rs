// SPDX-License-Identifier: LGPL-3.0-only
//
//! r72 — I72 inners-concurrency boundary probe (production N=19, secure-8192/small).
//!
//! Premise (source RAN, re-verified this round): the 108 inners = 78.9% of the per-node c3-bulk
//! DKG wall (r69 RAN 4196.3 s @4c SERIAL). Production dispatches every inner as an independent
//! concurrent TaskPool job (TaskPool `concurrent_jobs`; ciphernode default = all threads, pool.rs
//! + ciphernode_builder.rs:939-943) ⇒ a 4c production node proves inners 4-at-a-time, but the
//! inners term was only ever RAN-measured SERIALLY (r69 38.85 s/inner; r70 re-run 40.26).
//! This leg RANs the concurrency boundary cheaply (10 fresh inners, not 108):
//!   Phase S: 4 inners serial       — per-inner solo wall + CPU busy (cores to saturate one inner).
//!   Phase P2: 2 FRESH inners, 2-way parallel (std::thread::scope, shared ZkProver) — wall + busy.
//!   Phase P4: 4 FRESH inners, 4-way parallel (the 4c production-node shape) — wall + busy +
//!             process VmHWM delta + system MemAvailable/SwapFree before/after (the RAM-fit
//!             check r69/r66 left as a box-2 DRAFT; OOM/kill is a RAN ceiling find, not a fail).
//! Load-bearing rows: (1) does ONE inner saturate the 4c box (busy ≈ 4.0 ⇒ K-way parallel buys
//! ~0 wall at 4c); (2) P2/P4 wall gain at 4c; (3) does 4-concurrent fit 7.8 GiB ⇒ on-box
//! rescoping of the batched-inners lever + the 4c solo anchors for the >=8c projection.
//!
//! Run: `cargo test --release -p e3-zk-prover --test inners_par_tests_r72 -- --nocapture`
//! (quiet box, release, ~7 min wall; out teed to /tmp/r72_inners_par_out.txt + poc/r72/).
//!
//! Untracked test only — no repo source change, no circuit rebuild (secure-8192/small leaf set
//! staged on disk 08-28 per the r65/r69 pattern; the r70 leg re-confirmed that artifact set).

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitVariant;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_encryption::{ShareEncryptionCircuit, ShareEncryptionCircuitData};
use e3_zk_helpers::{CiphernodesCommittee, CiphernodesCommitteeSize};
use e3_zk_prover::{Provable, ZkBackend, ZkProver};

const COMMITTEE: &str = "small";
const N_CORES: f64 = 4.0;

/// (busy jiffies, total jiffies) summed over all cores, guest ignored: busy = user+nice+system+
/// irq+softirq+steal (idle and iowait excluded — a blocked-on-procfs reader still burns a core).
fn cpu_busy() -> (i64, i64) {
    let s = std::fs::read_to_string("/proc/stat").expect("read /proc/stat");
    let n: Vec<i64> = s
        .lines()
        .next()
        .and_then(|f| {
            let v: Vec<i64> = f
                .split_whitespace()
                .skip(1)
                .filter_map(|t| t.parse().ok())
                .collect();
            if v.len() >= 8 {
                Some(v)
            } else {
                None
            }
        })
        .expect("/proc/stat cpu line fields");
    let busy = n[0] + n[1] + n[2] + n[5] + n[6] + n[7];
    (busy, busy + n[3] + n[4])
}

fn val_mb(prefix: &str) -> f64 {
    let k = std::fs::read_to_string("/proc/meminfo")
        .expect("read /proc/meminfo")
        .lines()
        .find(|l| l.starts_with(prefix))
        .expect("meminfo key")
        .split_whitespace()
        .nth(1)
        .expect("meminfo value")
        .parse::<f64>()
        .expect("meminfo parse");
    k / 1024.0
}

fn vmhwm_mb() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("self status")
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<f64>().ok())
        .map(|k| k / 1024.0)
        .unwrap_or(0.0)
}

/// Stage the on-disk secure-8192/small recursive share_encryption leaf into the temp backend
/// (r70 pattern: `stage_circuit` for the dkg group, recursive variant). The secure leaf set was
/// staged 08-28 (r61_stage.sh) and is what the r70 leg ran against.
async fn stage_secure_leaf(backend: &ZkBackend) {
    let pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../circuits/bin/dkg/target");
    let json = pkg_dir.join("share_encryption.json");
    let vk = pkg_dir.join("share_encryption.vk_noir");
    let vk_h = pkg_dir.join("share_encryption.vk_noir_hash");
    assert!(
        json.exists(),
        "missing secure-8192/small share_encryption.json — run poc/r61_stage.sh first"
    );
    let (vk_src, hash_src) = if vk.exists() {
        (vk, vk_h)
    } else {
        (pkg_dir.join("share_encryption.vk_recursive"), pkg_dir.join("share_encryption.vk_recursive_hash"))
    };
    let base = backend.circuits_dir.join("secure-8192").join(COMMITTEE);
    let dest = base.join("recursive").join("dkg").join("share_encryption");
    tokio::fs::create_dir_all(&dest).await.unwrap();
    tokio::fs::copy(&json, dest.join("share_encryption.json")).await.unwrap();
    assert!(vk_src.exists(), "no recursive VK for share_encryption");
    tokio::fs::copy(&vk_src, dest.join("share_encryption.vk")).await.unwrap();
    if hash_src.exists() {
        tokio::fs::copy(&hash_src, dest.join("share_encryption.vk_hash")).await.unwrap();
    }
}

/// Prove `n` FRESH inners (independent samples) in `par`-way std::thread::scope blocks, sharing
/// one ZkProver + backend across threads (the production shape: one ZkProver behind an actor,
/// TaskPool rayon threads each `StdCommand::new(bb).output()` — there is no per-prove in-process
/// global state; prover.rs:215/385 confirm the prove call is a spawned subprocess).
fn phase(
    label: &str,
    par: usize,
    n: usize,
    prover: Arc<ZkProver>,
    preset: BfvPreset,
    committee: CiphernodesCommittee,
    ad: String,
    z: u128,
    dd: u64,
) -> (f64, f64, f64) {
    let h0 = vmhwm_mb();
    let mema0 = val_mb("MemAvailable:");
    let swap0 = val_mb("SwapFree:");
    let (b0, t0) = cpu_busy();
    let t = Instant::now();
    let mut done = 0usize;
    for block in 0..(n + par - 1) / par {
        std::thread::scope(|sc| {
            for w in 0..par.min(n - block * par) {
                let pi = dd + block as u64 * par as u64 + w as u64;
                let prover = Arc::clone(&prover);
                let preset = preset.clone();
                let committee = committee.clone();
                let ad = ad.clone();
                sc.spawn(move || {
                    let presenter = ShareEncryptionCircuit;
                    let sample = ShareEncryptionCircuitData::generate_sample(
                        preset,
                        committee.clone(),
                        DkgInputType::SecretKey,
                        z,
                    )
                    .expect("r72 sample");
                    let _ = presenter.prove_with_variant(
                        &prover,
                        &BfvPreset::SecureThreshold8192,
                        &sample,
                        &format!("e3-r72-{label}-i{pi}"),
                        CircuitVariant::Recursive,
                        &ad,
                    );
                });
            }
        });
        done += par.min(n - block * par);
    }
    let wall = t.elapsed().as_secs_f64();
    let (b1, t1) = cpu_busy();
    let dt = t1 - t0;
    let busy_cores = if dt > 0 { (b1 - b0) as f64 / dt as f64 } else { 0.0 };
    let h1 = vmhwm_mb();
    let mema1 = val_mb("MemAvailable:");
    let swap1 = val_mb("SwapFree:");
    println!(
            "  [{label}] n={n} par={par}: wall={wall:.1}s ({} inners) avg={:.2}s/inner busy={busy_cores:.2} cores (of {N_CORES})  VmHWM {} -> {} MB (phase-+{:.0})  MemAvailable {:.0} -> {:.0}  SwapFree {:.0} -> {:.0}  RAN",
            done, done as f64 / wall, h1 - h0, h0, h1, mema0, mema1, swap0, swap1
        );
    (wall, busy_cores, h1 - h0)
}

#[tokio::test]
async fn inners_par_boundary() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let sd = BfvPreset::SecureThreshold8192
        .search_defaults()
        .expect("secure search defaults");
    let _ = sd;
    let (backend, _temp) = setup_test_prover(&bb).await;
    stage_secure_leaf(&backend).await;
    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Small.values();
    let prover = Arc::new(ZkProver::new(&backend));
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);
    println!("r72 inners-par boundary probe (secure-8192/small, node P=1 W_1 class inners)");
    let z = sd.z;
    let (ws, bs, _) = phase("S", 1, 4, Arc::clone(&prover), preset.clone(), committee.clone(), ad.clone(), z, 0);
    let (w2, b2, _) = phase("P2", 2, 2, Arc::clone(&prover), preset.clone(), committee.clone(), ad.clone(), z, 10);
    let (w4, b4, _) = phase("P4", 4, 4, Arc::clone(&prover), preset.clone(), committee.clone(), ad.clone(), z, 20);
    println!(
        "  SUMMARY (RAN, same box @4c): solo={:.1}s busy={:.2}cores  P2 wall={w2:.1}s busy={b2:.2}  P4 wall={w4:.1}s busy={b4:.2}  S-total({:.1}s/4 inners)@par1-serial-reference  P4-vs-serial(4 inners): serial-DRAFT=4*{:.1}={:.1}s",
        ws / 4.0, bs, ws, ws / 4.0,
        4.0 * (ws / 4.0)
    );
    drop(_temp);
}