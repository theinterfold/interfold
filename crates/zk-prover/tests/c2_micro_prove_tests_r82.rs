// SPDX-License-Identifier: LGPL-3.0-only
//
//! r82 — the C2 per-recipient PROVE curve's SECOND RAN point: the secure-8192/micro (N=9/T=4/H=5)
//! C2a/C2b leaf PROVE walls on this 4c/7.8 GiB box. r75 RAN the curve's min endpoint (N=3):
//! c2a 15.7 s / c2b 28.8 s @4c RAN (poc/r75/r75_fn_out.txt). r80 RAN the micro GATE endpoints
//! (c2a 4,283,789 / c2b 5,726,442 g, sha-pinned 96aae9c6…/588dbfa7…) and r81 RAN the micro
//! COMPILE walls (c2a 910.65 s @7.34 GiB peak / c2b 1179.75 s @7.39 GiB, Swaps 0, both
//! bit-reproducible) — but the micro PROVE wall was never measured: the N=19 node wall table's
//! (model.py) single residual DRAFT is the C2 SMALL per-recipient PROVE delta, and this leg gives
//! it a 2pt RAN anchor at micro (min + micro) to RAN-extrapolate the small endpoint (linearity,
//! flagged as the one DRAFT assumption; the small C2 LEAVES themselves OOM-compile on-box r45).
//! Fit evidence for the PROVE (compile is already RAN at r81): c2b-micro 5.73M gates < the M7x
//! 5.94M-gate circuit this box RAN-proved at 7.47 GiB peak / Swaps 0 (r70); the r52 b10 8.35M-gate
//! prove peaked 4.04 GB at 16 GiB class. Witness arrays are the same class as min (9 vs 3 parties
//! in [N][moduli] share arrays) ⇒ the 7.8 GiB box is expected to carry both proves (c2a first as
//! the smaller 4.28M-gate leg).
//!
//! Artifacts: the stage tree is the r76/r81 sha-pinned micro C2 jsons (on-disk bin/dkg/target,
//! r81 bit-reproducible) + FRESHLY write_vk'd noir-recursive VKs (r75/r77 convention: never
//! reuse an off-class on-disk .vk) — poc/r82/stage_micro.sh builds it:
//!   <root>/secure-8192/micro/recursive/dkg/<sk_...|e_sm_share_computation>/{nn.json,nn.vk,nn.vk_hash}
//!
//! Run (quiet box, release): E3_R82_STAGE_ROOT=/home/dev/interfold-research/poc/r82/root \
//!   cargo test --release -p e3-zk-prover --test c2_micro_prove_tests_r82 -- --nocapture

mod common;
#[path = "common/node_fold_witness.rs"]
mod node_fold_witness;

use std::path::{Path, PathBuf};
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitVariant;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::Computation;
use e3_zk_helpers::dkg::share_computation::ShareComputationCircuit;
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{Provable, ZkProver};
use node_fold_witness::{
    pk_generation_sample_with_esi, share_computation_esm_from_esi, share_computation_sk_from_pk,
};

const COMMITTEE: &str = "micro";

async fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut rd = tokio::fs::read_dir(src).await?;
    while let Some(e) = rd.next_entry().await? {
        let t = e.path();
        let target = dst.join(e.file_name());
        if t.is_dir() {
            Box::pin(copy_dir(&t, &target)).await?;
        } else {
            tokio::fs::copy(&t, &target).await?;
        }
    }
    Ok(())
}

fn stage_root() -> PathBuf {
    match std::env::var("E3_R82_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R82_STAGE_ROOT unset — run poc/r82/stage_micro.sh first"),
    }
}

#[tokio::test]
async fn c2_micro_prove_walls() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join(COMMITTEE);
    assert!(preset_tree.is_dir(), "stage tree {preset_tree:?} missing — run poc/r82/stage_micro.sh");

    let (backend, _temp) = setup_test_prover(&bb).await;
    // Hand the pre-built secure-8192/micro tree (C2 pair only) into this run's backend (isolate; no on-disk bin writes).
    copy_dir(
        &preset_tree,
        &backend.circuits_dir.join("secure-8192").join(COMMITTEE),
    )
    .await
    .expect("stage tree handoff");

    let preset = BfvPreset::SecureThreshold8192;
    let committee = CiphernodesCommitteeSize::Micro.values();
    assert_eq!((committee.n, committee.threshold, committee.h), (9, 4, 5), "micro committee (N=9/T=4/H=5)");
    let prover = ZkProver::new(&backend);
    let ad = preset.artifacts_dir_for_committee(COMMITTEE);
    assert_eq!(ad, format!("secure-8192/{COMMITTEE}"));

    // ---- correlated sample chain (same secrets: C1 <-> C2 commitments align), micro committee. ----
    let (pk_gen, esi, pk_secret_key) =
        pk_generation_sample_with_esi(preset, committee.clone())
            .expect("pk + esi correlated sample");
    let share_sk = share_computation_sk_from_pk(preset, committee.clone(), &pk_gen, &pk_secret_key)
        .expect("C2a data");
    let share_esm = share_computation_esm_from_esi(preset, committee.clone(), &pk_gen, &esi)
        .expect("C2b data");
    let _ = e3_zk_helpers::dkg::share_computation::Inputs::compute(preset, &share_sk).expect("C2a inputs");
    let _ = e3_zk_helpers::dkg::share_computation::Inputs::compute(preset, &share_esm).expect("C2b inputs");

    // leaves (Recursive variant — the proof kind node_fold embeds), micro committee. c2a first
    // (4.28M gates < c2b 5.73M): if the RAM wall bites, c2a's number is already on stdout.
    let mut wall = Vec::new();
    let mut t = Instant::now();
    let c2a_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_sk, "e3-r82-c2a", CircuitVariant::Recursive, &ad)
        .expect("C2a proof (micro)");
    wall.push(("c2a", t.elapsed().as_secs_f64(), c2a_proof.public_signals.len() / 32));
    t = Instant::now();
    let c2b_proof = ShareComputationCircuit
        .prove_with_variant(&prover, &preset, &share_esm, "e3-r82-c2b", CircuitVariant::Recursive, &ad)
        .expect("C2b proof (micro)");
    wall.push(("c2b", t.elapsed().as_secs_f64(), c2b_proof.public_signals.len() / 32));

    // top-level verify both (Recursive variant, against the freshly staged VKs).
    let vok_a = prover.verify_proof(&c2a_proof, "e3-r82-vfy-a", 0, &ad).expect("verify c2a");
    let vok_b = prover.verify_proof(&c2b_proof, "e3-r82-vfy-b", 0, &ad).expect("verify c2b");
    println!("R82 verify_proof(c2a) = {vok_a}  RAN");
    println!("R82 verify_proof(c2b) = {vok_b}  RAN");
    assert!(vok_a, "c2a proof must verify");
    assert!(vok_b, "c2b proof must verify");

    for (label, secs, npub) in &wall {
        println!("R82-leaf {label} = {secs:.1}s  publics={npub}  RAN");
    }
    drop(_temp);
}