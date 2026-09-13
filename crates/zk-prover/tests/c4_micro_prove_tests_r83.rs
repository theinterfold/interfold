// SPDX-License-Identifier: LGPL-3.0-only
//
//! r83 - the C4 per-H PROVE curve's SECOND RAN point: the secure-8192/micro (N=9/T=4/H=5)
//! C4a/C4b (share_decryption, both DkgInputType lanes) leaf PROVE walls on this 4c/7.8 GiB
//! box. r75 RAN the curve's min endpoint (N=3/T=1/H=2): c4a 18.2 s / c4b 18.1 s @4c RAN
//! (poc/r75/r75_fn_out.txt). r48 RAN the micro COMPILE gate (2,418,273 g / 655,396 ACIR,
//! r46-era toolchain) - but the micro PROVE wall was never measured, and the N=19 node wall
//! table's (model.py r76) C4 min->small scaling is a PURE 1-point RAN ratio (x2.0455 =
//! C4 gate small/min, r46) with NO second RAN anchor on the PROVE side. This leg gives the
//! C4 PROVE curve its 2pt RAN min->micro basis exactly as r82 gave the C2 pair:
//! H scales C4 N-parties-invariant (R48/R49 source-verified: C4 reads ONLY H; N/T 0 refs),
//! so H 2->5 spin = C4 committee scaling itself. Fit evidence for the PROVE (compile
//! already RAN): C4 micro 2.42M gates < C2b micro 5.73M (R82 PROVE, 7.4 GiB peak with
//! witness margin) and < M7x 5.94M (R70, 7.47 GiB); C4 secure MIN PROVE RAN 4.17 GiB class
//! (r46 architecture; r75 min leg 4.54 GiB whole) => the 7.8 GiB box should carry both
//! micro proves (c4a first = same-circuit anchor).
//!
//! Artifacts: the stage tree carries the fresh R83 secure-8192/micro C4 json (leg
//! `r83_c4_micro_compile.sh`; sha-pin R83_GATE digit-match to R48 2,418,273 g) +
//! freshly write_vk'd noir-recursive VKs (r75/r77 convention: don't reuse off-class
//! on-disk .vk - the on-disk bin C4 .vk is the INSECURE-512 class).
//!   <root>/secure-8192/micro/recursive/dkg/share_decryption/{share_decryption.json,.vk,.vk_hash}
//!
//! Run (quiet box, release): E3_R83_STAGE_ROOT=/home/dev/interfold-research/poc/r83/root \
//!   cargo test --release -p e3-zk-prover --test c4_micro_prove_tests_r83 -- --nocapture

mod common;

use std::path::{Path, PathBuf};
use std::time::Instant;

use common::{find_bb, setup_test_prover};
use e3_events::CircuitVariant;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::computation::DkgInputType;
use e3_zk_helpers::dkg::share_decryption::{ShareDecryptionCircuit, ShareDecryptionCircuitData};
use e3_zk_helpers::CiphernodesCommitteeSize;
use e3_zk_prover::{Provable, ZkProver};

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
    match std::env::var("E3_R83_STAGE_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => panic!("E3_R83_STAGE_ROOT unset - run poc/r83/r83_stage_c4_micro.sh first"),
    }
}

#[tokio::test]
async fn c4_micro_prove_walls() {
    let Some(bb) = find_bb().await else {
        println!("skipping: bb not found");
        return;
    };
    let root = stage_root();
    let preset_tree = root.join("secure-8192").join(COMMITTEE);
    assert!(preset_tree.is_dir(), "stage tree {preset_tree:?} missing - run poc/r83/r83_stage_c4_micro.sh");

    let (backend, _temp) = setup_test_prover(&bb).await;
    // Hand the pre-built secure-8192/micro C4 leaf into this run's backend (isolated; no on-disk bin writes).
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

    // Honest rows triplicated: all H rows = a copy of row0, keeping the H=5
    // decryption rows self-consistent (r75 min leg's pattern; the own slot
    let trip = |mut d: ShareDecryptionCircuitData| -> ShareDecryptionCircuitData {
        let row0 = d.honest_ciphertexts[0].clone();
        d.honest_ciphertexts = (0..d.honest_ciphertexts.len()).map(|_| row0.clone()).collect();
        d
    };
    let c4a_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SecretKey).expect("c4a"));
    let c4b_data = trip(ShareDecryptionCircuitData::generate_sample(preset, committee.clone(), DkgInputType::SmudgingNoise).expect("c4b"));

    // Leaves (Recursive variant - the proof kind the R75 function embeds), micro committee.
    // c4a first: same-circuit anchor is guaranteed on stdout if the later RAM won't.
    let mut wall = Vec::new();
    let mut t = Instant::now();
    let c4a_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4a_data, "e3-r83-c4a", CircuitVariant::Recursive, &ad)
        .expect("C4a proof (micro)");
    wall.push(("c4a", t.elapsed().as_secs_f64(), c4a_proof.public_signals.len() / 32));
    t = Instant::now();
    let c4b_proof = ShareDecryptionCircuit
        .prove_with_variant(&prover, &preset, &c4b_data, "e3-r83-c4b", CircuitVariant::Recursive, &ad)
        .expect("C4b proof (micro)");
    wall.push(("c4b", t.elapsed().as_secs_f64(), c4b_proof.public_signals.len() / 32));

    // Top-level verify both (Recursive variant, against the freshly staged VKs).
    let vok_a = prover.verify_proof(&c4a_proof, "e3-r83-vfy-a", 0, &ad).expect("verify c4a");
    let vok_b = prover.verify_proof(&c4b_proof, "e3-r83-vfy-b", 0, &ad).expect("verify c4b");
    println!("R83 verify_proof(c4a) = {vok_a}  RAN");
    println!("R83 verify_proof(c4b) = {vok_b}  RAN");
    assert!(vok_a, "c4a proof must verify");
    assert!(vok_b, "c4b proof must verify");

    for (label, secs, npub) in &wall {
        println!("R83-leaf {label} = {secs:.1}s  publics={npub}  RAN");
    }
    drop(_temp);
}